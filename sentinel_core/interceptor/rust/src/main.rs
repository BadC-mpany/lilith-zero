// Main entry point for Sentinel Interceptor

use sentinel_interceptor::api::{create_router, AppState, RedisStore as ApiRedisStore, ToolRegistry};
use sentinel_interceptor::auth::audit_logger::AuditLogger;
use sentinel_interceptor::auth::auth_middleware::AuthState;
use sentinel_interceptor::auth::customer_store::{DbCustomerStore, YamlCustomerStore};
use sentinel_interceptor::auth::policy_store::{DbPolicyStore, YamlPolicyStore};
use sentinel_interceptor::config::Config;
use sentinel_interceptor::core::crypto::CryptoSigner;
use sentinel_interceptor::core::models::HistoryEntry;
use sentinel_interceptor::loader::policy_loader::PolicyLoader;
use sentinel_interceptor::loader::tool_registry::ToolRegistry as ToolRegistryImpl;
use sentinel_interceptor::proxy::ProxyClientImpl;
use sentinel_interceptor::state::redis_store::RedisStore as RedisStoreImpl;
use sentinel_interceptor::state::policy_cache::MokaPolicyCache;
use sentinel_interceptor::api::evaluator_adapter::PolicyEvaluatorAdapter;

use std::sync::Arc;
use tracing::{error, info};
use tokio::signal;

/// Adapter to convert RedisStore struct to RedisStore trait
struct RedisStoreAdapter {
    inner: Arc<RedisStoreImpl>,
}

#[async_trait::async_trait]
impl ApiRedisStore for RedisStoreAdapter {
    async fn get_session_taints(&self, session_id: &str) -> Result<Vec<String>, String> {
        self.inner
            .get_taints(session_id)
            .await
            .map(|set| set.into_iter().collect())
            .map_err(|e| e.to_string())
    }
    
    async fn add_taint(&self, session_id: &str, tag: &str) -> Result<(), String> {
        self.inner
            .add_taint(session_id, tag)
            .await
            .map_err(|e| e.to_string())
    }
    
    async fn remove_taint(&self, _session_id: &str, _tag: &str) -> Result<(), String> {
        // Redis is append-only, taints are removed via TTL expiration
        Ok(())
    }
    
    async fn add_to_history(&self, session_id: &str, tool: &str, classes: &[String]) -> Result<(), String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        
        self.inner
            .add_history_entry(session_id, tool, classes, timestamp)
            .await
            .map_err(|e| e.to_string())
    }
    
    async fn get_session_history(&self, session_id: &str) -> Result<Vec<HistoryEntry>, String> {
        self.inner
            .get_history(session_id)
            .await
            .map_err(|e| e.to_string())
    }
    
    async fn ping(&self) -> Result<(), String> {
        // Use proper Redis PING command for reliable health checks
        // This avoids issues with broken connections and provides better error handling
        self.inner
            .ping()
            .await
            .map_err(|e| format!("Redis ping failed: {}", e))
    }
}

/// Adapter to convert ToolRegistry struct to ToolRegistry trait
struct ToolRegistryAdapter {
    inner: Arc<ToolRegistryImpl>,
}

#[async_trait::async_trait]
impl ToolRegistry for ToolRegistryAdapter {
    async fn get_tool_classes(&self, tool_name: &str) -> Result<Vec<String>, String> {
        Ok(self.inner.get_tool_classes(tool_name))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up panic hook to catch Redis connection panics
    std::panic::set_hook(Box::new(|panic_info| {
        let location = panic_info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        
        eprintln!("PANIC: {} at {}", message, location);
        
        // Check if this is a Redis connection panic
        if message.contains("Multiplexed connection driver") || message.contains("connection driver") {
            eprintln!("\nRedis connection panic detected!");
            eprintln!("This usually means:");
            eprintln!("  1. Redis connection was lost during runtime");
            eprintln!("  2. WSL port forwarding connection broke");
            eprintln!("  3. Redis server restarted or became unavailable");
            eprintln!("\nThe server will continue running, but Redis operations may fail.");
            eprintln!("Troubleshooting:");
            eprintln!("  - Check Redis is running: wsl redis-cli ping");
            eprintln!("  - Verify port forwarding: netsh interface portproxy show all");
            eprintln!("  - Restart Redis: wsl redis-cli shutdown && wsl redis-server --daemonize yes");
            eprintln!("  - Restart WSL if needed: wsl --shutdown (wait 10s)");
            eprintln!("\nNote: Health endpoint will report Redis as disconnected until reconnected.");
        }
    }));
    
    // 1. Load and validate configuration first (before any logging)
    let config = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };
    
    // 2. Initialize tracing subscriber with config values
    // Must be done only once - tracing panics if init() is called multiple times
    init_tracing(&config)?;
    
    info!("Starting Sentinel Interceptor (Rust)");
    
    info!(
        bind_address = %config.bind_address,
        port = config.port,
        "Configuration loaded"
    );
    
    // 3. Initialize Redis store with retry logic
    info!(redis_url = %config.redis_url, "Connecting to Redis...");
    let redis_store_impl = Arc::new(
        RedisStoreImpl::new(&config.redis_url)
            .await
            .map_err(|e| {
                error!(error = %e, redis_url = %config.redis_url, "Failed to initialize Redis store");
                eprintln!("\nRedis connection failed!");
                eprintln!("Error: {}", e);
                eprintln!("\nTroubleshooting for WSL Redis:");
                eprintln!("  1. Check Redis is running: wsl redis-cli ping");
                eprintln!("  2. Verify port forwarding: netsh interface portproxy show all");
                eprintln!("  3. If missing, run: .\\scripts\\setup_wsl_redis_forwarding.ps1");
                eprintln!("  4. Check REDIS_URL in .env file");
                eprintln!("  5. WSL can be slow - wait 30s after 'wsl --shutdown'");
                e
            })?
    );
    
    let redis_store = Arc::new(RedisStoreAdapter {
        inner: redis_store_impl,
    });
    
    info!("Redis store initialized");
    
    // 4. Initialize database pool (if configured)
    let db_pool: Option<Arc<sqlx::PgPool>> = if let Some(ref database_url) = config.database_url {
        Some(Arc::new(
            sqlx::PgPool::connect(database_url)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to connect to database");
                    e
                })?
        ))
    } else {
        None
    };
    
    if db_pool.is_some() {
        info!("Database pool initialized");
    }
    
    // 5. Initialize policy loader (YAML fallback)
    let policy_loader: Option<Arc<PolicyLoader>> = if let Some(ref policies_path) = config.policies_yaml_path {
        Some(Arc::new(
            PolicyLoader::from_file(policies_path)
                .map_err(|e| {
                    error!(error = %e, path = ?policies_path, "Failed to load policies");
                    e
                })?
        ))
    } else {
        None
    };
    
    if policy_loader.is_some() {
        info!("Policy loader initialized");
    }
    
    // 6. Initialize customer store (DB or YAML)
    // Use references to avoid moving db_pool and policy_loader
    let customer_store: Arc<dyn sentinel_interceptor::api::CustomerStore + Send + Sync> = 
        if let Some(ref pool) = db_pool {
            Arc::new(DbCustomerStore::new((**pool).clone()))
        } else if let Some(ref loader) = policy_loader {
            Arc::new(YamlCustomerStore::new((**loader).clone()))
        } else {
            return Err("Either DATABASE_URL or POLICIES_YAML_PATH must be set".into());
        };
    
    info!("Customer store initialized");
    
    // 7. Initialize policy store (DB or YAML)
    let policy_store: Arc<dyn sentinel_interceptor::api::PolicyStore + Send + Sync> = 
        if let Some(ref pool) = db_pool {
            Arc::new(DbPolicyStore::new((**pool).clone()))
        } else if let Some(ref loader) = policy_loader {
            Arc::new(YamlPolicyStore::new((**loader).clone()))
        } else {
            return Err("Either DATABASE_URL or POLICIES_YAML_PATH must be set".into());
        };
    
    info!("Policy store initialized");
    
    // 8. Initialize tool registry
    let tool_registry_impl = Arc::new(
        ToolRegistryImpl::from_file(&config.tool_registry_yaml_path)
            .map_err(|e| {
                error!(error = %e, path = ?config.tool_registry_yaml_path, "Failed to load tool registry");
                e
            })?
    );
    
    let tool_registry = Arc::new(ToolRegistryAdapter {
        inner: tool_registry_impl,
    });
    
    info!("Tool registry initialized");
    
    // 9. Initialize crypto signer
    let crypto_signer = Arc::new(
        CryptoSigner::from_pem_file(
            config.interceptor_private_key_path
                .to_str()
                .ok_or("Invalid private key path encoding")?
        )
        .map_err(|e| {
            error!(error = ?e, path = ?config.interceptor_private_key_path, "Failed to load private key");
            e
        })?
    );
    
    info!("Crypto signer initialized");
    
    // 10. Initialize policy evaluator adapter
    let evaluator = Arc::new(
        PolicyEvaluatorAdapter::new(redis_store.clone())
    );
    
    info!("Policy evaluator initialized");
    
    // 11. Initialize proxy client
    let proxy_client = Arc::new(
        ProxyClientImpl::new(config.mcp_proxy_timeout_secs)
            .map_err(|e| {
                error!(error = %e, "Failed to create proxy client");
                e
            })?
    );
    
    info!("Proxy client initialized");
    
    // 12. Initialize policy cache (Moka-based with 60s TTL, 1000 capacity)
    let policy_cache = Arc::new(
        MokaPolicyCache::new(
            policy_store.clone(),
            60,  // TTL: 60 seconds
            1000, // Max capacity: 1000 policies
        )
    );
    
    info!("Policy cache initialized");
    
    // 13. Initialize audit logger
    let audit_logger = Arc::new(
        AuditLogger::new(db_pool.clone())
    );
    
    info!("Audit logger initialized");
    
    // 14. Create AuthState
    let auth_state = Arc::new(AuthState {
        customer_store: customer_store.clone(),
        policy_store: policy_store.clone(),
        audit_logger: audit_logger.clone(),
        yaml_fallback: policy_loader.clone(),
    });
    
    // 15. Create AppState
    let app_state = AppState {
        crypto_signer,
        redis_store: redis_store.clone(),
        policy_cache,
        evaluator,
        proxy_client,
        customer_store,
        policy_store,
        tool_registry,
        config: Arc::new(config.clone()),
    };
    
    // 16. DEBUG: Force a check on AppState traits to identify any non-cloneable fields
    fn assert_router_state<S: Clone + Send + Sync + 'static>(_: &S) {}
    assert_router_state(&app_state);
    
    // 17. Create router (returns Router<AppState> - still "hungry" for state)
    // Pass reference to app_state since create_router only needs to read config values
    let router = create_router(&app_state, Some(auth_state));
    
    info!("Router created");
    
    // 18. Finalize the router by providing state
    // .with_state() converts Router<AppState> -> Router<()> (complete application)
    let app = router.with_state(app_state);
    
    // 19. Convert to MakeService (now possible because Router<()> implements IntoMakeService)
    let make_service = app.into_make_service();
    
    // 20. Start HTTP server
    let addr = format!("{}:{}", config.bind_address, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| {
            error!(error = %e, addr = %addr, "Failed to bind to address");
            e
        })?;
    
    info!(addr = %addr, "Server listening on {}", addr);
    
    axum::serve(listener, make_service)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| {
            error!(error = %e, "Server error");
            e
        })?;
    
    info!("Server shutdown complete");
    Ok(())
}


/// Initialize tracing subscriber based on configuration
fn init_tracing(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;
    
    // Parse log level
    let level = parse_log_level(&config.log_level)?;
    
    // Create filter from RUST_LOG env var or config
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    let subscriber = fmt()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_env_filter(filter);
    
    if config.log_format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
    
    Ok(())
}

/// Parse log level string to tracing Level
fn parse_log_level(level: &str) -> Result<tracing::Level, String> {
    match level.to_lowercase().as_str() {
        "trace" => Ok(tracing::Level::TRACE),
        "debug" => Ok(tracing::Level::DEBUG),
        "info" => Ok(tracing::Level::INFO),
        "warn" => Ok(tracing::Level::WARN),
        "error" => Ok(tracing::Level::ERROR),
        _ => Err(format!("Invalid log level: {}", level)),
    }
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };
    
    #[cfg(unix)]
    let terminate = async {
        use signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };
    
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    
    tokio::select! {
        _ = ctrl_c => {
            info!("Ctrl+C received, starting graceful shutdown");
        },
        _ = terminate => {
            info!("SIGTERM received, starting graceful shutdown");
        },
    }
    
    // Note: Do NOT sleep here - axum::serve's graceful_shutdown handles waiting
    // for existing connections to finish. Sleeping here delays the shutdown signal
    // and allows new connections to be accepted during the delay period.
}
