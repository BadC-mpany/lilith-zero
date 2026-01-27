// Main entry point for Sentinel MCP Middleware
use clap::Parser;
use std::sync::Arc;
use tracing::info;

use sentinel_interceptor::config::Config;
use sentinel_interceptor::mcp::server::McpMiddleware;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Upstream tool command (e.g., "python")
    #[arg(short, long)]
    upstream_cmd: String,

    /// Path to policy YAML file
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Upstream tool arguments (e.g. "tools.py")
    #[arg(last = true)]
    upstream_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Install panic hook
    install_panic_hook();

    // Load config and init tracing
    let mut config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("Warning: Failed to load config from env, using defaults: {}", e);
        Config::default()
    });

    // Override policy from CLI
    if let Some(p) = cli.policy {
        config.policies_yaml_path = Some(p);
    }
    
    if let Err(e) = init_tracing(&config) {
        eprintln!("Failed to init tracing: {}", e);
    }

    info!("Starting Sentinel in Middleware Mode");
    info!("Upstream: {} {:?}", cli.upstream_cmd, cli.upstream_args);

    // Bootstrap minimal infrastructure needed for MCP
    // In the future, we might re-introduce Redis/Supabase for cloud-sync,
    // but for standalone middleware, we can keep it simple.
    
    let mut middleware = McpMiddleware::new(
        cli.upstream_cmd, 
        cli.upstream_args,
        Arc::new(config)
    );
    
    middleware.run().await?;

    Ok(())
}

fn install_panic_hook() {
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
    }));
}

fn init_tracing(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;
    
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    let subscriber = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_writer(std::io::stderr);
    
    if config.log_format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
    
    Ok(())
}
