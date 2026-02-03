// Main entry point for Sentinel MCP Middleware
use clap::Parser;
use std::sync::Arc;
use tracing::info;

use sentinel::config::Config;
use sentinel::mcp::server::McpMiddleware;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Upstream tool command (e.g., "python")
    #[arg(short, long)]
    upstream_cmd: Option<String>,

    /// Path to policy YAML file
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Upstream tool arguments (e.g. "tools.py")
    #[arg(last = true)]
    upstream_args: Vec<String>,

    /// explicit read permissions
    #[arg(long)]
    allow_read: Vec<String>,

    /// explicit write permissions
    #[arg(long)]
    allow_write: Vec<String>,

    /// explicit network permission
    #[arg(long)]
    allow_net: bool,

    /// explicit env vars
    #[arg(long)]
    allow_env: Vec<String>,

    /// Use a pre-defined language profile (e.g. "python:./venv")
    #[arg(long)]
    language_profile: Option<String>,

    /// Dry run: Prints the effective sandbox configuration and exits via stdout.
    #[arg(long)]
    dry_run: bool,

    /// Inspect a binary to find its dependencies (DLLs).
    #[arg(long)]
    inspect: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Install panic hook
    install_panic_hook();

    // Load config and init tracing
    let mut config = Config::from_env().unwrap_or_else(|e| {
        eprintln!(
            "Warning: Failed to load config from env, using defaults: {}",
            e
        );
        Config::default()
    });

    // Override policy from CLI
    if let Some(p) = &cli.policy { 
        config.policies_yaml_path = Some(p.clone());
    }

    // Configure Sandbox Policy
    let mut policy = sentinel::mcp::sandbox::SandboxPolicy::default();
    let mut use_sandbox = false;

    // 1. Load from YAML if exists (Base Layer)
    if let Some(path) = &config.policies_yaml_path {
        if let Ok(content) = std::fs::read_to_string(path) {
             if let Ok(policy_def) = serde_yaml::from_str::<sentinel::core::models::PolicyDefinition>(&content) {
                 if let Some(s) = policy_def.sandbox {
                     info!("Loaded sandbox policy from YAML");
                     policy = s;
                     use_sandbox = true;
                 }
             }
        }
    }

    // 2. Apply CLI Flags (Overlay Layer)
    if !cli.allow_read.is_empty() {
        use_sandbox = true;
        for p in cli.allow_read {
            policy.read_paths.push(PathBuf::from(p));
        }
    }
    if !cli.allow_write.is_empty() {
        use_sandbox = true;
        for p in cli.allow_write {
            policy.write_paths.push(PathBuf::from(p));
        }
    }
    if cli.allow_net {
        use_sandbox = true;
        policy.allow_network = true;
    }
    if !cli.allow_env.is_empty() {
        use_sandbox = true;
        policy.allow_env.extend(cli.allow_env);
    }

    // 3. Apply Language Profile (Profile Layer)
    if let Some(profile_str) = cli.language_profile {
        use_sandbox = true;
        let parts: Vec<&str> = profile_str.splitn(2, ':').collect();
        if parts.len() < 2 {
            eprintln!("Error: profile must be format 'lang:env_path[,core_path]', e.g. 'python:./venv' or 'python:./venv,C:\\Python312'");
            std::process::exit(1);
        }
        let lang = parts[0];
        let paths_str = parts[1];
        let paths: Vec<&str> = paths_str.split(',').collect();
        
        let env_path = paths[0];
        let core_path = paths.get(1).map(|&p| PathBuf::from(p));
        
        info!("Applying language profile: {} for env_path {}", lang, env_path);
        
        use sentinel::mcp::sandbox::SandboxProfile;
        match lang {
            "python" => {
                 let profile = sentinel::mcp::sandbox::profiles::python::PythonProfile::new(env_path, core_path);
                 profile.apply(&mut policy)?;
            },
            _ => {
                eprintln!("Error: Unknown language profile '{}'", lang);
                std::process::exit(1);
            }
        }
    }

    if use_sandbox {
        info!("Sandbox Enabled. Policy: {:?}", policy);
        config.sandbox = Some(policy.clone());
    } else {
        info!("Sandbox Disabled.");
    }
    
    if let Err(e) = init_tracing(&config) {
        eprintln!("Failed to init tracing: {}", e);
    }

    // DRY RUN / INSPECT LOGIC
    if cli.dry_run {
        println!("--- Dry Run: Effective Sandbox Configuration ---");
        if use_sandbox {
            println!("{}", serde_json::to_string_pretty(&policy).unwrap());
        } else {
            println!("No sandbox configuration.");
        }
        return Ok(());
    }

    if let Some(path) = cli.inspect {
        println!("--- Binary Inspection: {} ---", path.display());
        match sentinel::utils::pe::get_dependencies(&path) {
            Ok(deps) => {
                println!("Dependencies found:");
                for dep in deps {
                    println!("  - {}", dep);
                }
            },
            Err(e) => {
                eprintln!("Error inspecting binary: {}", e);
                std::process::exit(1);
            }
        }
        return Ok(());
    }


    info!("Starting Sentinel in Middleware Mode");
    let cmd = cli.upstream_cmd.ok_or_else(|| anyhow::anyhow!("Missing --upstream-cmd"))?;
    info!("Upstream: {} {:?}", cmd, cli.upstream_args);

    let mut middleware = McpMiddleware::new(cmd, cli.upstream_args, Arc::new(config))?;

    middleware.run().await?;

    Ok(())
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic_info| {
        let location = panic_info
            .location()
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
        .unwrap_or_else(|_| EnvFilter::new("sentinel=debug,info"));

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
