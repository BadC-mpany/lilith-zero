// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use clap::{Parser, Subcommand};
use lilith_zero::mcp::supervisor;
use std::sync::Arc;
use tracing::info;

use lilith_zero::config::Config;
use lilith_zero::mcp::server::McpMiddleware;

use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    upstream_cmd: Option<String>,

    #[arg(long)]
    policy: Option<PathBuf>,

    #[arg(long)]
    audit_logs: Option<PathBuf>,

    #[arg(long)]
    telemetry_link: Option<String>,

    #[arg(last = true)]
    upstream_args: Vec<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(hide = true, name = "__supervisor")]
    __Supervisor {
        #[arg(long)]
        parent_pid: u32,

        cmd_args: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Description: Executes the main logic.
    let cli = Cli::parse();

    install_panic_hook();

    let mut config = Config::from_env().unwrap_or_else(|e| {
        eprintln!(
            "Warning: Failed to load config from env, using defaults: {}",
            e
        );
        Config::default()
    });

    if let Some(p) = &cli.policy {
        config.policies_yaml_path = Some(p.clone());
    }

    if let Err(e) = init_tracing(&config) {
        eprintln!("Failed to init tracing: {}", e);
    }

    if let Some(Commands::__Supervisor {
        parent_pid,
        cmd_args,
    }) = cli.command
    {
        if cmd_args.is_empty() {
            return Err("Missing command for supervisor".into());
        }
        let cmd = cmd_args[0].clone();
        let args = cmd_args[1..].to_vec();

        supervisor::supervisor_main(parent_pid, cmd, args).await?;
        return Ok(());
    }

    info!("Starting lilith-zero in Middleware Mode");
    let upstream_cmd = cli
        .upstream_cmd
        .ok_or_else(|| anyhow::anyhow!("Missing --upstream-cmd"))?;
    info!("Upstream: {} {:?}", upstream_cmd, cli.upstream_args);

    #[cfg(feature = "telemetry")]
    {
        if let Some(link_str) = cli.telemetry_link {
            info!("Telemetry link provided, initializing FlockMember mode");
            let link = lilith_telemetry::FlockLink::parse(&link_str)?;
            lilith_telemetry::init(lilith_telemetry::DeploymentMode::FlockMember {
                target_api_endpoint: format!("{}:{}", link.host, link.port),
                auth_key: lilith_telemetry::crypto::KeyHandle(link.key_id),
            });
        } else {
            info!("No telemetry link provided, running in Alone mode");
            lilith_telemetry::init(lilith_telemetry::DeploymentMode::Alone);
        }
    }
    #[cfg(not(feature = "telemetry"))]
    {
        if cli.telemetry_link.is_some() {
            tracing::warn!("Telemetry link provided but telemetry feature is disabled");
        }
    }

    let mut middleware = McpMiddleware::new(
        upstream_cmd,
        cli.upstream_args,
        Arc::new(config),
        cli.audit_logs,
    )?;

    middleware.run().await?;

    Ok(())
}

fn install_panic_hook() {
    // Description: Executes the install_panic_hook logic.
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
    // Description: Executes the init_tracing logic.
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new("lilith_zero=debug,info"));

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
