// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use clap::{Parser, Subcommand, ValueEnum};
use lilith_zero::mcp::supervisor;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;

use lilith_zero::config::Config;
use lilith_zero::mcp::server::McpMiddleware;

/// Transport mode for the upstream MCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Transport {
    /// Spawn a child process and communicate over stdio (default).
    Stdio,
    /// Connect to an upstream MCP server over Streamable HTTP (2025-11-25).
    Http,
}

/// Lilith Zero — deterministic MCP security middleware.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    // --- Backward-compatible flat-arg middleware mode ---
    /// Upstream MCP server command (backward-compat; prefer `lilith-zero run`).
    #[arg(short, long)]
    upstream_cmd: Option<String>,

    /// URL of an upstream Streamable HTTP MCP server (backward-compat; prefer `lilith-zero run --upstream-url`).
    /// Mutually exclusive with --upstream-cmd.
    #[arg(long)]
    upstream_url: Option<String>,

    /// Transport mode: stdio (child process) or http (Streamable HTTP).
    /// Inferred from --upstream-cmd / --upstream-url when omitted.
    #[arg(long)]
    transport: Option<Transport>,

    /// Policy YAML path (backward-compat; prefer `lilith-zero run`).
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Audit log output path (backward-compat; prefer `lilith-zero run`).
    #[arg(long)]
    audit_logs: Option<PathBuf>,

    /// Extra arguments forwarded to the upstream server after `--`.
    #[arg(last = true)]
    upstream_args: Vec<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run Lilith as MCP middleware (explicit form of the default flat-arg mode).
    ///
    /// stdio:  lilith-zero run --transport stdio -u "python server.py" --policy policy.yaml
    /// HTTP:   lilith-zero run --transport http --upstream-url http://localhost:8080/mcp --policy policy.yaml
    Run {
        /// Command to run the upstream MCP server (e.g. "python -u server.py").
        /// Mutually exclusive with --upstream-url.
        #[arg(short = 'u', long)]
        upstream_cmd: Option<String>,
        /// URL of an upstream Streamable HTTP MCP server.
        /// Mutually exclusive with --upstream-cmd.
        #[arg(long)]
        upstream_url: Option<String>,
        /// Transport mode: stdio or http. Inferred when omitted.
        #[arg(long)]
        transport: Option<Transport>,
        /// Path to policy YAML.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Path for audit log output.
        #[arg(long)]
        audit_logs: Option<PathBuf>,
        /// Extra arguments forwarded to the upstream server after `--`.
        #[arg(last = true)]
        upstream_args: Vec<String>,
    },

    /// Validate a policy YAML file without starting the middleware.
    ///
    /// Exit 0: valid (may have warnings). Exit 1: structural errors found.
    Validate {
        /// Path to the policy YAML file.
        policy: PathBuf,
    },

    /// Read and summarise a JSONL audit log file.
    ///
    /// Reports event counts, sessions, and structural integrity.
    /// Signature verification requires the ephemeral session key and is not
    /// supported offline.
    Audit {
        /// Path to the JSONL audit log file.
        log_file: PathBuf,
        /// Print each log entry payload in addition to the summary.
        #[arg(short, long)]
        verbose: bool,
    },

    /// Inspect or manage the tool-description pin store.
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },

    #[command(hide = true, name = "__supervisor")]
    __Supervisor {
        #[arg(long)]
        parent_pid: u32,

        cmd_args: Vec<String>,
    },

    /// Claude Code hook integration.
    ///
    /// Reads JSON from stdin and enforces security policies.
    Hook {
        /// Name of the hook event (e.g. "PreToolUse", "PostToolUse").
        /// Inferred from JSON if omitted.
        #[arg(short, long)]
        event: Option<String>,

        /// Path to policy YAML.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Path for audit log output.
        #[arg(long)]
        audit_logs: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum PinAction {
    /// Display all pinned tool descriptions.
    Show {
        /// Path to the pin JSON file.
        #[arg(short, long)]
        pin_file: PathBuf,
    },
    /// Remove all pins (next run re-pins from scratch).
    Reset {
        /// Path to the pin JSON file.
        #[arg(short, long)]
        pin_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    install_panic_hook();

    match cli.command {
        // --- Internal: process supervisor (hidden) ---
        Some(Commands::__Supervisor {
            parent_pid,
            cmd_args,
        }) => {
            if cmd_args.is_empty() {
                return Err("Missing command for supervisor".into());
            }
            let cmd = cmd_args[0].clone();
            let args = cmd_args[1..].to_vec();
            supervisor::supervisor_main(parent_pid, cmd, args).await?;
        }

        // --- Explicit middleware run subcommand ---
        Some(Commands::Run {
            upstream_cmd,
            upstream_url,
            transport,
            policy,
            audit_logs,
            upstream_args,
        }) => {
            let mut config = build_config(policy)?;
            apply_transport(&mut config, transport, upstream_cmd, upstream_url)?;
            let cmd = config.upstream_cmd.clone().unwrap_or_default();
            init_tracing(&config)?;
            print_banner();
            run_middleware(cmd, upstream_args, audit_logs, config).await?;
        }

        // --- Policy validation ---
        Some(Commands::Validate { policy }) => {
            validate_command(&policy)?;
        }

        // --- Audit log reading ---
        Some(Commands::Audit { log_file, verbose }) => {
            audit_command(&log_file, verbose)?;
        }

        // --- Pin store management ---
        Some(Commands::Pin { action }) => {
            pin_command(action)?;
        }

        // --- State persistence / Hook mode ---
        Some(Commands::Hook {
            event,
            policy,
            audit_logs,
        }) => {
            let config = build_config(policy)?;
            init_tracing(&config)?;
            run_hook(event, audit_logs, config).await?;
        }

        // --- Backward-compatible flat-arg middleware mode ---
        None => {
            let mut config = build_config(cli.policy)?;
            apply_transport(
                &mut config,
                cli.transport,
                cli.upstream_cmd,
                cli.upstream_url,
            )?;
            let cmd = config.upstream_cmd.clone().unwrap_or_default();
            init_tracing(&config)?;
            print_banner();
            run_middleware(cmd, cli.upstream_args, cli.audit_logs, config).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Middleware runner (shared by `run` subcommand and flat-arg backward compat)
// ---------------------------------------------------------------------------

async fn run_middleware(
    upstream_cmd: String,
    upstream_args: Vec<String>,
    audit_logs: Option<PathBuf>,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting lilith-zero");
    if config.upstream_http_url.is_some() {
        info!(
            "Transport: HTTP → {}",
            config.upstream_http_url.as_deref().unwrap_or("")
        );
    } else {
        info!("Transport: stdio → {} {:?}", upstream_cmd, upstream_args);
    }

    let mut middleware =
        McpMiddleware::new(upstream_cmd, upstream_args, Arc::new(config), audit_logs)?;

    middleware.run().await?;
    Ok(())
}

async fn run_hook(
    event_override: Option<String>,
    audit_logs: Option<PathBuf>,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use lilith_zero::hook::{HookHandler, HookInput};
    use std::io::Read;

    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    if buffer.trim().is_empty() {
        return Err("No input received on stdin".into());
    }

    let mut input: HookInput =
        serde_json::from_str(&buffer).map_err(|e| format!("Invalid hook JSON: {e}"))?;

    if let Some(ev) = event_override {
        input.hook_event_name = ev;
    }

    let mut handler = HookHandler::new(Arc::new(config), audit_logs)?;
    let exit_code = handler.handle(input).await?;

    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// `validate` command
// ---------------------------------------------------------------------------

fn validate_command(policy_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use lilith_zero::engine_core::models::PolicyDefinition;
    use lilith_zero::utils::policy_validator::{PolicyValidator, ValidationSeverity};

    let content = std::fs::read_to_string(policy_path)
        .map_err(|e| format!("Cannot read '{}': {e}", policy_path.display()))?;

    let policy: PolicyDefinition = serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("YAML parse error in '{}': {e}", policy_path.display()))?;

    let diagnostics = PolicyValidator::validate_policy_detailed(&policy);

    if diagnostics.is_empty() {
        println!(
            "OK  Policy '{}' is valid  ({} static rules, {} taint rules)",
            policy.name,
            policy.static_rules.len(),
            policy.taint_rules.len(),
        );
        return Ok(());
    }

    let error_count = diagnostics
        .iter()
        .filter(|d| d.severity == ValidationSeverity::Error)
        .count();
    let warn_count = diagnostics.len() - error_count;

    for d in &diagnostics {
        let tag = if d.severity == ValidationSeverity::Error {
            "ERROR"
        } else {
            "WARN "
        };
        println!("[{tag}] {}  —  {}", d.field_path, d.message);
        if let Some(s) = &d.suggestion {
            println!("       hint: {s}");
        }
    }

    println!();
    if error_count > 0 {
        Err(format!(
            "Policy '{}' has {error_count} error(s) and {warn_count} warning(s) — cannot be loaded",
            policy.name,
        )
        .into())
    } else {
        println!(
            "OK  Policy '{}' loaded with {warn_count} warning(s)",
            policy.name,
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `audit` command
// ---------------------------------------------------------------------------

fn audit_command(log_file: &Path, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(log_file)
        .map_err(|e| format!("Cannot read '{}': {e}", log_file.display()))?;

    let mut total: usize = 0;
    let mut parse_failures: usize = 0;
    let mut missing_sig: usize = 0;
    let mut event_counts: HashMap<String, usize> = HashMap::new();
    let mut decision_counts: HashMap<String, usize> = HashMap::new();
    let mut session_ids: HashSet<String> = HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        total += 1;

        let outer: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                parse_failures += 1;
                continue;
            }
        };

        if outer.get("signature").and_then(|v| v.as_str()).is_none() {
            missing_sig += 1;
        }

        let payload_raw = match outer.get("payload").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                parse_failures += 1;
                continue;
            }
        };

        let payload: serde_json::Value = match serde_json::from_str(payload_raw) {
            Ok(v) => v,
            Err(_) => {
                parse_failures += 1;
                continue;
            }
        };

        if let Some(et) = payload.get("event_type").and_then(|v| v.as_str()) {
            *event_counts.entry(et.to_string()).or_insert(0) += 1;
        }
        if let Some(sid) = payload.get("session_id").and_then(|v| v.as_str()) {
            session_ids.insert(sid.to_string());
        }
        if let Some(decision) = payload
            .get("details")
            .and_then(|d| d.get("decision"))
            .and_then(|d| d.as_str())
        {
            *decision_counts.entry(decision.to_string()).or_insert(0) += 1;
        }

        if verbose {
            println!("{payload_raw}");
        }
    }

    println!("Audit log: {}", log_file.display());
    println!("  Entries       : {total}");
    println!(
        "  Parse errors  : {}{}",
        parse_failures,
        if parse_failures > 0 {
            "  ← possible corruption or tampering"
        } else {
            ""
        }
    );
    println!(
        "  Missing sigs  : {}{}",
        missing_sig,
        if missing_sig > 0 {
            "  ← entries without HMAC signature"
        } else {
            ""
        }
    );
    println!("  Sessions      : {}", session_ids.len());

    println!();
    println!("Event types:");
    let mut events: Vec<_> = event_counts.iter().collect();
    events.sort_by_key(|(k, _)| k.as_str());
    for (et, count) in &events {
        println!("  {et:<22}  {count}");
    }

    if !decision_counts.is_empty() {
        println!();
        println!("Decisions:");
        let mut decs: Vec<_> = decision_counts.iter().collect();
        decs.sort_by_key(|(k, _)| k.as_str());
        for (d, count) in &decs {
            println!("  {d:<22}  {count}");
        }
    }

    println!();
    println!(
        "Note: signature verification requires the ephemeral session HMAC key (never persisted)."
    );

    if parse_failures > 0 {
        Err(format!("{parse_failures} entries failed to parse").into())
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// `pin` command
// ---------------------------------------------------------------------------

fn pin_command(action: PinAction) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        PinAction::Show { pin_file } => {
            let content = std::fs::read_to_string(&pin_file)
                .map_err(|e| format!("Cannot read '{}': {e}", pin_file.display()))?;
            let records: Vec<serde_json::Value> =
                serde_json::from_str(&content).map_err(|e| format!("Invalid pin file: {e}"))?;

            println!(
                "Pin store: {}  ({} pins)",
                pin_file.display(),
                records.len()
            );
            println!("{:<36}  SHA-256", "Tool");
            println!("{}", "-".repeat(100));
            for r in &records {
                let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let digest = r.get("digest").and_then(|v| v.as_str()).unwrap_or("?");
                println!("{name:<36}  {digest}");
            }
        }
        PinAction::Reset { pin_file } => {
            if pin_file.exists() {
                std::fs::remove_file(&pin_file)
                    .map_err(|e| format!("Cannot remove '{}': {e}", pin_file.display()))?;
                println!("Pin store reset: {}", pin_file.display());
                println!("Next run will re-pin tool descriptions from scratch.");
            } else {
                println!("Pin store not found: {}", pin_file.display());
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Apply the CLI transport arguments to the config.
///
/// Validates that the transport flag is consistent with the supplied URL/command args,
/// and records `upstream_cmd` or `upstream_http_url` in the config.
fn apply_transport(
    config: &mut Config,
    transport: Option<Transport>,
    upstream_cmd: Option<String>,
    upstream_url: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match (upstream_cmd, upstream_url) {
        (Some(_), Some(_)) => {
            return Err("--upstream-cmd and --upstream-url are mutually exclusive".into());
        }
        (Some(cmd), None) => {
            if transport == Some(Transport::Http) {
                return Err("--transport http requires --upstream-url, not --upstream-cmd".into());
            }
            config.upstream_cmd = Some(cmd);
        }
        (None, Some(url)) => {
            if transport == Some(Transport::Stdio) {
                return Err("--transport stdio requires --upstream-cmd, not --upstream-url".into());
            }
            config.upstream_http_url = Some(url);
        }
        (None, None) => {
            // Neither provided — check env / existing config values.
            if config.upstream_http_url.is_none() && config.upstream_cmd.is_none() {
                return Err(
                    "Specify --upstream-cmd <cmd> (stdio) or --upstream-url <url> (http).\n\
                     Examples:\n  \
                       lilith-zero run --transport stdio -u \"python server.py\" --policy policy.yaml\n  \
                       lilith-zero run --transport http --upstream-url http://localhost:8080/mcp --policy policy.yaml"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

fn print_banner() {
    let ver = env!("CARGO_PKG_VERSION");
    eprintln!("██╗     ██╗██╗     ██╗████████╗██╗  ██╗     ███████╗███████╗██████╗  ██████╗ ");
    eprintln!("██║     ██║██║     ██║╚══██╔══╝██║  ██║     ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗");
    eprintln!("██║     ██║██║     ██║   ██║   ███████║█████╗ ███╔╝ █████╗  ██████╔╝██║   ██║");
    eprintln!("██║     ██║██║     ██║   ██║   ██╔══██║╚════╝███╔╝  ██╔══╝  ██╔══██╗██║   ██║");
    eprintln!("███████╗██║███████╗██║   ██║   ██║  ██║     ███████╗███████╗██║  ██║╚██████╔╝");
    eprintln!("╚══════╝╚═╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ");
    eprintln!("  MCP security middleware  v{ver}  — deterministic, fail-closed, sub-ms");
    eprintln!();
}

fn build_config(policy: Option<PathBuf>) -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::from_env().unwrap_or_else(|e| {
        eprintln!("Warning: failed to load config from env, using defaults: {e}");
        Config::default()
    });
    if let Some(p) = policy {
        config.policies_yaml_path = Some(p);
    }
    Ok(config)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        eprintln!("PANIC: {message} at {location}");
    }));
}

fn init_tracing(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
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
