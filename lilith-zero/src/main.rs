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

/// Authentication mode for the Copilot Studio webhook server.
///
/// Selected at startup via `--auth-mode`. The mode cannot be changed without
/// restarting the server — changing it mid-session would create a TOCTOU gap.
#[cfg(feature = "webhook")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AuthMode {
    /// No JWT validation — **development only**.
    ///
    /// All requests are accepted without a token. A prominent warning is
    /// logged on every request. Never use this in production.
    None,
    /// HS256 shared-secret validation.
    ///
    /// Requires `LILITH_ZERO_JWT_SECRET` env var or `--jwt-secret` flag.
    /// Suitable for internal deployments where both sides share a secret.
    SharedSecret,
    /// RS256 validation via Microsoft Entra ID JWKS endpoint (production).
    ///
    /// Requires `--entra-tenant-id` and `--entra-audience`. Public keys are
    /// fetched from the tenant's JWKS endpoint and cached for 1 hour.
    Entra,
}

/// Hook output format: controls how the allow/deny decision is communicated.
///
/// Each format is a thin adapter over the same internal policy engine.
/// Adding a new integration requires only a new format variant and adapter —
/// the engine, taint tracking, and persistence are never touched.
///
/// | Format   | Caller                              | Decision mechanism                  |
/// |----------|-------------------------------------|-------------------------------------|
/// | `claude` | Claude Code                         | Exit code 0 (allow) / 2 (deny)     |
/// | `copilot`| Copilot CLI / GitHub cloud agent    | JSON stdout `permissionDecision`    |
/// | `vscode` | VS Code Copilot sidebar agent mode  | JSON stdout `hookSpecificOutput`    |
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum HookFormat {
    /// Claude Code: decision via exit code 0 (allow) or 2 (deny). Default.
    Claude,
    /// GitHub Copilot CLI / cloud coding agent: flat `{"permissionDecision":...}` on stdout.
    Copilot,
    /// VS Code Copilot sidebar agent mode: `{"hookSpecificOutput":{...}}` wrapper on stdout.
    /// Covers all built-in tools (editFiles, runTerminalCommand, #fetch, …) and MCP tools.
    #[value(name = "vscode")]
    VsCode,
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

    /// Start the Copilot Studio external threat detection webhook server.
    ///
    /// Implements the Microsoft Copilot Studio external security provider API:
    ///   POST /validate                  — health check
    ///   POST /analyze-tool-execution    — tool execution evaluation
    ///
    /// Examples:
    ///   # Development (no auth, localhost only):
    ///   lilith-zero serve --bind 127.0.0.1:8080 --auth-mode none --policy policy.yaml
    ///
    ///   # Production with Entra ID:
    ///   lilith-zero serve --bind 0.0.0.0:8443 \
    ///     --auth-mode entra \
    ///     --entra-tenant-id <TENANT_GUID> \
    ///     --entra-audience https://security.contoso.com \
    ///     --policy policy.yaml
    #[cfg(feature = "webhook")]
    Serve {
        /// Address and port to bind the server to.
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,

        /// Authentication mode for incoming requests.
        #[arg(long, value_enum, default_value = "none")]
        auth_mode: AuthMode,

        /// Shared secret for HS256 JWT validation (`--auth-mode shared-secret`).
        /// Can also be set via `LILITH_ZERO_JWT_SECRET` env var.
        #[arg(long)]
        jwt_secret: Option<String>,

        /// Microsoft Entra ID tenant GUID (`--auth-mode entra`).
        /// Can also be set via `LILITH_ZERO_ENTRA_TENANT_ID` env var.
        #[arg(long)]
        entra_tenant_id: Option<String>,

        /// Expected JWT audience for Entra ID validation (`--auth-mode entra`).
        /// Typically the root URL of your threat detection API (e.g.
        /// `https://security.contoso.com`).
        /// Can also be set via `LILITH_ZERO_ENTRA_AUDIENCE` env var.
        #[arg(long)]
        entra_audience: Option<String>,

        /// Path to policy YAML.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Path for audit log output.
        #[arg(long)]
        audit_logs: Option<PathBuf>,
    },

    #[command(hide = true, name = "__supervisor")]
    __Supervisor {
        #[arg(long)]
        parent_pid: u32,

        cmd_args: Vec<String>,
    },

    /// Agent hook integration (Claude Code, GitHub Copilot, VS Code Copilot).
    ///
    /// Reads a JSON event from stdin, evaluates it against the active policy,
    /// and signals the decision to the caller via the selected format.
    /// The policy engine is the same regardless of format — only the I/O adapter changes.
    ///
    /// Claude Code (default):
    ///   lilith-zero hook --policy policy.yaml
    ///
    /// GitHub Copilot CLI / cloud coding agent:
    ///   lilith-zero hook --format copilot --event preToolUse --policy policy.yaml
    ///
    /// VS Code Copilot sidebar agent mode (agent mode, built-in + MCP tools):
    ///   lilith-zero hook --format vscode --policy policy.yaml
    ///   (event is inferred from hookEventName in the JSON payload)
    Hook {
        /// Name of the hook event.
        /// Claude Code: "PreToolUse" | "PostToolUse" (inferred from JSON when omitted).
        /// Copilot:     "preToolUse" | "postToolUse" | "sessionStart" | "sessionEnd"
        ///              (must be supplied via --event since Copilot omits it from JSON).
        #[arg(short, long)]
        event: Option<String>,

        /// Path to policy YAML.
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Path for audit log output.
        #[arg(long)]
        audit_logs: Option<PathBuf>,

        /// Output format: how the allow/deny decision is communicated.
        /// `claude` (default) uses exit codes; `copilot` writes JSON to stdout.
        #[arg(long, value_enum, default_value = "claude")]
        format: HookFormat,
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

        // --- Copilot Studio webhook server ---
        #[cfg(feature = "webhook")]
        Some(Commands::Serve {
            bind,
            auth_mode,
            jwt_secret,
            entra_tenant_id,
            entra_audience,
            policy,
            audit_logs,
        }) => {
            let config = build_config(policy)?;
            init_tracing(&config)?;
            run_webhook_server(
                bind,
                auth_mode,
                jwt_secret,
                entra_tenant_id,
                entra_audience,
                audit_logs,
                config,
            )
            .await?;
        }

        // --- State persistence / Hook mode ---
        Some(Commands::Hook {
            event,
            policy,
            audit_logs,
            format,
        }) => {
            let config = build_config(policy)?;
            init_tracing(&config)?;
            run_hook(event, audit_logs, config, format).await?;
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
    format: HookFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    use lilith_zero::hook::copilot::{
        derive_session_id, is_output_ignored_event, normalize_event_name, CopilotHookInput,
        CopilotHookOutput,
    };
    use lilith_zero::hook::vscode::{
        VsCodeGenericOutput, VsCodeHookInput, VsCodePostToolOutput, VsCodePreToolOutput,
    };
    use lilith_zero::hook::{HookHandler, HookInput};
    use std::io::Read;

    let mut buffer = String::new();
    std::io::stdin().read_to_string(&mut buffer)?;

    match format {
        // ----------------------------------------------------------------
        // Claude Code — decision via exit code 0 (allow) or 2 (deny).
        // No JSON written to stdout.
        // ----------------------------------------------------------------
        HookFormat::Claude => {
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

        // ----------------------------------------------------------------
        // GitHub Copilot CLI / cloud coding agent.
        // Decision: flat {"permissionDecision":"allow"|"deny"} on stdout.
        // Exit code always 0.
        // ----------------------------------------------------------------
        HookFormat::Copilot => {
            if buffer.trim().is_empty() {
                println!(
                    "{}",
                    CopilotHookOutput::deny("no input received on stdin").to_json_line()
                );
                return Ok(());
            }

            let copilot_input: CopilotHookInput = match serde_json::from_str(&buffer) {
                Ok(v) => v,
                Err(e) => {
                    println!(
                        "{}",
                        CopilotHookOutput::deny(format!("JSON parse error: {e}")).to_json_line()
                    );
                    return Ok(());
                }
            };

            let event_name: &str = match event_override.as_deref() {
                Some(ev) => ev,
                None => infer_copilot_event(&copilot_input),
            };

            let normalized = normalize_event_name(event_name);

            if is_output_ignored_event(normalized) {
                println!("{}", CopilotHookOutput::allow().to_json_line());
                return Ok(());
            }

            let session_id = derive_session_id(&copilot_input.cwd);
            let tool_args = copilot_input.decoded_tool_args();
            let tool_output = copilot_input
                .tool_result
                .as_ref()
                .map(|r| serde_json::json!({"resultType": r.result_type, "text": r.text_result}));

            let hook_input = HookInput {
                session_id,
                hook_event_name: normalized.to_string(),
                tool_name: copilot_input.tool_name.clone(),
                tool_input: if normalized == "PreToolUse" {
                    Some(tool_args)
                } else {
                    None
                },
                tool_output: if normalized == "PostToolUse" {
                    tool_output
                } else {
                    None
                },
            };

            let mut handler = HookHandler::new(Arc::new(config), audit_logs)?;
            let exit_code = match handler.handle(hook_input).await {
                Ok(code) => code,
                Err(e) => {
                    println!(
                        "{}",
                        CopilotHookOutput::deny(format!("handler error: {e}")).to_json_line()
                    );
                    return Ok(());
                }
            };

            let output = if exit_code == 0 {
                CopilotHookOutput::allow()
            } else {
                CopilotHookOutput::deny("blocked by Lilith Zero security policy")
            };
            println!("{}", output.to_json_line());
        }

        // ----------------------------------------------------------------
        // VS Code Copilot sidebar agent mode.
        // Decision: {"hookSpecificOutput":{"permissionDecision":...}} on stdout.
        // Exit code always 0. Event name inferred from hookEventName in payload.
        // Covers all VS Code tools: editFiles, runTerminalCommand, #fetch, MCP, …
        // ----------------------------------------------------------------
        HookFormat::VsCode => {
            let debug = std::env::var("LILITH_ZERO_DEBUG").as_deref() == Ok("1");

            if buffer.trim().is_empty() {
                if debug {
                    eprintln!("[lilith-zero] DEBUG: empty stdin");
                }
                println!(
                    "{}",
                    VsCodePreToolOutput::deny("no input received on stdin").to_json_line()
                );
                return Ok(());
            }

            if debug {
                eprintln!("[lilith-zero] DEBUG stdin: {buffer}");
            }

            let vscode_input: VsCodeHookInput = match serde_json::from_str(&buffer) {
                Ok(v) => v,
                Err(e) => {
                    if debug {
                        eprintln!("[lilith-zero] DEBUG parse error: {e}");
                    }
                    println!(
                        "{}",
                        VsCodePreToolOutput::deny(format!("JSON parse error: {e}")).to_json_line()
                    );
                    return Ok(());
                }
            };

            // Event priority: --event flag > hookEventName in payload > inferred from shape.
            let inferred = vscode_input.hook_event_name.as_deref().unwrap_or_else(|| {
                if vscode_input.tool_output.is_some() {
                    "PostToolUse"
                } else if vscode_input.tool_name.is_some() {
                    "PreToolUse"
                } else {
                    "SessionStart"
                }
            });
            let event = event_override.as_deref().unwrap_or(inferred);

            if debug {
                eprintln!(
                    "[lilith-zero] DEBUG event={event} tool={} session={}",
                    vscode_input.tool_name.as_deref().unwrap_or("-"),
                    vscode_input.session_id.as_deref().unwrap_or("(derived)")
                );
            }

            // Non-tool events: VS Code ignores our output but we write a valid response.
            let is_pre_tool = event == "PreToolUse";
            let is_post_tool = event == "PostToolUse";
            if !is_pre_tool && !is_post_tool {
                println!("{}", VsCodeGenericOutput::for_event(event).to_json_line());
                return Ok(());
            }

            // Normalise to internal format and evaluate.
            let hook_input = vscode_input.to_hook_input();
            let mut handler = HookHandler::new(Arc::new(config), audit_logs)?;
            let exit_code = match handler.handle(hook_input).await {
                Ok(code) => code,
                Err(e) => {
                    println!(
                        "{}",
                        VsCodePreToolOutput::deny(format!("handler error: {e}")).to_json_line()
                    );
                    return Ok(());
                }
            };

            if is_pre_tool {
                let output = if exit_code == 0 {
                    VsCodePreToolOutput::allow()
                } else {
                    VsCodePreToolOutput::deny("blocked by Lilith Zero security policy")
                };
                println!("{}", output.to_json_line());
            } else {
                // PostToolUse: engine runs for taint propagation; always allow output
                // through (blocking post-tool output requires explicit policy support).
                println!("{}", VsCodePostToolOutput::allow().to_json_line());
            }
            // Always exit 0 — decision is in the JSON, not the exit code.
        }
    }

    Ok(())
}

/// Launch the Copilot Studio webhook server.
#[cfg(feature = "webhook")]
async fn run_webhook_server(
    bind: String,
    auth_mode: AuthMode,
    jwt_secret: Option<String>,
    entra_tenant_id: Option<String>,
    entra_audience: Option<String>,
    audit_logs: Option<PathBuf>,
    config: Config,
) -> Result<(), Box<dyn std::error::Error>> {
    use lilith_zero::server::auth::{
        EntraAuthenticator, NoAuthAuthenticator, SharedSecretAuthenticator,
    };
    use lilith_zero::server::webhook::{serve, WebhookState};
    use std::sync::Arc;

    let auth: Arc<dyn lilith_zero::server::auth::Authenticator> = match auth_mode {
        AuthMode::None => {
            tracing::warn!(
                "SECURITY WARNING: webhook server starting in no-auth mode. \
                 All requests will be accepted without authentication. \
                 Use --auth-mode shared-secret or --auth-mode entra for production."
            );
            Arc::new(NoAuthAuthenticator)
        }
        AuthMode::SharedSecret => {
            let secret = jwt_secret
                .or_else(|| std::env::var("LILITH_ZERO_JWT_SECRET").ok())
                .ok_or(
                    "--auth-mode shared-secret requires --jwt-secret or LILITH_ZERO_JWT_SECRET",
                )?;
            let audience = config.expected_audience.clone();
            Arc::new(SharedSecretAuthenticator::new(secret, audience))
        }
        AuthMode::Entra => {
            let tenant_id = entra_tenant_id
                .or_else(|| std::env::var("LILITH_ZERO_ENTRA_TENANT_ID").ok())
                .ok_or(
                    "--auth-mode entra requires --entra-tenant-id or LILITH_ZERO_ENTRA_TENANT_ID",
                )?;
            let audience = entra_audience
                .or_else(|| std::env::var("LILITH_ZERO_ENTRA_AUDIENCE").ok())
                .ok_or(
                    "--auth-mode entra requires --entra-audience or LILITH_ZERO_ENTRA_AUDIENCE",
                )?;
            Arc::new(EntraAuthenticator::new(tenant_id, audience))
        }
    };

    let state = WebhookState {
        config: Arc::new(config),
        audit_log_path: audit_logs,
        auth,
    };

    serve(&bind, state).await?;
    Ok(())
}

/// Infer the Copilot event name from the payload shape when `--event` is omitted.
///
/// This is a best-effort heuristic. Callers should prefer `--event` for
/// correctness; auto-detection is provided as a convenience for testing.
fn infer_copilot_event(input: &lilith_zero::hook::copilot::CopilotHookInput) -> &'static str {
    if input.tool_name.is_some() && input.tool_result.is_some() {
        "postToolUse"
    } else if input.tool_name.is_some() {
        "preToolUse"
    } else if input.source.is_some() {
        "sessionStart"
    } else if input.reason.is_some() {
        "sessionEnd"
    } else {
        "unknown"
    }
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
