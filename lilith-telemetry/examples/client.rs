use lilith_telemetry::crypto::KeyHandle;
use lilith_telemetry::{
    DeploymentMode, FlockLink, SpanKind, dispatcher::EventLevel, init, telemetry_event,
    telemetry_span,
};
use std::io::{self, BufRead};
use std::thread;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: cargo run --example client -- \"lilith://host:port?key_id=0x...\"");
        return;
    }

    let link_str = &args[1];
    println!("--- Lilith Telemetry Node (FlockMember) ---");

    // 1. Parse the connection link
    let link = match FlockLink::parse(link_str) {
        Ok(l) => l,
        Err(e) => {
            println!("Error parsing link: {}", e);
            return;
        }
    };

    println!("Connecting to FlockHead at {}:{}", link.host, link.port);
    println!("Device Key ID: 0x{:x}", link.key_id);

    // 2. Initialize Telemetry as a FlockMember
    init(DeploymentMode::FlockMember {
        target_api_endpoint: format!("{}:{}", link.host, link.port),
        auth_key: KeyHandle(link.key_id),
    });

    println!("Telemetry initialized. Enter messages to send as events (or 'exit' to quit):");

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let input = line.unwrap();
        if input == "exit" {
            break;
        }

        if input.is_empty() {
            continue;
        }

        if input.starts_with("tool ") {
            let parts: Vec<&str> = input.splitn(3, ' ').collect();
            let tool_name = parts.get(1).unwrap_or(&"unknown");
            let tool_args = parts.get(2).unwrap_or(&"");

            // 3. Simulate a multi-event Tool Trace
            let _span = telemetry_span!("agent_action", SpanKind::Client);

            // Event 1: The Call
            telemetry_event!(
                EventLevel::RoutineAllow,
                format!("CALL tool: {} with args: {}", tool_name, tool_args).as_bytes()
            );

            thread::sleep(std::time::Duration::from_millis(500)); // Simulate work

            // Event 2: The Result
            telemetry_event!(
                EventLevel::RoutineAllow,
                format!(
                    "RESULT tool: {} -> [success: {}, items: 42]",
                    tool_name, tool_args
                )
                .as_bytes()
            );

            println!("[Node] Executed tool trace: {}", tool_name);
            continue;
        }

        // Default: Manual standalone event
        {
            let _span = telemetry_span!("manual_trigger", SpanKind::Client);

            telemetry_event!(
                EventLevel::CriticalDeny,
                input.as_bytes(),
                ["triggered_by" => "user_shell"]
            );

            println!("[Node] Dispatched event: '{}'", input);
        }
    }
}
