# Lilith Telemetry — LangChain Agent Demo

This example demonstrates how to orchestrate a distributed AI agent network using **LangChain** and **Lilith Zero**.

It shows off the `lilith-telemetry` system where multiple `FlockMember` (Nodes) connect to a single `FlockHead` (Collector) to stream high-performance, critical security events dynamically generated through runtime policy evaluations.

## Architecture

*   **Node (FlockMember):** Your LangChain python process running the `agent.py` script. The Lilith-Zero SDK intercepts tool access, generates deterministic telemetry logs using `RDTSC` (CPU cycles) and signs them with a provisioned Node Key.
*   **Head (FlockHead):** The collector running the `lilith-telemetry` server example. It receives UDP telemetry streams from all members and aggregates them.

## Setup & Running the Demo

### 1. Provision Node Keys (FlockHead Terminal)
First, you need to generate a `flock_keys.db` registry for the server to recognize the nodes.
```bash
cd lilith-telemetry
cargo run --example provision
```
*Note the keys outputted in the terminal. You will use these connection strings for the agents.*

### 2. Start the Telemetry Collector (FlockHead Terminal)
In the same terminal, boot up the UDP listening collection server.
```bash
cargo run --example server
```
*The collector will now listen on `127.0.0.1:44317`.*

### 3. Start Agent 1 (Node Terminal 1)
Open a new terminal. Compile the `lilith-zero` binary and run the LangChain example using the first connection link provisioned in Step 1.
```bash
cd lilith-zero
cargo build

cd examples/python/langchain
python agent.py --telemetry-link "lilith://127.0.0.1:44317?key_id=<KEY_1>"
```

### 4. Start Agent 2 (Node Terminal 2)
In another terminal, start the secondary agent to see interleaved logs.
```bash
cd examples/python/langchain
python agent.py --telemetry-link "lilith://127.0.0.1:44317?key_id=<KEY_2>"
```

## Observing Telemetry

**Local Node Logging:**
A file named `node_telemetry_local.log` will be created in your working directory (`examples/python/langchain`). This allows you to witness the `BinaryEvent` logs written directly to disk at the edge without the collector.

**Collector Aggregation:**
A `telemetry.log` file is created inside the `lilith-telemetry` directory. If you inspect this file or watch the collector output, you will see events streaming in labeled by the `NODE` and `SESSION` identifiers.

Trigger a tool like `Compute 5 + 5` in the python Agent chat interface, and you will see a `RoutineAllow` event show up immediately in both locations!
