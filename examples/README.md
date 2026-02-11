# Lilith Zero Examples

Curated examples of the Lilith Security Middleware in action.

##  Directory Structure

- **`simple_demo/`**: The minimalist "Hello World". Demonstrates basic connectivity and static policy (Allow/Deny).
- **`enterprise_demo/`**: Comprehensive feature showcase. Demonstrates **Taint Tracking (Induction/Enforcement/Removal)**, **Logic Rules with Exceptions**, **Resource Access Control**, and **Resource Discovery**.
- **`react_agent_demo/`**: Autonomous Agent loop. Shows Lilith guarding a ReAct reasoning loop using LLMs.
- **`langchain_agent/`**: Framework integration. Demonstrates wrapping LangChain tools with Lilith security.
- **`lovable_demo/`**: "Vibe Coding" Protection. Secures Lovable-generated apps against RLS bypass and data exfiltration.

##  Requirements

1. **Python 3.10+**
2. **Lilith Binary**: Built via `cargo build -p lilith-zero` in the project root.
3. **API Keys**: For LLM-based examples, set `OPENROUTER_API_KEY` in `examples/.env`.

##  Running Examples

From the project root:

```bash
# 1. Simple Demo
python examples/simple_demo/agent.py

# 2. Enterprise Demo
python examples/enterprise_demo/agent.py

# 3. ReAct Agent (Requires LLM)
python examples/react_agent_demo/agent.py

# 4. MCP Security Middleware Demo (Automated Setup)
# On Windows:
powershell examples/lovable_demo/run_demo.ps1        # Launches CLI
powershell examples/lovable_demo/run_demo.ps1 --ui   # Launches Streamlit Dashboard

# On macOS/Linux:
chmod +x examples/lovable_demo/run_demo.sh
./examples/lovable_demo/run_demo.sh                  # Launches CLI
./examples/lovable_demo/run_demo.sh --ui             # Launches Streamlit Dashboard
```

##  Key Concepts Demonstrated

- **Policy Enforcement**: Declarative security rules in `policy.yaml`.
- **Taint Tracking**: Preventing data exfiltration by marking sensitive sources.
- **Spotlighting**: Randomized delimiters to prevent LLM prompt injection and data leakage.
- **Fail-Closed Design**: Defaults to Deny-All if policy is missing or malformed.
