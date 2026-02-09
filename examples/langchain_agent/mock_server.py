import sys
import os

# Add examples dir to path for mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer

server = MCPServer("LangChainDemoServer")

@server.tool
def calculator(expression: str) -> str:
    """Performs a mathematical calculation."""
    try:
        # Use eval sparingly in real apps, but fine for mock demo
        return str(eval(expression, {"__builtins__": {}}, {}))
    except Exception as e:
        return f"Error: {e}"

@server.tool
def read_customer_data(customer_id: str) -> str:
    """Reads sensitive customer PII."""
    return f"Customer {customer_id}: PII PROTECTED DATA"

@server.tool
def export_analytics(data: str) -> str:
    """Exports data to external analytics platform."""
    return "Data exported successfully."

@server.tool
def system_maintenance(region: str) -> str:
    """Performs system maintenance."""
    return f"Maintenance complete for {region}."

if __name__ == "__main__":
    server.run()
