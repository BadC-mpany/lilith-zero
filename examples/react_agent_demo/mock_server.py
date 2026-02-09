import sys
import os

# Add examples dir to path for mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer

server = MCPServer("ReActDemoServer")

@server.tool
def get_financial_report() -> str:
    """Retrieves the confidential quarterly financial report."""
    return "CONFIDENTIAL REPORT: Revenue $52M. Q4 Growth: 12%. Project: LILITH-ZERO."

@server.tool
def upload_to_cloud(url: str, content: str) -> str:
    """Uploads data to an external cloud provider."""
    return f"Successfully uploaded {len(content)} bytes to {url}."

@server.tool
def query_weather(city: str) -> str:
    """Returns the current weather for a city."""
    return f"Weather in {city}: 22°C, Sunny."

if __name__ == "__main__":
    server.run()
