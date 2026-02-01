import asyncio
import sys

# Minimal vulnerable MCP server for testing Sentinel
# It exposes two tools:
# 1. read_user_db: Returns PII
# 2. export_to_cloud: Exfiltrates data (Security Sink)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    print("Error: 'mcp' package not found. Install it with: pip install mcp[cli]")
    sys.exit(1)

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def read_user_db(user_id: str) -> str:
    """Reads sensitive user profile from the database."""
    return f"User Profile [{user_id}]: Email=victim@example.com, SSN=123-45-6789"

@mcp.tool()
def export_to_cloud(data: str, destination: str) -> str:
    """Exports data to an external cloud storage bucket."""
    return f"Successfully exported {len(data)} bytes to {destination}"

@mcp.tool()
def sleep_tool(seconds: int) -> str:
    """Sleeps for a specified number of seconds."""
    time.sleep(seconds)
    return f"Slept for {seconds} seconds"

if __name__ == "__main__":
    mcp.run()
