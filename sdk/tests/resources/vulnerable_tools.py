from mcp.server.fastmcp import FastMCP
import time

mcp = FastMCP("VulnerableTools")

@mcp.tool()  # type: ignore[untyped-decorator]
def read_db(query: str) -> str:
    """Mock database read for basic flow tests."""
    return f"Result for {query}"

@mcp.tool()  # type: ignore[untyped-decorator]
def send_slack(msg: str) -> str:
    """Mock slack send."""
    return f"Sent: {msg}"

@mcp.tool()  # type: ignore[untyped-decorator]
def read_user_db(user_id: str) -> str:
    """Reads sensitive user data (PII)."""
    return f"User data for {user_id}: Sensitive PII Data. [CONFIDENTIAL]"

@mcp.tool()  # type: ignore[untyped-decorator]
def export_to_cloud(data: str, destination: str = "default-sink") -> str:
    """Exports data to an external cloud sink."""
    return f"Successfully exported data to {destination}: {data}"

@mcp.tool()  # type: ignore[untyped-decorator]
def sleep_tool(seconds: int) -> str:
    """Simulates a long-running process."""
    time.sleep(seconds)
    return f"Slept for {seconds} seconds"

@mcp.tool()  # type: ignore[untyped-decorator]
def ping() -> str:
    """Simple health check."""
    return "pong"

if __name__ == "__main__":
    mcp.run()
