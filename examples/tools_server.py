from mcp.server.fastmcp import FastMCP
import os

mcp = FastMCP("SentinelDemo")

@mcp.tool()
def read_database(query: str) -> str:
    """Read data from the database."""
    return f"Result for query: {query}. [SENTINEL_DEMO_DATA: 42]"

@mcp.tool()
def write_database(key: str, value: str) -> str:
    """Write data to the database."""
    return f"Successfully wrote {key}={value} to database."

@mcp.tool()
def send_email(recipient: str, body: str) -> str:
    """Send an email."""
    return f"Email sent to {recipient}."

if __name__ == "__main__":
    mcp.run()
