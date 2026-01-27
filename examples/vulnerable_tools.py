from fastmcp import FastMCP

mcp = FastMCP("Vulnerable Tools")

@mcp.tool()
def read_db(query: str) -> str:
    """Read from the database. PII Source."""
    return f"DB Results for {query}: User: Alice, Email: alice@example.com"

@mcp.tool()
def send_slack(msg: str) -> str:
    """Send to Slack. External Sink."""
    return f"Sent to Slack: {msg}"

if __name__ == "__main__":
    mcp.run()
