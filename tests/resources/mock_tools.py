from mcp.server.fastmcp import FastMCP
import datetime
import os

mcp = FastMCP("LilithEnterpriseDemo")

# --- SCENARIO 1: Safe Tools ---

@mcp.tool()
def get_current_time() -> str:
    """Returns the current system time."""
    now = datetime.datetime.now()
    return f"Current time is: {now.strftime('%Y-%m-%d %H:%M:%S')}"

@mcp.tool()
def calculate(expression: str) -> str:
    """Performs a mathematical calculation."""
    try:
        # Note: In a real app, use a safe math parser, not eval!
        # But for mock tools, this is fine.
        res = eval(expression, {"__builtins__": {}}, {})
        return f"Result: {res}"
    except Exception as e:
        return f"Error: {e}"

# --- SCENARIO 2: PII Sources ---

@mcp.tool()
def get_user_profile(user_id: str) -> str:
    """Returns sensitive user profile data (PII)."""
    # This tool is marked as a TAINT SOURCE in the policy.
    profiles = {
        "12345": {"name": "Alice Smith", "email": "alice@example.com", "ssn": "XXX-XX-1234"},
        "67890": {"name": "Bob Jones", "email": "bob@example.com", "ssn": "XXX-XX-5678"}
    }
    data = profiles.get(user_id, "User not found")
    return f"Profile Data: {data}"

# --- SCENARIO 3: External Sinks ---

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Sends an email to an external recipient."""
    # This tool is marked as a TAINT SINK in the policy.
    return f"Email sent to {to} with subject: {subject}"

@mcp.tool()
def post_to_slack(channel: str, message: str) -> str:
    """Posts a message to a Slack channel."""
    # This tool is also a TAINT SINK.
    return f"Posted to Slack channel #{channel}: {message}"

# --- SCENARIO 4: Administrative/Denied Tools ---

@mcp.tool()
def execute_shell(command: str) -> str:
    """Executes a shell command (Extremely Dangerous)."""
    # This tool is BLOCKED by static policy.
    return "This should NEVER be executed!"

@mcp.tool()
def delete_records(table: str, condition: str) -> str:
    """Deletes records from a database table."""
    # This tool is also BLOCKED by static policy.
    return f"Records deleted from {table} where {condition}"

if __name__ == "__main__":
    mcp.run()
