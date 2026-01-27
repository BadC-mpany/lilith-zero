"""
Mock MCP Tool Server using FastMCP.
Simulates a realistic set of tools for demonstrating Sentinel security policies.
"""
from fastmcp import FastMCP
import json
from datetime import datetime

mcp = FastMCP("Mock Enterprise Tools")

# ============================================================================
# PII/Sensitive Data Sources (Should be taint-tracked)
# ============================================================================

@mcp.tool()
def get_user_profile(user_id: str) -> str:
    """Fetch user profile from database. Contains PII."""
    return json.dumps({
        "user_id": user_id,
        "name": "Alice Johnson",
        "email": "alice.johnson@company.com",
        "phone": "+1-555-0123",
        "ssn_last4": "4567",
        "department": "Engineering"
    })

@mcp.tool()
def query_database(sql: str) -> str:
    """Execute SQL query against internal database."""
    # Simulate query results
    if "users" in sql.lower():
        return json.dumps([
            {"id": 1, "name": "Alice", "email": "alice@example.com", "salary": 95000},
            {"id": 2, "name": "Bob", "email": "bob@example.com", "salary": 87000},
        ])
    elif "orders" in sql.lower():
        return json.dumps([
            {"order_id": "ORD-001", "customer": "Alice", "amount": 299.99},
        ])
    return json.dumps({"rows": 0, "message": "No results"})

@mcp.tool()
def read_file(path: str) -> str:
    """Read contents of an internal file."""
    # Simulated file contents
    files = {
        "/etc/config.yaml": "database_url: postgres://prod:secret@db.internal:5432/app",
        "/var/log/app.log": "[2024-01-15] User login: alice@company.com from 192.168.1.50",
        "/home/user/notes.txt": "Meeting notes: Q1 revenue projections confidential",
    }
    return files.get(path, f"File not found: {path}")

# ============================================================================
# External Sinks (Dangerous for data exfiltration)
# ============================================================================

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to external recipient."""
    return f"Email sent to {to} with subject: {subject}"

@mcp.tool()
def post_to_slack(channel: str, message: str) -> str:
    """Post message to Slack channel."""
    return f"Posted to #{channel}: {message[:50]}..."

@mcp.tool()
def upload_to_s3(bucket: str, key: str, content: str) -> str:
    """Upload content to S3 bucket."""
    return f"Uploaded to s3://{bucket}/{key} ({len(content)} bytes)"

@mcp.tool()
def call_external_api(url: str, method: str, payload: str) -> str:
    """Make HTTP request to external API."""
    return json.dumps({
        "status": 200,
        "response": f"Mock response from {url}"
    })

# ============================================================================
# Safe/Internal Operations
# ============================================================================

@mcp.tool()
def get_current_time() -> str:
    """Get current server time."""
    return datetime.now().isoformat()

@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate a mathematical expression."""
    try:
        # Safe eval for simple math
        allowed = set("0123456789+-*/(). ")
        if all(c in allowed for c in expression):
            return str(eval(expression))
        return "Invalid expression"
    except:
        return "Error evaluating expression"

@mcp.tool()
def format_text(text: str, style: str) -> str:
    """Format text (uppercase, lowercase, title)."""
    if style == "upper":
        return text.upper()
    elif style == "lower":
        return text.lower()
    elif style == "title":
        return text.title()
    return text

@mcp.tool()
def summarize_text(text: str, max_length: int = 100) -> str:
    """Generate a summary of the input text."""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# ============================================================================
# Administrative Tools (High privilege)
# ============================================================================

@mcp.tool()
def execute_shell(command: str) -> str:
    """Execute shell command on server."""
    # NEVER actually execute - just simulate
    return f"[SIMULATED] Would execute: {command}"

@mcp.tool()
def modify_user_permissions(user_id: str, role: str) -> str:
    """Change user's permission level."""
    return f"[SIMULATED] User {user_id} role changed to: {role}"

@mcp.tool()
def delete_records(table: str, condition: str) -> str:
    """Delete records from database table."""
    return f"[SIMULATED] Would delete from {table} where {condition}"


if __name__ == "__main__":
    mcp.run()
