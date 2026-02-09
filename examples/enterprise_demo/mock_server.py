import sys
import os

# Add examples dir to path for mcp_helper
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from mcp_helper import MCPServer
import datetime

server = MCPServer("EnterpriseServer")

@server.tool
def get_current_time() -> str:
    """Returns the current system time."""
    return f"Current time is: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

@server.tool
def get_user_profile(user_id: str) -> str:
    """Returns sensitive user profile data (PII)."""
    profiles = {
        "123": {"name": "Alice admin", "role": "Full Access", "secret": "Kryptos-42"},
        "456": {"name": "Bob user", "role": "Guest", "secret": "none"}
    }
    return str(profiles.get(user_id, "User not found"))

@server.tool
def sanitize_data(data: str) -> str:
    """Removes sensitive identifiers from the data (Scrubber)."""
    return f"CLEANED: {data.replace('Kryptos-42', '[REDACTED]')}"

@server.tool
def execute_system_command(command: str, force: str = "false") -> str:
    """Executes a system maintenance command."""
    if force.lower() == "true":
        return f"EXECUTED: {command}"
    return "DRY RUN: System safe."

@server.tool
def upload_to_archive(content: str) -> str:
    """Uploads data to the corporate secure archive."""
    return "Data successfully archived."

@server.tool
def export_to_untrusted_cloud(data: str) -> str:
    """Exports data to an external provider (Untrusted)."""
    return "Data exported to external cloud."

# --- Resources ---

@server.resource("s3://internal/audit_logs.txt")
def audit_logs():
    return "INTERNAL AUDIT LOG: All clear."

@server.resource("s3://public/release_notes.txt")
def release_notes():
    return "RELEASE NOTES: High performance security middleware."

if __name__ == "__main__":
    server.run()
