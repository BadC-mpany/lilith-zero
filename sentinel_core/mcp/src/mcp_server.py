# sentinel-core/mcp/src/mcp_server.py

import logging
from fastapi import FastAPI, Depends
from pydantic_settings import BaseSettings, SettingsConfigDict

# Use relative imports since all modules are in PYTHONPATH
from token_verifier import verify_sentinel_token, ToolRequest
from tool_executor import execute_tool_logic

# --- LOGGING CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- CONFIGURATION CLASS ---
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    # No redis/key config here, it's handled by dependencies in the verifier

app = FastAPI(title="Secure MCP Resource (Zone C)")


@app.post("/execute")
def execute_tool(
    req: ToolRequest, 
    authorized: bool = Depends(verify_sentinel_token)
):
    """
    This endpoint executes a tool only if the `verify_sentinel_token` 
    dependency check passes without raising an HTTPException.
    """
    return execute_tool_logic(req.tool, req.args)


if __name__ == "__main__":
    import uvicorn
    # The Uvicorn server needs to be started with a reload path that includes the project root
    # so that the absolute imports can be resolved.
    # Example: uvicorn sentinel-core.mcp.src.mcp_server:app --reload --reload-dir .
    uvicorn.run(app, host="0.0.0.0", port=9000)