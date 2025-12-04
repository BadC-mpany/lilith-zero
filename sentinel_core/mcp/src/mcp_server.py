# sentinel-core/mcp/src/mcp_server.py

import logging
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, Optional

# Import from src package (when running as python -m uvicorn src.mcp_server:app)
from src.token_verifier import verify_sentinel_token, verify_sentinel_token_mcp, ToolRequest, MCPCallParams
from src.tool_executor import execute_tool_logic
from src.tool_registry_loader import get_tool_registry_loader

# --- LOGGING CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- CONFIGURATION CLASS ---


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')
    # No redis/key config here, it's handled by dependencies in the verifier


settings = Settings()
app = FastAPI(title="Secure MCP Resource (Zone C)")

# Security: Request size limits
MAX_REQUEST_SIZE = 1024 * 1024  # 1MB limit

# Initialize tool registry loader
tool_registry = get_tool_registry_loader()


# --- Security Middleware ---

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Limit request body size to prevent DoS attacks."""
    if request.method == "POST":
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > MAX_REQUEST_SIZE:
                    return JSONResponse(
                        status_code=413,
                        content={"jsonrpc": "2.0", "error": {"code": -32600, "message": "Request too large"}, "id": None}
                    )
            except ValueError:
                pass  # Invalid content-length, let FastAPI handle it
    
    response = await call_next(request)
    return response


# --- JSON-RPC 2.0 Models ---

class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    method: str
    params: Optional[Dict[str, Any]] = None
    id: Optional[Any] = None


class JSONRPCError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    result: Optional[Any] = None
    error: Optional[JSONRPCError] = None
    id: Optional[Any] = None


# --- JSON-RPC 2.0 Error Codes ---
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def create_jsonrpc_error(code: int, message: str, request_id: Optional[Any] = None, data: Any = None) -> JSONResponse:
    """Create a JSON-RPC 2.0 error response."""
    error_response = JSONRPCResponse(
        jsonrpc="2.0",
        error=JSONRPCError(code=code, message=message, data=data),
        id=request_id
    )
    return JSONResponse(content=error_response.model_dump(exclude_none=True), status_code=200)


def create_jsonrpc_success(result: Any, request_id: Optional[Any] = None) -> JSONResponse:
    """Create a JSON-RPC 2.0 success response."""
    success_response = JSONRPCResponse(
        jsonrpc="2.0",
        result=result,
        id=request_id
    )
    return JSONResponse(content=success_response.model_dump(exclude_none=True), status_code=200)


# --- MCP Method Handlers ---

def handle_tools_list(request_id: Optional[Any] = None) -> JSONResponse:
    """Handle tools/list MCP method."""
    try:
        tools = tool_registry.get_tools_list()
        result = {"tools": tools}
        return create_jsonrpc_success(result, request_id)
    except Exception as e:
        logger.error(f"Error in tools/list: {e}", exc_info=True)
        # Don't expose internal error details to client
        return create_jsonrpc_error(INTERNAL_ERROR, "Internal error", request_id)


def handle_tools_call(
    params: Dict[str, Any],
    request_id: Optional[Any] = None,
    auth: Optional[Any] = None
) -> JSONResponse:
    """Handle tools/call MCP method with token verification."""
    try:
        # Validate params structure
        if "name" not in params:
            return create_jsonrpc_error(INVALID_PARAMS, "Missing 'name' parameter", request_id)
        if "arguments" not in params:
            return create_jsonrpc_error(INVALID_PARAMS, "Missing 'arguments' parameter", request_id)
        
        tool_name = params["name"]
        tool_args = params.get("arguments", {})
        
        # Check if tool exists
        if not tool_registry.tool_exists(tool_name):
            return create_jsonrpc_error(METHOD_NOT_FOUND, f"Tool '{tool_name}' not found", request_id)
        
        # Token verification is handled before calling this function
        # If we reach here, token is verified
        
        # Execute tool
        try:
            result = execute_tool_logic(tool_name, tool_args)
            return create_jsonrpc_success(result, request_id)
        except Exception as e:
            logger.error(f"Error executing tool '{tool_name}': {e}", exc_info=True)
            # Don't expose internal error details to client
            return create_jsonrpc_error(INTERNAL_ERROR, "Tool execution failed", request_id)
            
    except Exception as e:
        logger.error(f"Error in tools/call: {e}", exc_info=True)
        # Don't expose internal error details to client
        return create_jsonrpc_error(INTERNAL_ERROR, "Internal error", request_id)


# --- Health Check Endpoint ---

@app.get("/health")
async def health_check():
    """Health check endpoint for service verification."""
    return {"status": "healthy", "service": "mcp-server"}


# --- Main JSON-RPC 2.0 Endpoint ---

@app.post("/")
async def mcp_jsonrpc_endpoint(request: Request):
    """
    Main MCP JSON-RPC 2.0 endpoint.
    Accepts JSON-RPC 2.0 requests and routes to appropriate method handlers.
    """
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse JSON request: {e}")
        return create_jsonrpc_error(PARSE_ERROR, "Parse error", None)
    
    # Validate JSON-RPC 2.0 structure
    if not isinstance(body, dict):
        return create_jsonrpc_error(INVALID_REQUEST, "Invalid request", None)
    
    if body.get("jsonrpc") != "2.0":
        return create_jsonrpc_error(INVALID_REQUEST, "Invalid JSON-RPC version", body.get("id"))
    
    method = body.get("method")
    params = body.get("params")
    request_id = body.get("id")
    
    if not method:
        return create_jsonrpc_error(INVALID_REQUEST, "Missing 'method' field", request_id)
    
    # Route to appropriate handler
    if method == "tools/list":
        return handle_tools_list(request_id)
    
    elif method == "tools/call":
        if not params:
            return create_jsonrpc_error(INVALID_PARAMS, "Missing 'params' field", request_id)
        
        # Extract Authorization header for token verification
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return create_jsonrpc_error(INVALID_REQUEST, "Missing or invalid Authorization header", request_id)
        
        # Parse params into MCPCallParams for verification
        try:
            mcp_params = MCPCallParams(**params)
        except Exception as e:
            logger.debug(f"Invalid params structure: {e}")
            # Don't expose validation details to client
            return create_jsonrpc_error(INVALID_PARAMS, "Invalid params structure", request_id)
        
        # Verify token using direct verification function
        from src.token_verifier import verify_token_direct
        from fastapi import HTTPException
        
        try:
            token = auth_header.replace("Bearer ", "")
            verify_token_direct(token, mcp_params.name, mcp_params.arguments)
            # Token verified, proceed with tool execution
            return handle_tools_call(params, request_id)
        except HTTPException as http_e:
            # HTTPException from verify_token_direct - convert to JSON-RPC error
            # Map HTTP status codes to JSON-RPC error codes
            if http_e.status_code == 401:
                error_code = INVALID_REQUEST  # Authentication errors
            elif http_e.status_code == 403:
                error_code = INVALID_REQUEST  # Authorization/scope errors
            elif http_e.status_code == 500:
                error_code = INTERNAL_ERROR  # Server errors
            else:
                error_code = INTERNAL_ERROR  # Default to internal error
            
            logger.error(f"Token verification HTTPException: {http_e.detail} (status: {http_e.status_code})")
            return create_jsonrpc_error(error_code, http_e.detail, request_id)
        except Exception as e:
            logger.error(f"Token verification error: {e}", exc_info=True)
            # Include error details in logs but return generic message
            error_msg = f"Authentication failed: {type(e).__name__}: {str(e)}"
            logger.error(f"Full error details: {error_msg}")
            return create_jsonrpc_error(INTERNAL_ERROR, "Authentication failed", request_id)
    
    else:
        return create_jsonrpc_error(METHOD_NOT_FOUND, f"Method '{method}' not found", request_id)


# --- Legacy /execute endpoint (deprecated) ---

@app.post("/execute")
def execute_tool(
    req: ToolRequest,
    authorized: bool = Depends(verify_sentinel_token)
):
    """
    Legacy endpoint (deprecated).
    This endpoint executes a tool only if the `verify_sentinel_token`
    dependency check passes without raising an HTTPException.
    
    DEPRECATED: Use JSON-RPC 2.0 endpoint at / instead.
    """
    logger.warning("Legacy /execute endpoint called. Consider migrating to JSON-RPC 2.0 endpoint.")
    return execute_tool_logic(req.tool, req.args)


if __name__ == "__main__":
    import uvicorn
    # The Uvicorn server needs to be started with a reload path that includes the project root
    # so that the absolute imports can be resolved.
    # Example: uvicorn sentinel-core.mcp.src.mcp_server:app --reload --reload-dir .
    uvicorn.run(app, host="0.0.0.0", port=9000)
