# sentinel-core/interceptor/python/src/interceptor_service.py

import logging
import time
import uuid
import jwt
import httpx
import redis
import json
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, List, Optional

# JSON-RPC 2.0 error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# Use absolute paths for core dependencies
from crypto_utils import CryptoUtils
from policy_loader import get_policy_loader

# --- LOGGING CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# --- CONFIGURATION CLASSES ---
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    interceptor_private_key_path: str = "/app/secrets/interceptor_private.pem"
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_db: int = 0


class ProxyRequest(BaseModel):
    session_id: str
    tool_name: str
    args: Dict[str, Any]


# --- PATTERN EVALUATION HELPERS ---
class PatternEvaluator:
    """Evaluates pattern-based rules against session history."""

    def __init__(self, redis_client: redis.Redis, policy_loader):
        self.redis = redis_client
        self.policy_loader = policy_loader

    def get_session_history(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve execution history for a session."""
        history_key = f"session:{session_id}:history"
        raw_history = self.redis.lrange(history_key, 0, -1)
        return [json.loads(item.decode('utf-8')) for item in raw_history]

    def add_to_history(self, session_id: str, tool_name: str, tool_classes: List[str]):
        """Add a tool execution to session history."""
        history_key = f"session:{session_id}:history"
        entry = {
            "tool": tool_name,
            "classes": tool_classes,
            "timestamp": time.time()
        }
        self.redis.rpush(history_key, json.dumps(entry))
        self.redis.expire(history_key, 3600)
        self.redis.ltrim(history_key, -1000, -1)

    def evaluate_sequence_pattern(
        self,
        pattern: Dict[str, Any],
        session_id: str,
        current_tool: str,
        current_classes: List[str]
    ) -> bool:
        steps = pattern.get("steps", [])
        if not steps:
            return False

        history = self.get_session_history(session_id)
        full_sequence = history + [{"tool": current_tool, "classes": current_classes}]

        return self._sequence_matches(full_sequence, steps, pattern.get("max_distance"))

    def _sequence_matches(
        self,
        full_sequence: List[Dict[str, Any]],
        steps: List[Dict[str, Any]],
        max_distance: Optional[int]
    ) -> bool:
        if len(steps) > len(full_sequence):
            return False

        step_idx = 0
        start_idx = 0
        for i, entry in enumerate(full_sequence):
            if step_idx >= len(steps):
                break

            if self._entry_matches_step(entry, steps[step_idx]):
                if step_idx == 0:
                    start_idx = i
                step_idx += 1

                if max_distance is not None and step_idx > 1 and (i - start_idx > max_distance):
                    step_idx = 0

        return step_idx == len(steps)

    def _entry_matches_step(self, entry: Dict[str, Any], step: Dict[str, Any]) -> bool:
        if "tool" in step:
            return entry["tool"] == step["tool"]
        elif "class" in step:
            return step["class"] in entry.get("classes", [])
        return False

    def evaluate_logic_pattern(
        self,
        pattern: Dict[str, Any],
        session_id: str,
        current_tool: str,
        current_classes: List[str]
    ) -> bool:
        condition = pattern.get("condition", {})

        if "AND" in condition:
            return all(self._evaluate_condition_item(item, session_id, current_tool, current_classes) for item in condition["AND"])
        elif "OR" in condition:
            return any(self._evaluate_condition_item(item, session_id, current_tool, current_classes) for item in condition["OR"])
        elif "NOT" in condition:
            return not self._evaluate_condition_item(condition["NOT"], session_id, current_tool, current_classes)

        return self._evaluate_condition_item(condition, session_id, current_tool, current_classes)

    def _evaluate_condition_item(
        self,
        item: Dict[str, Any],
        session_id: str,
        current_tool: str,
        current_classes: List[str]
    ) -> bool:
        if "current_tool_class" in item:
            return item["current_tool_class"] in current_classes
        if "current_tool" in item:
            return item["current_tool"] == current_tool

        if "session_has_class" in item or "session_has_tool" in item:
            history = self.get_session_history(session_id)
            if "session_has_class" in item:
                return any(item["session_has_class"] in entry.get("classes", []) for entry in history)
            if "session_has_tool" in item:
                return any(entry["tool"] == item["session_has_tool"] for entry in history)

        if "session_has_taint" in item:
            taint_key = f"session:{session_id}:taints"
            return self.redis.sismember(taint_key, item["session_has_taint"])

        return False


# --- GLOBAL INITIALIZATION ---
settings = Settings()
policy_loader = get_policy_loader()

try:
    with open(settings.interceptor_private_key_path, "rb") as f:
        SIGNING_KEY = f.read()
except FileNotFoundError:
    raise RuntimeError(f"Private key not found at {settings.interceptor_private_key_path}. Please run key_gen.py first!")

app = FastAPI(title="Sentinel Interceptor (Zone B)")
redis_client = redis.Redis(host=settings.redis_host, port=settings.redis_port, db=settings.redis_db)
pattern_evaluator = PatternEvaluator(redis_client, policy_loader)


@app.post("/v1/proxy-execute")
async def interceptor_proxy(req: ProxyRequest, x_api_key: str = Header(None)):
    logger.info(f"Received proxy request for tool '{req.tool_name}' from session '{req.session_id}'")

    # 1. AUTHENTICATION & POLICY LOADING
    customer_config = policy_loader.get_customer_config(x_api_key)
    if not customer_config:
        logger.warning(f"Rejected request with invalid API key: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API Key")

    policy_definition = policy_loader.get_policy(customer_config.policy_name)
    if not policy_definition:
        raise HTTPException(status_code=500, detail=f"Policy '{customer_config.policy_name}' not found.")

    tool_classes = policy_loader.get_tool_classes(req.tool_name)
    logger.info(f"Tool '{req.tool_name}' has classes: {tool_classes}")

    # 2. STATIC RULE CHECK (ACL)
    permission = policy_definition.static_rules.get(req.tool_name, "DENY")
    if permission == "DENY":
        logger.warning(f"STATIC BLOCK: Tool '{req.tool_name}' denied for session '{req.session_id}'.")
        raise HTTPException(status_code=403, detail=f"Policy Violation: Tool '{req.tool_name}' is forbidden.")

    # 3. DYNAMIC STATE & TAINT CHECK
    taint_key = f"session:{req.session_id}:taints"
    current_taints = {t.decode('utf-8') for t in redis_client.smembers(taint_key)}
    logger.info(f"Session '{req.session_id}' has taints: {current_taints or 'None'}")

    for rule in policy_definition.taint_rules:
        # Evaluate patterns first
        if rule.pattern:
            pattern_type = rule.pattern.get("type")
            pattern_matched = False
            if pattern_type == "sequence":
                pattern_matched = pattern_evaluator.evaluate_sequence_pattern(rule.pattern, req.session_id, req.tool_name, tool_classes)
            elif pattern_type == "logic":
                pattern_matched = pattern_evaluator.evaluate_logic_pattern(rule.pattern, req.session_id, req.tool_name, tool_classes)

            if pattern_matched and rule.action in ["BLOCK", "BLOCK_CURRENT", "BLOCK_SECOND"]:
                error_msg = rule.error or "Pattern-based security block"
                logger.warning(f"PATTERN BLOCK: Tool '{req.tool_name}' for session '{req.session_id}'. Pattern: {pattern_type}")
                raise HTTPException(status_code=403, detail=error_msg)

        # Evaluate simple taint rules
        elif rule.matches_tool(req.tool_name, tool_classes):
            if rule.action == "CHECK_TAINT" and rule.forbidden_tags:
                if current_taints.intersection(rule.forbidden_tags):
                    error_msg = rule.error or "Security block: forbidden taint detected"
                    logger.warning(f"TAINT BLOCK: Tool '{req.tool_name}' for session '{req.session_id}'.")
                    raise HTTPException(status_code=403, detail=error_msg)

    # 4. MINT CAPABILITY TOKEN
    now = time.time()
    token_payload = {
        "iss": "sentinel-interceptor",
        "sub": req.session_id,
        "scope": f"tool:{req.tool_name}",
        "p_hash": CryptoUtils.hash_params(req.args),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 5
    }
    signed_token = jwt.encode(token_payload, SIGNING_KEY, algorithm="EdDSA")
    logger.info(f"Request approved. Minting token with jti: {token_payload['jti']}")

    # 5. SECURE PROXY EXECUTION (JSON-RPC 2.0)
    async with httpx.AsyncClient() as client:
        try:
            # Construct JSON-RPC 2.0 request
            jsonrpc_request = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": req.tool_name,
                    "arguments": req.args
                },
                "id": str(uuid.uuid4())
            }
            
            mcp_response = await client.post(
                customer_config.mcp_upstream_url,
                json=jsonrpc_request,
                headers={"Authorization": f"Bearer {signed_token}"},
                timeout=5.0
            )
            mcp_response.raise_for_status()
            
            # Parse JSON-RPC 2.0 response
            response_data = mcp_response.json()
            
            # Check for JSON-RPC error
            if "error" in response_data:
                error_info = response_data["error"]
                error_msg = error_info.get("message", "Unknown error")
                error_code = error_info.get("code", INTERNAL_ERROR)
                
                # Map JSON-RPC error codes to HTTP status codes
                if error_code in [PARSE_ERROR, INVALID_REQUEST]:
                    status_code = 400
                elif error_code == METHOD_NOT_FOUND:
                    status_code = 404
                elif error_code == INVALID_PARAMS:
                    status_code = 400
                elif "Token" in error_msg or "Signature" in error_msg or "Replay" in error_msg:
                    status_code = 401
                elif "Scope" in error_msg or "Integrity" in error_msg:
                    status_code = 403
                else:
                    status_code = 500
                
                logger.warning(f"MCP server returned error: {error_msg} (code: {error_code})")
                raise HTTPException(status_code=status_code, detail=error_msg)
            
            # Extract result from JSON-RPC response
            if "result" not in response_data:
                logger.error(f"Invalid JSON-RPC response: missing 'result' field")
                raise HTTPException(status_code=502, detail="Invalid response from MCP server")
            
            mcp_result = response_data["result"]
            
        except httpx.RequestError as e:
            logger.error(f"Upstream MCP connection error: {e}")
            raise HTTPException(status_code=502, detail=f"Upstream MCP Unreachable: {e}")
        except HTTPException:
            # Re-raise HTTPExceptions (including those from error handling above)
            raise

    # 6. STATE UPDATE (Taints and History)
    pattern_evaluator.add_to_history(req.session_id, req.tool_name, tool_classes)
    for rule in policy_definition.taint_rules:
        if rule.matches_tool(req.tool_name, tool_classes):
            if rule.action == "ADD_TAINT" and rule.tag:
                redis_client.sadd(taint_key, rule.tag)
                redis_client.expire(taint_key, 3600)
                logger.info(f"STATE UPDATE: Added taint '{rule.tag}' to session '{req.session_id}'")
            elif rule.action == "REMOVE_TAINT" and rule.tag:
                redis_client.srem(taint_key, rule.tag)
                logger.info(f"STATE UPDATE: Removed taint '{rule.tag}' from session '{req.session_id}'")

    return mcp_result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
