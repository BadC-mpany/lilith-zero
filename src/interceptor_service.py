import logging
import time
import uuid
import jwt
import httpx
import redis
import yaml
import os
import json
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Dict, Any, List, Optional
from .sentinel_core import CryptoUtils
from .tool_registry import get_registry

# --- LOGGING CONFIGURATION ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# --- CONFIGURATION CLASSES ---
class PolicyRule(BaseModel):
    """
    Represents a single policy rule.
    Supports both simple rules and pattern-based rules.
    """
    # Simple rule fields (backward compatible)
    tool: Optional[str] = None  # Specific tool name
    tool_class: Optional[str] = None  # Tool class (e.g., SENSITIVE_READ)
    action: str  # ADD_TAINT, CHECK_TAINT, REMOVE_TAINT, BLOCK, ALLOW
    tag: Optional[str] = None
    forbidden_tags: Optional[List[str]] = None
    error: Optional[str] = None
    
    # Pattern-based rule fields
    pattern: Optional[Dict[str, Any]] = None  # For sequence/logic patterns
    
    def matches_tool(self, tool_name: str, tool_classes: List[str]) -> bool:
        """Check if this rule applies to the given tool."""
        if self.tool and self.tool == tool_name:
            return True
        if self.tool_class and self.tool_class in tool_classes:
            return True
        return False


class PolicyDefinition(BaseModel):
    name: str
    static_rules: Dict[str, str]
    taint_rules: List[PolicyRule]


class CustomerConfig(BaseModel):
    owner: str
    mcp_upstream_url: str
    policy_name: str


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    interceptor_private_key_path: str = "secrets/interceptor_private.pem"
    policies_yaml_path: str = "policies.yaml"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0


class ProxyRequest(BaseModel):
    session_id: str
    tool_name: str
    args: Dict[str, Any]


# --- PATTERN EVALUATION HELPERS ---
class PatternEvaluator:
    """Evaluates pattern-based rules against session history."""
    
    def __init__(self, redis_client: redis.Redis, tool_registry):
        self.redis = redis_client
        self.registry = tool_registry
    
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
        # Set expiry to match taint TTL
        self.redis.expire(history_key, 3600)
        # Limit history to last 1000 entries
        self.redis.ltrim(history_key, -1000, -1)
    
    def evaluate_sequence_pattern(
        self, 
        pattern: Dict[str, Any], 
        session_id: str, 
        current_tool: str,
        current_classes: List[str]
    ) -> bool:
        """
        Evaluates a sequence pattern.
        Returns True if the sequence is detected (and should be blocked/allowed).
        """
        steps = pattern.get("steps", [])
        max_distance = pattern.get("max_distance")
        
        if not steps:
            return False
        
        # Get history + current tool
        history = self.get_session_history(session_id)
        
        # Build full sequence including current
        full_sequence = history + [{
            "tool": current_tool,
            "classes": current_classes
        }]
        
        # Check if sequence pattern matches
        return self._sequence_matches(full_sequence, steps, max_distance)
    
    def _sequence_matches(
        self, 
        full_sequence: List[Dict[str, Any]], 
        steps: List[Dict[str, Any]], 
        max_distance: Optional[int]
    ) -> bool:
        """Check if the required sequence appears in the full sequence."""
        if len(steps) > len(full_sequence):
            return False
        
        # Try to find the sequence
        step_idx = 0
        start_idx = 0
        for i, entry in enumerate(full_sequence):
            if step_idx >= len(steps):
                break
            
            required_step = steps[step_idx]
            
            # Check if current entry matches required step
            if self._entry_matches_step(entry, required_step):
                if step_idx == 0:
                    start_idx = i
                step_idx += 1
                
                # Check max_distance constraint
                if max_distance is not None and step_idx > 1:
                    if i - start_idx > max_distance:
                        # Reset if distance exceeded
                        step_idx = 0
        
        return step_idx == len(steps)
    
    def _entry_matches_step(self, entry: Dict[str, Any], step: Dict[str, Any]) -> bool:
        """Check if a history entry matches a step requirement."""
        # Step can specify tool name or class
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
        """
        Evaluates a logic pattern with AND/OR/NOT conditions.
        Returns True if the condition is met.
        """
        condition = pattern.get("condition", {})
        
        if "AND" in condition:
            return all(
                self._evaluate_condition_item(item, session_id, current_tool, current_classes)
                for item in condition["AND"]
            )
        elif "OR" in condition:
            return any(
                self._evaluate_condition_item(item, session_id, current_tool, current_classes)
                for item in condition["OR"]
            )
        elif "NOT" in condition:
            return not self._evaluate_condition_item(
                condition["NOT"], session_id, current_tool, current_classes
            )
        
        # Single condition item
        return self._evaluate_condition_item(condition, session_id, current_tool, current_classes)
    
    def _evaluate_condition_item(
        self,
        item: Dict[str, Any],
        session_id: str,
        current_tool: str,
        current_classes: List[str]
    ) -> bool:
        """Evaluate a single condition item."""
        # Current tool conditions (no I/O needed)
        if "current_tool_class" in item:
            return item["current_tool_class"] in current_classes
        if "current_tool" in item:
            return item["current_tool"] == current_tool
        
        # History-based conditions (fetch once if needed)
        if "session_has_class" in item or "session_has_tool" in item:
            history = self.get_session_history(session_id)
            if "session_has_class" in item:
                return any(item["session_has_class"] in entry.get("classes", []) for entry in history)
            if "session_has_tool" in item:
                return any(entry["tool"] == item["session_has_tool"] for entry in history)
        
        # Taint-based conditions
        if "session_has_taint" in item:
            taint_key = f"session:{session_id}:taints"
            current_taints = {t.decode('utf-8') for t in self.redis.smembers(taint_key)}
            return item["session_has_taint"] in current_taints
        
        return False


# --- GLOBAL CONFIGURATION LOAD ---
settings = Settings()

try:
    with open(settings.interceptor_private_key_path, "rb") as f:
        SIGNING_KEY = f.read()
except FileNotFoundError:
    raise RuntimeError(
        f"Private key not found at {settings.interceptor_private_key_path}. "
        "Please run keygen.py first!"
    )

CUSTOMERS: Dict[str, CustomerConfig] = {}
POLICIES: Dict[str, PolicyDefinition] = {}


def load_policies_from_yaml(file_path: str):
    """Loads customer and policy definitions from a YAML file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Policies YAML file not found at {file_path}")

    with open(file_path, 'r') as f:
        config = yaml.safe_load(f)

    # Load customers
    for customer_data in config.get("customers", []):
        api_key = customer_data.pop("api_key")
        CUSTOMERS[api_key] = CustomerConfig(**customer_data)

    # Load policies
    for policy_data in config.get("policies", []):
        policy_name = policy_data["name"]
        POLICIES[policy_name] = PolicyDefinition(**policy_data)


try:
    load_policies_from_yaml(settings.policies_yaml_path)
except Exception as e:
    raise RuntimeError(f"Failed to load policies from YAML: {e}")

app = FastAPI(title="Sentinel Interceptor (Zone B)")
redis_client = redis.Redis(
    host=settings.redis_host, port=settings.redis_port, db=settings.redis_db
)

# Initialize tool registry and pattern evaluator
tool_registry = get_registry()
pattern_evaluator = PatternEvaluator(redis_client, tool_registry)


@app.post("/v1/proxy-execute")
async def interceptor_proxy(req: ProxyRequest, x_api_key: str = Header(None)):
    """
    The Core Policy Engine.
    1. Authenticates Client via API Key.
    2. Checks Static & Dynamic Rules (including patterns).
    3. Mints Capability Token (Ed25519).
    4. Proxies request to hidden MCP URL.
    5. Updates session state (taints, history).
    """

    logger.info(f"Received proxy request for tool '{req.tool_name}' from session '{req.session_id}'")

    # 1. AUTHENTICATION
    if not x_api_key or x_api_key not in CUSTOMERS:
        logger.warning(f"Rejected request with invalid API key: {x_api_key}")
        raise HTTPException(status_code=401, detail="Invalid API Key")

    customer_config = CUSTOMERS[x_api_key]
    policy_definition = POLICIES.get(customer_config.policy_name)

    if not policy_definition:
        raise HTTPException(
            status_code=500, detail=f"Policy '{customer_config.policy_name}' not found."
        )

    # Get tool classes from registry
    tool_classes = tool_registry.get_tool_classes(req.tool_name)
    logger.info(f"Tool '{req.tool_name}' has classes: {tool_classes}")

    # 2. STATIC RULE CHECK (ACL)
    permission = policy_definition.static_rules.get(req.tool_name, "DENY")
    if permission == "DENY":
        logger.warning(f"STATIC BLOCK: Tool '{req.tool_name}' denied for session '{req.session_id}' by static policy.")
        raise HTTPException(
            status_code=403, detail=f"Policy Violation: Tool '{req.tool_name}' is forbidden."
        )

    # 3. DYNAMIC STATE CHECK (Taint Analysis)
    taint_key = f"session:{req.session_id}:taints"
    current_taints = {t.decode('utf-8') for t in redis_client.smembers(taint_key)}
    logger.info(f"Session '{req.session_id}' has taints: {current_taints if current_taints else 'None'}")

    # 4. EVALUATE TAINT RULES (both simple and pattern-based)
    for rule in policy_definition.taint_rules:
        # Handle pattern-based rules
        if rule.pattern:
            pattern_type = rule.pattern.get("type")
            pattern_matched = False
            
            if pattern_type == "sequence":
                pattern_matched = pattern_evaluator.evaluate_sequence_pattern(
                    rule.pattern, req.session_id, req.tool_name, tool_classes
                )
            elif pattern_type == "logic":
                pattern_matched = pattern_evaluator.evaluate_logic_pattern(
                    rule.pattern, req.session_id, req.tool_name, tool_classes
                )
            
            if pattern_matched:
                if rule.action in ["BLOCK", "BLOCK_CURRENT", "BLOCK_SECOND"]:
                    error_msg = rule.error or f"Pattern-based security block: {rule.action}"
                    logger.warning(f"PATTERN BLOCK: Tool '{req.tool_name}' denied for session '{req.session_id}'. Pattern: {pattern_type}")
                    raise HTTPException(status_code=403, detail=error_msg)
                # ALLOW_ALL or other actions - continue
        
        # Handle simple rules (tool name or class based)
        elif rule.matches_tool(req.tool_name, tool_classes):
            if rule.action == "CHECK_TAINT" and rule.forbidden_tags:
                forbidden = set(rule.forbidden_tags)
                intersection = current_taints.intersection(forbidden)
                if intersection:
                    logger.warning(f"TAINT BLOCK: Tool '{req.tool_name}' denied for session '{req.session_id}' due to taints: {intersection}")
                    error_msg = rule.error or f"Security block: forbidden taint detected"
                    raise HTTPException(status_code=403, detail=error_msg)

    # 5. MINT CAPABILITY (Cryptographic Binding)
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
    logger.info(f"Request approved. Minting capability token for tool '{req.tool_name}' with jti: {token_payload['jti']}")

    signed_token = jwt.encode(token_payload, SIGNING_KEY, algorithm="EdDSA")

    # 6. SECURE PROXY EXECUTION
    upstream_url = customer_config.mcp_upstream_url
    logger.info(f"Proxying request to MCP at {upstream_url}")

    async with httpx.AsyncClient() as client:
        try:
            mcp_response = await client.post(
                upstream_url,
                json={"tool": req.tool_name, "args": req.args},
                headers={"Authorization": f"Bearer {signed_token}"},
                timeout=5.0
            )
        except httpx.RequestError as e:
            logger.error(f"Upstream MCP connection error: {e}")
            raise HTTPException(
                status_code=502, detail=f"Upstream MCP Resource Unreachable: {e}")

    if mcp_response.status_code != 200:
        logger.error(f"MCP returned an error: {mcp_response.status_code} - {mcp_response.text}")
        raise HTTPException(
            status_code=mcp_response.status_code, detail=mcp_response.text)

    # 7. STATE UPDATE (Taints and History)
    # Add to execution history
    pattern_evaluator.add_to_history(req.session_id, req.tool_name, tool_classes)
    logger.info(f"Added tool '{req.tool_name}' to session history")
    
    # Process taint rules (ADD_TAINT, REMOVE_TAINT)
    for rule in policy_definition.taint_rules:
        if rule.matches_tool(req.tool_name, tool_classes):
            if rule.action == "ADD_TAINT" and rule.tag:
                logger.info(f"STATE UPDATE: Adding taint '{rule.tag}' to session '{req.session_id}'")
                redis_client.sadd(taint_key, rule.tag)
                redis_client.expire(taint_key, 3600)
            
            elif rule.action == "REMOVE_TAINT" and rule.tag:
                logger.info(f"STATE UPDATE: Removing taint '{rule.tag}' from session '{req.session_id}'")
                redis_client.srem(taint_key, rule.tag)

    return mcp_response.json()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
