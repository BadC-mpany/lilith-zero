import httpx
import os
import logging
from typing import List, Optional, Any, Dict, Union
from contextlib import asynccontextmanager

logger = logging.getLogger("sentinel_sdk")

class SentinelClient:
    """
    Minimalist Sentinel Client for secure AI agent sessions.
    
    Usage:
        async with SentinelClient(api_key="...", url="...") as client:
            tools = await client.get_langchain_tools()
            agent = create_agent(llm, tools, ...)
            await agent.ainvoke(...)
    """
    
    def __init__(self, api_key: Optional[str] = None, base_url: str = "http://localhost:8000"):
        self.api_key = api_key or os.getenv("SENTINEL_API_KEY")
        if not self.api_key:
            raise ValueError("SENTINEL_API_KEY must be provided")
        
        self.base_url = base_url.rstrip("/")
        self.session_id: Optional[str] = None
        self.http_client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"X-Sentinel-Key": self.api_key},
            timeout=30.0
        )

    async def __aenter__(self):
        await self.start_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session_id:
            try:
                await self.stop_session()
            except Exception as e:
                logger.error(f"Failed to stop session: {e}", exc_info=True)
                # Don't suppress exception

    async def start_session(self) -> str:
        """Start a new secure session."""
        try:
            response = await self.http_client.post("/v1/session/start")
            response.raise_for_status()
            data = response.json()
            self.session_id = data["session_id"]
            logger.info(f"Sentinel session started: {self.session_id}")
            return self.session_id
        except httpx.HTTPError as e:
            logger.error(f"Failed to start session: {e}")
            if hasattr(e, 'response') and e.response is not None:
                 logger.error(f"Response Body: {e.response.text}")
            raise

    async def stop_session(self):
        """Stop the current session."""
        if not self.session_id:
            return
            
        try:
            await self.http_client.post("/v1/session/stop", json={"session_id": self.session_id})
            logger.info(f"Sentinel session stopped: {self.session_id}")
            self.session_id = None
        except httpx.HTTPError as e:
            logger.error(f"Failed to stop session: {e}")
            raise

    async def get_tools_config(self) -> List[Dict[str, Any]]:
        """Fetch raw tool configurations allowed for this session."""
        if not self.session_id:
            raise RuntimeError("Session not started")
            
        response = await self.http_client.post("/v1/tools/list", json={"session_id": self.session_id})
        response.raise_for_status()
        data = response.json()
        return data.get("tools", [])

    async def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute a tool via the Sentinel Proxy."""
        if not self.session_id:
            raise RuntimeError("Session not started")
            
        payload = {
            "session_id": self.session_id,
            "tool_name": tool_name,
            "args": args
        }
        
        response = await self.http_client.post("/v1/proxy-execute", json=payload)
        response.raise_for_status()
        result = response.json()
        return result.get("result")

    # --- Integrations ---

    async def get_langchain_tools(self):
        """Convert Sentinel tools to LangChain compatible tools."""
        try:
            from langchain_core.tools import StructuredTool
        except ImportError:
            raise ImportError("langchain-core is required for get_langchain_tools")

        configs = await self.get_tools_config()
        tools = []
        
        for config in configs:
            name = config["name"]
            description = config["description"]
            
            # Create a closure to capture the tool name
            async def _tool_func(tool_name=name, **kwargs):
                return await self.execute_tool(tool_name, kwargs)
            
            # Pydantic schema generation from JSON Schema is complex dynamically.
            # LangChain's StructuredTool expects a Pydantic model for args_schema.
            # We can use the JSON schema directly if we infer a dynamic model,
            # or we rely on LangChain's ability to infer from function signature (which is **kwargs here, so weak).
            
            # Better approach: Create a dynamic Pydantic model from the input_schema.
            # Minimal implementation:
            args_schema = self._create_pydantic_model(name, config.get("inputSchema", {}))
            
            # Debugging Pydantic mismatch
            from pydantic import BaseModel as PydanticBaseModel
            # logger.info(f"Model type: {type(args_schema)}")
            # logger.info(f"Is subclass of PydanticBaseModel: {issubclass(args_schema, PydanticBaseModel)}")
            # logger.info(f"PydanticBaseModel id: {id(PydanticBaseModel)}")
            
            tool = StructuredTool.from_function(
                coroutine=_tool_func,
                name=name,
                description=description,
                args_schema=args_schema,
            )
            tools.append(tool)
            
        return tools

    def _create_pydantic_model(self, name: str, json_schema: Dict[str, Any]):
        try:
            # Prefer Pydantic V1 for LangChain compatibility if available
            try:
                from pydantic.v1 import create_model, Field
            except ImportError:
                from pydantic import create_model, Field
        except ImportError:
             raise ImportError("pydantic is required for tool schema generation")

        fields = {}
        properties = json_schema.get("properties", {})
        required = set(json_schema.get("required", []))
        
        for field_name, field_info in properties.items():
            field_type = str
            if field_info.get("type") == "integer":
                field_type = int
            elif field_info.get("type") == "boolean":
                field_type = bool
            elif field_info.get("type") == "number":
                field_type = float
            elif field_info.get("type") == "array":
                field_type = list
            elif field_info.get("type") == "object":
                field_type = dict

            is_required = field_name in required
            default = ... if is_required else None
            
            fields[field_name] = (field_type, Field(default=default, description=field_info.get("description", "")))
        
        return create_model(f"{name}Schema", **fields)
