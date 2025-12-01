import os
import json
import logging
from typing import Optional, Any
import httpx

# Import Pydantic v1 components from langchain_core for compatibility with BaseTool
from langchain_core.pydantic_v1 import BaseModel, Field
from langchain_core.tools import BaseTool, ToolException

# --- LOGGING CONFIGURATION ---
logger = logging.getLogger(__name__)


class SecurityBlockException(ToolException):
    """
    Exception raised when a security policy blocks a tool execution.
    This is a permanent denial - the agent should not retry.
    """
    def __init__(self, message: str, tool_name: str, reason: str):
        # The 'message' is what the LLM will see.
        super().__init__(f"Tool '{tool_name}' was blocked by a security policy. Reason: {reason}")
        self.tool_name = tool_name
        self.reason = reason




class SentinelSecureTool(BaseTool):
    """
    A robust tool wrapper that correctly handles multiple LangChain invocation patterns.
    """
    name: str = Field(..., description="The name of the tool.")
    description: str = Field(..., description="A description of the tool.")
    args_schema: Optional[type[BaseModel]] = Field(None, description="The Pydantic model for the tool's arguments.")

    # These are managed internally and are not part of the Pydantic model state.
    _api_key: Optional[str]
    _interceptor_url: str
    _session_id: Optional[str]

    def __init__(self, **data: Any):
        super().__init__(**data)
        # Use object.__setattr__ to set these attributes without triggering Pydantic validation
        object.__setattr__(self, "_api_key", os.getenv("SENTINEL_API_KEY"))
        object.__setattr__(self, "_interceptor_url", os.getenv("SENTINEL_URL", "http://localhost:8000"))
        object.__setattr__(self, "_session_id", None)
        if not self._api_key:
            raise ValueError("Environment Error: SENTINEL_API_KEY is missing or not set.")

    def set_session_id(self, session_id: str):
        object.__setattr__(self, "_session_id", session_id)

    def _parse_input(self, *args: Any, **kwargs: Any) -> dict:
        """
        Universally handles arguments, whether they are passed positionally
        (as a single dict or JSON string) or as keyword arguments.
        """
        if kwargs:
            return kwargs
        if args:
            tool_input = args[0]
            if isinstance(tool_input, dict):
                return tool_input
            try:
                # Agent is passing a JSON string
                return json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                # Agent is passing a raw string, wrap it in the schema
                if self.args_schema and len(self.args_schema.__fields__) == 1:
                    field_name = list(self.args_schema.__fields__.keys())[0]
                    return {field_name: tool_input}
                else:
                    raise ValueError(f"Received a non-JSON string '{tool_input}' and could not map it to the tool schema.")
        return {}

    def _run(self, *args: Any, **kwargs: Any) -> str:
        if self._session_id is None:
            raise ValueError("Session ID must be set before running the tool.")

        try:
            args_dict = self._parse_input(*args, **kwargs)
        except ValueError as e:
            return f"Input Parsing Error: {e}"

        payload = {"session_id": self._session_id, "tool_name": self.name, "args": args_dict}
        headers = {"X-API-Key": self._api_key, "Content-Type": "application/json"}

        try:
            with httpx.Client() as client:
                response = client.post(f"{self._interceptor_url}/v1/proxy-execute", json=payload, headers=headers, timeout=10) # timeout is 10 seconds. let's do a default, with user-configurable timeout.
                response.raise_for_status()
            return str(response.json())
        except httpx.HTTPStatusError as e:
            detail = e.response.json().get('detail', e.response.text)
            logger.warning(f"Access Denied for tool '{self.name}': {detail}")
            raise SecurityBlockException(
                message=f"Tool '{self.name}' was blocked by a security policy.",
                tool_name=self.name,
                reason=detail
            )
        except Exception as e:
            logger.error(f"An unexpected system error occurred while running tool '{self.name}': {e}", exc_info=True)
            return f"Result: SYSTEM_ERROR: {str(e)}"

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        if self._session_id is None:
            raise ValueError("Session ID must be set before running the tool.")

        try:
            args_dict = self._parse_input(*args, **kwargs)
        except ValueError as e:
            return f"Input Parsing Error: {e}"

        payload = {"session_id": self._session_id, "tool_name": self.name, "args": args_dict}
        headers = {"X-API-Key": self._api_key, "Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(f"{self._interceptor_url}/v1/proxy-execute", json=payload, headers=headers, timeout=10)
                response.raise_for_status()
            return str(response.json())
        except httpx.HTTPStatusError as e:
            detail = e.response.json().get('detail', e.response.text)
            logger.warning(f"(Async) Access Denied for tool '{self.name}': {detail}")
            raise SecurityBlockException(
                message=f"Tool '{self.name}' was blocked by a security policy.",
                tool_name=self.name,
                reason=detail
            )
        except Exception as e:
            logger.error(f"(Async) An unexpected system error occurred while running tool '{self.name}': {e}", exc_info=True)
            return f"Result: SYSTEM_ERROR: {str(e)}"
