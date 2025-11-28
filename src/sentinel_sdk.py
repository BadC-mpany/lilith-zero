import os
import requests
from langchain.tools import BaseTool
from pydantic import PrivateAttr


class SentinelSecureTool(BaseTool):
    """
    The 'Blind' Client Wrapper.
    This runs in the Agent's environment (Zone A).
    It knows nothing about the MCP server or the signing keys.
    """
    name: str
    description: str

    # Private attributes are not exposed to the LLM
    _api_key: str = PrivateAttr()
    _interceptor_url: str = PrivateAttr()
    _session_id: str = PrivateAttr()

    def __init__(self, name: str, description: str, session_id: str):
        super().__init__(name=name, description=description)
        self._session_id = session_id

        # Load Infrastructure Secrets
        self._api_key = os.getenv("SENTINEL_API_KEY")
        self._interceptor_url = os.getenv("SENTINEL_URL", "http://localhost:8000")

        if not self._api_key:
            raise ValueError("Environment Error: SENTINEL_API_KEY is missing")

    def _run(self, **kwargs) -> str:
        """
        Synchronous run method.
        Proxies the intent to the Interceptor.
        """
        payload = {
            "session_id": self._session_id,
            "tool_name": self.name,
            "args": kwargs
        }

        headers = {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json"
        }

        try:
            print(f"[Agent] Requesting approval for {self.name}...")
            response = requests.post(
                f"{self._interceptor_url}/v1/proxy-execute",
                json=payload,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                print(f"[Agent] Access Granted. Result received.")
                return str(response.json())
            else:
                print(f"[Agent] Access Denied: {response.text}")
                return f"SECURITY_BLOCK: {response.json().get('detail')}"

        except Exception as e:
            return f"SYSTEM_ERROR: {str(e)}"

    async def _arun(self, **kwargs) -> str:
        raise NotImplementedError("Async not implemented in prototype")
