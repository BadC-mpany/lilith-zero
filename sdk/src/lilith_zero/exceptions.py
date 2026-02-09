# Copyright 2026 BadCompany
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Lilith SDK Exceptions.

Defines the hierarchy of errors raised by the Lilith middleware.
"""

from typing import Any, Optional, Dict

class LilithError(Exception):
    """Base class for all Lilith SDK errors.
    
    Attributes:
        message: A human-readable error message.
        context: Optional dictionary containing debugging metadata.
    """
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} (context: {self.context})"
        return self.message

class LilithConfigError(LilithError):
    """Raised when configuration is invalid or missing.
    
    Attributes:
        config_key: The name of the configuration setting that caused the error.
    """
    def __init__(
        self, 
        message: str, 
        config_key: Optional[str] = None, 
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        ctx = context or {}
        if config_key:
            ctx["config_key"] = config_key
        super().__init__(message, context=ctx)
        self.config_key = config_key

class LilithConnectionError(LilithError):
    """Raised when the SDK fails to connect to or loses connection with Lilith.
    
    Attributes:
        phase: The lifecycle phase where the failure occurred (e.g., 'spawn', 'handshake').
    """
    def __init__(
        self, 
        message: str, 
        phase: Optional[str] = None, 
        underlying_error: Optional[Exception] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        ctx = context or {}
        if phase:
            ctx["connection_phase"] = phase
        if underlying_error:
            ctx["underlying_error"] = str(underlying_error)
            
        super().__init__(message, context=ctx)
        self.phase = phase
        self.underlying_error = underlying_error

class LilithProcessError(LilithError):
    """Raised when the Lilith process behaves unexpectedly (crashes, strict IO).
    
    Includes exit code and stderr if the process crashed.
    """
    def __init__(
        self, 
        message: str, 
        exit_code: Optional[int] = None, 
        stderr: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        ctx = context or {}
        if exit_code is not None:
            ctx["exit_code"] = exit_code
        if stderr:
            # Clean up stderr: last 500 chars, stripped
            ctx["stderr"] = stderr.strip()[-500:]
            
        super().__init__(message, context=ctx)
        self.exit_code = exit_code
        self.stderr = stderr

class PolicyViolationError(LilithError):
    """Raised when a tool execution is blocked by the security policy."""
    def __init__(self, message: str, policy_details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message, context={"policy_details": policy_details or {}})
        self.policy_details: Dict[str, Any] = policy_details or {}

class ToolExecutionError(LilithError):
    """Raised when the upstream tool itself fails (not a policy block)."""
    def __init__(
        self, 
        message: str, 
        tool_name: Optional[str] = None, 
        upstream_error: Any = None
    ) -> None:
        super().__init__(
            message, 
            context={"tool": tool_name, "upstream_error": upstream_error}
        )
        self.tool_name = tool_name
        self.upstream_error = upstream_error
