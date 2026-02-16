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
Lilith SDK - Secure MCP Middleware for AI Agents.

Provides security controls for Model Context Protocol tool servers including:
- Session integrity (HMAC-signed session IDs)
- Policy enforcement (static rules, dynamic taint tracking)
- Process isolation
"""

from .client import _MCP_PROTOCOL_VERSION, Lilith

__version__ = "0.1.1"
__all__ = [
    "_MCP_PROTOCOL_VERSION",
    "Lilith",
    "__version__",
]
