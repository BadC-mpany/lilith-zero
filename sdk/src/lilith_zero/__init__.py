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

import sys

from .client import Lilith
from .exceptions import LilithError, PolicyViolationError

__version__ = "0.2.6"
__all__ = [
    "Lilith",
    "LilithError",
    "PolicyViolationError",
    "__version__",
]

ASCII_ART = """
\033[38;2;255;255;255m██╗     ██╗██╗     ██╗████████╗██╗  ██╗     ███████╗███████╗██████╗  ██████╗ \033[0m
\033[38;2;230;190;255m██║     ██║██║     ██║╚══██╔══╝██║  ██║     ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗\033[0m
\033[38;2;200;130;255m██║     ██║██║     ██║   ██║   ███████║█████╗ ███╔╝ █████╗  ██████╔╝██║   ██║\033[0m
\033[38;2;160;70;255m██║     ██║██║     ██║   ██║   ██╔══██║╚════╝███╔╝  ██╔══╝  ██╔══██╗██║   ██║\033[0m
\033[38;2;120;20;255m███████╗██║███████╗██║   ██║   ██║  ██║     ███████╗███████╗██║  ██║╚██████╔╝\033[0m
\033[38;2;80;0;200m╚══════╝╚═╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ \033[0m
"""

sys.stdout.write(ASCII_ART + "\n")
sys.stdout.flush()
