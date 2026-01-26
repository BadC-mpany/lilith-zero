from typing import List, Dict, Optional, Union
import os
import subprocess
import json

class Sentinel:
    """
    Sentinel MCP Middleware.
    Provides a security layer for Model Context Protocol servers.
    """
    
    @staticmethod
    def wrap_command(
        upstream_cmd: str,
        upstream_args: List[str],
        sentinel_path: str = "sentinel-interceptor",
        policies_path: Optional[str] = None,
        log_level: str = "info"
    ) -> Dict[str, Union[str, List[str], Dict[str, str]]]:
        """
        Generates the command to run an MCP server through the Sentinel interceptor.
        
        Args:
            upstream_cmd: The executable of the tool server (e.g., 'python', 'node').
            upstream_args: Arguments for the tool server (e.g., ['tools.py']).
            sentinel_path: Path to the sentinel-interceptor binary.
            policies_path: Optional path to a YAML policy file.
            log_level: Logging level (trace, debug, info, warn, error).
            
        Returns:
            A dictionary compatible with MCP configuration.
        """
        
        # sentinel-interceptor --upstream-cmd "cmd" -- args...
        args = ["--upstream-cmd", upstream_cmd, "--"] + upstream_args
        
        env = os.environ.copy()
        if policies_path:
            env["POLICIES_YAML_PATH"] = os.path.abspath(policies_path)
        env["LOG_LEVEL"] = log_level
        
        return {
            "command": sentinel_path,
            "args": args,
            "env": env
        }

    @staticmethod
    def get_version() -> str:
        return "0.1.0"
