"""
Utility functions for finding project root and resolving paths.
This ensures paths work regardless of where the script is run from.
"""
import os
from pathlib import Path


def find_project_root(marker_file: str = "docker-compose.yml") -> Path:
    """
    Find the project root by looking for a marker file (docker-compose.yml).
    This works regardless of where the script is executed from.
    
    Args:
        marker_file: Name of a file that exists at the project root
        
    Returns:
        Path object pointing to the project root
        
    Raises:
        FileNotFoundError: If project root cannot be found
    """
    current = Path(__file__).resolve()
    
    # Start from this file's directory and walk up
    for parent in current.parents:
        if (parent / marker_file).exists():
            return parent
    
    # If we're in the project, try current working directory
    cwd = Path.cwd()
    if (cwd / marker_file).exists():
        return cwd
    
    raise FileNotFoundError(
        f"Could not find project root. Looking for '{marker_file}'. "
        f"Current file: {current}, CWD: {cwd}"
    )


def get_project_path(*path_parts: str) -> Path:
    """
    Get an absolute path relative to the project root.
    
    Args:
        *path_parts: Path components relative to project root
        
    Returns:
        Path object with absolute path
    """
    project_root = find_project_root()
    return project_root.joinpath(*path_parts)

