"""
MCP Security Tools integration for SOC Blackboard system.

This module handles initialization and management of MCP security tools
that are shared across all investigator and synthesizer agents.
"""

import asyncio
import os
import sys
from pathlib import Path
from contextlib import AsyncExitStack
from typing import List, Any, Optional, Tuple
from datetime import datetime

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

try:
    from .config import SOCBlackboardConfig
except ImportError:
    from config import SOCBlackboardConfig

TIMEOUT = 60


def get_current_time() -> dict:
    """Gets the current time, formatted for use in filenames or timestamps.
    
    Returns:
        dict: A dictionary with a single key "current_time" and a string value
              representing the current time in "YYYYMMDD_HHMMSS" format.
    """
    return {
        "current_time": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }


def write_report(report_name: str, report_contents: str):
    """Writes a report to a file in the designated reports directory.
    
    This function saves the given report content to a markdown file.
    It ensures that the filename is unique by appending a timestamp if one
    is not already present in the format _YYYYMMDD_HHMMSS. The file will be
    saved in the `soc-blackboard/reports/` directory.
    
    Args:
        report_name (str): The base name for the report file. The .md extension
                           will be added if not present.
        report_contents (str): The markdown content to write to the report.
    """
    # Determine the reports directory relative to this file's location.
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "reports")
    )
    
    # Create reports directory if it doesn't exist
    os.makedirs(reports_dir, exist_ok=True)
    
    # Separate base name and extension
    base_name, ext = os.path.splitext(report_name)
    if not ext:
        ext = ".md"
    
    # Check if a timestamp is already part of the base name to avoid duplication.
    # This checks for _YYYYMMDD or _YYYYMMDD_HHMMSS at the end of the name.
    import re
    if re.search(r"_\d{8}(_\d{6})?$", base_name):
        file_name = f"{base_name}{ext}"
    else:
        timestamp = get_current_time()["current_time"]
        file_name = f"{base_name}_{timestamp}{ext}"
    
    file_path = os.path.join(reports_dir, file_name)
    
    with open(file_path, "w") as f:
        f.write(report_contents)


async def initialize_mcp_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> Tuple[Tuple[Any, ...], AsyncExitStack]:
    """
    Initialize MCP security tools for use by all agents.
    
    Args:
        config: SOC Blackboard configuration
        exit_stack: Async exit stack for resource management
        
    Returns:
        Tuple containing (tools tuple, exit_stack)
    """
    
    # Get the base path of the project (adk_runbooks directory)
    base_path = Path(__file__).resolve().parent.parent
    mcp_security_path = base_path / "external" / "mcp-security"
    
    # Create MCPToolset instances using the new constructor
    siem_toolset = MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command='/Users/dandye/homebrew/bin/uv',
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "secops" / "secops_mcp"),
                    "run",
                    "--reinstall-package",
                    "secops-mcp",
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "server.py"
                ],
            ),
            timeout=TIMEOUT,
        )
    )
    
    soar_toolset = MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command='/Users/dandye/homebrew/bin/uv',
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "secops-soar" / "secops_soar_mcp"),
                    "run",
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "server.py",
                    "--integrations",
                    "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
                ],
            ),
            timeout=TIMEOUT,
        )
    )
    
    gti_toolset = MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command='/Users/dandye/homebrew/bin/uv',
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "gti"),
                    "run",
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "gti_mcp"
                ],
            ),
            timeout=TIMEOUT,
        )
    )
    
    # Register toolsets for cleanup
    exit_stack.push_async_callback(siem_toolset.close)
    exit_stack.push_async_callback(soar_toolset.close)
    exit_stack.push_async_callback(gti_toolset.close)
    
    return (
        siem_toolset,
        soar_toolset,
        gti_toolset,
        write_report,
        get_current_time,
    ), exit_stack


async def get_shared_tools(config: Optional[SOCBlackboardConfig] = None) -> tuple[Tuple[Any, ...], AsyncExitStack]:
    """
    Get shared tools and exit stack for use across the system.
    
    Args:
        config: Optional configuration (will load default if not provided)
        
    Returns:
        Tuple of (tools tuple, exit stack)
    """
    
    if config is None:
        try:
            from .config import get_default_config
        except ImportError:
            from config import get_default_config
        config = get_default_config()
    
    exit_stack = AsyncExitStack()
    
    try:
        tools, exit_stack = await initialize_mcp_tools(config, exit_stack)
        return tools, exit_stack
    except Exception:
        await exit_stack.aclose()
        raise