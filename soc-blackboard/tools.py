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
from typing import List, Any, Optional

from .config import SOCBlackboardConfig


async def initialize_mcp_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> List[Any]:
    """
    Initialize MCP security tools for use by all agents.
    
    Args:
        config: SOC Blackboard configuration
        exit_stack: Async exit stack for resource management
        
    Returns:
        List of initialized MCP tools
    """
    
    tools = []
    
    # Add the external/mcp-security path to Python path for imports
    mcp_security_path = Path(__file__).parent.parent / "external" / "mcp-security" / "server"
    if mcp_security_path.exists():
        sys.path.insert(0, str(mcp_security_path))
    
    try:
        # Initialize Google Security Operations (Chronicle) tools
        if config.security_tools.chronicle_project_id:
            chronicle_tools = await initialize_chronicle_tools(config, exit_stack)
            tools.extend(chronicle_tools)
        
        # Initialize Google Threat Intelligence tools
        gti_tools = await initialize_gti_tools(config, exit_stack)
        tools.extend(gti_tools)
        
        # Initialize SOAR tools if configured
        if config.security_tools.soar_url:
            soar_tools = await initialize_soar_tools(config, exit_stack)
            tools.extend(soar_tools)
        
        # Initialize Security Command Center tools
        scc_tools = await initialize_scc_tools(config, exit_stack)
        tools.extend(scc_tools)
        
    except ImportError as e:
        print(f"Warning: Could not import MCP security tools: {e}")
        print("Falling back to placeholder tools for testing")
        
        # Fallback to placeholder tools
        tools.extend([
            create_placeholder_chronicle_tool(),
            create_placeholder_soar_tool(),
            create_placeholder_virustotal_tool()
        ])
    
    return tools


async def initialize_chronicle_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> List[Any]:
    """Initialize Google Security Operations (Chronicle) MCP tools."""
    try:
        from secops_mcp.tools import (
            search_security_events,
            search_security_alerts,
            entity_lookup,
            search_security_rules,
            search_ioc_matches,
            search_threat_intel
        )
        
        # Set environment variables for Chronicle authentication
        if config.security_tools.chronicle_project_id:
            os.environ["CHRONICLE_PROJECT_ID"] = config.security_tools.chronicle_project_id
        if config.security_tools.chronicle_customer_id:
            os.environ["CHRONICLE_CUSTOMER_ID"] = config.security_tools.chronicle_customer_id
        if config.security_tools.chronicle_region:
            os.environ["CHRONICLE_REGION"] = config.security_tools.chronicle_region
        
        return [
            search_security_events,
            search_security_alerts,
            entity_lookup,
            search_security_rules,
            search_ioc_matches,
            search_threat_intel
        ]
    except ImportError as e:
        print(f"Could not import Chronicle tools: {e}")
        return []


async def initialize_gti_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> List[Any]:
    """Initialize Google Threat Intelligence MCP tools."""
    try:
        from gti_mcp.tools import (
            search_collections,
            search_files,
            search_intelligence,
            search_netloc,
            search_threat_profiles,
            search_urls
        )
        
        return [
            search_collections,
            search_files,
            search_intelligence,
            search_netloc,
            search_threat_profiles,
            search_urls
        ]
    except ImportError as e:
        print(f"Could not import GTI tools: {e}")
        return []


async def initialize_soar_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> List[Any]:
    """Initialize SOAR MCP tools."""
    try:
        from secops_soar_mcp.case_management import (
            create_case,
            get_case,
            update_case,
            list_cases
        )
        
        # Set environment variables for SOAR authentication
        if config.security_tools.soar_url:
            os.environ["SOAR_URL"] = config.security_tools.soar_url
        if config.security_tools.soar_app_key:
            os.environ["SOAR_APP_KEY"] = config.security_tools.soar_app_key
        
        return [
            create_case,
            get_case,
            update_case,
            list_cases
        ]
    except ImportError as e:
        print(f"Could not import SOAR tools: {e}")
        return []


async def initialize_scc_tools(config: SOCBlackboardConfig, exit_stack: AsyncExitStack) -> List[Any]:
    """Initialize Security Command Center MCP tools."""
    try:
        # The SCC module appears to be a single file, let's try importing it
        import scc_mcp
        
        # SCC tools would be defined in the scc_mcp module
        # For now, return empty list until we examine the actual structure
        return []
    except ImportError as e:
        print(f"Could not import SCC tools: {e}")
        return []


def create_placeholder_chronicle_tool():
    """Create a placeholder Chronicle SIEM tool for testing."""
    
    async def chronicle_search(query: str, time_range: str = "1h"):
        """
        Search Chronicle SIEM for security events.
        
        Args:
            query: UDM search query
            time_range: Time range for search (e.g., "1h", "24h", "7d")
            
        Returns:
            Mock search results
        """
        return {
            "query": query,
            "time_range": time_range,
            "results": [
                {
                    "timestamp": "2024-01-01T12:00:00Z",
                    "event_type": "NETWORK_CONNECTION",
                    "principal": {"ip": "10.0.0.100"},
                    "target": {"ip": "192.168.1.1"},
                    "network": {"sent_bytes": 1024, "received_bytes": 2048}
                }
            ],
            "total_results": 1,
            "note": "This is a placeholder tool for testing"
        }
    
    return chronicle_search


def create_placeholder_soar_tool():
    """Create a placeholder SOAR platform tool for testing."""
    
    async def soar_create_case(title: str, description: str, priority: str = "medium"):
        """
        Create a new case in the SOAR platform.
        
        Args:
            title: Case title
            description: Case description
            priority: Case priority (low, medium, high, critical)
            
        Returns:
            Mock case creation result
        """
        return {
            "case_id": "CASE-2024-001",
            "title": title,
            "description": description,
            "priority": priority,
            "status": "open",
            "created_at": "2024-01-01T12:00:00Z",
            "note": "This is a placeholder tool for testing"
        }
    
    return soar_create_case


def create_placeholder_virustotal_tool():
    """Create a placeholder VirusTotal tool for testing."""
    
    async def virustotal_lookup(indicator: str, indicator_type: str):
        """
        Look up an indicator in VirusTotal.
        
        Args:
            indicator: The indicator to look up (IP, domain, hash, etc.)
            indicator_type: Type of indicator (ip, domain, file_hash, url)
            
        Returns:
            Mock VirusTotal results
        """
        return {
            "indicator": indicator,
            "type": indicator_type,
            "scan_date": "2024-01-01T12:00:00Z",
            "positives": 5,
            "total": 50,
            "reputation": "malicious" if indicator_type == "file_hash" else "clean",
            "details": {
                "first_seen": "2024-01-01T10:00:00Z",
                "last_seen": "2024-01-01T12:00:00Z",
                "country": "US" if indicator_type == "ip" else None
            },
            "note": "This is a placeholder tool for testing"
        }
    
    return virustotal_lookup


async def get_shared_tools(config: Optional[SOCBlackboardConfig] = None) -> tuple[List[Any], AsyncExitStack]:
    """
    Get shared tools and exit stack for use across the system.
    
    Args:
        config: Optional configuration (will load default if not provided)
        
    Returns:
        Tuple of (tools list, exit stack)
    """
    
    if config is None:
        from .config import get_default_config
        config = get_default_config()
    
    exit_stack = AsyncExitStack()
    
    try:
        tools = await initialize_mcp_tools(config, exit_stack)
        return tools, exit_stack
    except Exception:
        await exit_stack.aclose()
        raise


# Tool integration notes for future implementation:
"""
To integrate with real MCP security tools:

1. Install the mcp-security package:
   pip install -e ../external/mcp-security

2. Import the tools:
   from mcp_security.chronicle import ChronicleClient
   from mcp_security.soar import SOARClient
   from mcp_security.virustotal import VirusTotalClient

3. Initialize tools with proper credentials:
   chronicle = ChronicleClient(
       project_id=config.security_tools.chronicle_project_id,
       customer_id=config.security_tools.chronicle_customer_id,
       region=config.security_tools.chronicle_region
   )

4. Add proper error handling and connection management

5. Ensure tools are properly closed when the system shuts down
"""