#!/usr/bin/env python3
"""
Test script for SOC Blackboard MCP Security Tools integration.

This script verifies that MCP security tools can be imported and are ready for use.
"""

import asyncio
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_default_config
from tools import get_shared_tools


async def test_mcp_tools():
    """Test MCP security tools integration."""
    print("SOC Blackboard MCP Tools Test")
    print("=" * 40)
    
    try:
        # Load configuration
        print("1. Loading configuration...")
        try:
            config = get_default_config()
            print("   ✓ Configuration loaded successfully")
        except Exception as e:
            print(f"   ⚠ Configuration warning: {e}")
            print("   This is normal if .env file is not configured yet")
            # Use minimal config for testing
            from config import SOCBlackboardConfig, SecurityToolsConfig, InvestigationConfig, BlackboardConfig, AgentConfig, LoggingConfig
            config = SOCBlackboardConfig(
                google_api_key="test_key",
                security_tools=SecurityToolsConfig(),
                investigation=InvestigationConfig(),
                blackboard=BlackboardConfig(),
                agents=AgentConfig(),
                logging=LoggingConfig()
            )
        
        # Test MCP tools initialization
        print("2. Initializing MCP security tools...")
        tools, exit_stack = await get_shared_tools(config)
        
        print(f"   ✓ Initialized {len(tools)} tools successfully")
        
        # List available tools
        print("3. Available tools:")
        for i, tool in enumerate(tools, 1):
            tool_name = getattr(tool, '__name__', str(tool))
            print(f"   {i:2d}. {tool_name}")
        
        # Clean up
        await exit_stack.aclose()
        print("4. Cleanup completed")
        
        print("\n" + "=" * 40)
        print("✅ MCP Tools integration test PASSED")
        print("\nReady to run SOC Blackboard investigations!")
        
        return True
        
    except Exception as e:
        print(f"\n❌ MCP Tools integration test FAILED: {e}")
        print("\nTroubleshooting:")
        print("1. Run ./setup_mcp_tools.sh to install MCP dependencies")
        print("2. Configure .env file with your credentials")
        print("3. Set up Google Cloud authentication: gcloud auth application-default login")
        return False


if __name__ == "__main__":
    success = asyncio.run(test_mcp_tools())
    sys.exit(0 if success else 1)