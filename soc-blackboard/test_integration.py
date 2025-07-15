#!/usr/bin/env python3
"""
Test script to verify SOC Blackboard integration with MCP tools.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from coordinator import agent as coordinator_agent
from tools import get_shared_tools


async def test_integration():
    """Test the SOC Blackboard system with MCP tools."""
    
    print("Testing SOC Blackboard Integration")
    print("==================================")
    print()
    
    try:
        # Initialize shared MCP tools
        print("1. Initializing MCP security tools...")
        tools, exit_stack = await get_shared_tools()
        print(f"   ✓ Initialized {len(tools)} tools")
        
        # Initialize coordinator agent
        print("\n2. Initializing coordinator agent...")
        coordinator, _ = await coordinator_agent.initialize(tools, exit_stack)
        print(f"   ✓ Coordinator agent: {coordinator.name}")
        
        # Check available tools
        print("\n3. Available tools:")
        for i, tool in enumerate(coordinator.tools):
            if hasattr(tool, '__name__'):
                print(f"   - {tool.__name__}")
            elif hasattr(tool, 'name'):
                print(f"   - {tool.name}")
            else:
                print(f"   - Tool {i+1}: {type(tool).__name__}")
        
        print("\n✅ Integration test successful!")
        print("\nThe SOC Blackboard system is ready to use with ADK:")
        print("- Run: cd soc-blackboard && adk run coordinator")
        print("- Or: cd soc-blackboard && adk web")
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Clean up
        if 'exit_stack' in locals():
            await exit_stack.aclose()
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(test_integration())
    sys.exit(exit_code)