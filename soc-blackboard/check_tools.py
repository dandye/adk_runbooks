#!/usr/bin/env python3
"""
Simple script to check if MCP tools are accessible.
"""

import sys
import asyncio
from pathlib import Path

async def check_tools():
    """Check if MCP tools can be initialized."""
    try:
        # Import tools module
        from tools import get_shared_tools
        print("✅ Successfully imported tools module")
        
        # Try to initialize tools
        print("🔄 Initializing MCP tools...")
        tools, exit_stack = await get_shared_tools()
        print(f"✅ Initialized {len(tools)} tools")
        
        # List tools
        print("\n📋 Available tools:")
        for i, tool in enumerate(tools):
            if hasattr(tool, '__name__'):
                print(f"  {i+1}. {tool.__name__}")
            elif hasattr(tool, 'name'):
                print(f"  {i+1}. {tool.name}")
            elif hasattr(tool, '__class__'):
                print(f"  {i+1}. {tool.__class__.__name__}")
            else:
                print(f"  {i+1}. {type(tool).__name__}")
        
        # Clean up
        await exit_stack.aclose()
        print("\n✅ Tools check completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error checking tools: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(check_tools())
    sys.exit(0 if success else 1)