"""
SOC Blackboard - Multi-agent Security Investigation System

A collaborative SOC investigation platform built on Google's Agent Development Kit (ADK)
using the Blackboard architectural pattern.
"""

__version__ = "0.1.0"

# Lazy initialization to avoid import errors
_root_agent = None


def _create_root_agent():
    """Create the root agent with proper error handling."""
    try:
        # Try to initialize with full ADK and tools
        from google.adk.agents import Agent
        from .coordinator import get_agent as get_coordinator
        from .tools import get_shared_tools
        import asyncio
        
        # Check if we're already in an event loop
        try:
            loop = asyncio.get_running_loop()
            # If we're in a loop, we can't use asyncio.run()
            print("Already in event loop, using fallback agent")
            return _create_fallback_agent()
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            async def init_with_tools():
                try:
                    tools, exit_stack = await get_shared_tools()
                    return get_coordinator(tools, exit_stack)
                except Exception as e:
                    print(f"MCP tools not available, using fallback: {e}")
                    return _create_fallback_agent()
            
            return asyncio.run(init_with_tools())
        
    except Exception as e:
        print(f"Full initialization failed, using fallback: {e}")
        return _create_fallback_agent()


def _create_fallback_agent():
    """Create a minimal fallback agent."""
    from google.adk.agents import Agent
    return Agent(
        name="soc_blackboard_coordinator",
        model="gemini-2.5-pro-preview-05-06", 
        description="SOC Blackboard coordinator (limited mode)",
        instruction="""
You are a SOC Blackboard Coordinator in limited mode.

The full SOC Blackboard system with MCP security tools is not available.
You can provide guidance on:
- Security investigation workflows
- Blackboard pattern concepts
- SOC analysis methodologies

To enable full functionality:
1. Install MCP security tools: ./setup_mcp_tools.sh
2. Configure .env with your credentials  
3. Set up Google Cloud authentication

For now, you can discuss investigation approaches and methodologies.
""",
        tools=[]
    )


# Initialize root_agent on first access
def __getattr__(name):
    if name == "root_agent":
        global _root_agent
        if _root_agent is None:
            _root_agent = _create_root_agent()
        return _root_agent
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = ["root_agent"]