"""
SOC Blackboard Coordinator module.
"""

from .agent import get_agent, initialize, BlackboardCoordinator

# Lazy initialization for ADK discovery
_root_agent = None

def _create_coordinator_root_agent():
    """Create the coordinator root agent with proper error handling."""
    try:
        from google.adk.agents import Agent
        import sys
        from pathlib import Path
        # Add parent directory to Python path
        parent_dir = Path(__file__).parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))
        from tools import get_shared_tools
        import asyncio
        
        # Check if we're already in an event loop
        try:
            loop = asyncio.get_running_loop()
            # If we're in a loop, create fallback
            print("Already in event loop, creating fallback coordinator")
            return _create_fallback_coordinator()
        except RuntimeError:
            # No running loop, safe to use asyncio.run()
            async def init_coordinator():
                try:
                    tools, exit_stack = await get_shared_tools()
                    return get_agent(tools, exit_stack)
                except Exception as e:
                    print(f"Coordinator tools not available, using fallback: {e}")
                    return _create_fallback_coordinator()
            
            return asyncio.run(init_coordinator())
        
    except Exception as e:
        print(f"Coordinator initialization failed, using fallback: {e}")
        return _create_fallback_coordinator()

def _create_fallback_coordinator():
    """Create a minimal fallback coordinator agent."""
    from google.adk.agents import Agent
    return Agent(
        name="blackboard_coordinator",
        model="gemini-2.5-pro-preview-05-06",
        description="SOC Blackboard coordinator (direct access)",
        instruction="""
You are the SOC Blackboard Coordinator agent.

This is the direct coordinator agent that orchestrates SOC investigations using the Blackboard pattern.

The full SOC Blackboard system with MCP security tools may not be available.
You can provide guidance on:
- Security investigation workflows
- Blackboard pattern implementation
- SOC coordination methodologies

To enable full functionality:
1. Install MCP security tools: ./setup_mcp_tools.sh
2. Configure .env with your credentials
3. Set up Google Cloud authentication

For full system access, use: adk run soc-blackboard
""",
        tools=[]
    )

# Initialize root_agent on first access
def __getattr__(name):
    if name == "root_agent":
        global _root_agent
        if _root_agent is None:
            _root_agent = _create_coordinator_root_agent()
        return _root_agent
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = ["get_agent", "initialize", "BlackboardCoordinator", "root_agent"]