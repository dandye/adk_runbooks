"""
SOC Blackboard Coordinator module.
"""

from .agent import get_agent, initialize, BlackboardCoordinator
from google.adk.agents import Agent
import asyncio
import sys
from pathlib import Path

# Lazy initialization for ADK discovery
_root_agent = None
_initialization_error = None

class DeferredCoordinatorAgent(Agent):
    """A coordinator agent that defers MCP tool initialization until first use."""
    
    def __init__(self):
        # Initialize with minimal config
        super().__init__(
            name="blackboard_coordinator",
            model="gemini-2.5-pro-preview-05-06", 
            description="SOC Blackboard Coordinator - MCP tools pending initialization",
            instruction="Initializing MCP security tools...",
            tools=[]
        )
        self._initialized = False
        self._real_agent = None
        self._initialization_error = None
        
    async def _ensure_initialized(self):
        """Initialize MCP tools and real agent on first async call."""
        if self._initialized:
            return
            
        if self._initialization_error:
            raise self._initialization_error
            
        try:
            # Add parent directory to Python path
            parent_dir = Path(__file__).parent.parent
            if str(parent_dir) not in sys.path:
                sys.path.insert(0, str(parent_dir))
                
            try:
                # Import from the tools.py file, not the tools/ directory
                import importlib.util
                tools_file_path = parent_dir / "tools.py"
                spec = importlib.util.spec_from_file_location("tools", tools_file_path)
                tools_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(tools_module)
                get_shared_tools = tools_module.get_shared_tools
            except Exception as e:
                raise ImportError(f"Failed to import get_shared_tools from tools.py: {e}")
                
            # Initialize tools
            tools, exit_stack = await get_shared_tools()
            
            # Store the original tools for the coordinator to use
            self._original_tools = tools
            self._exit_stack = exit_stack
            
            # Create the real agent with tools
            self._real_agent = get_agent(tools, exit_stack)
            
            # Copy over the real agent's attributes
            self.description = self._real_agent.description
            self.instruction = self._real_agent.instruction
            self.tools = self._real_agent.tools
            
            self._initialized = True
            
        except Exception as e:
            self._initialization_error = RuntimeError(
                f"Failed to initialize MCP security tools: {e}\n"
                "Ensure that:\n"
                "1. The external/mcp-security submodule is initialized\n"
                "2. The .env file exists with proper credentials\n" 
                "3. Python dependencies are installed"
            )
            raise self._initialization_error
    
    async def run_async(self, invocation_context):
        """Override to ensure initialization before running."""
        await self._ensure_initialized()
        if self._real_agent:
            async for event in self._real_agent.run_async(invocation_context):
                yield event
        else:
            raise RuntimeError("Agent initialization failed")
    
    async def process_request(self, request, invocation_context=None, tools_code_execution_config=None):
        """Override to ensure initialization before processing."""
        await self._ensure_initialized()
        if self._real_agent:
            return await self._real_agent.process_request(
                request, invocation_context, tools_code_execution_config
            )
        else:
            raise RuntimeError("Agent initialization failed")

def _create_coordinator_root_agent():
    """Create the coordinator root agent with deferred initialization."""
    return DeferredCoordinatorAgent()


# Initialize root_agent on first access
def __getattr__(name):
    if name == "root_agent":
        global _root_agent
        if _root_agent is None:
            _root_agent = _create_coordinator_root_agent()
        return _root_agent
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = ["get_agent", "initialize", "BlackboardCoordinator", "root_agent"]