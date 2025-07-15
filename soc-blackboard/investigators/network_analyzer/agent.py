"""
Network Analyzer Investigator Agent

Specializes in analyzing network traffic patterns for security investigations.
Writes findings to the 'network_analysis' knowledge area of the blackboard.
"""

from pathlib import Path
from google.adk.agents import Agent

# Try relative import first, fall back to absolute
try:
    from ...tools.utils import load_persona_and_runbooks, get_blackboard_instructions
except ImportError:
    from tools.utils import load_persona_and_runbooks, get_blackboard_instructions


def get_agent(tools, exit_stack):
    """
    Create Network Analyzer agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools (tuple of toolsets)
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for network traffic analysis
    """
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="network_analyzer",
        runbook_names=["network_investigation_blackboard"],
        default_persona="You are a Network Security Analyst specializing in network traffic analysis."
    )
    
    # Add blackboard-specific instructions
    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## Network Analysis Specific Instructions
- Write all network findings to 'network_analysis' knowledge area
- Tag findings appropriately: [data_exfiltration, c2, lateral_movement, etc.]
- Focus on network traffic patterns, connections, and DNS activity
- Correlate with endpoint findings when available
"""

    return Agent(
        name="network_analyzer",
        model="gemini-2.5-pro-preview-05-06",
        description="Network traffic analysis specialist for SOC investigations",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the network analyzer."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)