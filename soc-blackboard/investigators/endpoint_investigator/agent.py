"""
Endpoint Investigator Agent

Specializes in analyzing endpoint/host-based security events and behaviors.
Writes findings to the 'endpoint_behaviors' knowledge area of the blackboard.
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
    Create Endpoint Investigator agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools (tuple of toolsets)
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for endpoint behavior analysis
    """
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="endpoint_investigator",
        runbook_names=["endpoint_investigation_blackboard"],
        default_persona="You are an Endpoint Security Analyst specializing in host-based threat detection."
    )
    
    # Add blackboard-specific instructions
    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## Endpoint Investigation Specific Instructions
- Write all endpoint findings to 'endpoint_behaviors' knowledge area
- Tag findings appropriately: [malware, persistence, lateral_movement, etc.]
- Focus on process behaviors, file system changes, and registry modifications
- Correlate with network findings to identify responsible processes
- Look for evidence of persistence mechanisms and privilege escalation
"""

    return Agent(
        name="endpoint_investigator",
        model="gemini-2.5-pro-preview-05-06",
        description="Endpoint behavior analysis specialist for SOC investigations",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the endpoint investigator."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)