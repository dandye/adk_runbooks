"""
IOC Enricher Investigator Agent

Specializes in enriching indicators of compromise with threat intelligence.
Writes findings to 'ioc_enrichments' and 'threat_intelligence' knowledge areas.
"""

from google.adk.agents import Agent

# Try relative import first, fall back to absolute
try:
    from ...tools.utils import load_persona_and_runbooks, get_blackboard_instructions
except ImportError:
    from tools.utils import load_persona_and_runbooks, get_blackboard_instructions


def get_agent(tools, exit_stack):
    """
    Create IOC Enricher agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools (tuple of toolsets)
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for IOC enrichment and threat intelligence
    """
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="ioc_enricher",
        runbook_names=["ioc_enrichment_blackboard"],
        default_persona="You are a Threat Intelligence Analyst specializing in indicator enrichment."
    )
    
    # Add blackboard-specific instructions
    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## IOC Enrichment Specific Instructions
- Write enrichments to 'ioc_enrichments' knowledge area
- Write threat intelligence to 'threat_intelligence' knowledge area
- Tag findings appropriately: [reputation, attribution, mitre, etc.]
- Extract IOCs from all blackboard findings for enrichment
- Prioritize high-confidence IOCs from other investigators
- Focus on threat attribution and related infrastructure discovery

## Tool Usage
You have access to:
- MCP Security tools (Chronicle, GTI, SOAR)
- Blackboard tools (blackboard_read, blackboard_write, blackboard_query)
- Reporting tools (write_report, get_current_time)
"""

    return Agent(
        name="ioc_enricher",
        model="gemini-2.5-pro-preview-05-06",
        description="IOC enrichment and threat intelligence specialist",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the IOC enricher."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)