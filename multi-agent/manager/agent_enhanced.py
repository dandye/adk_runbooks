"""
Enhanced Manager Agent with structured configuration-based delegation.
This module demonstrates how to integrate the configuration loader.
"""

import asyncio
import logging
from pathlib import Path

from google.adk.agents import Agent

# Import sub-agents
from .sub_agents.soc_analyst_tier1 import agent as soc_analyst_tier1_agent_module
from .sub_agents.soc_analyst_tier2 import agent as soc_analyst_tier2_agent_module
from .sub_agents.cti_researcher import agent as cti_researcher_agent_module
from .sub_agents.threat_hunter import agent as threat_hunter_agent_module
from .sub_agents.soc_analyst_tier3 import agent as soc_analyst_tier3_agent_module
from .sub_agents.incident_responder import agent as incident_responder_agent_module
from .sub_agents.detection_engineer import agent as detection_engineer_agent_module
from .sub_agents.soar_specialist import agent as soar_specialist_agent_module

# Import tools and configuration
from .tools.tools import get_current_time, write_report, get_agent_tools, load_persona_and_runbooks
from .config.config_loader import load_agent_config

# Set the root logger to output debug messages
logging.basicConfig(level=logging.ERROR)


async def initialize_enhanced_manager_agent():
    """Initializes the Manager Agent with configuration-based delegation.
    
    This enhanced version uses structured configuration files to determine
    agent capabilities and delegation logic, making the system more maintainable
    and reducing hardcoded instructions.
    
    Returns:
        Agent: The fully configured Manager Agent with dynamic delegation.
    """
    # Load configuration
    config_loader = load_agent_config()
    
    # Get agent tools
    shared_tools, shared_exit_stack = await get_agent_tools()
    
    # Initialize all sub-agents
    sub_agents = {}
    agent_modules = {
        'soc_analyst_tier1': soc_analyst_tier1_agent_module,
        'soc_analyst_tier2': soc_analyst_tier2_agent_module,
        'cti_researcher': cti_researcher_agent_module,
        'threat_hunter': threat_hunter_agent_module,
        'soc_analyst_tier3': soc_analyst_tier3_agent_module,
        'incident_responder': incident_responder_agent_module,
        'detection_engineer': detection_engineer_agent_module,
        'soar_specialist': soar_specialist_agent_module,
    }
    
    # Initialize each sub-agent
    for agent_name, agent_module in agent_modules.items():
        if hasattr(agent_module, 'initialize'):
            initialized_agent, _ = await agent_module.initialize(shared_tools, shared_exit_stack)
            sub_agents[agent_name] = initialized_agent
            
    # Load manager persona and runbooks
    BASE_DIR = Path(__file__).resolve().parent
    persona_file_path = (BASE_DIR / "../../../adk_runbooks/rules-bank/personas/soc_manager.md").resolve()
    runbook_files = [
        (BASE_DIR / "../../../adk_runbooks/rules-bank/irps/malware_irp.md").resolve(),
        (BASE_DIR / "../../../adk_runbooks/rules-bank/irps/phishing_irp.md").resolve(),
        (BASE_DIR / "../../../adk_runbooks/rules-bank/irps/ransomware_irp.md").resolve(),
    ]
    
    persona_description = load_persona_and_runbooks(persona_file_path, runbook_files)
    
    # Build dynamic delegation instructions from configuration
    delegation_instructions = config_loader.build_delegation_instructions()
    agent_summaries = config_loader.get_all_agent_summaries()
    
    # Create enhanced instruction string
    instruction = f"""You are the SOC Manager Agent, responsible for orchestrating and delegating security tasks to specialized sub-agents.

{persona_description}

## Configuration-Based Delegation

This manager uses structured configuration files to determine the best agent for each task.
The delegation logic is based on:
1. Request pattern matching
2. Required tool availability
3. Agent expertise areas
4. Task complexity and severity

{delegation_instructions}

## Available Sub-Agents

{agent_summaries}

## Delegation Process

1. **Analyze the Request**: Understand what the user needs
2. **Match Patterns**: Check if the request matches known patterns
3. **Consider Tools**: Identify which tools might be needed
4. **Select Agent**: Choose the most appropriate agent based on:
   - Pattern matches
   - Tool requirements
   - Expertise alignment
   - Current workload
5. **Delegate**: Pass the request to the selected agent
6. **Monitor**: Track progress and results

## Dynamic Agent Selection

When a request comes in, I will:
- Use the configuration loader to find the best agent
- Consider both primary and alternative agents
- Provide clear reasoning for my delegation decision

## Response Format

When delegating, I will:
1. Identify the task type and requirements
2. Explain which agent I'm selecting and why
3. Delegate the task with clear instructions
4. Summarize the results when complete

Remember: The configuration files in `config/agents/` define each agent's capabilities,
and `config/tool_agent_mapping.yaml` shows which agents can use which tools.
"""

    # Create the enhanced manager agent
    enhanced_manager = Agent(
        id="soc_manager_enhanced",
        name="Enhanced SOC Manager",
        description="Security Operations Center Manager with configuration-based delegation",
        instruction=instruction,
        sub_agents=list(sub_agents.values()),
        tools=[get_current_time, write_report],
        capabilities={
            "Uses configuration files for intelligent delegation",
            "Dynamically determines best agent for each task",
            "Provides clear delegation reasoning",
            "Monitors and reports on sub-agent activities"
        }
    )
    
    # Store configuration loader reference for runtime use
    enhanced_manager._config_loader = config_loader
    
    return enhanced_manager


# Create a wrapper class that provides the config loader functionality
class ConfigAwareManagerAgent:
    """Manager agent with configuration awareness for delegation decisions."""
    
    def __init__(self, agent: Agent, config_loader):
        self.agent = agent
        self.config_loader = config_loader
        
    def suggest_agent_for_request(self, request: str) -> str:
        """Suggest the best agent for a given request.
        
        Args:
            request: The user's request
            
        Returns:
            Suggested agent name and reasoning
        """
        suggested_agent = self.config_loader.get_agent_for_request(request)
        
        if suggested_agent:
            agent_config = self.config_loader.get_agent_capabilities(suggested_agent)
            return (f"Suggested agent: {suggested_agent}\n"
                   f"Reason: {agent_config.get('description', 'No description')}")
        else:
            return "No specific agent match found. Manual delegation required."


# Example usage function
async def demonstrate_enhanced_manager():
    """Demonstrate the enhanced manager's capabilities."""
    manager = await initialize_enhanced_manager_agent()
    config_loader = load_agent_config()
    
    # Example requests to show delegation logic
    test_requests = [
        "I need to triage a security alert",
        "Investigate this SOAR case in detail",
        "Analyze this malware sample",
        "Research the FIN7 threat actor",
        "Hunt for threats in our environment",
        "Create a detection rule for this behavior",
        "Set up SOAR automation for phishing"
    ]
    
    print("Enhanced Manager Agent Delegation Examples:\n")
    
    for request in test_requests:
        suggested = config_loader.get_agent_for_request(request)
        if suggested:
            config = config_loader.get_agent_capabilities(suggested)
            print(f"Request: '{request}'")
            print(f"  → Delegates to: {config.get('display_name', suggested)}")
            print(f"  → Reason: Matches expertise in {config.get('expertise_areas', [])[:2]}")
            print()


# For testing purposes
if __name__ == "__main__":
    asyncio.run(demonstrate_enhanced_manager())