"""SOC Manager Host Agent with A2A capabilities for ADK Web."""

import asyncio
import logging
from typing import Any, Dict, List
from pathlib import Path

from google.adk.agents import Agent
try:
    from a2a.client import A2ACardResolver, A2AClient
    import httpx
    A2A_SDK_AVAILABLE = True
except ImportError:
    A2A_SDK_AVAILABLE = False
    print("Warning: a2a-sdk not available. A2A functionality will be limited.")
    
    # Create mock classes for fallback
    class A2ACardResolver:
        def __init__(self, httpx_client, base_url):
            self.httpx_client = httpx_client
            self.base_url = base_url
            
        async def resolve(self):
            return {
                "name": "mock_agent",
                "description": "Mock agent (a2a-sdk not available)",
                "tools": []
            }
    
    class A2AClient:
        pass

try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    print("Warning: nest_asyncio not available. May have issues with nested event loops.")

from .tools.tools import get_current_time, write_report, load_persona_and_runbooks
from .remote_agent_connection import RemoteAgentConnection

# Apply nest_asyncio to handle nested event loops
nest_asyncio.apply()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global storage for agent connections (to avoid Pydantic attribute issues)
_agent_connections = {
    "urls": {
        "cti_researcher": "http://localhost:8001",
        "soc_analyst_tier1": "http://localhost:8002",
        "soar_specialist": "http://localhost:8003",
    },
    "connections": {},
    "available_agents": []
}


async def send_message_to_agent(agent_name: str, message: str) -> str:
    """
    Send a message to a remote agent via A2A.
    
    Args:
        agent_name: Name of the agent to send to (e.g., "cti_researcher", "soc_analyst_tier1", "soar_specialist")
        message: The message/task to send to the agent
        
    Returns:
        The agent's response as a string
    """
    if agent_name not in _agent_connections["connections"]:
        available = list(_agent_connections["connections"].keys())
        return f"Error: Agent '{agent_name}' not found. Available agents: {available}"
    
    connection = _agent_connections["connections"][agent_name]
    
    if connection is None:
        return f"Error: Connection to agent '{agent_name}' is not established."
    
    try:
        # Send message and get response
        response = await connection.send_message(message)
        return response
        
    except Exception as e:
        logger.error(f"Error sending message to {agent_name}: {e}")
        return f"Error communicating with {agent_name}: {str(e)}"


async def initialize_a2a_connections():
    """Initialize connections to remote A2A agents."""
    logger.info("Initializing A2A connections...")
    
    # Create an httpx client for A2A connections
    async with httpx.AsyncClient() as client:
        for agent_name, agent_url in _agent_connections["urls"].items():
            try:
                # Get agent card directly from root endpoint
                response = await client.get(agent_url + '/')
                response.raise_for_status()
                agent_card = response.json()
                
                # Create connection
                connection = RemoteAgentConnection(
                    agent_name=agent_name,
                    agent_url=agent_url,
                    agent_card=agent_card
                )
                
                _agent_connections["connections"][agent_name] = connection
                _agent_connections["available_agents"].append({
                    "name": agent_name,
                    "url": agent_url,
                    "description": agent_card.get("description", "No description available"),
                    "status": "online"
                })
                
                logger.info(f"Successfully connected to {agent_name} at {agent_url}")
                
            except Exception as e:
                logger.error(f"Failed to connect to {agent_name} at {agent_url}: {e}")
                _agent_connections["available_agents"].append({
                    "name": agent_name,
                    "url": agent_url,
                    "description": "Connection failed",
                    "status": "offline"
                })


def create_soc_manager_host_agent():
    """Create the SOC Manager Host Agent."""
    # Initialize base configuration
    BASE_DIR = Path(__file__).resolve().parent
    persona_file_path = (BASE_DIR / "../../../rules-bank/personas/soc_manager.md").resolve()
    runbook_files = [
        # Guidelines
        (BASE_DIR / "../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
        # IRPs
        (BASE_DIR / "../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/phishing_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
        # Runbooks
        (BASE_DIR / "../../../rules-bank/run_books/triage_alerts.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/prioritize_and_investigate_a_case.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/basic_ioc_enrichment.md").resolve(),
    ]
    
    persona_description = load_persona_and_runbooks(
        persona_file_path,
        runbook_files,
        default_persona_description="SOC Manager: Orchestrates security operations and coordinates between specialized agents."
    )
    
    # Create and return the agent
    return Agent(
        name="soc_manager_host",
        model="gemini-2.5-pro-preview-05-06",
        description=persona_description,
        instruction="""
You are the SOC Manager host agent, responsible for orchestrating security operations through A2A coordination with specialized agents.

**A2A Agent Coordination:**
You can delegate tasks to specialized agents using the send_message_to_agent tool:
- CTI Researcher: For threat intelligence, IOC analysis, and threat actor tracking
- SOC Analyst Tier 1: For initial alert triage and basic investigation
- SOAR Specialist: For SOAR platform operations, case management, and workflow automation

When delegating tasks:
1. Use send_message_to_agent() to communicate with the appropriate agent
2. Provide clear context and requirements in your message
3. Wait for and process the agent's response
4. Coordinate between multiple agents when needed
5. Synthesize results and provide comprehensive analysis

**Your Direct Tools:**
- get_current_time: Check current time for reporting
- write_report: Generate comprehensive security reports
- send_message_to_agent: Communicate with A2A agents

**Available Agents:**
The CTI Researcher (8001), SOC Analyst Tier 1 (8002), and SOAR Specialist (8003) agents should be running on their respective ports.

Always aim for efficient coordination and clear communication when working with sub-agents.
""",
        tools=[
            get_current_time,
            write_report,
            send_message_to_agent,  # A2A communication tool
        ],
    )


# Function to get the initialized host agent (for ADK web compatibility)
def _get_initialized_host_agent_sync():
    """Synchronously return a host agent instance for ADK registration."""
    # Create the event loop if it doesn't exist
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    # Initialize A2A connections
    loop.run_until_complete(initialize_a2a_connections())
    
    # Create and return the agent
    return create_soc_manager_host_agent()


# Create the agent instance for module-level access
agent = _get_initialized_host_agent_sync()