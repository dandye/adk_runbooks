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
        "soc_analyst_tier2": "http://localhost:8004",
        "soc_analyst_tier3": "http://localhost:8008",
        "threat_hunter": "http://localhost:8005",
        "detection_engineer": "http://localhost:8006",
        "incident_responder": "http://localhost:8007",
    },
    "connections": {},
    "available_agents": []
}


async def send_message_to_agent(agent_name: str, message: str) -> str:
    """
    Send a message to a remote agent via A2A.

    Args:
        agent_name: Name of the agent to send to (e.g., "cti_researcher", "soc_analyst_tier1", "soc_analyst_tier2")
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
        # Reporting Templates
        (BASE_DIR / "../../../rules-bank/reporting_templates.md").resolve(),
        # IRPs
        (BASE_DIR / "../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/phishing_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/malware_incident_response.md").resolve(),
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
- SOC Analyst Tier 2: For advanced alert triage and investigation
- Threat Hunter: For proactive threat hunting and hypothesis-driven investigation
- Detection Engineer: For creating and tuning detection rules
- Incident Responder: For containing and eradicating threats
- SOC Analyst Tier 3: For advanced investigation and threat hunting

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
The CTI Researcher (8001), SOC Analyst Tier 1 (8002), SOC Analyst Tier 2 (8004), SOC Analyst Tier 3 (8008), Threat Hunter (8005), Detection Engineer (8006), and Incident Responder (8007) agents should be running on their respective ports.

**Sub-Agent Response Handling:**
All A2A sub-agents return structured responses following sub_agent_response_format.md. When receiving responses:
1. Parse the structured sections (Task Summary, Findings, Analysis, Actions Taken, Recommendations)
2. Extract key information for compilation into reports
3. Track tool usage and create consolidated workflow diagrams
4. Maintain a running compilation of findings for final IRP reporting

**Incident Response Plan (IRP) Execution:**
When an IRP is invoked (e.g., "Start Malware IRP for CASE_ID 123"):
1. Your **first priority** is to understand the active IRP. The IRP details, including phases, steps, and responsible personas, are part of your contextual description.
2. You **MUST** meticulously follow the IRP. For each step, identify the responsible personas and delegate to the appropriate A2A agent.
3. Delegate tasks **strictly according to IRP assignments**. For example, if the IRP says "SOC Analyst T1" is responsible, delegate to the SOC Analyst Tier 1 agent.
4. Ensure you receive and process responses from each agent before proceeding to the next IRP step.
5. Provide clear context and necessary inputs from the IRP or previous steps when delegating.
6. If the IRP specifies "SOC Manager (Approval)" for a step, you must make an explicit approval decision.
7. **Track IRP Progress:** Maintain awareness of which IRP phase you are currently executing (Phase 1-6). After completing each phase, explicitly acknowledge the phase completion.
8. **Phase 6 Leadership:** For Phase 6 (Lessons Learned), you are the lead. Coordinate with all involved agents to gather their feedback.

**IRP Completion and Reporting:**
When all phases of an IRP have been completed (including Phase 6: Lessons Learned):
1. Compile all findings and actions from each phase - gather comprehensive input from all involved A2A agents
2. Generate a Post-Incident Report following the template structure:
   - Executive Summary (2-3 paragraphs for management)
   - Incident Classification (type, severity, MITRE ATT&CK TTPs)
   - Incident Timeline (chronological table of events)
   - Technical Details (attack vector, progression, IOCs, affected assets)
   - Impact Assessment (business and technical impact)
   - Response Actions Taken (organized by timeframe)
   - Root Cause Analysis
   - Lessons Learned (what worked well, areas for improvement)
   - Recommendations (immediate, short-term, long-term actions)
   - Workflow Diagram (Mermaid diagram showing agent/tool interactions)
3. Use the write_report tool to save the report with naming format: "IRP_[Type]_Report_CASE_[ID]_[timestamp].md"
4. Include in the report:
   - **Runbook Used:** [IRP name]
   - **Case ID:** [CASE_ID]
   - **Generated:** [timestamp from get_current_time]
   - Complete Mermaid sequence diagram showing all A2A agent communications throughout the IRP
5. Announce to the user that the IRP is complete and provide the path to the generated report

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
