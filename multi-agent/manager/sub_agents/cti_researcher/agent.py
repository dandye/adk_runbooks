from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks
from ..response_format_instruction import get_agent_instruction


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns a CTI Researcher Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for Cyber Threat Intelligence research.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the CTI Researcher agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/cti_researcher.md").resolve()
  runbook_files = [
    # Guidelines
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/threat_intel_workflows.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/sub_agent_response_format.md").resolve(),
    # Runbooks
    (BASE_DIR / "../../../../rules-bank/run_books/investigate_a_gti_collection_id.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
  ]
  persona_data = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default CTI Researcher description: Responsible for threat intelligence."
  )
  agent_instance = Agent( # Renamed to avoid conflict with module-level var if any
      name="cti_researcher",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_data,
      instruction=get_agent_instruction("""You are a CTI Researcher specializing in threat intelligence analysis.

        **Your MCP Tool Access:**
        - **GTI tools** - Google Threat Intelligence platform for IOC lookups, threat actor profiles, malware analysis
        - **SIEM tools** - Query security logs to correlate with threat intelligence
        - **SOAR tools** - Access case data for threat intelligence context
        
        **Key Capabilities:**
        - When asked about any hash, IP, domain, or URL - use GTI tools immediately
        - Perform threat actor attribution and campaign analysis
        - Analyze malware families and their behaviors
        - Provide strategic threat intelligence assessments
        
        Always use your GTI MCP tools proactively when any IOC or threat intelligence is requested."""),
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the CTI Researcher agent.

    This function serves as the entry point for creating an instance of the
    CTI Researcher agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized CTI Researcher agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
    return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
