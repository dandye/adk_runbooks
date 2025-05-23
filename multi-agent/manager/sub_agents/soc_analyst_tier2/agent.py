from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns a SOC Analyst Tier 2 Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for Tier 2 SOC operations, including deeper
  investigation and case management.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 2 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_2.md").resolve()
  runbook_files = [
    # Guidelines
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
    # Runboosk
    (BASE_DIR / "../../../../rules-bank/run_books/case_event_timeline_and_process_analysis.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/cloud_vulnerability_triage_and_contextualization.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/create_an_investigation_report.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/investigate_a_gti_collection_id.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/prioritize_and_investigate_a_case.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/investgate_a_case_w_external_tools.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases_v2.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/malware_triage.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md").resolve(),

    (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Tier 2 SOC Analyst."
  )

  agent_instance = Agent( # Corrected variable name
      name="soc_analyst_tier2",
      #model="gemini-2.0-flash",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="You are a Tier 2 SOC Analyst.",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the SOC Analyst Tier 2 agent.

    This function serves as the entry point for creating an instance of the
    SOC Analyst Tier 2 agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized SOC Analyst Tier 2 agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
    return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
