from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks
from ..response_format_instruction import get_agent_instruction


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns a SOC Analyst Tier 1 Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for Tier 1 SOC operations.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 1 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_1.md").resolve()
  runbook_files = [
    # Guidelines
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/sub_agent_response_format.md").resolve(),
    # Runbooks
    (BASE_DIR / "../../../../rules-bank/run_books/triage_alerts.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/close_duplicate_or_similar_cases.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/investgate_a_case_w_external_tools.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases_v2.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/basic_ioc_enrichment.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/suspicious_login_triage.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default SOC Analyst Tier 1 description: Responsible for initial alert triage and basic IOC enrichment."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="soc_analyst_tier1",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction=get_agent_instruction("""You are SOC Analyst Tier 1 responsible for initial alert triage and investigation.

        **Your MCP Tool Access:**
        - **SIEM tools** - Query security logs, search for IOCs, analyze basic events
        - **SOAR tools** - View cases for context during triage
        - **GTI tools** - Basic IOC lookups for enrichment
        
        **Key Capabilities:**
        - Perform initial alert triage using SIEM queries
        - Search for IOCs across security logs
        - Basic endpoint analysis and data gathering
        - Initial assessment of security alerts
        
        Always use your SIEM MCP tools proactively to investigate alerts and gather evidence."""),
      tools=tools,
  )
  return agent_instance # Only return the agent instance


# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the SOC Analyst Tier 1 agent.

    This function serves as the entry point for creating an instance of the
    SOC Analyst Tier 1 agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized SOC Analyst Tier 1 agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    # global soc_analyst_tier1, exit_stack # No longer needed
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      # soc_analyst_tier1, exit_stack = await agent_coroutine # Old way
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent soc_analyst_tier1: {e}") # Added agent name for clarity
      # You might want to clean up any partially initialized resources
      # The shared_exit_stack is managed by the caller (manager agent)
      # if shared_exit_stack: # This check might not be necessary if manager handles it
      #     await shared_exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed
