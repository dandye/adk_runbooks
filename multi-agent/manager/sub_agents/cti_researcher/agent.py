from google.adk.agents import Agent
from ...tools.tools import load_persona_and_runbooks

# Removed: from manager.tools.tools import get_agent_tools


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
  # Removed: tools, exit_stack = await get_agent_tools()
  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/cti_researcher.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investigate_a_gti_collection_id.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/apt_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
    #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/threat_intel_workflows.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
    #  # `case_event_timeline_and_process_analysis.md`, `create_an_investigation_report.md`, `phishing_response.md`, or `ransomware_response.md`.

    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/demo_cti_gti_runbook.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/demo_threat_intel_workflows.md",
  ]

  persona_data = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default CTI Researcher description: Responsible for threat intelligence."
  )

  agent_instance = Agent( # Renamed to avoid conflict with module-level var if any
      name="cti_researcher",
      # model="gemini-2.0-flash",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_data,
      instruction="You are a CTI Researcher.",
      tools=tools, # Use passed-in tools
      # enabled_mcp_servers=["gti-mcp"],
  )
  return agent_instance # Only return the agent instance

# Removed module-level agent_coroutine, cti_researcher, exit_stack

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
    # global cti_researcher, exit_stack # No longer needed
    agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
    # cti_researcher, exit_stack = await agent_coroutine # Old way
    return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
