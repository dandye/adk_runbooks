from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns a Threat Hunter Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools tailored for proactive threat hunting activities.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the Threat Hunter agent.
  """
  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/threat_hunter.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/advanced_threat_hunting.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/apt_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md", # Added report writing
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Threat Hunter description: Responsible for proactive threat hunting."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="threat_hunter",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Threat Hunter agent.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the Threat Hunter agent.

    This function serves as the entry point for creating an instance of the
    Threat Hunter agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized Threat Hunter agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent threat_hunter: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
