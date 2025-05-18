from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns a Detection Engineer Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools focused on creating, tuning, and managing security
  detection rules and analytics.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the Detection Engineer agent.
  """
  # Removed: tools, common_exit_stack = await get_agent_tools()

  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/detection_engineer.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/detection_as_code_workflows.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/detection_report.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(), # For TTP understanding
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(), # For documenting detections
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Detection Engineer description: "
      "Responsible for creating, tuning, and managing security detection rules."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="detection_engineer",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="You are a Detection Engineer. "
      "Your role involves designing, developing, testing, and maintaining "
      "security detection rules and analytics to identify threats and "
      "malicious activities.",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Removed module-level agent_coroutine, detection_engineer, exit_stack

# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the Detection Engineer agent.

    This function serves as the entry point for creating an instance of the
    Detection Engineer agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized Detection Engineer agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    # global detection_engineer, exit_stack # No longer needed
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent detection_engineer: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
