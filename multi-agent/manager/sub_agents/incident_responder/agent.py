from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  """Configures and returns an Incident Responder Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools focused on incident response procedures, including containment,
  eradication, and recovery.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.
      exit_stack (contextlib.AsyncExitStack): The shared asynchronous exit stack
          for managing resources. (Currently not directly used by the synchronous
          agent creation but passed for consistency with async initialization patterns).

  Returns:
      Agent: An initialized instance of the Incident Responder agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/incident_responder.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/irps/malware_incident_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/irps/phishing_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/basic_endpoint_triage_isolation.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/ioc_containment.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/create_an_investigation_report.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Incident Responder description: Responsible for managing and responding to security incidents."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="incident_responder",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are an Incident Responder. Your primary role is to manage the full lifecycle of security incidents, from initial detection and triage through containment, eradication, recovery, and post-incident analysis.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    """Asynchronously initializes the Incident Responder agent.

    This function serves as the entry point for creating an instance of the
    Incident Responder agent, utilizing shared toolsets and an exit stack.

    Args:
        shared_tools (tuple): The pre-initialized MCP toolsets to be used by the agent.
        shared_exit_stack (contextlib.AsyncExitStack): The asynchronous exit stack
            for managing the lifecycle of shared resources like MCP connections.

    Returns:
        tuple: A tuple containing:
            - Agent: The initialized Incident Responder agent instance.
            - contextlib.AsyncExitStack: The shared exit stack.

    Raises:
        Exception: Propagates any exceptions encountered during agent creation.
    """
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent incident_responder: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
