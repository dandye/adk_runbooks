from google.adk.agents import Agent
from ...tools.tools import load_persona_and_runbooks

# Removed: from manager.tools.tools import get_agent_tools


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  # Removed: tools, common_exit_stack = await get_agent_tools()

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


# Removed module-level agent_coroutine, threat_hunter, exit_stack

# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    # global threat_hunter, exit_stack # No longer needed
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent threat_hunter: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
