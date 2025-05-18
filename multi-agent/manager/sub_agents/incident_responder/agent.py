from google.adk.agents import Agent

# Removed: from manager.tools.tools import get_agent_tools


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  # Removed: tools, common_exit_stack = await get_agent_tools()

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/incident_responder.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/compromised_user_account_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/malware_incident_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/phishing_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/ransomware_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/basic_endpoint_triage_isolation.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_containment.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/create_an_investigation_report.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default Incident Responder description: Responsible for managing and responding to security incidents."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  agent_instance = Agent( # Renamed to avoid conflict
      name="incident_responder",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are an Incident Responder. Your primary role is to manage the full lifecycle of security incidents, from initial detection and triage through containment, eradication, recovery, and post-incident analysis.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Removed module-level agent_coroutine, incident_responder, exit_stack

# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    # global incident_responder, exit_stack # No longer needed
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent incident_responder: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
