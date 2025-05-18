from google.adk.agents import Agent

from manager.tools.tools import get_agent_tools


async def get_agent():
  tools, common_exit_stack = await get_agent_tools()

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

  incident_responder = Agent(
      name="incident_responder",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are an Incident Responder. Your primary role is to manage the full lifecycle of security incidents, from initial detection and triage through containment, eradication, recovery, and post-incident analysis.""",
      tools=tools,
  )
  return incident_responder, common_exit_stack


agent_coroutine = get_agent()
#
## Export these for other modules to use
incident_responder = None
exit_stack = None
#
## Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global incident_responder, exit_stack
    try:
      incident_responder, exit_stack = await agent_coroutine
      return incident_responder, exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent: {e}")
      # You might want to clean up any partially initialized resources
      if exit_stack:
          await exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed
