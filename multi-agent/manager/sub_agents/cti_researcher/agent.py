from google.adk.agents import Agent

from manager.tools.tools import get_agent_tools


async def get_agent():
  tools, exit_stack = await get_agent_tools()
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

  try:
    with open(persona_file_path, 'r') as f:
      persona_data = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_data = "Default CTI Researcher description: Responsible for threat intelligence."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_data += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")


  cti_researcher = Agent(
      name="cti_researcher",
      # model="gemini-2.0-flash",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_data,
      instruction="You are a CTI Researcher.",
      tools=tools,
      # enabled_mcp_servers=["gti-mcp"],
  )
  return cti_researcher, exit_stack

agent_coroutine = get_agent()

# Export these for other modules to use
cti_researcher = None
exit_stack = None

# Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global cti_researcher, exit_stack
    cti_researcher, exit_stack = await agent_coroutine
    return cti_researcher, exit_stack
