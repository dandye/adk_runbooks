from google.adk.agents import Agent

from manager.tools.tools import get_agent_tools


async def get_agent():
  tools, common_exit_stack = await get_agent_tools()
  #siem_tools, soar_tools, common_exit_stack = tools

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_1.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/triage_alerts.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/close_duplicate_or_similar_cases.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investgate_a_case_w_external_tools.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases_v2.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/basic_ioc_enrichment.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/suspicious_login_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/demo_soc_t1_siem_runbook.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/demo_threat_intel_workflows.md",
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default CTI Researcher description: Responsible for threat intelligence."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  soc_analyst_tier1 = Agent(
      name="soc_analyst_tier1",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Tier 1 SOC Analyst.""",
      #tools=[*siem_tools, *soar_tools],
      tools=tools,
  )
  return soc_analyst_tier1, common_exit_stack


agent_coroutine = get_agent()
#
## Export these for other modules to use
soc_analyst_tier1 = None
exit_stack = None
#
## Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global soc_analyst_tier1, exit_stack
    try:
      soc_analyst_tier1, exit_stack = await agent_coroutine
      return soc_analyst_tier1, exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent: {e}")
      # You might want to clean up any partially initialized resources
      if exit_stack:
          await exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed