from google.adk.agents import Agent

from manager.tools.tools import get_agent_tools


async def get_agent():
  tools, common_exit_stack = await get_agent_tools()

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_3.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/compromised_user_account_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ransomware_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/detection_rule_validation_tuning.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/create_an_investigation_report.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default SOC Analyst Tier 3 description: Responsible for advanced incident response and analysis."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  soc_analyst_tier3 = Agent(
      name="soc_analyst_tier3",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Tier 3 SOC Analyst. You handle escalated incidents, perform deep-dive analysis, and lead response efforts.""",
      tools=tools,
  )
  return soc_analyst_tier3, common_exit_stack


agent_coroutine = get_agent()
#
## Export these for other modules to use
soc_analyst_tier3 = None
exit_stack = None
#
## Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global soc_analyst_tier3, exit_stack
    try:
      soc_analyst_tier3, exit_stack = await agent_coroutine
      return soc_analyst_tier3, exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent: {e}")
      # You might want to clean up any partially initialized resources
      if exit_stack:
          await exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed
