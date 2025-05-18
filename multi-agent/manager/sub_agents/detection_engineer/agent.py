from google.adk.agents import Agent

from manager.tools.tools import get_agent_tools


async def get_agent():
  tools, common_exit_stack = await get_agent_tools()

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/detection_engineer.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/detection_rule_validation_tuning.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/detection_as_code_workflows.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/detection_report.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access.md", # For TTP understanding
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md", # For documenting detections
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default Detection Engineer description: Responsible for creating, tuning, and managing security detection rules."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  detection_engineer = Agent(
      name="detection_engineer",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Detection Engineer. Your role involves designing, developing, testing, and maintaining security detection rules and analytics to identify threats and malicious activities.""",
      tools=tools,
  )
  return detection_engineer, common_exit_stack


agent_coroutine = get_agent()
#
## Export these for other modules to use
detection_engineer = None
exit_stack = None
#
## Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global detection_engineer, exit_stack
    try:
      detection_engineer, exit_stack = await agent_coroutine
      return detection_engineer, exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent: {e}")
      # You might want to clean up any partially initialized resources
      if exit_stack:
          await exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed
