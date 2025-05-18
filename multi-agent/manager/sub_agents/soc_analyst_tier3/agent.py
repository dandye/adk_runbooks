from google.adk.agents import Agent

# Removed: from manager.tools.tools import get_agent_tools


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  # Removed: tools, common_exit_stack = await get_agent_tools()

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_3.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/compromised_user_account_response.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/irps/ransomware_response.md",
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

  agent_instance = Agent( # Renamed to avoid conflict
      name="soc_analyst_tier3",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Tier 3 SOC Analyst. You handle escalated incidents, perform deep-dive analysis, and lead response efforts.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


# Removed module-level agent_coroutine, soc_analyst_tier3, exit_stack

# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    # global soc_analyst_tier3, exit_stack # No longer needed
    try:
      agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
      return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent soc_analyst_tier3: {e}") # Added agent name for clarity
      # The shared_exit_stack is managed by the caller (manager agent)
      raise  # Re-raise the exception to let callers know initialization failed
