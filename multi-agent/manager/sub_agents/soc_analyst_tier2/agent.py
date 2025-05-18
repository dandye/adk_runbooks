from google.adk.agents import Agent

# Removed: from manager.tools.tools import get_agent_tools


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools, exit_stack):
  # Removed: tools, exit_stack = await get_agent_tools()
  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_2.md"
  runbook_files = [

    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/case_event_timeline_and_process_analysis.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/cloud_vulnerability_triage_and_contextualization.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/create_an_investigation_report.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investigate_a_gti_collection_id.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/prioritize_and_investigate_a_case.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investgate_a_case_w_external_tools.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases_v2.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/report_writing.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/apt_threat_hunt.md",

    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/demo_soc_t2_soar_runbook.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/demo_threat_intel_workflows.md",
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default Tier 2 SOC Analyst."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  agent_instance = Agent( # Corrected variable name
      name="soc_analyst_tier2",
      #model="gemini-2.0-flash",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="You are a Tier 2 SOC Analyst.",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance

# Removed module-level agent_coroutine, soc_analyst_tier2, exit_stack

# Function to initialize the agent, now accepts shared_tools and shared_exit_stack
async def initialize(shared_tools, shared_exit_stack):
    # global soc_analyst_tier2, exit_stack # No longer needed
    agent_instance = get_agent(shared_tools, shared_exit_stack) # Call synchronous get_agent
    return agent_instance, shared_exit_stack # Return agent and the shared_exit_stack
