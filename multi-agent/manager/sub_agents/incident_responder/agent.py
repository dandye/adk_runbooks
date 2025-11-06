from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools):
  """Configures and returns an Incident Responder Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools focused on incident response procedures, including containment,
  eradication, and recovery.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

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
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""You are an Incident Responder. Your primary role is to manage the full lifecycle of security incidents, from initial detection and triage through containment, eradication, recovery, and post-incident analysis.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance
