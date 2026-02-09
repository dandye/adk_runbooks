from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


def get_agent(tools):
  """Configures and returns a Threat Hunter Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools tailored for proactive threat hunting activities.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the Threat Hunter agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/threat_hunter.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/advanced_threat_hunting.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/proactive_threat_hunting_based_on_gti_campaign_or_actor.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Threat Hunter description: Responsible for proactive threat hunting."
  )

  agent_instance = Agent(
      name="threat_hunter",
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""You are a Threat Hunter agent.""",
      tools=tools,
  )
  return agent_instance


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the Threat Hunter agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/threat_hunter.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)