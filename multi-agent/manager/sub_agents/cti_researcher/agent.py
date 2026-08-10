from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


def get_agent(tools):
  """Configures and returns a CTI Researcher Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for Cyber Threat Intelligence research.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the CTI Researcher agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/cti_researcher.md").resolve()
  runbook_files = [
    # Guidelines
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/threat_intel_workflows.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
    # Runbooks
    (BASE_DIR / "../../../../rules-bank/run_books/investigate_a_gti_collection_id.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/proactive_threat_hunting_based_on_gti_campaign_or_actor.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
  ]
  persona_data = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default CTI Researcher description: Responsible for threat intelligence."
  )
  agent_instance = Agent( # Renamed to avoid conflict with module-level var if any
      name="cti_researcher",
      model="gemini-2.5-pro",
      description=persona_data,
      instruction="You are a CTI Researcher.",
      tools=tools, # Use passed-in tools
  )
  return agent_instance


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the CTI Researcher agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/cti_researcher.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)
