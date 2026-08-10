from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


def get_agent(tools):
  """Configures and returns a SOC Analyst Tier 1 Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for Tier 1 SOC operations.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 1 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_1.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/triage_alerts.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/close_duplicate_or_similar_cases.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/investigate_a_case_w_external_tools.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/group_cases_v2.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/basic_ioc_enrichment.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/suspicious_login_triage.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default SOC Analyst Tier 1 description: Responsible for initial alert triage and basic IOC enrichment."
  )

  agent_instance = Agent(
      name="soc_analyst_tier1",
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""You are a Tier 1 SOC Analyst.""",
      tools=tools,
  )
  return agent_instance


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the SOC Analyst Tier 1 agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/soc_analyst_tier1.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)