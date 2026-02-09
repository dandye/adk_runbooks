from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools):
  """Configures and returns a SOC Analyst Tier 3 Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools necessary for advanced Tier 3 SOC operations, including
  complex incident response, deep-dive analysis, and potentially
  leading response efforts.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 3 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_3.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/malware_triage.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/create_an_investigation_report.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default SOC Analyst Tier 3 description: Responsible for advanced incident response and analysis."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="soc_analyst_tier3",
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""You are a Tier 3 SOC Analyst. You handle escalated incidents, perform deep-dive analysis, and lead response efforts.""",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the SOC Analyst Tier 3 agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/soc_analyst_tier3.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)
