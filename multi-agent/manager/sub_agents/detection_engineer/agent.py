from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_and_runbooks


# Changed to a synchronous function that accepts tools and exit_stack
def get_agent(tools):
  """Configures and returns a Detection Engineer Agent instance.

  This function sets up the agent with a specific persona, runbooks,
  and tools focused on creating, tuning, and managing security
  detection rules and analytics.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the Detection Engineer agent.
  """
  # Removed: tools, common_exit_stack = await get_agent_tools()

  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/detection_engineer.md").resolve()
  runbook_files = [
    (BASE_DIR / "../../../../rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/detection_as_code_workflows.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/detection_report.md").resolve(),
    (BASE_DIR / "../../../../rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(), # For TTP understanding
    (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(), # For documenting detections
  ]

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="Default Detection Engineer description: "
      "Responsible for creating, tuning, and managing security detection rules."
  )

  agent_instance = Agent( # Renamed to avoid conflict
      name="detection_engineer",
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="You are a Detection Engineer. "
      "Your role involves designing, developing, testing, and maintaining "
      "security detection rules and analytics to identify threats and "
      "malicious activities.",
      tools=tools, # Use passed-in tools
  )
  return agent_instance # Only return the agent instance


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the Detection Engineer agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/detection_engineer.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)
