from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a Detection Engineer Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools focused on creating, tuning, and managing security
  detection rules and analytics.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the Detection Engineer agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/detection_engineer.md").resolve()
  skills = [
      "detection-engineering-coverage-evaluation",
      "detection-rule-validation-tuning",
      "detection-as-code-workflows",
      "detection-report",
      "guided-ttp-hunt-credential-access",
      "report-writing-guidelines",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default Detection Engineer description: "
      "Responsible for creating, tuning, and managing security detection rules."
  )

  agent_instance = Agent(
      name="detection_engineer",
      model="gemini-3-flash-preview",
      description=persona_description,
      instruction="""You are a Detection Engineer (`detection_engineer`). Never call `transfer_to_agent` with `detection_engineer` (yourself). Before calling `execute_mcp_tool`, you MUST call `load_skill(skill_name)` FIRST as your initial action to load the matching runbook. Then use progressive MCP discovery: call `search_mcp_tools` or `get_mcp_tool_schema` to verify exact tool names and parameter schemas before calling `execute_mcp_tool`. Always validate candidate YARA-L 2.0 rules with `validate_yaral2_rule`. Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
