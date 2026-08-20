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
      model="gemini-2.5-flash",
      description=persona_description,
      instruction="""You are a Detection Engineer. Your role involves designing, developing, testing, and maintaining security detection rules and analytics to identify threats and malicious activities. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.""",
      tools=tools,
  )
  return agent_instance
