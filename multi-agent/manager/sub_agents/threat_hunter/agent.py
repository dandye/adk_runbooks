from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a Threat Hunter Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools tailored for proactive threat hunting activities.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the Threat Hunter agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/threat_hunter.md").resolve()
  skills = [
      "advanced-threat-hunting",
      "apt-threat-hunt",
      "ioc-threat-hunt",
      "guided-ttp-hunt-credential-access",
      "lateral-movement-hunt-psexec-wmi",
      "proactive-hunt-gti-campaign",
      "report-writing-guidelines",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default Threat Hunter description: Responsible for proactive threat hunting."
  )

  agent_instance = Agent(
      name="threat_hunter",
      model="gemini-3.7-flash",
      description=persona_description,
      instruction="""You are a Threat Hunter agent. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.""",
      tools=tools,
  )
  return agent_instance
