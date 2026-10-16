from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a CTI Researcher Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools necessary for Cyber Threat Intelligence research.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the CTI Researcher agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/cti_researcher.md").resolve()
  skills = [
      "gti-collection-threat-hunt",
      "report-writing-guidelines",
      "investigate-gti-collection",
      "proactive-hunt-gti-campaign",
      "compare-gti-collection",
      "ioc-threat-hunt",
      "apt-threat-hunt",
      "deep-dive-ioc-analysis",
  ]
  persona_data = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default CTI Researcher description: Responsible for threat intelligence."
  )
  agent_instance = Agent(
      name="cti_researcher",
      model="gemini-3-flash-preview",
      description=persona_data,
      instruction="""You are a Cyber Threat Intelligence (CTI) Researcher (`cti_researcher`). Never call `transfer_to_agent` with `cti_researcher` (yourself). Before calling `execute_mcp_tool`, you MUST call `load_skill(skill_name)` FIRST as your initial action to load the matching runbook. Then use progressive MCP discovery: call `search_mcp_tools` or `get_mcp_tool_schema` to verify exact tool names and parameter schemas before calling `execute_mcp_tool`. Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
