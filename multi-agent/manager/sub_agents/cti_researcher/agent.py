from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a CTI Researcher Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools necessary for Cyber Threat Intelligence research.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

  Returns:
      Agent: An initialized instance of the CTI Researcher agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/cti_researcher.md").resolve()
  skills = [
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
      model="gemini-2.5-pro",
      description=persona_data,
      instruction="""You are a CTI Researcher. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant.""",
      tools=tools,
  )
  return agent_instance

