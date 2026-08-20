from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a Threat Hunter Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools tailored for proactive threat hunting activities.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets.

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
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""You are a Threat Hunter agent. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant.""",
      tools=tools,
  )
  return agent_instance