from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a SOC Analyst Tier 2 Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools necessary for Tier 2 SOC operations, including deeper
  investigation and case management.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 2 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_2.md").resolve()
  skills = [
      "report-writing-guidelines",
      "case-event-timeline-analysis",
      "cloud-vulnerability-triage",
      "compare-gti-collection",
      "create-investigation-report",
      "investigate-gti-collection",
      "proactive-hunt-gti-campaign",
      "prioritize-and-investigate-case",
      "investigate-case-external-tools",
      "group-cases",
      "group-cases-v2",
      "deep-dive-ioc-analysis",
      "guided-ttp-hunt-credential-access",
      "malware-triage",
      "lateral-movement-hunt-psexec-wmi",
      "ioc-threat-hunt",
      "apt-threat-hunt",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default SOC Analyst Tier 2 description: Responsible for deeper investigation, threat hunting, and case management."
  )

  agent_instance = Agent(
      name="soc_analyst_tier2",
      model="gemini-2.5-flash-lite",
      description=persona_description,
      instruction="""You are a Tier 2 SOC Analyst responsible for deeper investigations and threat hunting. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.""",
      tools=tools,
  )
  return agent_instance
