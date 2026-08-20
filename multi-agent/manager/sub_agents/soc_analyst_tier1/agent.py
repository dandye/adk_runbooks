from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a SOC Analyst Tier 1 Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools necessary for Tier 1 SOC operations.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 1 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_1.md").resolve()
  skills = [
      "triage-alerts",
      "close-duplicate-cases",
      "investigate-case-external-tools",
      "group-cases",
      "group-cases-v2",
      "basic-ioc-enrichment",
      "suspicious-login-triage",
      "report-writing-guidelines",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default SOC Analyst Tier 1 description: Responsible for initial alert triage and basic IOC enrichment."
  )

  agent_instance = Agent(
      name="soc_analyst_tier1",
      model="gemini-2.5-flash-lite",
      description=persona_description,
      instruction="""You are a Tier 1 SOC Analyst. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. To query external systems (SIEM, SOAR, GTI, SecOps), use progressive MCP discovery: use `search_mcp_tools` to find available tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them. Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
