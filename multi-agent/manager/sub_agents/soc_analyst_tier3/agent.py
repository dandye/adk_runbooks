from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns a SOC Analyst Tier 3 Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools necessary for advanced Tier 3 SOC operations, including
  complex incident response, deep-dive analysis, and potentially
  leading response efforts.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the SOC Analyst Tier 3 agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_3.md").resolve()
  skills = [
      "deep-dive-ioc-analysis",
      "malware-triage",
      "compromised-user-account-response",
      "ransomware-response",
      "detection-rule-validation-tuning",
      "create-investigation-report",
      "report-writing-guidelines",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default SOC Analyst Tier 3 description: Responsible for advanced incident response and analysis."
  )

  agent_instance = Agent(
      name="soc_analyst_tier3",
      model="gemini-3.7-flash",
      description=persona_description,
      instruction="""You are a Tier 3 SOC Analyst. You handle escalated incidents, perform deep-dive analysis, and lead response efforts. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.""",
      tools=tools,
  )
  return agent_instance
