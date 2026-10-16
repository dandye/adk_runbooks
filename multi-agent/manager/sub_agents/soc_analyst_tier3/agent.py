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
      "cloud-honeytoken-deception-triage",
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
      model="gemini-3-flash-preview",
      description=persona_description,
      instruction="""You are a Tier 3 SOC Analyst (`soc_analyst_tier3`). Never call `transfer_to_agent` with `soc_analyst_tier3` (yourself). Before calling `execute_mcp_tool`, you MUST call `load_skill(skill_name)` FIRST as your initial action to load the matching runbook. Then use progressive MCP discovery: call `search_mcp_tools` or `get_mcp_tool_schema` to verify exact tool names and parameter schemas before calling `execute_mcp_tool`. In your final summary, list every distinct hostname, user principal, external IP, domain, and SHA256 hash observed across all case alerts and SIEM events (even when `BENIGN`). Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
