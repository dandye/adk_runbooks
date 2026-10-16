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
      "gti-collection-threat-hunt",
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
      model="gemini-3-flash-preview",
      description=persona_description,
      instruction="""You are a Threat Hunter (`threat_hunter`). Never call `transfer_to_agent` with `threat_hunter` (yourself). Before calling `execute_mcp_tool`, you MUST call `load_skill(skill_name)` FIRST as your initial action to load the matching runbook. Then use progressive MCP discovery: call `search_mcp_tools` or `get_mcp_tool_schema` to verify exact tool names and parameter schemas before calling `execute_mcp_tool`. In your final summary, list every distinct hostname, user principal, external IP, domain, and SHA256 hash observed across all SIEM events (even when `BENIGN`). Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
