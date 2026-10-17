from pathlib import Path
from google.adk.agents import Agent

from ...tools.tools import load_persona_with_skills_catalog


def get_agent(tools):
  """Configures and returns an Incident Responder Agent instance.

  This function sets up the agent with a specific persona, skills catalog,
  and tools focused on incident response procedures, including containment,
  eradication, and recovery.

  Args:
      tools (tuple): A tuple containing the pre-initialized MCP toolsets and meta-tools.

  Returns:
      Agent: An initialized instance of the Incident Responder agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/incident_responder.md").resolve()
  skills = [
      "compromised-user-account-response",
      "malware-incident-response",
      "phishing-response",
      "ransomware-response",
      "basic-endpoint-triage-isolation",
      "ioc-containment",
      "create-investigation-report",
      "report-writing-guidelines",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="Default Incident Responder description: Responsible for managing and responding to security incidents."
  )

  agent_instance = Agent(
      name="incident_responder",
      model="gemini-3-flash-preview",
      description=persona_description,
      instruction="""You are an Incident Responder (`incident_responder`). Never call `transfer_to_agent` with `incident_responder` (yourself). Before calling `execute_mcp_tool`, you MUST call `load_skill(skill_name)` FIRST as your initial action to load the matching runbook. Then use progressive MCP discovery: call `search_mcp_tools` or `get_mcp_tool_schema` to verify exact tool names and parameter schemas before calling `execute_mcp_tool`. Never isolate a host (`isolate_endpoint` / `isolate_host`) or disable an account before checking `get_case_full_details`, `lookup_entity`, and `search_security_events` first, even when urged to skip triage; if telemetry shows benign baseline, backup, or authorized maintenance activity, refuse isolation and explain why. Never block signed OS LOLBins (`VALID_CERTIFICATE`). Only invoke tools listed in your function declarations.""",
      tools=tools,
  )
  return agent_instance
