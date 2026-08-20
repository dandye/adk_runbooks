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
      model="gemini-3.7-flash",
      description=persona_description,
      instruction="""You are an Incident Responder. Your primary role is to manage the full lifecycle of security incidents, from initial detection and triage through containment, eradication, recovery, and post-incident analysis. When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant. You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.""",
      tools=tools,
  )
  return agent_instance
