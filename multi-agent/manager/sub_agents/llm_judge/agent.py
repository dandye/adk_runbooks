from pathlib import Path
from google.adk.agents import Agent
from ...tools.tools import load_persona_with_skills_catalog

def get_agent(tools):
  """Initializes and returns the LLM Judge agent.

  Args:
      tools: A list of tools available to the agent.

  Returns:
      Agent: The initialized LLM Judge agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/llm_judge.md").resolve()

  skills = [
      "report-writing-guidelines",
      "create-investigation-report",
      "alert-report",
      "case-report",
      "detection-report",
  ]

  persona_description = load_persona_with_skills_catalog(
      str(persona_file_path),
      skill_names=skills,
      default_persona_description="LLM Judge: Evaluates runbook and skill executions based on rubrics."
  )

  return Agent(
      name="llm_judge",
      model="gemini-2.5-flash",
      description=persona_description,
      instruction="""
      You are the LLM Judge. Your task is to evaluate the work of other agents.
      When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant.
      You have access to progressive MCP tool discovery: use `search_mcp_tools` to find tools, `get_mcp_tool_schema` to inspect arguments, and `execute_mcp_tool` to run them.

      When evaluating:
      1. Use `load_skill` or `read_file_content` to access the specific skill or rubric needed for grading.
      2. Use `read_file_content` with paths under the designated artifacts directory (for example, `artifacts/` or `reports/`) to read the artifacts produced by the agent (reports, logs, etc.).
      3. Strictly apply the Rubric criteria when forming your evaluation.
      4. Use `write_report` to save your evaluation as a Markdown file.
      """,
      tools=tools,
  )
