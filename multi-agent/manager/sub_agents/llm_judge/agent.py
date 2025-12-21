from pathlib import Path
from google.adk.agents import Agent
from ...tools.tools import load_persona_and_runbooks

def get_agent(tools):
  """Initializes and returns the LLM Judge agent.

  Args:
      tools: A list of tools available to the agent.

  Returns:
      Agent: The initialized LLM Judge agent.
  """
  BASE_DIR = Path(__file__).resolve().parent
  # Adjust path to point to rules-bank/personas/llm_judge.md
  # BASE_DIR is .../multi-agent/manager/sub_agents/llm_judge
  # Go up 4 levels to get to repo root:
  # 1. sub_agents
  # 2. manager
  # 3. multi-agent
  # 4. repo root
  persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/llm_judge.md").resolve()

  # The Judge doesn't need specific runbooks loaded into its persona instructions
  # because it reads them dynamically.
  runbook_files = []

  persona_description = load_persona_and_runbooks(
      persona_file_path,
      runbook_files,
      default_persona_description="LLM Judge: Evaluates runbook executions based on rubrics."
  )

  return Agent(
      name="llm_judge",
      model="gemini-2.5-pro",
      description=persona_description,
      instruction="""
      You are the LLM Judge. Your task is to evaluate the work of other agents.

      When evaluating:
      1. Use `read_file_content` to read the specific Runbook Markdown file to retrieve the Grading Rubric. Runbooks are located in `rules-bank/run_books/`.
      2. Use `read_file_content` to read the artifacts produced by the agent (Reports, Logs, etc.).
      3. strictly apply the Rubric criteria.
      4. Use `write_report` to save your evaluation as a Markdown file.
      """,
      tools=tools,
  )
