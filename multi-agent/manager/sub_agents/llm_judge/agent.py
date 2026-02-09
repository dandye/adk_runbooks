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
      model="gemini-1.5-pro",
      description=persona_description,
      instruction="""
      You are the LLM Judge. Your task is to evaluate the work of other agents.

      When evaluating:
      1. Use `read_file_content` only with paths under the repository's `rules-bank/run_books/` directory to read the specific Runbook Markdown file that contains the Grading Rubric. Do not use `..` path segments or absolute paths when specifying the runbook path.
      2. Use `read_file_content` only with paths under the designated artifacts directory (for example, `artifacts/`) to read the artifacts produced by the agent (reports, logs, etc.). Do not use `..` path segments or absolute paths when specifying artifact paths.
      3. Do not attempt to read files from any directories other than `rules-bank/run_books/` for runbooks and the designated artifacts directory for agent outputs.
      4. Strictly apply the Rubric criteria when forming your evaluation.
      5. Use `write_report` to save your evaluation as a Markdown file.
      """,
      tools=tools,
  )


def get_a2a_app(tools, host="0.0.0.0", port=8000):
  """Creates and returns an A2A application for the LLM Judge agent."""
  from ...utils.a2a import get_a2a_app_from_config
  agent = get_agent(tools)
  config_path = (Path(__file__).resolve().parent.parent.parent / "config/agents/llm_judge.yaml").resolve()
  return get_a2a_app_from_config(agent, str(config_path), host=host, port=port)
