from datetime import datetime
import asyncio
import contextlib
import os

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


def get_current_time() -> dict:
    """Gets the current time, formatted for use in filenames or timestamps.

    Returns:
        dict: A dictionary with a single key "current_time" and a string value
              representing the current time in "YYYYMMDD_HHMMSS" format.
    """
    return {
        "current_time": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }

def write_report(report_name: str, report_contents: str):
    """Writes a report with the given name and content to a timestamped markdown file.

    The file will be saved in the `../reports/` directory relative to the
    `multi-agent/manager/` directory. The filename will be in the format
    `{report_name}_{YYYYMMDD_HHMMSS}.md`.

    Args:
        report_name (str): The base name for the report file (without extension).
        report_contents (str): The markdown content to write to the report file.
    """
    # Ensure the reports directory exists, relative to this tools.py file
    reports_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    timestamp = get_current_time()['current_time'] # ToDo: and ends with .md?
    if timestamp[:8] in report_name:
        file_path = os.path.join(reports_dir, f"{report_name}")
    else:
        file_path = os.path.join(reports_dir, f"{report_name}_{timestamp}.md")
    with open(file_path, "w") as f:
        f.write(f"{report_contents}")

def load_persona_and_runbooks(persona_file_path: str, runbook_files: list, default_persona_description: str = "Default persona description.") -> str:
    """
    Loads persona description from a file and appends contents from runbook files.

    Args:
        persona_file_path: Path to the persona file.
        runbook_files: A list of paths to runbook files.
        default_persona_description: Default description if persona file is not found.

    Returns:
        A string containing the persona description and appended runbook contents.
    """
    persona_description = ""
    try:
        with open(persona_file_path, 'r') as f:
            persona_description = f.read()
    except FileNotFoundError:
        persona_description = default_persona_description
        print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

    for runbook_file in runbook_files:
        try:
            with open(runbook_file, 'r') as f:
                runbook_content = f.read()
            persona_description += "\n\n" + runbook_content
        except FileNotFoundError:
            print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")
    return persona_description

async def get_agent_tools():
  """Initializes and returns MCP toolsets for SIEM, SOAR, and GTI functionalities.

  This function sets up connections to locally running MCP servers specified by
  their command-line arguments. It manages the lifecycle of these connections
  using an AsyncExitStack.

  Assumes that the necessary MCP servers (SecOps, SecOps-SOAR, GTI) can be
  started using the `uv run` commands with paths and environment files
  as defined within this function.

  Returns:
      tuple: A tuple containing:
          - tuple: A combined tuple of all initialized MCP tools (*siem_tools, *soar_tools, *gti_tools).
          - contextlib.AsyncExitStack: The exit stack managing the MCP server connections.
  """
  common_exit_stack = contextlib.AsyncExitStack()
  siem_tools, common_exit_stack = await asyncio.shield(MCPToolset.from_server(
    connection_params=StdioServerParameters(
    command='uv',
    args=[
        "--directory",
        "/Users/dandye/Projects/google-mcp-security/server/secops/secops_mcp",
        "run",
        "--env-file",
        "/Users/dandye/Projects/google-mcp-security/.env",
        "server.py"
      ],
    ),
    async_exit_stack=common_exit_stack
  ))

  await asyncio.sleep(2)  # Give the first server time to stabilize
  soar_tools, common_exit_stack = await asyncio.shield(MCPToolset.from_server(
     connection_params=StdioServerParameters(
     command='uv',
     args=[
         "--directory",
         "/Users/dandye/Projects/google-mcp-security/server/secops-soar/secops_soar_mcp",
         "run",
         "--env-file",
         "/Users/dandye/Projects/google-mcp-security/.env",
         "server.py",
         "--integrations",
         "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
       ],
     ),
     async_exit_stack=common_exit_stack
  ))
  await asyncio.sleep(2)  # Give the first server time to stabilize
  gti_tools, common_exit_stack = await MCPToolset.from_server(
    connection_params=StdioServerParameters(
    command='uv',
    args=[
        "--directory",
        "/Users/dandye/Projects/google-mcp-security/server/gti/gti_mcp",
        "run",
        "--env-file",
        "/Users/dandye/Projects/google-mcp-security/.env",
        "server.py"
      ],
    ),
    async_exit_stack=common_exit_stack
  )

  return (
      *siem_tools,
      *soar_tools,
      *gti_tools,
      write_report,
      get_current_time,
  ), common_exit_stack
