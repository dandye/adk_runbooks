from datetime import datetime
import contextlib
import os
import re

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

TIMEOUT = 60


def ask_follow_up_question(*args, **kwargs):
  pass


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
  """Writes a report to a file in the designated reports directory.

  This function saves the given report content to a markdown file.
  It ensures that the filename is unique by appending a timestamp if one
  is not already present in the format _YYYYMMDD_HHMMSS. The file will be
  saved in the `multi-agent/reports/` directory.

  Args:
      report_name (str): The base name for the report file. The .md extension
                         will be added if not present.
      report_contents (str): The markdown content to write to the report.
  """
  # Determine the reports directory relative to this file's location.
  reports_dir = os.path.abspath(
      os.path.join(os.path.dirname(__file__), "..", "..", "reports")
  )

  # Separate base name and extension
  base_name, ext = os.path.splitext(report_name)
  if not ext:
      ext = ".md"

  # Check if a timestamp is already part of the base name to avoid duplication.
  # This checks for _YYYYMMDD or _YYYYMMDD_HHMMSS at the end of the name.
  if re.search(r"_\d{8}(_\d{6})?$", base_name):
      file_name = f"{base_name}{ext}"
  else:
      timestamp = get_current_time()["current_time"]
      file_name = f"{base_name}_{timestamp}{ext}"

  file_path = os.path.join(reports_dir, file_name)

  with open(file_path, "w") as f:
      f.write(report_contents)

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
          - tuple: A combined tuple of all initialized MCP toolsets and built-in tools.
          - contextlib.AsyncExitStack: The exit stack managing the MCP server connections.
  """
  common_exit_stack = contextlib.AsyncExitStack()

  # Create MCPToolset instances using the new constructor
  siem_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            "/Users/dandye/Projects/mcp_security_debugging/server/secops/secops_mcp",
            "run",
            "--env-file",
            "/Users/dandye/Projects/google-mcp-security/.env",
            "server.py"
          ],
        ),
      timeout=TIMEOUT,
    )
  )

  soar_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            "/Users/dandye/Projects/mcp_security_debugging/server/secops-soar/secops_soar_mcp",
            "run",
            "--env-file",
            "/Users/dandye/Projects/google-mcp-security/.env",
            "server.py",
            "--integrations",
            "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
          ],
        ),
    timeout=TIMEOUT,
    )
  )

  gti_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            "/Users/dandye/Projects/mcp_security_debugging/server/gti/gti_mcp",
            "run",
            "--refresh",
            "--env-file",
            "/Users/dandye/Projects/google-mcp-security/.env",
            "server.py"
          ],
        ),
    timeout=TIMEOUT,
    )
  )

  # Register toolsets for cleanup
  common_exit_stack.push_async_callback(siem_toolset.close)
  common_exit_stack.push_async_callback(soar_toolset.close)
  common_exit_stack.push_async_callback(gti_toolset.close)

  return (
      siem_toolset,
      soar_toolset,
      gti_toolset,
      write_report,
      get_current_time,
  ), common_exit_stack
