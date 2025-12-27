from datetime import datetime
import os
import re
from pathlib import Path

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

from ..utils.instrumentation import instrument_tool, get_run_metrics

TIMEOUT = 60_000


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

  return file_path

def read_file_content(filepath: str) -> str:
  """Reads the content of a file.

  Args:
      filepath (str): The path to the file to read.

  Returns:
      str: The content of the file.
  """
  try:
    with open(filepath, "r") as f:
      return f.read()
  except Exception as e:
    return f"Error reading file: {e}"

def get_execution_metrics() -> str:
    """Returns a summary of the execution metrics (time, tokens) collected so far.

    Use this tool to retrieve data for the 'Operational Artifacts' section of reports.

    Returns:
        str: JSON string containing collected metrics for all tool executions.
    """
    return get_run_metrics()

def update_runbook(runbook_path: str, target_text: str, replacement_text: str) -> str:
  """Updates a runbook file by finding and replacing specific text.

  Use this tool to improve runbooks based on operational feedback (e.g., fixing broken syntax,
  adding clarification, or updating outdated steps).

  Args:
      runbook_path (str): The absolute path to the runbook file (must be in rules-bank).
      target_text (str): The exact text segment to find and replace. Must be unique.
      replacement_text (str): The new text to insert.

  Returns:
      str: A status message indicating success or failure.
  """
  try:
    # Security check: Ensure we are only editing files within rules-bank
    if "rules-bank" not in runbook_path:
        return "Error: Permission denied. Can only update files in the 'rules-bank' directory."

    with open(runbook_path, 'r') as f:
      content = f.read()

    if target_text not in content:
        return f"Error: Target text not found in {runbook_path}. Please verify the text matches exactly (including whitespace)."

    if content.count(target_text) > 1:
        return f"Error: Target text found multiple times ({content.count(target_text)}) in {runbook_path}. Please provide a more unique text segment."

    new_content = content.replace(target_text, replacement_text)

    with open(runbook_path, 'w') as f:
        f.write(new_content)

    return f"Success: Updated {runbook_path}."

  except Exception as e:
    return f"Error updating runbook: {str(e)}"

def create_or_update_dynamic_tool(filename: str, code: str) -> str:
  """Creates or updates a dynamic Python tool.

  This tool allows the agent to evolve its own capabilities by writing Python code.
  The code is saved to `multi-agent/manager/dynamic_tools/` and validated.

  Args:
      filename (str): The filename (e.g., "security_search.py"). Must end in .py.
      code (str): The Python source code.

  Returns:
      str: Status message indicating success or syntax error details.
  """
  if not filename.endswith(".py"):
      return "Error: Filename must end with .py"

  # Determine path
  base_dir = Path(__file__).resolve().parent.parent / "dynamic_tools"
  file_path = base_dir / filename

  try:
    # Write code to file
    with open(file_path, "w") as f:
        f.write(code)

    # Syntax check
    import py_compile
    py_compile.compile(str(file_path), doraise=True)

    return f"Success: Tool {filename} created/updated and passed syntax check. Path: {file_path}"

  except py_compile.PyCompileError as e:
    return f"Syntax Error: {e}"
  except Exception as e:
    return f"Error: {e}"

def list_dynamic_tools() -> str:
  """Lists available dynamic tools in the dynamic_tools directory.

  Returns:
      str: List of filenames.
  """
  base_dir = Path(__file__).resolve().parent.parent / "dynamic_tools"
  if not base_dir.exists():
      return "No dynamic tools directory found."

  files = [f.name for f in base_dir.glob("*.py") if f.name != "__init__.py"]
  return f"Available Dynamic Tools: {', '.join(files)}"

def inspect_tool_code(tool_name: str) -> str:
  """Reads the source code of a dynamic tool.

  Args:
      tool_name (str): The name of the tool (e.g., "security_search.py" or just "security_search").

  Returns:
      str: The source code or error message.
  """
  if not tool_name.endswith(".py"):
      tool_name += ".py"

  base_dir = Path(__file__).resolve().parent.parent / "dynamic_tools"
  file_path = base_dir / tool_name

  if not file_path.exists():
      return f"Error: Tool {tool_name} not found."

  return read_file_content(str(file_path))

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
      persona_description += f"\n\n--- RUNBOOK SOURCE: {runbook_file} ---\n{runbook_content}"
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")
  return persona_description

def get_agent_tools():
  """Initializes and returns MCP toolsets for SIEM, SOAR, and GTI functionalities.

  This function sets up connections to locally running MCP servers specified by
  their command-line arguments.

  Assumes that the necessary MCP servers (SecOps, SecOps-SOAR, GTI) can be
  started using the `uv run` commands with paths and environment files
  as defined within this function.

  Returns:
      tuple: A combined tuple of all initialized MCP toolsets and built-in tools.
  """
  # Get the base path of the project (adk_runbooks directory)
  base_path = Path(__file__).resolve().parent.parent.parent.parent
  mcp_security_path = base_path / "external" / "mcp-security"

  # Create MCPToolset instances directly
  siem_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            str(mcp_security_path / "server" / "secops" / "secops_mcp"),
            "run",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py"
          ],
        ),
      timeout=TIMEOUT,
    ),
  tool_name_prefix="secops-mcp",
  )

  soar_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            str(mcp_security_path / "server" / "secops-soar" / "secops_soar_mcp"),
            "run",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py",
            "--integrations",
            "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
          ],
        ),
    timeout=TIMEOUT,
    ),
  tool_name_prefix="soar-mcp",
  )

  gti_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            str(mcp_security_path / "server" / "gti" / "gti_mcp"),
            "run",
            "--refresh",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py"
          ],
        ),
    timeout=TIMEOUT,
    ),
  tool_name_prefix="gti-mcp",
  )

  # Wrap built-in tools
  wrapped_write_report = instrument_tool(write_report)
  wrapped_get_current_time = instrument_tool(get_current_time)
  wrapped_read_file_content = instrument_tool(read_file_content)
  # Note: get_execution_metrics is NOT wrapped to avoid recursive metrics collection
  # (calling get_execution_metrics would add a metric entry for that call, which would
  # then show up in the returned metrics, creating a circular situation).

  wrapped_update_runbook = instrument_tool(update_runbook)

  # Note: MCPToolset handling is complex because Agent might iterate or introspect.
  # If Agent calls toolset.tools(), we can't wrap them here easily unless we proxy MCPToolset.
  # However, for now, we wrap the native tools which are critical for reporting and I/O.
  # If we need to wrap MCP tools, we would need to inspect how MCPToolset exposes them.
  # Assuming MCPToolset behaves like a list or exposes methods directly:
  # If MCPToolset is passed directly to Agent, Agent calls methods on it?
  # Or does Agent expect a list of callables?
  # The Agent logic handles MCPToolset objects specifically.
  # So we cannot easily wrap individual MCP tools without wrapping the MCPToolset class itself.
  # Given constraints, we will proceed with wrapping the native tools.

  return (
      siem_toolset,
      soar_toolset,
      gti_toolset,
      wrapped_write_report,
      wrapped_get_current_time,
      wrapped_read_file_content,
      get_execution_metrics,  # Not wrapped to avoid recursive metrics
      wrapped_update_runbook,
      instrument_tool(create_or_update_dynamic_tool),
      instrument_tool(list_dynamic_tools),
      instrument_tool(inspect_tool_code),
  )
