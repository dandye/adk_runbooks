import asyncio
import inspect
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

from ..utils.instrumentation import instrument_tool, get_run_metrics
from skills.registry import SkillRegistry
from .mcp_registry import MCPToolRegistry

logger = logging.getLogger(__name__)

TIMEOUT = 60_000

# Initialize global registries
global_skill_registry = SkillRegistry()
global_mcp_registry = MCPToolRegistry()


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


def load_skill(skill_name: str) -> str:
    """Loads the full markdown instructions, procedures, and rubrics for a specified skill.

    Use this tool when you need complete step-by-step procedures, execution guidelines,
    or validation rubrics to perform a security investigation, threat hunt, alert triage,
    or incident response task.

    Args:
        skill_name: The name or identifier of the skill to load (e.g. 'triage-alerts',
                    'compromised-user-account-response', 'basic-ioc-enrichment').

    Returns:
        str: The complete markdown content of the requested skill, or an error message if not found.
    """
    return global_skill_registry.get_skill_content(skill_name)


def list_available_skills(category: str = "") -> str:
    """Lists available progressive disclosure skills, optionally filtered by category.

    Use this tool to discover available security skills and capabilities that you can load
    on-demand using `load_skill`.

    Args:
        category: Optional category name to filter skills (e.g. 'triage', 'hunting',
                  'irps', 'remediation', 'guidelines', 'detection'). If empty, all
                  available skills are listed.

    Returns:
        str: Formatted list of matching skills with their descriptions.
    """
    if category:
        skills = global_skill_registry.list_skills_by_category(category)
        if not skills:
            return f"No skills found in category '{category}'."
        lines = [f"### Available Skills in '{category}' (Progressive Disclosure)\n"]
        for s in skills:
            lines.append(f"- **`{s.name}`**: {s.description}")
        return "\n".join(lines)
    else:
        catalog = global_skill_registry.get_skill_catalog()
        return catalog if catalog else "No skills registered."


def search_mcp_tools(query: str = "", server: str = "") -> str:
    """Discovers available MCP security tools by keyword or server without loading full schemas.

    Use this tool to find relevant MCP tools for SIEM (Chronicle), SOAR (SecOps SOAR),
    or GTI (VirusTotal) before requesting their schema or executing them.

    Args:
        query: Optional search keyword to filter tool names, descriptions, or servers.
        server: Optional server filter ('siem', 'soar', 'gti', etc.).

    Returns:
        str: Formatted list of matching tools with concise descriptions.
    """
    tools = global_mcp_registry.search_tools(query=query, server=server)
    if not tools:
        msg = "No MCP tools found"
        if query and server:
            msg += f" matching query '{query}' and server '{server}'."
        elif query:
            msg += f" matching query '{query}'."
        elif server:
            msg += f" for server '{server}'."
        else:
            msg += " in registry."
        return msg

    lines = ["### Discovered MCP Security Tools\n"]
    for t in tools:
        lines.append(f"- **`{t['name']}`** (`{t['server']}`): {t['description']}")
    return "\n".join(lines)


def get_mcp_tool_schema(tool_name: str) -> str:
    """Retrieves the full JSON Schema, parameter definitions, and descriptions for an MCP tool.

    Use this tool to inspect required parameters, types, and schema details before executing
    an MCP tool via `execute_mcp_tool`.

    Args:
        tool_name: The name of the MCP tool (e.g. 'secops_get_alert', 'soar_close_case').

    Returns:
        str: Formatted JSON schema description of the tool's parameters.
    """
    schema_info = global_mcp_registry.get_tool_schema(tool_name)
    if not schema_info:
        return f"Error: MCP tool '{tool_name}' not found in registry. Use `search_mcp_tools` to discover available tools."

    return json.dumps(schema_info, indent=2)


def execute_mcp_tool(tool_name: str, arguments: dict[str, Any] | str | None = None) -> str:
    """Executes an MCP security tool dynamically with the supplied arguments.

    Args:
        tool_name: The name of the MCP tool to execute.
        arguments: Dictionary of arguments matching the tool's input schema (or JSON string).

    Returns:
        str: JSON-formatted result of the tool execution, or an error message.
    """
    if arguments is None:
        arguments = {}
    elif isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except Exception as e:
            return f"Error parsing arguments JSON: {e}"

    if not isinstance(arguments, dict):
        return f"Error: arguments must be a dictionary or valid JSON object, got {type(arguments).__name__}."

    try:
        result = global_mcp_registry.execute_tool(tool_name, arguments)
        if inspect.iscoroutine(result):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(asyncio.run, result).result()
            else:
                result = asyncio.run(result)

        if isinstance(result, str):
            return result
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return f"Error executing tool '{tool_name}': {e}"


def load_persona_with_skills_catalog(
    persona_file_path: str,
    skill_names: list[str] | None = None,
    default_persona_description: str = "Default persona description."
) -> str:
    """Loads persona description and appends progressive disclosure skill catalog.

    Reads the persona markdown file and appends the catalog of available skills
    so the agent is aware of what skills it can dynamically load during execution.

    Args:
        persona_file_path: Path to the persona markdown file.
        skill_names: Optional list of skill names allowed/relevant for this agent.
                     If None, includes all registered skills.
        default_persona_description: Fallback text if persona file is not found.

    Returns:
        str: The combined persona description with appended skills catalog.
    """
    persona_description = ""
    try:
        with open(persona_file_path, "r", encoding="utf-8") as f:
            persona_description = f.read()
    except FileNotFoundError:
        persona_description = default_persona_description
        print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

    catalog = global_skill_registry.get_skill_catalog(skill_names)
    if catalog:
        persona_description += "\n\n" + catalog

    return persona_description


def load_persona_and_runbooks(
    persona_file_path: str,
    runbook_files: list,
    default_persona_description: str = "Default persona description."
) -> str:
    """[Legacy] Loads persona description from a file and appends contents from runbook files.

    Deprecated: Use load_persona_with_skills_catalog() instead for progressive disclosure.

    Args:
        persona_file_path: Path to the persona file.
        runbook_files: A list of paths to runbook files.
        default_persona_description: Default description if persona file is not found.

    Returns:
        A string containing the persona description and appended runbook contents.
    """
    persona_description = ""
    try:
        with open(persona_file_path, 'r', encoding="utf-8") as f:
            persona_description = f.read()
    except FileNotFoundError:
        persona_description = default_persona_description
        print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

    for runbook_file in runbook_files:
        try:
            with open(runbook_file, 'r', encoding="utf-8") as f:
                runbook_content = f.read()
            persona_description += "\n\n" + runbook_content
        except FileNotFoundError:
            print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")
    return persona_description


def init_shared_mcp_tools():
  """Initializes and registers MCP toolsets for SIEM, SOAR, and GTI into global_mcp_registry.

  Returns:
      tuple: (siem_toolset, soar_toolset, gti_toolset)
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

  # Register toolsets into global_mcp_registry
  global_mcp_registry.register_mcp_toolset(siem_toolset, server_name="siem")
  global_mcp_registry.register_mcp_toolset(soar_toolset, server_name="soar")
  global_mcp_registry.register_mcp_toolset(gti_toolset, server_name="gti")

  return (siem_toolset, soar_toolset, gti_toolset)


def get_agent_tools():
  """Initializes and returns MCP toolsets and progressive discovery tools.

  This function sets up connections to locally running MCP servers and provides
  meta-tools for on-demand MCP discovery and execution.

  Returns:
      tuple: A combined tuple of all initialized MCP toolsets, progressive meta-tools, and built-in tools.
  """
  siem_toolset, soar_toolset, gti_toolset = init_shared_mcp_tools()

  # Wrap built-in tools
  wrapped_write_report = instrument_tool(write_report)
  wrapped_get_current_time = instrument_tool(get_current_time)
  wrapped_read_file_content = instrument_tool(read_file_content)
  wrapped_load_skill = instrument_tool(load_skill)
  wrapped_list_available_skills = instrument_tool(list_available_skills)

  # Wrap progressive MCP discovery meta-tools
  wrapped_search_mcp_tools = instrument_tool(search_mcp_tools)
  wrapped_get_mcp_tool_schema = instrument_tool(get_mcp_tool_schema)
  wrapped_execute_mcp_tool = instrument_tool(execute_mcp_tool)

  # Import executable ADK Graph Workflow tools
  from .workflow_tools import get_all_workflow_tools
  workflow_tools = [instrument_tool(t) for t in get_all_workflow_tools()]

  return (
      siem_toolset,
      soar_toolset,
      gti_toolset,
      wrapped_write_report,
      wrapped_get_current_time,
      wrapped_read_file_content,
      wrapped_load_skill,
      wrapped_list_available_skills,
      wrapped_search_mcp_tools,
      wrapped_get_mcp_tool_schema,
      wrapped_execute_mcp_tool,
      get_execution_metrics,  # Not wrapped to avoid recursive metrics
      *workflow_tools,
  )
