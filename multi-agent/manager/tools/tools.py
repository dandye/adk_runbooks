import asyncio
from datetime import datetime
import inspect
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Optional

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams

from skills.registry import SkillRegistry
from ..utils.instrumentation import (
    get_run_metrics,
    instrument_tool,
    record_schema_inspection,
    record_skill_activation,
)
from .mcp_registry import MCPToolMetadata, MCPToolRegistry
from .offline_mcp_mocks import (
    OfflineResilientMCPToolset,
    build_canonical_mcp_tools,
)

logger = logging.getLogger(__name__)

TIMEOUT = 60_000

# Initialize global registries
global_skill_registry = SkillRegistry()
global_mcp_registry = MCPToolRegistry()
_CACHED_WORKFLOW_TOOLS: list[Any] | None = None


def _build_canonical_mcp_tools(server: str) -> list[BaseTool]:
    """Build lightweight FunctionTool representations of canonical SIEM, SOAR, and GTI MCP tools."""
    return build_canonical_mcp_tools(server, global_mcp_registry)


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
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "reports")
    )

    base_name, ext = os.path.splitext(report_name)
    if not ext:
        ext = ".md"

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
    content = global_skill_registry.get_skill_content(skill_name)
    if not content.startswith("Error:"):
        record_skill_activation(skill_name)
        meta = global_skill_registry.get_skill(skill_name)
        assoc_tools = (
            ", ".join(f"`{t}`" for t in meta.adk_additional_tools)
            if meta and meta.adk_additional_tools
            else "discover via `search_mcp_tools`"
        )
        content += (
            "\n\n---\n"
            "### MANDATORY PROGRESSIVE DISCLOSURE TOOL EXECUTION PROTOCOL\n"
            "1. **NEVER** call SIEM, SOAR, GTI, or workflow tools (e.g. `get_case_full_details`, "
            "`lookup_entity`, `run_*_workflow`) as direct top-level function calls — they are NOT "
            "bound directly as top-level tools and calling them directly will raise a `ValueError`.\n"
            "2. Before calling `execute_mcp_tool` for any tool, you **MUST** first call "
            "`get_mcp_tool_schema(tool_name=...)` (or `search_mcp_tools(query=...)`) at least once "
            "in the session to inspect its required parameter schema.\n"
            "3. Then invoke the tool exclusively via `execute_mcp_tool(tool_name=\"<tool_name>\", "
            "arguments={...})`.\n"
            f"4. Candidate tools associated with `{skill_name}`: {assoc_tools}\n"
        )
    return content


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
        server: Optional server filter ('siem', 'soar', 'gti', 'workflows', etc.).

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

    lines = [
        "### Discovered MCP Security Tools\n",
        "**IMPORTANT**: Do NOT call the tools below as direct top-level function calls. "
        "First inspect parameters with `get_mcp_tool_schema(tool_name=\"...\")`, then invoke via "
        "`execute_mcp_tool(tool_name=\"...\", arguments={...})`.\n",
    ]
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

    record_schema_inspection(tool_name)
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
    default_persona_description: str = "Default persona description.",
) -> str:
    """Loads persona description and appends progressive disclosure skill catalog."""
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

    persona_description += (
        "\n\n**Progressive Tool Protocol**: First call `load_skill`, then `get_mcp_tool_schema`, "
        "then `execute_mcp_tool(tool_name, arguments)`. Never invoke discovered MCP tools directly."
    )

    return persona_description


def load_persona_and_runbooks(
    persona_file_path: str,
    runbook_files: list,
    default_persona_description: str = "Default persona description.",
) -> str:
    """[Legacy] Loads persona description from a file and appends contents from runbook files."""
    persona_description = ""
    try:
        with open(persona_file_path, "r", encoding="utf-8") as f:
            persona_description = f.read()
    except FileNotFoundError:
        persona_description = default_persona_description
        print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

    for runbook_file in runbook_files:
        try:
            with open(runbook_file, "r", encoding="utf-8") as f:
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
    base_path = Path(__file__).resolve().parent.parent.parent.parent
    mcp_security_path = base_path / "external" / "mcp-security"
    env_file = mcp_security_path / ".env"

    siem_offline = _build_canonical_mcp_tools("siem")
    soar_offline = _build_canonical_mcp_tools("soar")
    gti_offline = _build_canonical_mcp_tools("gti")

    siem_toolset = OfflineResilientMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "secops" / "secops_mcp"),
                    "run",
                    "--with",
                    "mcp<2.0.0",
                    "--env-file",
                    str(env_file),
                    "server.py",
                ],
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="secops-mcp",
        env_file_path=env_file,
        offline_tools=siem_offline,
    )

    soar_toolset = OfflineResilientMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "secops-soar" / "secops_soar_mcp"),
                    "run",
                    "--with",
                    "mcp<2.0.0",
                    "--env-file",
                    str(env_file),
                    "server.py",
                    "--integrations",
                    "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities",
                ],
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="soar-mcp",
        env_file_path=env_file,
        offline_tools=soar_offline,
    )

    gti_toolset = OfflineResilientMCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command="uv",
                args=[
                    "--directory",
                    str(mcp_security_path / "server" / "gti" / "gti_mcp"),
                    "run",
                    "--with",
                    "mcp<2.0.0",
                    "--refresh",
                    "--env-file",
                    str(env_file),
                    "server.py",
                ],
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="gti-mcp",
        env_file_path=env_file,
        offline_tools=gti_offline,
    )

    return (siem_toolset, soar_toolset, gti_toolset)


def get_agent_tools(disclosure_mode: str | None = None):
    """Initializes and returns agent tools according to the specified progressive disclosure mode.

    Supported disclosure_mode values:
    - "dual_progressive" (default): Returns only the 9 core/meta progressive discovery tools while
      registering SIEM, SOAR, GTI, and all 36 workflow tools in `global_mcp_registry`.
    - "skill_toolset": Uses native ADK 2.7.1 `SkillToolset` with `additional_tools` so candidate
      MCP and workflow tools are hidden at Turn 0 and dynamically bound only after `load_skill`.
    - "skills_only": Exposes SIEM/SOAR/GTI toolsets + `load_skill` and `list_available_skills`,
      withholding direct `run_*_workflow` bindings.
    - "static": Legacy baseline exposing all SIEM/SOAR/GTI toolsets, meta-tools, and all 36
      `run_*_workflow` functions directly.
    """
    mode = (disclosure_mode or os.environ.get("ADK_DISCLOSURE_MODE", "dual_progressive")).strip().lower()

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

    # Import executable ADK Graph Workflow tools and register them once in global_mcp_registry
    global _CACHED_WORKFLOW_TOOLS
    if _CACHED_WORKFLOW_TOOLS is None:
        from .workflow_tools import get_all_workflow_tools

        _CACHED_WORKFLOW_TOOLS = [instrument_tool(t) for t in get_all_workflow_tools()]
        global_mcp_registry.register_mcp_toolset(_CACHED_WORKFLOW_TOOLS, server_name="workflows")
    workflow_tools = _CACHED_WORKFLOW_TOOLS

    if mode == "dual_progressive":
        return (
            wrapped_write_report,
            wrapped_get_current_time,
            wrapped_read_file_content,
            wrapped_load_skill,
            wrapped_list_available_skills,
            wrapped_search_mcp_tools,
            wrapped_get_mcp_tool_schema,
            wrapped_execute_mcp_tool,
            get_execution_metrics,
        )
    if mode == "skills_only":
        return (
            siem_toolset,
            soar_toolset,
            gti_toolset,
            wrapped_write_report,
            wrapped_get_current_time,
            wrapped_read_file_content,
            wrapped_load_skill,
            wrapped_list_available_skills,
            get_execution_metrics,
        )
    if mode == "skill_toolset":
        skill_toolset = global_skill_registry.build_skill_toolset(
            additional_tools=[
                siem_toolset,
                soar_toolset,
                gti_toolset,
                *workflow_tools,
            ]
        )
        return (
            skill_toolset,
            wrapped_write_report,
            wrapped_get_current_time,
            wrapped_read_file_content,
            get_execution_metrics,
        )
    if mode == "static":
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
            get_execution_metrics,
            *workflow_tools,
        )

    raise ValueError(
        f"Unsupported disclosure_mode '{disclosure_mode}'. "
        "Expected one of: 'dual_progressive', 'skill_toolset', 'skills_only', 'static'."
    )
