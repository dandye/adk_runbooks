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
from google.adk.tools.tool_context import ToolContext

from ..utils.instrumentation import instrument_tool, get_run_metrics
from skills.registry import SkillRegistry
from skills.drive_registry import DriveMcpError, DriveRegistryConfigError
from .mcp_registry import MCPToolRegistry
from .drive_tools import (
    build_skill_registry,
    drive_toolset_configured,
    init_drive_toolset,
    publish_report_to_drive,
    reports_folder_id,
)
from .grounding_tools import (
    init_developer_knowledge_mcp_tools,
    init_web_search_agent_tool,
)
from .docs_review_tools import (
    create_google_doc as _create_google_doc,
    export_accepted_doc_to_markdown as _export_accepted_doc_to_markdown,
    insert_doc_comments as _insert_doc_comments,
    inspect_doc_suggestions as _inspect_doc_suggestions,
    propose_doc_suggested_edits as _propose_doc_suggested_edits,
    read_google_doc as _read_google_doc,
    sanitize_and_redline_telemetry_in_doc as _sanitize_and_redline_telemetry_in_doc,
    verify_and_redline_mitre_and_cve_in_doc as _verify_and_redline_mitre_and_cve_in_doc,
    verify_and_redline_udm_queries_in_doc as _verify_and_redline_udm_queries_in_doc,
    verify_and_redline_yaral2_rules_in_doc as _verify_and_redline_yaral2_rules_in_doc,
)

logger = logging.getLogger(__name__)

TIMEOUT = 60_000

# Initialize global registries.
# Runbooks come from Google Drive when RUNBOOK_SOURCE=drive (the default on this
# branch) and DRIVE_RUNBOOKS_FOLDER_ID is set; otherwise the local skills/ tree.
global_skill_registry: SkillRegistry = build_skill_registry()
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

def write_report(report_name: str, report_contents: str) -> dict:
  """Writes a report to the reports directory and, when configured, to Google Drive.

  This function saves the given report content to a markdown file.
  It ensures that the filename is unique by appending a timestamp if one
  is not already present in the format _YYYYMMDD_HHMMSS. The file will be
  saved in the `multi-agent/reports/` directory. When the environment variable
  DRIVE_REPORTS_FOLDER_ID is set, the same Markdown is also published to that
  Google Drive folder through the Drive MCP server so analysts can read and
  share it from Drive.

  Args:
      report_name (str): The base name for the report file. The .md extension
                         will be added if not present.
      report_contents (str): The markdown content to write to the report.

  Returns:
      dict: {"local_path": str, "drive": {"id", "title", "viewUrl", "parentId"}
            or None, "drive_error": str or None}. A Drive failure never loses
            the local copy; it is reported in "drive_error".
  """
  # Determine the reports directory: REPORTS_DIR overrides the default location
  # relative to this file (multi-agent/reports/).
  reports_dir = os.environ.get("REPORTS_DIR", "").strip() or os.path.abspath(
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

  os.makedirs(reports_dir, exist_ok=True)
  file_path = os.path.join(reports_dir, file_name)

  with open(file_path, "w", encoding="utf-8") as f:
      f.write(report_contents)

  result: dict[str, Any] = {"local_path": file_path, "drive": None, "drive_error": None}
  if reports_folder_id():
      try:
          result["drive"] = publish_report_to_drive(file_name, report_contents)
          logger.info("Published report %s to Drive: %s", file_name, result["drive"].get("viewUrl"))
      except (DriveMcpError, DriveRegistryConfigError) as e:
          result["drive_error"] = str(e)
          logger.warning("Report %s saved locally but Drive publish failed: %s", file_name, e)
  return result

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

  child_env = dict(os.environ)

  # Create MCPToolset instances directly
  siem_toolset = MCPToolset(
    connection_params=StdioConnectionParams(
      server_params=StdioServerParameters(
        command='uv',
        args=[
            "--directory",
            str(mcp_security_path / "server" / "secops" / "secops_mcp"),
            "run",
            "--with",
            "mcp<2.0.0",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py"
          ],
        env=child_env,
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
            "--with",
            "mcp<2.0.0",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py",
            "--integrations",
            "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
          ],
        env=child_env,
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
            "--with",
            "mcp<2.0.0",
            "--refresh",
            "--env-file",
            str(mcp_security_path / ".env"),
            "server.py"
          ],
        env=child_env,
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


def init_drive_mcp_tools():
  """Builds and registers the Google Drive MCP toolset when Drive is configured.

  Returns:
      MCPToolset | None: the Drive toolset (tools prefixed ``drive_``), or None
      when no Drive folder is configured or the toolset cannot be built.
  """
  if not drive_toolset_configured():
    return None
  try:
    drive_toolset = init_drive_toolset()
  except (DriveRegistryConfigError, DriveMcpError, ImportError) as e:
    logger.warning("Drive MCP toolset unavailable: %s", e)
    return None
  global_mcp_registry.register_mcp_toolset(drive_toolset, server_name="drive")
  return drive_toolset


def create_google_doc(title: str, content: str, folder_id: str = "") -> dict:
  """Creates a collaborative Google Doc in Google Drive from Markdown or plain text.

  Unlike `write_report` (which stores raw `text/markdown` files), this tool
  creates a native Google Doc (`application/vnd.google-apps.document`) in
  `DRIVE_REPORTS_FOLDER_ID` (or `folder_id` when supplied) so analysts and agents
  can attach anchored comments and Suggested Edits via the Google Docs API v1.

  Args:
      title (str): Document title in Google Drive.
      content (str): Initial Markdown or plain-text content.
      folder_id (str): Optional target Google Drive folder ID.

  Returns:
      dict: {"status", "document_id", "title", "viewUrl", "parentId", "mimeType"}.
  """
  return _create_google_doc(title=title, content=content, folder_id=folder_id or None)


def read_google_doc(document_id: str, tool_context: ToolContext = None) -> dict:
  """Reads a Google Doc via the Google Docs API v1 and caches its 1-based UTF-16 index map.

  Always call `read_google_doc` before calling `insert_doc_comments` or
  `propose_doc_suggested_edits`.

  Args:
      document_id (str): The Google Docs documentId.

  Returns:
      dict: {"status", "document_id", "title", "content", "char_count"}.
  """
  return _read_google_doc(document_id=document_id, tool_context=tool_context)


def insert_doc_comments(
    document_id: str, comments: str, tool_context: ToolContext = None
) -> dict:
  """Anchors native review comments to exact text spans in a Google Doc.

  IMPORTANT: Always call `insert_doc_comments` BEFORE `propose_doc_suggested_edits`
  so comments attach to the pre-edit index spans captured by `read_google_doc`.

  Args:
      document_id (str): The Google Docs documentId.
      comments (str): JSON array of objects, each with keys "quote" (exact substring
                      in the document) and "comment" (rationale and citation URL).

  Returns:
      dict: {"status", "inserted_count", "comment_ids", "skipped"}.
  """
  return _insert_doc_comments(
      document_id=document_id, comments=comments, tool_context=tool_context
  )


def propose_doc_suggested_edits(
    document_id: str, edits: str, tool_context: ToolContext = None
) -> dict:
  """Proposes non-destructive Suggested Edits (writeMode="SUGGEST") in a Google Doc.

  Sorts replacement spans descending by `startIndex` (back-to-front) so earlier
  edits do not shift subsequent UTF-16 character offsets, and submits them under
  `writeControl: {"writeMode": "SUGGEST"}` so human authors can Accept or Reject
  each edit in Google Docs.

  Args:
      document_id (str): The Google Docs documentId.
      edits (str): JSON array of non-overlapping objects, each with keys "quote"
                   (exact substring to replace) and "replacement" (proposed text).

  Returns:
      dict: {"status", "applied_count", "skipped"}.
  """
  return _propose_doc_suggested_edits(
      document_id=document_id, edits=edits, tool_context=tool_context
  )


def review_google_doc_with_stage_a(
    document_id: str,
    semantic_comments: str = "[]",
    semantic_edits: str = "[]",
    tool_context: ToolContext = None,
) -> dict:
  """Executes the two-stage non-destructive review pipeline on a Google Doc.

  Automatically runs Stage A deterministic untrusted URL defanging by UTF-16
  span (`start_index`/`end_index`) without echoing URLs through the LLM, merges
  with Stage B `semantic_comments` and `semantic_edits`, anchors comments first,
  and stages Suggested Edits (`writeMode="SUGGEST"`) second.

  Args:
      document_id (str): The Google Docs documentId.
      semantic_comments (str): JSON array of Stage B comment objects.
      semantic_edits (str): JSON array of Stage B edit objects.

  Returns:
      dict: {"status", "document_id", "title", "char_count", "stage_a_url_count", "comments", "edits"}.
  """
  from .docs_review_tools import review_google_doc_with_stage_a as _review_stage_a

  return _review_stage_a(
      document_id=document_id,
      semantic_comments=semantic_comments,
      semantic_edits=semantic_edits,
      tool_context=tool_context,
  )


def stage_runbook_update_as_google_doc(
    skill_name: str,
    case_id: str,
    semantic_comments: str = "[]",
    semantic_edits: str = "[]",
    lessons_learned_markdown: str = "",
    folder_id: str = "",
    tool_context: ToolContext = None,
) -> dict:
  """Loads a Markdown runbook from SOC Runbooks, creates a Google Doc draft, and stages grounded red-lines.

  Args:
      skill_name (str): Name of the runbook skill in SOC Runbooks (e.g. 'compromised-user-account-response').
      case_id (str): Originating SOAR case ID (e.g. '33278').
      semantic_comments (str): JSON array of comment objects citing the SOAR case and authoritative docs.
      semantic_edits (str): JSON array of non-overlapping replacement objects (`writeMode="SUGGEST"`).
      lessons_learned_markdown (str): Optional Markdown section to append before reviewing.
      folder_id (str): Optional target Drive folder ID.

  Returns:
      dict: {"status", "skill_name", "case_id", "document_id", "title", "viewUrl", "comments", "edits"}.
  """
  from .docs_review_tools import stage_runbook_update_as_google_doc as _stage_runbook

  return _stage_runbook(
      skill_name=skill_name,
      case_id=case_id,
      semantic_comments=semantic_comments,
      semantic_edits=semantic_edits,
      lessons_learned_markdown=lessons_learned_markdown,
      folder_id=folder_id or None,
      tool_context=tool_context,
  )


def post_reviewed_doc_to_soar_case(
    case_id: str,
    doc_title: str,
    doc_url: str,
    skill_name: str,
    redline_summary: str,
    runbook_doc_url: str = "",
) -> dict:
  """Posts a sanitized summary of the grounded Google Doc review to a SOAR case timeline.

  Args:
      case_id (str): SOAR Case ID.
      doc_title (str): Title of the reviewed Google Doc.
      doc_url (str): URL of the reviewed Google Doc.
      skill_name (str): Active runbook skill name.
      redline_summary (str): JSON array or newline-separated summary of red-lined items.
      runbook_doc_url (str): Optional URL of the staged Runbook Red-Line Google Doc draft.

  Returns:
      dict: {"status", "case_id", "comment", "soar_response"}.
  """
  from .docs_review_tools import post_reviewed_doc_to_soar_case as _post_soar

  return _post_soar(
      case_id=case_id,
      doc_title=doc_title,
      doc_url=doc_url,
      skill_name=skill_name,
      redline_summary=redline_summary,
      runbook_doc_url=runbook_doc_url,
  )


def verify_and_redline_udm_queries_in_doc(
    document_id: str,
    run_live_siem_check: bool = False,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    tool_context: ToolContext = None,
) -> dict:
  """Verifies Chronicle UDM queries inside a Google Doc, optionally dry-runs them in SIEM, and stages red-lines.

  Scans the Google Doc for unprefixed or hallucinated Chronicle UDM fields by
  exact 1-based UTF-16 span (`start_index`/`end_index`), optionally executes a
  dry-run UDM query against Chronicle SIEM (`search_udm`) when
  `run_live_siem_check=True`, anchors verification comments first, and proposes
  non-destructive Suggested Edits (`writeMode="SUGGEST"`) second.

  Args:
      document_id (str): The Google Docs documentId.
      run_live_siem_check (bool): Whether to execute a live Chronicle SIEM dry-run query check.
      start_time (str): ISO-8601 start time for the SIEM dry-run search window.
      end_time (str): ISO-8601 end time for the SIEM dry-run search window.

  Returns:
      dict: {"status", "document_id", "title", "char_count", "udm_findings_count", "findings", "siem_checks", "comments", "edits"}.
  """
  return _verify_and_redline_udm_queries_in_doc(
      document_id=document_id,
      run_live_siem_check=run_live_siem_check,
      start_time=start_time,
      end_time=end_time,
      tool_context=tool_context,
  )


def inspect_doc_suggestions(
    document_id: str,
    accept_suggestion_ids: str = "",
    tool_context: ToolContext = None,
) -> dict:
  """Inspects pending Suggested Edits (`suggest.*`) in a Google Doc and returns a unified diff.

  Extracts clean `baseline_text` (excluding `suggestedInsertionIds` so deleted
  and inserted strings never fuse) and `accepted_text` (applying all or selected
  `accept_suggestion_ids`), groups paired `suggestedDeletionIds` and
  `suggestedInsertionIds` by `suggestion_id`, and computes a unified diff.

  Args:
      document_id (str): The Google Docs documentId.
      accept_suggestion_ids (str): Optional JSON array or comma-separated list of
                                   `suggest.*` IDs to accept. Defaults to empty string
                                   (accept all suggestions).

  Returns:
      dict: {"status", "document_id", "title", "suggestion_count", "accepted_suggestion_count",
             "suggestions", "baseline_text", "accepted_text", "unified_diff"}.
  """
  return _inspect_doc_suggestions(
      document_id=document_id,
      accept_suggestion_ids=accept_suggestion_ids or None,
      tool_context=tool_context,
  )


def export_accepted_doc_to_markdown(
    document_id: str,
    skill_name: str = "",
    accept_suggestion_ids: str = "",
    output_path: str = "",
    publish_to_drive: bool = False,
    drive_title: str = "",
    folder_id: str = "",
    tool_context: ToolContext = None,
) -> dict:
  """Exports a red-lined Google Doc with accepted Suggested Edits back to a canonical Markdown runbook.

  Applies all or selected `accept_suggestion_ids` without text fusion, restores
  canonical YAML frontmatter (`--- ... ---`) from the source `skill_name` when
  Google Docs horizontal-rule conversion stripped the frontmatter delimiters, and
  optionally writes the exported Markdown to `output_path` or publishes it to Drive.

  Args:
      document_id (str): The Google Docs documentId.
      skill_name (str): Optional runbook skill name in SOC Runbooks (e.g. 'compromised-user-account-response').
      accept_suggestion_ids (str): Optional JSON array or comma-separated list of `suggest.*` IDs to accept.
      output_path (str): Optional local file path to save the exported Markdown.
      publish_to_drive (bool): Whether to publish the exported Markdown to Google Drive.
      drive_title (str): Optional Drive filename override when publishing to Drive.
      folder_id (str): Optional target Drive folder ID when publishing to Drive.

  Returns:
      dict: {"status", "document_id", "title", "skill_name", "suggestion_count",
             "accepted_suggestion_count", "frontmatter_restored", "frontmatter_valid",
             "frontmatter", "accepted_markdown", "unified_diff", "output_path", "drive"}.
  """
  return _export_accepted_doc_to_markdown(
      document_id=document_id,
      skill_name=skill_name,
      accept_suggestion_ids=accept_suggestion_ids or None,
      output_path=output_path,
      publish_to_drive=publish_to_drive,
      drive_title=drive_title,
      folder_id=folder_id or None,
      tool_context=tool_context,
  )


def verify_and_redline_yaral2_rules_in_doc(
    document_id: str,
    run_live_siem_check: bool = False,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    tool_context: ToolContext = None,
) -> dict:
  """Lints YARA-L 2.0 (YL2) rules in a Google Doc, optionally compiles and retrohunts them in Chronicle SIEM, and stages red-lines.

  Scans the Google Doc for YARA-L 2.0 (`YL2`) rule blocks and identifies
  standard-YARA `strings:` sections used instead of YARA-L 2.0 `events:`,
  event-variable-prefixed invalid UDM fields (`$e.resource.name`, `$e.ip`,
  `re.regex($e.process.command_line, ...)`), and undeclared event variables in
  `condition:` by exact 1-based UTF-16 span. When `run_live_siem_check=True`,
  compiles the repaired YARA-L 2.0 rule against Chronicle SIEM (`validate_rule`)
  and dry-runs its `events:` predicates against historical UDM telemetry
  (`search_udm`) before anchoring comments and staging `writeMode="SUGGEST"` edits.

  Args:
      document_id (str): The Google Docs documentId.
      run_live_siem_check (bool): Whether to compile the repaired YARA-L 2.0 rule
                                  and dry-run its UDM predicates against live Chronicle SIEM.
      start_time (str): ISO-8601 start time for the SIEM retrohunt search window.
      end_time (str): ISO-8601 end time for the SIEM retrohunt search window.

  Returns:
      dict: {"status", "document_id", "title", "char_count", "yaral2_findings_count",
             "skipped_existing_suggestion_count", "findings", "siem_rule_checks", "comments", "edits"}.
  """
  return _verify_and_redline_yaral2_rules_in_doc(
      document_id=document_id,
      run_live_siem_check=run_live_siem_check,
      start_time=start_time,
      end_time=end_time,
      tool_context=tool_context,
  )


def verify_and_redline_mitre_and_cve_in_doc(
    document_id: str,
    run_web_grounding_check: bool = False,
    tool_context: ToolContext = None,
) -> dict:
  """Verifies MITRE ATT&CK technique/sub-technique IDs and CISA KEV CVE citations in a Google Doc and stages red-lines.

  Scans the Google Doc for MITRE ATT&CK (`Txxxx` / `Txxxx.xxx`) and CVE
  (`CVE-YYYY-NNNN+`) tokens by exact 1-based UTF-16 span (`start_index`/`end_index`),
  identifies deprecated ATT&CK IDs (`T1086`, `T1085`), sibling sub-technique
  mismatches (`T1059.003` vs `T1059.001`, `T1003.002` vs `T1003.001`, `T1078.001`
  vs `T1078.004`, `T1098.001` vs `T1098.003`, `T1218.010` vs `T1218.011`), and
  cross-vendor CISA KEV CVE attribution swaps (`CVE-2024-21887` vs `CVE-2024-21762`),
  anchors comments citing `attack.mitre.org`, `nvd.nist.gov`, and `cisa.gov` first,
  and proposes non-destructive Suggested Edits (`writeMode="SUGGEST"`) second.

  Args:
      document_id (str): The Google Docs documentId.
      run_web_grounding_check (bool): Whether to enrich comments with grounded
                                      MITRE ATT&CK / NVD / CISA KEV verification metadata.

  Returns:
      dict: {"status", "document_id", "title", "char_count", "mitre_cve_findings_count",
             "skipped_existing_suggestion_count", "findings", "grounding_checks", "comments", "edits"}.
  """
  return _verify_and_redline_mitre_and_cve_in_doc(
      document_id=document_id,
      run_web_grounding_check=run_web_grounding_check,
      tool_context=tool_context,
  )


def sanitize_and_redline_telemetry_in_doc(
    document_id: str,
    tool_context: ToolContext = None,
) -> dict:
  """Scans a Google Doc for unredacted offensive telemetry payloads and leaked secrets and stages Suggested Edits.

  Scans the Google Doc by exact 1-based UTF-16 span (`start_index`/`end_index`)
  for encoded PowerShell flags (`-e`/`-en`/`-enc`/`-EncodedCommand`), `.NET`
  `FromBase64String(...)` calls, standalone 64+ char Base64 stagers, PowerShell
  and LOLBin download cradles (`Net.WebClient`, `iwr ... | iex`, `certutil`,
  `bitsadmin`, `mshta`, `regsvr32`), credential-dumping arguments (`MiniDump`,
  `procdump`, `ntdsutil`, `reg save HKLM\\SAM`, `sekurlsa`, `lsadump::dcsync`),
  Linux reverse shells (`/dev/tcp/`, `nc -e`, `curl|bash`, `wget|sh`), and leaked
  cloud/API tokens (`ya29.` GCP OAuth2 tokens, `eyJ` JWTs, `AKIA`/`ASIA` AWS keys,
  PEM private keys) while strictly preserving MD5/SHA-1/SHA-256/UUID/SID/GCP
  resource identifiers. Anchors forensic safety comments first and stages
  non-destructive `writeMode="SUGGEST"` `<REDACTED_...:sha256=...>` replacements
  second without echoing raw payloads or secrets through an LLM.

  Args:
      document_id (str): The Google Docs documentId.

  Returns:
      dict: {"status", "document_id", "title", "char_count", "telemetry_hazard_findings_count",
             "skipped_existing_suggestion_count", "findings", "comments", "edits"}.
  """
  return _sanitize_and_redline_telemetry_in_doc(
      document_id=document_id,
      tool_context=tool_context,
  )


def get_agent_tools():
  """Initializes and returns MCP toolsets and progressive discovery tools.

  This function sets up connections to locally running MCP servers and provides
  meta-tools for on-demand MCP discovery and execution.

  Returns:
      tuple: A combined tuple of all initialized MCP toolsets, progressive meta-tools, and built-in tools.
  """
  siem_toolset, soar_toolset, gti_toolset = init_shared_mcp_tools()
  drive_toolset = init_drive_mcp_tools()
  drive_toolsets = (drive_toolset,) if drive_toolset is not None else ()
  devknowledge_toolset = init_developer_knowledge_mcp_tools(global_mcp_registry)
  devknowledge_toolsets = (
      (devknowledge_toolset,) if devknowledge_toolset is not None else ()
  )
  web_search_tool = init_web_search_agent_tool()

  # Wrap built-in tools
  wrapped_write_report = instrument_tool(write_report)
  wrapped_get_current_time = instrument_tool(get_current_time)
  wrapped_read_file_content = instrument_tool(read_file_content)
  wrapped_load_skill = instrument_tool(load_skill)
  wrapped_list_available_skills = instrument_tool(list_available_skills)

  # Wrap Google Docs API v1 non-destructive review tools
  wrapped_create_google_doc = instrument_tool(create_google_doc)
  wrapped_read_google_doc = instrument_tool(read_google_doc)
  wrapped_insert_doc_comments = instrument_tool(insert_doc_comments)
  wrapped_propose_doc_suggested_edits = instrument_tool(propose_doc_suggested_edits)
  wrapped_review_google_doc_with_stage_a = instrument_tool(review_google_doc_with_stage_a)
  wrapped_stage_runbook_update_as_google_doc = instrument_tool(stage_runbook_update_as_google_doc)
  wrapped_post_reviewed_doc_to_soar_case = instrument_tool(post_reviewed_doc_to_soar_case)
  wrapped_verify_and_redline_udm_queries_in_doc = instrument_tool(
      verify_and_redline_udm_queries_in_doc
  )
  wrapped_verify_and_redline_yaral2_rules_in_doc = instrument_tool(
      verify_and_redline_yaral2_rules_in_doc
  )
  wrapped_verify_and_redline_mitre_and_cve_in_doc = instrument_tool(
      verify_and_redline_mitre_and_cve_in_doc
  )
  wrapped_sanitize_and_redline_telemetry_in_doc = instrument_tool(
      sanitize_and_redline_telemetry_in_doc
  )
  wrapped_inspect_doc_suggestions = instrument_tool(inspect_doc_suggestions)
  wrapped_export_accepted_doc_to_markdown = instrument_tool(
      export_accepted_doc_to_markdown
  )

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
      *drive_toolsets,
      *devknowledge_toolsets,
      web_search_tool,
      wrapped_write_report,
      wrapped_create_google_doc,
      wrapped_read_google_doc,
      wrapped_insert_doc_comments,
      wrapped_propose_doc_suggested_edits,
      wrapped_review_google_doc_with_stage_a,
      wrapped_stage_runbook_update_as_google_doc,
      wrapped_post_reviewed_doc_to_soar_case,
      wrapped_verify_and_redline_udm_queries_in_doc,
      wrapped_verify_and_redline_yaral2_rules_in_doc,
      wrapped_verify_and_redline_mitre_and_cve_in_doc,
      wrapped_sanitize_and_redline_telemetry_in_doc,
      wrapped_inspect_doc_suggestions,
      wrapped_export_accepted_doc_to_markdown,
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
