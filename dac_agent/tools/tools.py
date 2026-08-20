import asyncio
import contextlib
import inspect
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure project root and multi-agent directory are in sys.path
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))
_multi_agent_dir = _project_root / "multi-agent"
if str(_multi_agent_dir) not in sys.path:
    sys.path.insert(0, str(_multi_agent_dir))

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters
from skills.registry import SkillRegistry
from manager.tools.mcp_registry import MCPToolRegistry

TIMEOUT = 60

# Initialize global skill registry and MCP tool registry
global_skill_registry = SkillRegistry()
global_mcp_registry = MCPToolRegistry()


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
    saved in the `dac-agent/reports/` directory.

    Args:
        report_name (str): The base name for the report file. The .md extension
                           will be added if not present.
        report_contents (str): The markdown content to write to the report.
    """
    # Determine the reports directory relative to this file's location.
    reports_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "reports")
    )
    
    # Create reports directory if it doesn't exist
    os.makedirs(reports_dir, exist_ok=True)

    # Separate base name and extension
    base_name, ext = os.path.splitext(report_name)
    if not ext:
        ext = ".md"

    # Timestamp pattern: matches _YYYYMMDD_HHMMSS at the end of the base name
    # e.g., _20250529_170700
    timestamp_pattern = r'_\d{8}_\d{6}$'

    if not re.search(timestamp_pattern, base_name):
        current_time_str = get_current_time()["current_time"]
        final_filename = f"{base_name}_{current_time_str}{ext}"
    else:
        final_filename = f"{base_name}{ext}"

    file_path = os.path.join(reports_dir, final_filename)
    try:
        with open(file_path, 'w', encoding="utf-8") as f:
            f.write(report_contents)
        return f"Report successfully written to {file_path}"
    except Exception as e:
        return f"Error writing report to {file_path}: {e}"


def git_create_branch(repo_path: str, branch_name: str) -> dict:
    """Creates a new git branch in the specified repository.

    Args:
        repo_path (str): Path to the git repository
        branch_name (str): Name of the branch to create

    Returns:
        dict: Result with 'success', 'branch', and optional 'error' message
    """
    try:
        # Check if repository exists and is clean
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Checkout main first to branch from clean state
        subprocess.run(
            ["git", "checkout", "main"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Create and checkout new branch
        subprocess.run(
            ["git", "checkout", "-b", branch_name],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        return {
            "success": True,
            "branch": branch_name,
            "message": f"Successfully created and checked out branch '{branch_name}'"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"Git operation failed: {e.stderr.strip() if e.stderr else str(e)}",
            "branch": branch_name
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "branch": branch_name
        }


def git_commit_changes(repo_path: str, file_paths: list, commit_message: str) -> dict:
    """Stages specified files and commits them with the given message.

    Args:
        repo_path (str): Path to the git repository
        file_paths (list): List of relative file paths to commit
        commit_message (str): Commit message following conventional commits

    Returns:
        dict: Result with 'success', 'commit_hash', and optional 'error' message
    """
    try:
        # Stage specified files
        for file_path in file_paths:
            subprocess.run(
                ["git", "add", file_path],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
        
        # Commit changes
        commit_result = subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Get commit hash
        hash_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        commit_hash = hash_result.stdout.strip()
        
        return {
            "success": True,
            "commit_hash": commit_hash,
            "message": f"Successfully committed changes with hash {commit_hash[:8]}"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"Git commit failed: {e.stderr.strip() if e.stderr else str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def git_push_branch(repo_path: str, branch_name: str, remote: str = "origin") -> dict:
    """Pushes a branch to the remote repository.

    Args:
        repo_path (str): Path to the git repository
        branch_name (str): Name of the branch to push
        remote (str): Remote name, defaults to 'origin'

    Returns:
        dict: Result with 'success', 'branch', and optional 'error' message
    """
    try:
        subprocess.run(
            ["git", "push", "-u", remote, branch_name],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        return {
            "success": True,
            "branch": branch_name,
            "remote": remote,
            "message": f"Successfully pushed branch '{branch_name}' to '{remote}'"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"Git push failed: {e.stderr.strip() if e.stderr else str(e)}",
            "branch": branch_name
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "branch": branch_name
        }


def create_github_pr(repo_path: str, branch_name: str, title: str, body: str, base: str = "main") -> dict:
    """Creates a GitHub Pull Request using GitHub CLI (gh).

    Args:
        repo_path (str): Path to the git repository
        branch_name (str): Head branch containing changes
        title (str): PR title following conventional format
        body (str): Comprehensive PR description with context and checklist
        base (str): Base branch to merge into, defaults to 'main'

    Returns:
        dict: Result with 'success', 'pr_url', 'pr_number', and optional 'error'
    """
    try:
        # Check if gh CLI is installed and authenticated
        auth_check = subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True
        )
        
        if auth_check.returncode != 0:
            return {
                "success": False,
                "error": "GitHub CLI (gh) is not authenticated. Please run 'gh auth login' first."
            }
        
        # Create pull request
        pr_result = subprocess.run(
            [
                "gh", "pr", "create",
                "--head", branch_name,
                "--base", base,
                "--title", title,
                "--body", body
            ],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
        )
        
        pr_url = pr_result.stdout.strip()
        
        # Extract PR number from URL
        pr_number_match = re.search(r'/pull/(\d+)', pr_url)
        pr_number = pr_number_match.group(1) if pr_number_match else None
        
        return {
            "success": True,
            "pr_url": pr_url,
            "pr_number": pr_number,
            "message": f"Successfully created PR #{pr_number}: {pr_url}"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": f"PR creation failed: {e.stderr.strip() if e.stderr else str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def validate_yaml_file(file_path: str) -> dict:
    """Validates YAML syntax of a detection rule file.

    Args:
        file_path (str): Path to the YAML file to validate

    Returns:
        dict: Result with 'valid', 'errors', and optional details
    """
    try:
        import yaml
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse all documents in the YAML file
        docs = list(yaml.safe_load_all(content))
        
        return {
            "valid": True,
            "documents_count": len(docs),
            "message": f"YAML syntax is valid ({len(docs)} documents found)"
        }
    except yaml.YAMLError as e:
        return {
            "valid": False,
            "error": f"YAML syntax error: {str(e)}",
            "line": getattr(e, 'problem_mark', None).line if hasattr(e, 'problem_mark') else None,
            "column": getattr(e, 'problem_mark', None).column if hasattr(e, 'problem_mark') else None
        }
    except Exception as e:
        return {
            "valid": False,
            "error": f"Failed to read or validate file: {str(e)}"
        }


def find_rule_files(repo_path: str, rule_pattern: str) -> dict:
    """Finds detection rule files matching a pattern in the repository.

    Args:
        repo_path (str): Path to the detection rules repository
        rule_pattern (str): Name or pattern to search for (e.g., 'suspicious_login')

    Returns:
        dict: Result with 'files' list and count
    """
    try:
        matching_files = []
        repo_path_obj = Path(repo_path)
        
        # Search for .yaml and .yml files
        for ext in ['*.yaml', '*.yml']:
            for file_path in repo_path_obj.rglob(ext):
                if rule_pattern.lower() in file_path.name.lower():
                    rel_path = file_path.relative_to(repo_path_obj)
                    matching_files.append({
                        "path": str(rel_path),
                        "full_path": str(file_path),
                        "filename": file_path.name
                    })
        
        return {
            "success": True,
            "matches": matching_files,
            "count": len(matching_files),
            "pattern": rule_pattern
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "pattern": rule_pattern,
            "matches": [],
            "count": 0
        }


def load_skill(skill_name: str) -> str:
    """Loads the full markdown instructions, procedures, and rubrics for a specified skill.

    Use this tool when you need complete step-by-step procedures, execution guidelines,
    or validation rubrics to perform detection-as-code rule tuning and engineering tasks.

    Args:
        skill_name: The name or identifier of the skill to load (e.g. 'detection-as-code-rule-tuning',
                    'detection-rule-validation-tuning', 'detection-as-code-workflows').

    Returns:
        str: The complete markdown content of the requested skill, or an error message if not found.
    """
    return global_skill_registry.get_skill_content(skill_name)


def list_available_skills(category: str = "") -> str:
    """Lists available progressive disclosure skills, optionally filtered by category.

    Use this tool to discover available security skills and capabilities that you can load
    on-demand using `load_skill`.

    Args:
        category: Optional category name to filter skills (e.g. 'detection', 'irps',
                  'guidelines', 'investigation', 'atomic'). If empty, all available skills are listed.

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


async def get_dac_agent_tools():
    """Initializes and returns MCP toolsets and custom tools for the DAC agent.

    This function sets up connections to MCP servers needed for detection-as-code
    rule tuning operations, including SOAR case monitoring, SIEM rule management,
    and GitHub operations.

    Returns:
        tuple: A tuple containing:
            - tuple: A combined tuple of all initialized MCP toolsets and custom tools.
            - contextlib.AsyncExitStack: The exit stack managing the MCP server connections.
    """
    common_exit_stack = contextlib.AsyncExitStack()
    
    # Get the base path of the project (adk_runbooks directory)
    base_path = Path(__file__).resolve().parent.parent.parent
    mcp_security_path = base_path / "external" / "mcp-security"

    # SOAR MCP Server for case monitoring and analysis
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
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="soar-mcp",
    )

    # SIEM MCP Server for rule validation and event analysis
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
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="secops-mcp",
    )

    # GTI MCP Server for threat intelligence context
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
            ),
            timeout=TIMEOUT,
        ),
        tool_name_prefix="gti-mcp",
    )

    # 1P Google SecOps MCP Server for Agentic Detection Engineering
    # (TDO generation, synthetic events, rule coverage, rule generation)
    secops_1p_toolset = None
    try:
        import google.auth
        from google.auth.transport.requests import Request
        from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPConnectionParams

        creds, _ = google.auth.default(scopes=[
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/chronicle",
        ])
        creds.refresh(Request())
        region = os.environ.get("CHRONICLE_REGION", "us")
        endpoint_url = os.environ.get(
            "CHRONICLE_MCP_ENDPOINT",
            f"https://chronicle.{region}.rep.googleapis.com/mcp",
        )
        project_id = os.environ.get("CHRONICLE_PROJECT_ID", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        headers = {
            "Authorization": f"Bearer {creds.token}",
            "x-goog-user-project": project_id,
            "Content-Type": "application/json",
        }
        secops_1p_toolset = MCPToolset(
            connection_params=StreamableHTTPConnectionParams(
                url=endpoint_url,
                headers=headers,
                timeout=TIMEOUT,
            ),
            tool_name_prefix="secops-1p",
        )
    except Exception as e:
        print(f"Warning: Could not initialize 1P Google SecOps MCP toolset: {e}")

    # Register toolsets into global_mcp_registry
    global_mcp_registry.register_mcp_toolset(soar_toolset, server_name="soar")
    global_mcp_registry.register_mcp_toolset(siem_toolset, server_name="siem")
    global_mcp_registry.register_mcp_toolset(gti_toolset, server_name="gti")
    if secops_1p_toolset:
        global_mcp_registry.register_mcp_toolset(secops_1p_toolset, server_name="secops_1p")

    # Register toolsets for cleanup
    common_exit_stack.push_async_callback(soar_toolset.close)
    common_exit_stack.push_async_callback(siem_toolset.close)
    common_exit_stack.push_async_callback(gti_toolset.close)
    if secops_1p_toolset:
        common_exit_stack.push_async_callback(secops_1p_toolset.close)

    # Return progressive discovery meta-tools and custom tools
    # All MCP toolsets (soar, siem, gti, secops_1p) are registered in global_mcp_registry
    # and discovered/executed on-demand via search_mcp_tools and execute_mcp_tool.
    tool_list = [
        get_current_time,
        write_report,
        git_create_branch,
        git_commit_changes,
        git_push_branch,
        create_github_pr,
        validate_yaml_file,
        find_rule_files,
        load_skill,
        list_available_skills,
        search_mcp_tools,
        get_mcp_tool_schema,
        execute_mcp_tool,
    ]

    return tuple(tool_list), common_exit_stack
