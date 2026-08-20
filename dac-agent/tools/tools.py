import contextlib
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters
from skills.registry import SkillRegistry

TIMEOUT = 60

# Initialize global skill registry
global_skill_registry = SkillRegistry()


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

    # Check if a timestamp is already part of the base name to avoid duplication.
    if re.search(r"_\d{8}(_\d{6})?$", base_name):
        file_name = f"{base_name}{ext}"
    else:
        timestamp = get_current_time()["current_time"]
        file_name = f"{base_name}_{timestamp}{ext}"

    file_path = os.path.join(reports_dir, file_name)

    with open(file_path, "w") as f:
        f.write(report_contents)


def git_create_branch(branch_name: str, base_branch: str = "main") -> dict:
    """Creates a new Git branch from the specified base branch.
    
    Args:
        branch_name: Name of the new branch to create
        base_branch: Base branch to create from (default: main)
    
    Returns:
        dict: Result of the Git operation
    """
    try:
        # Fetch latest changes
        subprocess.run(["git", "fetch", "origin"], check=True, capture_output=True)
        
        # Checkout base branch and pull latest
        subprocess.run(["git", "checkout", base_branch], check=True, capture_output=True)
        subprocess.run(["git", "pull", "origin", base_branch], check=True, capture_output=True)
        
        # Create and checkout new branch
        result = subprocess.run(
            ["git", "checkout", "-b", branch_name], 
            check=True, capture_output=True, text=True
        )
        
        return {
            "success": True,
            "branch_name": branch_name,
            "message": f"Created branch {branch_name} from {base_branch}",
            "output": result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": str(e),
            "stderr": e.stderr.decode() if e.stderr else "",
            "stdout": e.stdout.decode() if e.stdout else ""
        }


def git_commit_changes(file_paths: list, commit_message: str) -> dict:
    """Commits specified files with the given commit message.
    
    Args:
        file_paths: List of file paths to add and commit
        commit_message: Commit message
    
    Returns:
        dict: Result of the Git operation
    """
    try:
        # Add specified files
        for file_path in file_paths:
            subprocess.run(["git", "add", file_path], check=True, capture_output=True)
        
        # Commit changes
        result = subprocess.run(
            ["git", "commit", "-m", commit_message], 
            check=True, capture_output=True, text=True
        )
        
        return {
            "success": True,
            "message": f"Committed {len(file_paths)} files",
            "files": file_paths,
            "output": result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": str(e),
            "stderr": e.stderr.decode() if e.stderr else "",
            "stdout": e.stdout.decode() if e.stdout else ""
        }


def git_push_branch(branch_name: str) -> dict:
    """Pushes the current branch to origin.
    
    Args:
        branch_name: Name of the branch to push
    
    Returns:
        dict: Result of the Git operation
    """
    try:
        result = subprocess.run(
            ["git", "push", "-u", "origin", branch_name], 
            check=True, capture_output=True, text=True
        )
        
        return {
            "success": True,
            "branch_name": branch_name,
            "message": f"Pushed branch {branch_name} to origin",
            "output": result.stdout
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": str(e),
            "stderr": e.stderr.decode() if e.stderr else "",
            "stdout": e.stdout.decode() if e.stdout else ""
        }


def create_github_pr(title: str, body: str, base_branch: str = "main") -> dict:
    """Creates a GitHub pull request using the gh CLI.
    
    Args:
        title: PR title
        body: PR description/body
        base_branch: Target branch for the PR (default: main)
    
    Returns:
        dict: Result of the PR creation
    """
    try:
        result = subprocess.run([
            "gh", "pr", "create",
            "--title", title,
            "--body", body,
            "--base", base_branch
        ], check=True, capture_output=True, text=True)
        
        pr_url = result.stdout.strip()
        
        return {
            "success": True,
            "pr_url": pr_url,
            "title": title,
            "message": f"Created PR: {pr_url}"
        }
    except subprocess.CalledProcessError as e:
        return {
            "success": False,
            "error": str(e),
            "stderr": e.stderr.decode() if e.stderr else "",
            "stdout": e.stdout.decode() if e.stdout else ""
        }


def validate_yaml_file(file_path: str) -> dict:
    """Validates YAML syntax for detection rule files.
    
    Args:
        file_path: Path to the YAML file to validate
    
    Returns:
        dict: Validation result
    """
    try:
        import yaml
        
        with open(file_path, 'r') as f:
            yaml.safe_load(f)
        
        return {
            "valid": True,
            "file_path": file_path,
            "message": "YAML syntax is valid"
        }
    except yaml.YAMLError as e:
        return {
            "valid": False,
            "file_path": file_path,
            "error": str(e),
            "message": f"YAML syntax error in {file_path}"
        }
    except FileNotFoundError:
        return {
            "valid": False,
            "file_path": file_path,
            "error": "File not found",
            "message": f"File {file_path} not found"
        }
    except Exception as e:
        return {
            "valid": False,
            "file_path": file_path,
            "error": str(e),
            "message": f"Error validating {file_path}"
        }


def find_rule_files(rule_pattern: str, search_dir: str = None) -> dict:
    """Searches for detection rule files matching a pattern.
    
    Args:
        rule_pattern: Pattern to search for (rule name, ID, etc.)
        search_dir: Directory to search in (default: rules/ directory)
    
    Returns:
        dict: Search results with matching files
    """
    if search_dir is None:
        # Default to rules directory in dac-agent directory
        search_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
    
    matching_files = []
    
    try:
        for root, _dirs, files in os.walk(search_dir):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if rule_pattern.lower() in content.lower():
                                matching_files.append({
                                    "file_path": file_path,
                                    "file_name": file,
                                    "directory": root
                                })
                    except Exception:
                        continue
        
        return {
            "success": True,
            "pattern": rule_pattern,
            "matches": matching_files,
            "count": len(matching_files)
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
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "server.py",
                    "--integrations",
                    "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
                ],
            ),
            timeout=TIMEOUT,
        )
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
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "server.py"
                ],
            ),
            timeout=TIMEOUT,
        )
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
                    "--refresh",
                    "--env-file",
                    str(mcp_security_path / ".env"),
                    "server.py"
                ],
            ),
            timeout=TIMEOUT,
        )
    )

    # Register toolsets for cleanup
    common_exit_stack.push_async_callback(soar_toolset.close)
    common_exit_stack.push_async_callback(siem_toolset.close)
    common_exit_stack.push_async_callback(gti_toolset.close)

    return (
        soar_toolset,
        siem_toolset,
        gti_toolset,
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
    ), common_exit_stack