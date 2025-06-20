from datetime import datetime
import contextlib
import os
import re
import subprocess
from pathlib import Path

from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

TIMEOUT = 60


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
    ), common_exit_stack