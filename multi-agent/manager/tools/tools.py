from datetime import datetime
import asyncio
import contextlib
import os
from pathlib import Path
from dotenv import load_dotenv

from google.adk.agents import Agent
from ..utils.custom_adk_patches import CustomMCPToolset as MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

# Load environment variables
load_dotenv()


def ask_follow_up_question(*args, **kwargs):
    pass


def get_configured_model():
    """Gets the configured model from environment variables.
    
    Returns:
        str: The model name to use for agents. Defaults to gemini-2.5-pro-preview-05-06.
    """
    default_model = "gemini-2.5-pro-preview-05-06"
    model = os.getenv('ADK_MODEL', default_model)
    
    # Validate model name (basic check for common patterns)
    valid_models = [
        "gemini-2.0-flash",
        "gemini-2.5-flash-preview-05-20", 
        "gemini-2.5-pro-preview-05-06",
        "gemini-1.5-pro",
        "gemini-1.5-flash"
    ]
    
    if model not in valid_models:
        print(f"⚠️  Warning: Model '{model}' not in known valid models list. Using anyway.")
        print(f"   Valid models: {', '.join(valid_models)}")
    
    print(f"✓ Using model: {model}")
    return model


def validate_mcp_paths():
    """Validates that all required MCP directories exist and are accessible.
    
    Returns:
        dict: A dictionary with validated paths or raises FileNotFoundError if paths are invalid.
    """
    # Get MCP paths from environment variables
    siem_dir = os.getenv('MCP_SIEM_DIR', '/Users/dandye/Projects/mcp_security/server/secops/secops_mcp')
    soar_dir = os.getenv('MCP_SOAR_DIR', '/Users/dandye/Projects/mcp_security/server/secops-soar/secops_soar_mcp')
    gti_dir = os.getenv('MCP_GTI_DIR', '/Users/dandye/Projects/mcp_security/server/gti/gti_mcp')
    env_file = os.getenv('MCP_ENV_FILE', '/Users/dandye/Projects/google-mcp-security/.env')
    
    paths = {
        'siem_dir': siem_dir,
        'soar_dir': soar_dir,
        'gti_dir': gti_dir,
        'env_file': env_file
    }
    
    # Validate each path exists
    for name, path in paths.items():
        path_obj = Path(path)
        if not path_obj.exists():
            raise FileNotFoundError(
                f"MCP path '{name}' does not exist: {path}\n"
                f"Please update your .env file or create the required directory structure."
            )
        
        # For directories, ensure they contain expected files
        if name.endswith('_dir'):
            server_py = path_obj / 'server.py'
            if not server_py.exists():
                raise FileNotFoundError(
                    f"MCP directory '{name}' missing server.py: {path}\n"
                    f"Please ensure the MCP server is properly configured."
                )
    
    print(f"✓ All MCP paths validated successfully")
    return paths


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

  This function sets up connections to locally running MCP servers using configurable
  paths from environment variables. It validates all paths before attempting to connect
  and manages the lifecycle of these connections using an AsyncExitStack.

  Environment Variables (with defaults):
      MCP_SIEM_DIR: Path to SecOps MCP server directory
      MCP_SOAR_DIR: Path to SecOps-SOAR MCP server directory  
      MCP_GTI_DIR: Path to GTI MCP server directory
      MCP_ENV_FILE: Path to environment file for MCP servers

  Returns:
      tuple: A tuple containing:
          - tuple: A combined tuple of all initialized MCP toolsets and built-in tools.
          - contextlib.AsyncExitStack: The exit stack managing the MCP server connections.
          
  Raises:
      FileNotFoundError: If any required MCP paths don't exist or are invalid.
  """
  common_exit_stack = contextlib.AsyncExitStack()
  
  # Validate and get MCP paths from environment
  try:
    paths = validate_mcp_paths()
  except FileNotFoundError as e:
    print(f"❌ MCP Configuration Error: {e}")
    raise
  
  # Create MCPToolset instances using validated paths
  siem_toolset = MCPToolset(
    connection_params=StdioServerParameters(
      command='uv',
      args=[
          "--directory",
          paths['siem_dir'],
          "run",
          "--env-file",
          paths['env_file'],
          "server.py"
        ],
      )
  )
  
  soar_toolset = MCPToolset(
    connection_params=StdioServerParameters(
      command='uv',
      args=[
          "--directory",
          paths['soar_dir'],
          "run",
          "--env-file",
          paths['env_file'],
          "server.py",
          "--integrations",
          "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
        ],
      )
  )
  
  gti_toolset = MCPToolset(
    connection_params=StdioServerParameters(
      command='uv',
      args=[
          "--directory",
          paths['gti_dir'],
          "run",
          "--refresh",
          "--env-file",
          paths['env_file'],
          "server.py"
        ],
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
