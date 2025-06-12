from datetime import datetime
import asyncio
import contextlib
import os
import requests
from pathlib import Path
from dotenv import load_dotenv

from google.adk.agents import Agent
from ..utils.custom_adk_patches import CustomMCPToolset as MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters

# Load environment variables
load_dotenv()


def ask_follow_up_question(*args, **kwargs):
    pass


def fetch_available_models(api_key):
    """Fetches available models from the Google Gemini API.
    
    Args:
        api_key (str): Google API key for authentication
        
    Returns:
        list: List of available model names, or None if fetch fails
    """
    try:
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        params = {
            'key': api_key,
            'pageSize': 100  # Get more models in one request
        }
        
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        models = data.get('models', [])
        
        # Extract model names and filter for text generation models
        model_names = []
        for model in models:
            name = model.get('name', '')
            if name.startswith('models/'):
                model_name = name.replace('models/', '')
                # Filter for text generation models (exclude image/video generation)
                if any(keyword in model_name.lower() for keyword in ['gemini', 'text', 'chat']):
                    model_names.append(model_name)
        
        return sorted(model_names)
        
    except Exception as e:
        print(f"⚠️ Could not fetch models from API: {e}")
        return None


def get_configured_model():
    """Gets the configured model from environment variables with dynamic validation.
    
    Returns:
        str: The model name to use for agents. Defaults to gemini-2.5-pro-preview-05-06.
    """
    default_model = "gemini-2.5-pro-preview-05-06"
    model = os.getenv('ADK_MODEL', default_model)
    
    # Static fallback list for when API is unavailable
    fallback_models = [
        "gemini-2.0-flash",
        "gemini-2.5-flash-preview-05-20", 
        "gemini-2.5-pro-preview-05-06",
        "gemini-2.5-pro-preview-06-05",
        "gemini-1.5-pro",
        "gemini-1.5-flash"
    ]
    
    # Try to fetch live model list if API key is available
    api_key = os.getenv('GOOGLE_API_KEY')
    if api_key:
        live_models = fetch_available_models(api_key)
        if live_models:
            valid_models = live_models
            print(f"✓ Fetched {len(live_models)} available models from Google API")
        else:
            valid_models = fallback_models
            print(f"⚠️ Using fallback model list ({len(fallback_models)} models)")
    else:
        valid_models = fallback_models
        print("⚠️ No API key available, using fallback model list")
    
    # Validate the selected model
    if model not in valid_models:
        print(f"⚠️  Warning: Model '{model}' not in available models list. Using anyway.")
        print(f"   Available models: {', '.join(valid_models[:5])}{'...' if len(valid_models) > 5 else ''}")
        print(f"   Total models available: {len(valid_models)}")
    
    print(f"✓ Using model: {model}")
    return model


def validate_env_config():
    """Comprehensive validation of .env configuration with helpful error messages.
    
    Returns:
        dict: A dictionary with validated configuration or raises detailed errors.
    """
    errors = []
    warnings = []
    
    # Required fields check
    required_fields = {
        'GOOGLE_API_KEY': 'Google API key for Gemini models',
        'MCP_SIEM_DIR': 'Path to MCP SIEM server directory',
        'MCP_SOAR_DIR': 'Path to MCP SOAR server directory', 
        'MCP_GTI_DIR': 'Path to MCP GTI server directory',
        'MCP_ENV_FILE': 'Path to MCP environment file'
    }
    
    config = {}
    for field, description in required_fields.items():
        value = os.getenv(field)
        if not value:
            errors.append(f"❌ Missing required field: {field} ({description})")
        else:
            config[field] = value
    
    # Stop early if required fields missing
    if errors:
        raise ValueError(
            "Configuration errors found:\n" + 
            "\n".join(errors) + 
            "\n\nPlease update your .env file. See .env.example for guidance."
        )
    
    # Validate Google API Key format
    api_key = config['GOOGLE_API_KEY']
    if not api_key.startswith('AI') or len(api_key) < 20:
        warnings.append("⚠️ GOOGLE_API_KEY doesn't look like a valid Google AI API key (should start with 'AI')")
    
    # Validate Chronicle configuration if provided
    project_id = os.getenv('CHRONICLE_PROJECT_ID')
    customer_id = os.getenv('CHRONICLE_CUSTOMER_ID')
    
    if project_id or customer_id:
        if project_id and customer_id:
            # Check for common format mistakes
            if len(project_id) == 36 and '-' in project_id and len(project_id.split('-')) >= 4:
                warnings.append(
                    "⚠️ CHRONICLE_PROJECT_ID looks like a UUID format - did you swap PROJECT_ID and CUSTOMER_ID?\n"
                    "   PROJECT_ID should be like 'my-security-project-123' (GCP project format)\n"
                    "   CUSTOMER_ID should be like '12345678-abcd-1234-efgh-123456789012' (UUID format)"
                )
            if customer_id and len(customer_id) < 36:
                warnings.append(
                    "⚠️ CHRONICLE_CUSTOMER_ID looks too short for UUID format\n"
                    "   Should be 36 characters like '12345678-abcd-1234-efgh-123456789012'"
                )
        else:
            warnings.append("⚠️ Only one of CHRONICLE_PROJECT_ID/CHRONICLE_CUSTOMER_ID set - both are needed for Chronicle integration")
    
    # Print warnings
    for warning in warnings:
        print(warning)
    
    return config


def validate_mcp_paths():
    """Validates that all required MCP directories exist and are accessible.
    
    Returns:
        dict: A dictionary with validated paths or raises FileNotFoundError if paths are invalid.
    """
    # Get validated config first
    config = validate_env_config()
    
    paths = {
        'siem_dir': config['MCP_SIEM_DIR'],
        'soar_dir': config['MCP_SOAR_DIR'],
        'gti_dir': config['MCP_GTI_DIR'],
        'env_file': config['MCP_ENV_FILE']
    }
    
    # Validate each path exists
    for name, path in paths.items():
        path_obj = Path(path)
        if not path_obj.exists():
            suggestion = ""
            if name == 'env_file':
                suggestion = "\n   Try copying .env.example to create your MCP .env file"
            else:
                suggestion = "\n   Make sure you've cloned and set up the mcp_security repository"
            
            raise FileNotFoundError(
                f"❌ MCP path '{name}' does not exist: {path}{suggestion}\n"
                f"Please update your .env file with the correct path."
            )
        
        # For directories, ensure they contain expected files
        if name.endswith('_dir'):
            server_py = path_obj / 'server.py'
            if not server_py.exists():
                raise FileNotFoundError(
                    f"❌ MCP directory '{name}' missing server.py: {path}\n"
                    f"Please ensure the MCP server is properly installed and configured."
                )
    
    print("✓ All MCP paths validated successfully")
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

  Environment Variables (required - set in .env file):
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
      ValueError: If required .env configuration is missing or invalid.
  """
  print("🔧 Starting ADK Runbooks initialization...")
  print("📋 Validating configuration...")
  
  common_exit_stack = contextlib.AsyncExitStack()
  
  # Validate and get MCP paths from environment
  try:
    paths = validate_mcp_paths()
  except (FileNotFoundError, ValueError) as e:
    print(f"❌ Configuration Error: {e}")
    print("\n💡 Quick fix:")
    print("   1. Copy .env.example to .env: cp manager/.env.example manager/.env")
    print("   2. Edit .env and update the paths to match your system")
    print("   3. Ensure all MCP paths point to existing directories with server.py files")
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
