import json
import random
import asyncio
import contextlib
import sys
from typing import Any, AsyncIterable, Optional
from pathlib import Path
from google.adk.agents.llm_agent import LlmAgent
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.mcp_tool.mcp_session_manager import StdioServerParameters
from google.genai import types

# Add the manager directory to path to access custom patches
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from utils.custom_adk_patches import CustomMCPToolset as MCPToolset

# Inline function to avoid relative import issues when running standalone
def load_persona_and_runbooks(persona_file_path: str, runbook_files: list, default_persona_description: str = "Default persona description.") -> str:
    """Loads persona description from a file and appends contents from runbook files."""
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


# Local cache of created case_ids for demo purposes.
case_ids = set()


def create_case_management_form(
    case_type: Optional[str] = None,
    priority: Optional[str] = None,
    assignee: Optional[str] = None,
    description: Optional[str] = None,
    affected_systems: Optional[str] = None,
    source: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a SOAR case management form for the analyst to fill out.

    Args:
        case_type (str): Type of case (incident, investigation, maintenance). Can be empty.
        priority (str): Case priority (critical/high/medium/low). Can be empty.
        assignee (str): Person assigned to the case. Can be empty.
        description (str): Detailed description of the case. Can be empty.
        affected_systems (str): Systems affected by this case. Can be empty.
        source (str): Source of the case (alert, manual, external). Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the case management form data.
    """
    case_id = 'soar_case_' + str(random.randint(1000000, 9999999))
    case_ids.add(case_id)
    return {
        'case_id': case_id,
        'case_type': '<incident/investigation/maintenance>' if not case_type else case_type,
        'priority': '<critical/high/medium/low>' if not priority else priority,
        'assignee': '<assigned analyst>' if not assignee else assignee,
        'description': '<detailed case description>' if not description else description,
        'affected_systems': '<systems impacted>' if not affected_systems else affected_systems,
        'source': '<alert/manual/external>' if not source else source,
    }


def return_case_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating a SOAR case management form to complete.

    Args:
        form_request (dict[str, Any]): The case management form data.
        tool_context (ToolContext): The context in which the tool operates.
        instructions (str): Instructions for completing the form. Can be empty.

    Returns:
        dict[str, Any]: A JSON dictionary for the form response.
    """
    if isinstance(form_request, str):
        form_request = json.loads(form_request)

    tool_context.actions.skip_summarization = True
    tool_context.actions.escalate = True
    form_dict = {
        'type': 'form',
        'form': {
            'type': 'object',
            'properties': {
                'case_type': {
                    'type': 'string',
                    'description': 'Type of SOAR case',
                    'title': 'Case Type',
                    'enum': ['Incident', 'Investigation', 'Maintenance', 'Other'],
                },
                'priority': {
                    'type': 'string',
                    'description': 'Priority level of the case',
                    'title': 'Priority',
                    'enum': ['Critical', 'High', 'Medium', 'Low'],
                },
                'assignee': {
                    'type': 'string',
                    'description': 'Person assigned to handle this case',
                    'title': 'Assignee',
                },
                'description': {
                    'type': 'string',
                    'description': 'Detailed description of the case',
                    'title': 'Description',
                },
                'affected_systems': {
                    'type': 'string',
                    'description': 'Systems or assets affected by this case',
                    'title': 'Affected Systems',
                },
                'source': {
                    'type': 'string',
                    'description': 'Source or origin of this case',
                    'title': 'Source',
                    'enum': ['Alert', 'Manual', 'External', 'Escalation'],
                },
                'case_id': {
                    'type': 'string',
                    'description': 'SOAR case ID',
                    'title': 'Case ID',
                    'readOnly': True,
                },
            },
            'required': ['case_type', 'priority', 'case_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the SOAR case management form with at least the case type and priority.',
    }
    return json.dumps(form_dict)


def create_case(case_id: str) -> dict[str, Any]:
    """Create a new SOAR case for a given case_id."""
    if case_id not in case_ids:
        return {
            'case_id': case_id,
            'status': 'Error: Invalid case_id.',
        }
    return {
        'case_id': case_id,
        'status': 'Case created',
        'message': 'SOAR case has been created and is ready for investigation.'
    }


class SOARSpecialistA2A:
    """An agent that handles SOAR operations with A2A integration and full MCP tools."""

    SUPPORTED_CONTENT_TYPES = ['text', 'text/plain']

    def __init__(self):
        self._mcp_tools = []
        self._exit_stack = None
        self._soar_toolset = None
        self._initialized = False
        self._agent = None
        self._user_id = 'remote_agent'
        self._runner = None

    def get_processing_message(self) -> str:
        return 'Processing SOAR request...'
    
    async def _initialize_mcp_tools(self):
        """Initialize MCP tools for SOAR operations."""
        try:
            print("Initializing SOAR MCP tools...")
            self._exit_stack = contextlib.AsyncExitStack()
            
            # Create SOAR MCPToolset
            self._soar_toolset = MCPToolset(
                connection_params=StdioServerParameters(
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
                )
            )
            
            # Register for cleanup
            self._exit_stack.push_async_callback(self._soar_toolset.close)
            
            # Get the tools from the toolset
            self._mcp_tools = await self._soar_toolset.get_tools()
            print(f"Successfully loaded {len(self._mcp_tools)} MCP tools")
            
            return True
        except Exception as e:
            print(f"Failed to initialize MCP tools: {e}")
            if self._exit_stack:
                await self._exit_stack.aclose()
                self._exit_stack = None
            return False
    
    async def _ensure_initialized(self):
        """Ensure the agent is initialized with MCP tools."""
        if not self._initialized:
            # Initialize MCP tools first
            success = await self._initialize_mcp_tools()
            if not success:
                print("Warning: MCP tools initialization failed, continuing with form tools only")
                self._mcp_tools = []
            
            # Build the agent with available tools
            self._agent = self._build_agent()
            
            # Create the runner
            self._runner = Runner(
                app_name=self._agent.name,
                agent=self._agent,
                artifact_service=InMemoryArtifactService(),
                session_service=InMemorySessionService(),
                memory_service=InMemoryMemoryService(),
            )
            
            self._initialized = True

    def _build_agent(self) -> LlmAgent:
        """Builds the LLM agent for the SOAR specialist with full MCP capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_manager.md").resolve()
        runbook_files = [
            # Guidelines
            (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
            # SOAR-related runbooks
            (BASE_DIR / "../../../../rules-bank/run_books/triage_alerts.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/prioritize_and_investigate_a_case.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/close_duplicate_or_similar_cases.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/group_cases.md").resolve(),
        ]
        persona_data = load_persona_and_runbooks(
            persona_file_path,
            runbook_files,
            default_persona_description="SOAR Specialist responsible for case management and orchestration"
        )
        
        # Use the MCP tools that were initialized
        if self._mcp_tools:
            print(f"SOAR Specialist A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("SOAR Specialist A2A agent initialized with form-based case management tools only")
        
        return LlmAgent(
            model='gemini-2.5-pro-preview-05-06',
            name='soar_specialist_a2a',
            description=persona_data,
            instruction="""
You are a SOAR (Security Orchestration, Automation and Response) Specialist with comprehensive SOAR platform access through MCP tools.

You have access to multiple types of tools:
1. **SOAR Platform Tools** (via MCP): Full access to SOAR platform operations including:
   - List cases (secops_soar.list_cases)
   - Get case details (secops_soar.get_case_details)
   - Update case status (secops_soar.update_case_status)
   - Run playbooks (secops_soar.run_playbook)
   - And many more SOAR operations
2. **Case Management Forms**: For structured case creation workflows
3. **Investigation Tools**: Evidence collection, timeline analysis, response coordination

**How to handle different requests:**

**For SOAR Queries (like "list SOAR cases", "get case details", "update case status"):**
- Use the appropriate MCP SOAR tools directly
- For example, use secops_soar.list_cases to list recent cases
- Use secops_soar.get_case_details to get specific case information

**For Case Creation Requests:**
- You can use either:
  - The form-based workflow (create_case_management_form → return_case_form → create_case) for guided creation
  - Direct SOAR tools like secops_soar.create_case for quick case creation

**For Workflow/Playbook Operations:**
- Use SOAR automation tools directly (e.g., secops_soar.run_playbook)
- Execute playbooks and coordinate response activities

**Your core responsibilities:**
- SOAR platform operations and case management
- Security workflow orchestration and automation
- Incident case lifecycle management
- Response coordination and tracking
- Playbook execution and management
- Integration between security tools and processes

You have full access to SOAR platform capabilities through MCP tools. Use them to provide comprehensive SOAR services.
""",
            tools=[
                create_case_management_form,
                return_case_form,
                create_case,
            ] + (self._mcp_tools or []),
        )

    async def stream(self, query, session_id) -> AsyncIterable[dict[str, Any]]:
        # Ensure initialization is complete
        await self._ensure_initialized()
        
        session = await self._runner.session_service.get_session(
            app_name=self._agent.name,
            user_id=self._user_id,
            session_id=session_id,
        )
        content = types.Content(
            role='user', parts=[types.Part.from_text(text=query)]
        )
        if session is None:
            session = await self._runner.session_service.create_session(
                app_name=self._agent.name,
                user_id=self._user_id,
                state={},
                session_id=session_id,
            )
        async for event in self._runner.run_async(
            user_id=self._user_id, session_id=session.id, new_message=content
        ):
            if event.is_final_response():
                response = ''
                if (
                    event.content
                    and event.content.parts
                    and event.content.parts[0].text
                ):
                    response = '\n'.join(
                        [p.text for p in event.content.parts if p.text]
                    )
                elif (
                    event.content
                    and event.content.parts
                    and any(
                        [
                            True
                            for p in event.content.parts
                            if p.function_response
                        ]
                    )
                ):
                    response = next(
                        p.function_response.model_dump()
                        for p in event.content.parts
                    )
                yield {
                    'is_task_complete': True,
                    'content': response,
                }
            else:
                yield {
                    'is_task_complete': False,
                    'updates': self.get_processing_message(),
                }
    
    async def cleanup(self):
        """Clean up MCP connections and resources."""
        if self._exit_stack:
            try:
                await self._exit_stack.aclose()
            except Exception as e:
                print(f"Error during cleanup: {e}")
            finally:
                self._exit_stack = None
                self._soar_toolset = None
                self._mcp_tools = []
                self._initialized = False