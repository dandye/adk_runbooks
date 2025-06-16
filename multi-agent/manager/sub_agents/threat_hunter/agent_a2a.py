import json
import random
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
from ..response_format_instruction import get_agent_instruction

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


# Local cache of created hunt campaign IDs for demo purposes.
hunt_campaign_ids = set()


def create_threat_hunt_form(
    hunt_name: Optional[str] = None,
    hunt_hypothesis: Optional[str] = None,
    threat_actor: Optional[str] = None,
    ttps: Optional[str] = None,
    hunt_scope: Optional[str] = None,
    time_range: Optional[str] = None,
    hunt_techniques: Optional[str] = None,
    iocs_to_hunt: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a threat hunting campaign form for the threat hunter to fill out.

    Args:
        hunt_name (str): Name of the threat hunting campaign. Can be empty.
        hunt_hypothesis (str): Threat hunting hypothesis to test. Can be empty.
        threat_actor (str): Suspected threat actor or group to hunt for. Can be empty.
        ttps (str): Tactics, techniques, and procedures to hunt for. Can be empty.
        hunt_scope (str): Scope of the hunt (network, endpoints, cloud, etc.). Can be empty.
        time_range (str): Time range for the hunting campaign. Can be empty.
        hunt_techniques (str): Specific hunting techniques to employ. Can be empty.
        iocs_to_hunt (str): IOCs and indicators to hunt for. Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the threat hunt campaign form data.
    """
    hunt_id = 'threat_hunt_' + str(random.randint(1000000, 9999999))
    hunt_campaign_ids.add(hunt_id)
    return {
        'hunt_id': hunt_id,
        'hunt_name': '<descriptive hunt campaign name>' if not hunt_name else hunt_name,
        'hunt_hypothesis': '<hypothesis to test through hunting>' if not hunt_hypothesis else hunt_hypothesis,
        'threat_actor': '<suspected threat actor or group>' if not threat_actor else threat_actor,
        'ttps': '<tactics, techniques, procedures to hunt>' if not ttps else ttps,
        'hunt_scope': '<network, endpoints, cloud, enterprise-wide>' if not hunt_scope else hunt_scope,
        'time_range': '<e.g., last 30 days, last 6 months>' if not time_range else time_range,
        'hunt_techniques': '<behavioral analysis, IOC matching, anomaly detection>' if not hunt_techniques else hunt_techniques,
        'iocs_to_hunt': '<IOCs, file hashes, domains, IPs, TTPs>' if not iocs_to_hunt else iocs_to_hunt,
    }


def return_threat_hunt_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating a threat hunting campaign form to complete.

    Args:
        form_request (dict[str, Any]): The threat hunt campaign form data.
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
                'hunt_name': {
                    'type': 'string',
                    'description': 'Name of the threat hunting campaign',
                    'title': 'Hunt Name',
                },
                'hunt_hypothesis': {
                    'type': 'string',
                    'description': 'Threat hunting hypothesis to test',
                    'title': 'Hunt Hypothesis',
                },
                'threat_actor': {
                    'type': 'string',
                    'description': 'Suspected threat actor or group to hunt for',
                    'title': 'Threat Actor',
                    'enum': ['APT29', 'APT28', 'Lazarus Group', 'FIN7', 'Carbanak', 'Unknown APT', 'Ransomware Group', 'Other'],
                },
                'ttps': {
                    'type': 'string',
                    'description': 'Tactics, techniques, and procedures to hunt for (MITRE ATT&CK)',
                    'title': 'TTPs',
                },
                'hunt_scope': {
                    'type': 'string',
                    'description': 'Scope of the hunting campaign',
                    'title': 'Hunt Scope',
                    'enum': ['Network Traffic', 'Endpoint Logs', 'Cloud Infrastructure', 'Email/Communication', 'Enterprise-wide', 'Specific Systems'],
                },
                'time_range': {
                    'type': 'string',
                    'description': 'Time range for the hunting campaign',
                    'title': 'Time Range',
                    'enum': ['Last 24 hours', 'Last 7 days', 'Last 30 days', 'Last 90 days', 'Last 6 months', 'Custom Range'],
                },
                'hunt_techniques': {
                    'type': 'string',
                    'description': 'Specific hunting techniques to employ (comma-separated)',
                    'title': 'Hunt Techniques',
                },
                'iocs_to_hunt': {
                    'type': 'string',
                    'description': 'IOCs and indicators to hunt for (comma-separated)',
                    'title': 'IOCs to Hunt',
                },
                'hunt_id': {
                    'type': 'string',
                    'description': 'Threat hunt campaign ID',
                    'title': 'Hunt ID',
                    'readOnly': True,
                },
            },
            'required': ['hunt_name', 'hunt_hypothesis', 'hunt_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the threat hunting campaign form with at least the hunt name and hypothesis.',
    }
    return json.dumps(form_dict)


def initiate_threat_hunt(hunt_id: str) -> dict[str, Any]:
    """Begin threat hunting campaign for a given hunt_id."""
    if hunt_id not in hunt_campaign_ids:
        return {
            'hunt_id': hunt_id,
            'status': 'Error: Invalid hunt_id.',
        }
    return {
        'hunt_id': hunt_id,
        'status': 'Threat hunt initiated',
        'message': 'Threat hunting campaign has been started. Proactive hunting for indicators, TTPs, and threat actor activity will be conducted.'
    }


class ThreatHunterA2A:
    """An agent that handles Threat Hunting with A2A integration and full MCP tools."""

    SUPPORTED_CONTENT_TYPES = ['text', 'text/plain']

    def __init__(self):
        self._mcp_tools = []
        self._exit_stack = None
        self._gti_toolset = None
        self._initialized = False
        self._agent = None
        self._user_id = 'remote_agent'
        self._runner = None

    def get_processing_message(self) -> str:
        return 'Processing threat hunting request...'

    async def _initialize_mcp_tools(self):
        """Initialize MCP tools for all available servers."""
        try:
            print("Initializing MCP tools...")
            self._exit_stack = contextlib.AsyncExitStack()
            self._mcp_tools = []

            # SecOps MCP
            self._secops_toolset = MCPToolset(
                connection_params=StdioServerParameters(
                    command='/Users/dandye/homebrew/bin/uv',
                    args=[
                        "--directory",
                        "../../../external/mcp-security/server/secops/secops_mcp",
                        "run",
                        "--reinstall-package",
                        "secops-mcp",
                        "--env-file",
                        "../../../external/mcp-security/.env",
                        "server.py"
                    ],
                )
            )
            self._exit_stack.push_async_callback(self._secops_toolset.close)
            self._mcp_tools.extend(await self._secops_toolset.get_tools())

            # GTI MCP
            self._gti_toolset = MCPToolset(
                connection_params=StdioServerParameters(
                    command='/Users/dandye/homebrew/bin/uv',
                    args=[
                        "--directory",
                        "../../../external/mcp-security/server/gti",
                        "run",
                        "--env-file",
                        "../../../external/mcp-security/.env",
                        "gti_mcp"
                    ],
                )
            )
            self._exit_stack.push_async_callback(self._gti_toolset.close)
            self._mcp_tools.extend(await self._gti_toolset.get_tools())

            # SOAR MCP
            self._soar_toolset = MCPToolset(
                connection_params=StdioServerParameters(
                    command='uv',
                    args=[
                        "--directory",
                        "../../../external/mcp-security/server/secops-soar/secops_soar_mcp",
                        "run",
                        "--env-file",
                        "../../../external/mcp-security/.env",
                        "server.py",
                        "--integrations",
                        "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
                    ],
                )
            )
            self._exit_stack.push_async_callback(self._soar_toolset.close)
            self._mcp_tools.extend(await self._soar_toolset.get_tools())

            # SCC MCP
            self._scc_toolset = MCPToolset(
                connection_params=StdioServerParameters(
                    command='uv',
                    args=[
                        "--directory",
                        "../../../external/mcp-security/server/scc",
                        "run",
                        "scc_mcp.py"
                    ],
                )
            )
            self._exit_stack.push_async_callback(self._scc_toolset.close)
            self._mcp_tools.extend(await self._scc_toolset.get_tools())

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
        """Builds the LLM agent for the Threat Hunter with A2A capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/threat_hunter.md").resolve()
        runbook_files = [
            (BASE_DIR / "../../../../rules-bank/run_books/advanced_threat_hunting.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(),
        ]
        persona_data = load_persona_and_runbooks(
            persona_file_path,
            runbook_files,
            default_persona_description="Threat Hunter specializing in proactive threat detection and investigation"
        )

        # Use the MCP tools that were initialized
        if self._mcp_tools:
            print(f"Threat Hunter A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("Threat Hunter A2A agent initialized with form-based threat hunting tools only")

        # Load environment variables from .env file
        from dotenv import load_dotenv

        # Try multiple locations for .env file
        env_paths = [
            Path(__file__).parent.parent.parent / ".env",  # manager/.env
            Path(__file__).parent.parent.parent.parent / ".env",  # multi-agent/.env
        ]

        for env_path in env_paths:
            if env_path.exists():
                load_dotenv(env_path)
                break

        # LlmAgent will automatically use GOOGLE_API_KEY from environment
        return LlmAgent(
            model='gemini-2.5-pro-preview-05-06',
            name='threat_hunter_a2a',
            description=persona_data,
            instruction="""
You are a Threat Hunter with comprehensive security tools and A2A integration capabilities.

You have access to multiple types of tools:
1. **Threat Intelligence Tools** (via MCP): Full access to GTI operations including:
   - Get threat actor information for hunting campaign development
   - Get malware information for behavioral hunting patterns
   - Get vulnerability details for exploit hunting
   - Get indicator information for proactive IOC hunting
   - Search for threats to develop hunting hypotheses
   - And many more GTI operations for threat hunting intelligence
2. **Threat Hunt Campaign Forms**: For structured proactive hunting workflows
3. **Security Platform Tools**: SIEM, SOAR, and SCC integration for hunting data sources
4. **Hunting Tools**: Advanced log analysis, behavioral detection, and anomaly hunting capabilities

**How to handle different requests:**

**For Threat Hunting Campaign Requests:**
- Use the form-based workflow (create_threat_hunt_form → return_threat_hunt_form → initiate_threat_hunt)
- Develop hypothesis-driven hunting campaigns
- Use GTI tools to research threat actor TTPs and develop hunt queries
- Execute proactive hunting across enterprise environments

**For Threat Intelligence Research (for hunt development):**
- Use GTI tools to understand threat actor behaviors and TTPs
- Research recent campaigns and attack patterns for hunt hypotheses
- Analyze IOCs and infrastructure for proactive hunting
- Develop hunting signatures based on threat intelligence

**For Proactive Threat Detection:**
- Use GTI tools for comprehensive threat landscape analysis
- Develop behavioral hunting queries and detection logic
- Hunt for unknown threats using anomaly detection
- Search for indicators of compromise before they become alerts

**Your core responsibilities:**
- Developing and executing hypothesis-driven threat hunting campaigns
- Proactive threat detection and anomaly hunting
- Creating hunting queries and detection signatures
- Researching threat actor TTPs for hunting opportunities
- Hunting for advanced persistent threats and stealth malware
- Developing threat hunting methodologies and best practices
- Collaborating with threat intelligence teams for hunt development
- Training SOC analysts on threat hunting techniques

You have full access to security platforms and threat intelligence for proactive threat hunting and detection.
""",
            tools=[
                create_threat_hunt_form,
                return_threat_hunt_form,
                initiate_threat_hunt,
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
                self._gti_toolset = None
                self._mcp_tools = []
                self._initialized = False
