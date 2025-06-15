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


# Local cache of created investigation IDs for demo purposes.
investigation_ids = set()


def create_advanced_investigation_form(
    case_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    complexity: Optional[str] = None,
    investigation_scope: Optional[str] = None,
    threat_actors: Optional[str] = None,
    attack_timeline: Optional[str] = None,
    campaign_indicators: Optional[str] = None,
    attribution_confidence: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create an advanced investigation form for the SOC Tier 3 analyst to fill out.

    Args:
        case_id (str): Case ID from the case management system. Can be empty.
        threat_type (str): Type of advanced threat (e.g., APT, sophisticated malware, nation-state). Can be empty.
        complexity (str): Investigation complexity level (critical/high/medium/low). Can be empty.
        investigation_scope (str): Scope of the investigation (enterprise-wide, multi-vector, long-term). Can be empty.
        threat_actors (str): Suspected threat actors or groups. Can be empty.
        attack_timeline (str): Timeline of the attack progression. Can be empty.
        campaign_indicators (str): Campaign-level IOCs and TTPs. Can be empty.
        attribution_confidence (str): Confidence level in threat attribution. Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the advanced investigation form data.
    """
    investigation_id = 'advanced_investigation_' + str(random.randint(1000000, 9999999))
    investigation_ids.add(investigation_id)
    return {
        'investigation_id': investigation_id,
        'case_id': '<case management system ID>' if not case_id else case_id,
        'threat_type': '<e.g., APT, sophisticated malware, nation-state>' if not threat_type else threat_type,
        'complexity': '<critical/high/medium/low>' if not complexity else complexity,
        'investigation_scope': '<enterprise-wide, multi-vector, long-term>' if not investigation_scope else investigation_scope,
        'threat_actors': '<suspected threat actors or groups>' if not threat_actors else threat_actors,
        'attack_timeline': '<timeline of attack progression>' if not attack_timeline else attack_timeline,
        'campaign_indicators': '<campaign-level IOCs, TTPs, infrastructure>' if not campaign_indicators else campaign_indicators,
        'attribution_confidence': '<high/medium/low confidence>' if not attribution_confidence else attribution_confidence,
    }


def return_advanced_investigation_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating an advanced investigation form to complete.

    Args:
        form_request (dict[str, Any]): The advanced investigation form data.
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
                'case_id': {
                    'type': 'string',
                    'description': 'Case ID from the case management system',
                    'title': 'Case ID',
                },
                'threat_type': {
                    'type': 'string',
                    'description': 'Type of advanced threat',
                    'title': 'Threat Type',
                    'enum': ['APT', 'Nation-State', 'Sophisticated Malware', 'Ransomware Campaign', 'Supply Chain Attack', 'Zero-Day Exploit', 'Insider Threat', 'Multi-Stage Attack'],
                },
                'complexity': {
                    'type': 'string',
                    'description': 'Investigation complexity level',
                    'title': 'Complexity',
                    'enum': ['Critical', 'High', 'Medium', 'Low'],
                },
                'investigation_scope': {
                    'type': 'string',
                    'description': 'Scope of the investigation',
                    'title': 'Investigation Scope',
                    'enum': ['Enterprise-wide', 'Multi-Vector Attack', 'Long-term Campaign', 'Cross-Network', 'Single Advanced Threat', 'Attribution Required'],
                },
                'threat_actors': {
                    'type': 'string',
                    'description': 'Suspected threat actors or groups (comma-separated)',
                    'title': 'Threat Actors',
                },
                'attack_timeline': {
                    'type': 'string',
                    'description': 'Timeline of the attack progression',
                    'title': 'Attack Timeline',
                },
                'campaign_indicators': {
                    'type': 'string',
                    'description': 'Campaign-level IOCs, TTPs, and infrastructure (comma-separated)',
                    'title': 'Campaign Indicators',
                },
                'attribution_confidence': {
                    'type': 'string',
                    'description': 'Confidence level in threat attribution',
                    'title': 'Attribution Confidence',
                    'enum': ['High Confidence', 'Medium Confidence', 'Low Confidence', 'Insufficient Data'],
                },
                'investigation_id': {
                    'type': 'string',
                    'description': 'Advanced investigation tracking ID',
                    'title': 'Investigation ID',
                    'readOnly': True,
                },
            },
            'required': ['threat_type', 'complexity', 'investigation_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the advanced investigation form with at least the threat type and complexity.',
    }
    return json.dumps(form_dict)


def initiate_advanced_investigation(investigation_id: str) -> dict[str, Any]:
    """Begin advanced investigation for a given investigation_id."""
    if investigation_id not in investigation_ids:
        return {
            'investigation_id': investigation_id,
            'status': 'Error: Invalid investigation_id.',
        }
    return {
        'investigation_id': investigation_id,
        'status': 'Advanced investigation initiated',
        'message': 'Advanced threat investigation has been started. Deep analysis, threat hunting, and attribution research will be conducted.'
    }


class SOCAnalystTier3A2A:
    """An agent that handles SOC Tier 3 alert triage with A2A integration and full MCP tools."""

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
        return 'Processing advanced investigation request...'

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
        """Builds the LLM agent for the SOC Tier 3 analyst with A2A capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/soc_analyst_tier_3.md").resolve()
        runbook_files = [
            (BASE_DIR / "../../../../rules-bank/run_books/advanced_threat_hunting.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/malware_triage.md").resolve(),
        ]
        persona_data = load_persona_and_runbooks(
            persona_file_path,
            runbook_files,
            default_persona_description="SOC Tier 3 Analyst specializing in advanced investigation and threat hunting."
        )

        # Use the MCP tools that were initialized
        if self._mcp_tools:
            print(f"SOC Analyst Tier 3 A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("SOC Analyst Tier 3 A2A agent initialized with form-based advanced investigation tools only")

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
            name='soc_analyst_tier3_a2a',
            description=persona_data,
            instruction="""
You are a SOC (Security Operations Center) Tier 3 Analyst with comprehensive security tools and A2A integration capabilities.

You have access to multiple types of tools:
1. **Threat Intelligence Tools** (via MCP): Full access to GTI operations including:
   - Get threat actor information for attribution and campaign analysis
   - Get malware information for advanced behavioral analysis
   - Get vulnerability details for threat landscape assessment
   - Get indicator information for comprehensive IOC correlation
   - Search for threats to identify complex attack patterns
   - And many more GTI operations for deep threat analysis
2. **Advanced Investigation Forms**: For structured complex investigation workflows
3. **Security Platform Tools**: SIEM, SOAR, and SCC integration for enterprise-level analysis
4. **Forensic Tools**: Advanced log analysis, timeline reconstruction, and attribution capabilities

**How to handle different requests:**

**For Advanced Investigation Requests:**
- Use the form-based workflow (create_advanced_investigation_form → return_advanced_investigation_form → initiate_advanced_investigation)
- Collect complex investigation requirements systematically
- Use GTI tools for deep threat actor attribution and campaign analysis
- Conduct enterprise-wide threat hunting and correlation

**For APT and Nation-State Investigation:**
- Use GTI tools to understand sophisticated threat actor TTPs
- Research long-term campaigns and infrastructure patterns
- Analyze advanced persistent threats and their evolution
- Provide high-confidence attribution assessments

**For Complex Threat Analysis:**
- Use GTI tools for comprehensive threat landscape analysis
- Correlate indicators across multiple attack vectors
- Reconstruct attack timelines and progression
- Identify zero-day exploits and novel attack techniques

**Your core responsibilities:**
- Leading complex security investigations and APT analysis
- Advanced threat hunting across enterprise environments
- Threat actor attribution and campaign tracking
- Deep forensic analysis and timeline reconstruction
- Mentoring junior analysts and providing expert guidance
- Coordinating with external threat intelligence sources
- Developing advanced detection strategies and hunt hypotheses
- Managing critical incidents requiring expert-level analysis

You have full access to advanced security platforms and threat intelligence for expert-level security analysis and investigation.
""",
            tools=[
                create_advanced_investigation_form,
                return_advanced_investigation_form,
                initiate_advanced_investigation,
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
