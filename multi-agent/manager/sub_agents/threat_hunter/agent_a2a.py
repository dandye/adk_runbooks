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


# Local cache of created alert_ids for demo purposes.
alert_ids = set()


def create_alert_triage_form(
    alert_id: Optional[str] = None,
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_system: Optional[str] = None,
    affected_assets: Optional[str] = None,
    event_time: Optional[str] = None,
    description: Optional[str] = None,
    initial_indicators: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create an alert triage form for the SOC analyst to fill out.

    Args:
        alert_id (str): Alert ID from the SIEM/security system. Can be empty.
        alert_type (str): Type of security alert (e.g., malware, phishing, suspicious login). Can be empty.
        severity (str): Alert severity level (critical/high/medium/low). Can be empty.
        source_system (str): System that generated the alert. Can be empty.
        affected_assets (str): Affected systems, users, or IP addresses. Can be empty.
        event_time (str): When the security event occurred. Can be empty.
        description (str): Brief description of the alert. Can be empty.
        initial_indicators (str): Initial IOCs or suspicious indicators. Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the alert triage form data.
    """
    triage_id = 'soc_triage_' + str(random.randint(1000000, 9999999))
    alert_ids.add(triage_id)
    return {
        'triage_id': triage_id,
        'alert_id': '<SIEM alert ID>' if not alert_id else alert_id,
        'alert_type': '<e.g., malware, phishing, suspicious login>' if not alert_type else alert_type,
        'severity': '<critical/high/medium/low>' if not severity else severity,
        'source_system': '<e.g., Splunk, QRadar, CrowdStrike>' if not source_system else source_system,
        'affected_assets': '<affected systems, users, IPs>' if not affected_assets else affected_assets,
        'event_time': '<YYYY-MM-DD HH:MM:SS or relative time>' if not event_time else event_time,
        'description': '<brief alert description>' if not description else description,
        'initial_indicators': '<IOCs, suspicious files, IPs, domains>' if not initial_indicators else initial_indicators,
    }


def return_alert_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating an alert triage form to complete.

    Args:
        form_request (dict[str, Any]): The alert triage form data.
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
                'alert_id': {
                    'type': 'string',
                    'description': 'Alert ID from the SIEM or security system',
                    'title': 'Alert ID',
                },
                'alert_type': {
                    'type': 'string',
                    'description': 'Type of security alert',
                    'title': 'Alert Type',
                    'enum': ['Malware', 'Phishing', 'Suspicious Login', 'Data Exfiltration', 'Brute Force', 'Anomalous Activity', 'Policy Violation', 'Other'],
                },
                'severity': {
                    'type': 'string',
                    'description': 'Alert severity level',
                    'title': 'Severity',
                    'enum': ['Critical', 'High', 'Medium', 'Low'],
                },
                'source_system': {
                    'type': 'string',
                    'description': 'System that generated the alert',
                    'title': 'Source System',
                    'enum': ['Splunk', 'QRadar', 'CrowdStrike', 'Sentinel', 'Elastic', 'Other'],
                },
                'affected_assets': {
                    'type': 'string',
                    'description': 'Affected systems, users, or IP addresses (comma-separated)',
                    'title': 'Affected Assets',
                },
                'event_time': {
                    'type': 'string',
                    'description': 'When the security event occurred',
                    'title': 'Event Time',
                },
                'description': {
                    'type': 'string',
                    'description': 'Brief description of the alert',
                    'title': 'Alert Description',
                },
                'initial_indicators': {
                    'type': 'string',
                    'description': 'Initial IOCs or suspicious indicators (comma-separated)',
                    'title': 'Initial Indicators',
                },
                'triage_id': {
                    'type': 'string',
                    'description': 'Triage request ID',
                    'title': 'Triage ID',
                    'readOnly': True,
                },
            },
            'required': ['alert_type', 'severity', 'triage_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the alert triage form with at least the alert type and severity.',
    }
    return json.dumps(form_dict)


def start_triage(triage_id: str) -> dict[str, Any]:
    """Begin alert triage for a given triage_id."""
    if triage_id not in alert_ids:
        return {
            'triage_id': triage_id,
            'status': 'Error: Invalid triage_id.',
        }
    return {
        'triage_id': triage_id,
        'status': 'Triage initiated',
        'message': 'Alert triage has been started. Initial analysis will be performed.'
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
        return 'Processing alert triage request...'

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
                        "/Users/dandye/Projects/google-mcp-security/server/secops/secops_mcp",
                        "run",
                        "--reinstall-package",
                        "secops-mcp",
                        "--env-file",
                        "/Users/dandye/Projects/google-mcp-security/.env",
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
                        "/Users/dandye/Projects/google-mcp-security/server/gti",
                        "run",
                        "--env-file",
                        "/Users/dandye/Projects/google-mcp-security/.env",
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
                        "/Users/dandye/Projects/google-mcp-security/server/secops-soar/secops_soar_mcp",
                        "run",
                        "--env-file",
                        "/Users/dandye/Projects/google-mcp-security/.env",
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
                        "/Users/dandye/Projects/google-mcp-security/server/scc",
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
            print(f"SOC Analyst Tier 2 A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("SOC Analyst Tier 2 A2A agent initialized with form-based alert triage tools only")

        # Load environment variables from .env file
        import os
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
   - Get threat actor information (secops_gti.get_threat_actor)
   - Get malware information (secops_gti.get_malware)
   - Get vulnerability details (secops_gti.get_vulnerability)
   - Get indicator information (secops_gti.get_indicator)
   - Search for threats (secops_gti.search_threats)
   - And many more GTI operations
2. **Alert Triage Forms**: For structured alert processing workflows
3. **Investigation Tools**: IOC enrichment, log analysis, and forensic capabilities

**How to handle different requests:**

**For Alert Triage Requests:**
- Use the form-based workflow (create_alert_triage_form → return_alert_form → start_triage)
- Collect alert details systematically
- Enrich IOCs using GTI tools during triage

**For Threat Intelligence Queries (like "check threat intel", "lookup IOC", "get malware info"):**
- Use the appropriate MCP GTI tools directly
- For example, use secops_gti.get_indicator to lookup specific IOCs
- Use secops_gti.search_threats to find threat information
- Use secops_gti.get_malware for malware analysis

**For IOC Analysis:**
- Use GTI enrichment tools directly for comprehensive analysis
- Provide threat context from intelligence sources
- Cross-reference with known threat actors and campaigns

**Your core responsibilities:**
- Initial alert triage and classification with threat intelligence enrichment
- IOC analysis using GTI tools
- Threat actor and malware identification
- Identifying false positives using threat intelligence
- Escalating complex cases to Tier 2 with enriched context
- Documenting findings with threat intelligence insights

You have full access to Global Threat Intelligence (GTI) capabilities through MCP tools. Use them to enrich your alert triage and investigations.
""",
            tools=[
                create_alert_triage_form,
                return_alert_form,
                start_triage,
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
