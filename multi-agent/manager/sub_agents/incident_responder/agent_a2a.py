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
def load_persona_and_runbooks(persona_file_path: str, runbook_files: list, tool_card_files: list, default_persona_description: str = "Default persona description.") -> str:
    """Loads persona description from a file and appends contents from runbook and tool card files."""
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

    for tool_card_file in tool_card_files:
        try:
            with open(tool_card_file, 'r') as f:
                tool_card_content = f.read()
            persona_description += "\n\n" + tool_card_content
        except FileNotFoundError:
            print(f"Warning: Tool card file not found at {tool_card_file}. Skipping.")
    return persona_description


# Local cache of created incident IDs for demo purposes.
incident_ids = set()


def create_incident_response_form(
    incident_id: Optional[str] = None,
    incident_type: Optional[str] = None,
    severity: Optional[str] = None,
    affected_systems: Optional[str] = None,
    incident_scope: Optional[str] = None,
    detection_time: Optional[str] = None,
    containment_status: Optional[str] = None,
    threat_indicators: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create an incident response form for the incident responder to fill out.

    Args:
        incident_id (str): Incident ID from the incident management system. Can be empty.
        incident_type (str): Type of security incident (e.g., malware, phishing, data breach, ransomware). Can be empty.
        severity (str): Incident severity level (critical/high/medium/low). Can be empty.
        affected_systems (str): Systems, networks, or assets affected by the incident. Can be empty.
        incident_scope (str): Scope of the incident (single host, network segment, enterprise-wide). Can be empty.
        detection_time (str): When the incident was first detected. Can be empty.
        containment_status (str): Current containment status. Can be empty.
        threat_indicators (str): IOCs and threat indicators associated with the incident. Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the incident response form data.
    """
    response_id = 'incident_response_' + str(random.randint(1000000, 9999999))
    incident_ids.add(response_id)
    return {
        'response_id': response_id,
        'incident_id': '<incident management system ID>' if not incident_id else incident_id,
        'incident_type': '<e.g., malware, phishing, data breach, ransomware>' if not incident_type else incident_type,
        'severity': '<critical/high/medium/low>' if not severity else severity,
        'affected_systems': '<affected systems, networks, assets>' if not affected_systems else affected_systems,
        'incident_scope': '<single host, network segment, enterprise-wide>' if not incident_scope else incident_scope,
        'detection_time': '<YYYY-MM-DD HH:MM:SS or relative time>' if not detection_time else detection_time,
        'containment_status': '<not contained, partially contained, fully contained>' if not containment_status else containment_status,
        'threat_indicators': '<IOCs, file hashes, IPs, domains, TTPs>' if not threat_indicators else threat_indicators,
    }


def return_incident_response_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating an incident response form to complete.

    Args:
        form_request (dict[str, Any]): The incident response form data.
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
                'incident_id': {
                    'type': 'string',
                    'description': 'Incident ID from the incident management system',
                    'title': 'Incident ID',
                },
                'incident_type': {
                    'type': 'string',
                    'description': 'Type of security incident',
                    'title': 'Incident Type',
                    'enum': ['Malware', 'Phishing', 'Data Breach', 'Ransomware', 'APT', 'Insider Threat', 'DDoS', 'Compromise', 'Other'],
                },
                'severity': {
                    'type': 'string',
                    'description': 'Incident severity level',
                    'title': 'Severity',
                    'enum': ['Critical', 'High', 'Medium', 'Low'],
                },
                'affected_systems': {
                    'type': 'string',
                    'description': 'Systems, networks, or assets affected by the incident',
                    'title': 'Affected Systems',
                },
                'incident_scope': {
                    'type': 'string',
                    'description': 'Scope of the incident impact',
                    'title': 'Incident Scope',
                    'enum': ['Single Host', 'Multiple Hosts', 'Network Segment', 'Multiple Networks', 'Enterprise-wide', 'External Impact'],
                },
                'detection_time': {
                    'type': 'string',
                    'description': 'When the incident was first detected',
                    'title': 'Detection Time',
                },
                'containment_status': {
                    'type': 'string',
                    'description': 'Current containment status of the incident',
                    'title': 'Containment Status',
                    'enum': ['Not Contained', 'Partially Contained', 'Fully Contained', 'Eradicated'],
                },
                'threat_indicators': {
                    'type': 'string',
                    'description': 'IOCs and threat indicators associated with the incident (comma-separated)',
                    'title': 'Threat Indicators',
                },
                'response_id': {
                    'type': 'string',
                    'description': 'Incident response tracking ID',
                    'title': 'Response ID',
                    'readOnly': True,
                },
            },
            'required': ['incident_type', 'severity', 'response_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the incident response form with at least the incident type and severity.',
    }
    return json.dumps(form_dict)


def initiate_incident_response(response_id: str) -> dict[str, Any]:
    """Begin incident response for a given response_id."""
    if response_id not in incident_ids:
        return {
            'response_id': response_id,
            'status': 'Error: Invalid response_id.',
        }
    return {
        'response_id': response_id,
        'status': 'Incident response initiated',
        'message': 'Incident response has been started. Containment, eradication, and recovery procedures will be executed.'
    }


class IncidentResponderA2A:
    """An agent that handles Incident Response with A2A integration and full MCP tools."""

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
        return 'Processing incident response request...'

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
        """Builds the LLM agent for the Incident Responder with A2A capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/incident_responder.md").resolve()
        runbook_files = [
            (BASE_DIR / "../../../../rules-bank/run_books/irps/malware_incident_response.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/irps/phishing_response.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
        ]
        tool_card_files = [
            (BASE_DIR / "../../tool_cards/create_incident_response_form.md").resolve(),
            (BASE_DIR / "../../tool_cards/return_incident_response_form.md").resolve(),
            (BASE_DIR / "../../tool_cards/initiate_incident_response.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_search_security_events.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_get_security_alerts.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_get_security_alert_by_id.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_do_update_security_alert.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_lookup_entity.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_list_security_rules.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_search_security_rules.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_get_rule_detections.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_list_rule_errors.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_get_ioc_matches.md").resolve(),
            (BASE_DIR / "../../tool_cards/secops_mcp_get_threat_intel.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_collection_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_a_collection.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_threats.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_campaigns.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_threat_actors.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_malware_families.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_software_toolkits.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_threat_reports.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_vulnerabilities.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_collection_timeline_events.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_collection_mitre_tree.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_file_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_a_file.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_file_behavior_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_file_behavior_summary.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_analyse_file.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_search_iocs.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_hunting_ruleset.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_a_hunting_ruleset.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_domain_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_a_domain.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_ip_address_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_an_ip_address.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_list_threat_profiles.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_threat_profile.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_threat_profile_recommendations.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_threat_profile_associations_timeline.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_url_report.md").resolve(),
            (BASE_DIR / "../../tool_cards/gti_mcp_get_entities_related_to_an_url.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_list_cases.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_post_case_comment.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_list_alerts_by_case.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_list_alert_group_identifiers_by_case.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_list_events_by_alert.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_change_case_priority.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_get_entities_by_alert_group_identifiers.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_get_entity_details.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_search_entity.md").resolve(),
            (BASE_DIR / "../../tool_cards/soar_mcp_get_case_full_details.md").resolve(),
            (BASE_DIR / "../../tool_cards/scc_mcp_top_vulnerability_findings.md").resolve(),
            (BASE_DIR / "../../tool_cards/scc_mcp_get_finding_remediation.md").resolve(),
        ]
        persona_data = load_persona_and_runbooks(
            persona_file_path,
            runbook_files,
            tool_card_files,
            default_persona_description="Incident Responder specializing in containing and eradicating threats."
        )

        # Use the MCP tools that were initialized
        if self._mcp_tools:
            print(f"Incident Responder A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("Incident Responder A2A agent initialized with form-based incident response tools only")

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
            name='incident_responder_a2a',
            description=persona_data,
            instruction="""
You are an Incident Responder with comprehensive security tools and A2A integration capabilities.

You have access to multiple types of tools:
1. **Threat Intelligence Tools** (via MCP): Full access to GTI operations including:
   - Get threat actor information for attribution and TTPs
   - Get malware information for containment strategies
   - Get vulnerability details for remediation planning
   - Get indicator information for threat hunting
   - Search for threats to understand attack scope
   - And many more GTI operations for incident analysis
2. **Incident Response Forms**: For structured incident management workflows
3. **Security Platform Tools**: SIEM, SOAR, and SCC integration for response coordination
4. **Investigation Tools**: IOC enrichment, log analysis, and forensic capabilities

**How to handle different requests:**

**For Incident Response Requests:**
- Use the form-based workflow (create_incident_response_form → return_incident_response_form → initiate_incident_response)
- Collect incident details systematically
- Use GTI tools to understand threat context and attribution
- Execute containment, eradication, and recovery procedures

**For Threat Intelligence Research (for incident context):**
- Use GTI tools to understand threat actor TTPs and motivations
- Research malware families for containment and eradication strategies
- Analyze attack patterns to predict next steps
- Get IOC intelligence for threat hunting and indicator blocking

**For Incident Analysis and Attribution:**
- Use GTI tools for comprehensive threat analysis
- Provide threat actor context and campaign attribution
- Cross-reference with known attack patterns and TTPs
- Assess threat capability and likely next actions

**Your core responsibilities:**
- Leading incident containment to prevent spread
- Coordinating eradication of threats from the environment
- Managing recovery and restoration of affected systems
- Conducting forensic analysis and evidence collection
- Threat hunting to identify additional compromised assets
- Coordinating with stakeholders and external parties
- Documenting lessons learned and improving procedures
- Managing communication during critical incidents

You have full access to security platforms and threat intelligence to effectively contain, eradicate, and recover from security incidents.
""",
            tools=[
                create_incident_response_form,
                return_incident_response_form,
                initiate_incident_response,
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
