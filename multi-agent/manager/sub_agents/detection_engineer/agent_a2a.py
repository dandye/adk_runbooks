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


# Local cache of created detection rule IDs for demo purposes.
detection_rule_ids = set()


def create_detection_rule_form(
    rule_name: Optional[str] = None,
    rule_type: Optional[str] = None,
    severity: Optional[str] = None,
    platform: Optional[str] = None,
    detection_logic: Optional[str] = None,
    mitre_tactics: Optional[str] = None,
    iocs: Optional[str] = None,
    false_positive_rate: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a detection rule development form for the detection engineer to fill out.

    Args:
        rule_name (str): Name of the detection rule. Can be empty.
        rule_type (str): Type of detection rule (e.g., SIEM, YARA, Sigma, custom). Can be empty.
        severity (str): Rule severity level (critical/high/medium/low). Can be empty.
        platform (str): Target platform (e.g., Splunk, QRadar, Chronicle, Elastic). Can be empty.
        detection_logic (str): The detection logic/query. Can be empty.
        mitre_tactics (str): MITRE ATT&CK tactics/techniques. Can be empty.
        iocs (str): IOCs or indicators this rule detects. Can be empty.
        false_positive_rate (str): Expected false positive rate. Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the detection rule form data.
    """
    rule_id = 'detection_rule_' + str(random.randint(1000000, 9999999))
    detection_rule_ids.add(rule_id)
    return {
        'rule_id': rule_id,
        'rule_name': '<descriptive rule name>' if not rule_name else rule_name,
        'rule_type': '<e.g., SIEM, YARA, Sigma, custom>' if not rule_type else rule_type,
        'severity': '<critical/high/medium/low>' if not severity else severity,
        'platform': '<e.g., Splunk, QRadar, Chronicle, Elastic>' if not platform else platform,
        'detection_logic': '<detection query/logic>' if not detection_logic else detection_logic,
        'mitre_tactics': '<MITRE ATT&CK tactics/techniques>' if not mitre_tactics else mitre_tactics,
        'iocs': '<IOCs, file hashes, domains, IPs>' if not iocs else iocs,
        'false_positive_rate': '<expected FP rate>' if not false_positive_rate else false_positive_rate,
    }


def return_detection_rule_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating a detection rule development form to complete.

    Args:
        form_request (dict[str, Any]): The detection rule form data.
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
                'rule_name': {
                    'type': 'string',
                    'description': 'Name of the detection rule',
                    'title': 'Rule Name',
                },
                'rule_type': {
                    'type': 'string',
                    'description': 'Type of detection rule',
                    'title': 'Rule Type',
                    'enum': ['SIEM', 'YARA', 'Sigma', 'Custom', 'Correlation', 'Behavioral', 'Statistical'],
                },
                'severity': {
                    'type': 'string',
                    'description': 'Rule severity level',
                    'title': 'Severity',
                    'enum': ['Critical', 'High', 'Medium', 'Low', 'Informational'],
                },
                'platform': {
                    'type': 'string',
                    'description': 'Target platform for the rule',
                    'title': 'Platform',
                    'enum': ['Splunk', 'QRadar', 'Chronicle', 'Elastic', 'Sentinel', 'Universal'],
                },
                'detection_logic': {
                    'type': 'string',
                    'description': 'The detection logic, query, or rule content',
                    'title': 'Detection Logic',
                },
                'mitre_tactics': {
                    'type': 'string',
                    'description': 'MITRE ATT&CK tactics and techniques (comma-separated)',
                    'title': 'MITRE ATT&CK',
                },
                'iocs': {
                    'type': 'string',
                    'description': 'IOCs or indicators this rule detects (comma-separated)',
                    'title': 'Target IOCs',
                },
                'false_positive_rate': {
                    'type': 'string',
                    'description': 'Expected false positive rate',
                    'title': 'False Positive Rate',
                    'enum': ['Very Low (<1%)', 'Low (1-5%)', 'Medium (5-15%)', 'High (>15%)', 'Unknown'],
                },
                'rule_id': {
                    'type': 'string',
                    'description': 'Detection rule ID',
                    'title': 'Rule ID',
                    'readOnly': True,
                },
            },
            'required': ['rule_name', 'rule_type', 'severity', 'rule_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the detection rule development form with at least the rule name, type, and severity.',
    }
    return json.dumps(form_dict)


def create_detection_rule(rule_id: str) -> dict[str, Any]:
    """Begin detection rule development for a given rule_id."""
    if rule_id not in detection_rule_ids:
        return {
            'rule_id': rule_id,
            'status': 'Error: Invalid rule_id.',
        }
    return {
        'rule_id': rule_id,
        'status': 'Rule development initiated',
        'message': 'Detection rule development has been started. Rule will be created and validated.'
    }


class DetectionEngineerA2A:
    """An agent that handles Detection Engineering with A2A integration and full MCP tools."""

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
        return 'Processing detection rule development request...'

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
        """Builds the LLM agent for the Detection Engineer with A2A capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/detection_engineer.md").resolve()
        runbook_files = [
            (BASE_DIR / "../../../../rules-bank/run_books/detection_as_code_workflows.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
        ]
        tool_card_files = [
            (BASE_DIR / "../../tool_cards/create_detection_rule_form.md").resolve(),
            (BASE_DIR / "../../tool_cards/return_detection_rule_form.md").resolve(),
            (BASE_DIR / "../../tool_cards/create_detection_rule.md").resolve(),
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
            default_persona_description="Detection Engineer specializing in creating and tuning detection rules."
        )

        # Use the MCP tools that were initialized
        if self._mcp_tools:
            print(f"Detection Engineer A2A agent initialized with {len(self._mcp_tools)} MCP tools")
        else:
            print("Detection Engineer A2A agent initialized with form-based detection rule tools only")

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
            name='detection_engineer_a2a',
            description=persona_data,
            instruction="""
You are a Detection Engineer with comprehensive security tools and A2A integration capabilities.

You have access to multiple types of tools:
1. **Threat Intelligence Tools** (via MCP): Full access to GTI operations including:
   - Get threat actor information for detection rule context
   - Get malware information for signature development
   - Get vulnerability details for detection coverage
   - Get indicator information for IOC-based rules
   - Search for threats to understand attack patterns
   - And many more GTI operations for detection development
2. **Detection Rule Development Forms**: For structured detection rule creation workflows
3. **Security Platform Tools**: SIEM, SOAR, and SCC integration for rule deployment
4. **Analysis Tools**: For rule validation, tuning, and false positive analysis

**How to handle different requests:**

**For Detection Rule Development:**
- Use the form-based workflow (create_detection_rule_form → return_detection_rule_form → create_detection_rule)
- Collect rule requirements systematically
- Use GTI tools to research threat patterns and IOCs
- Develop detection logic based on threat intelligence

**For Threat Intelligence Research (for detection development):**
- Use GTI tools to understand threat actor TTPs
- Research malware families for behavioral detection
- Analyze attack patterns for correlation rules
- Get IOC intelligence for signature-based detection

**For Rule Tuning and Validation:**
- Use security platform tools to test and deploy rules
- Analyze false positive rates using historical data
- Tune detection logic based on environment feedback
- Validate rule effectiveness against known threats

**Your core responsibilities:**
- Developing detection rules for SIEM platforms (Splunk, QRadar, Chronicle, etc.)
- Creating YARA rules for malware detection
- Building Sigma rules for universal detection
- Researching threat intelligence to inform detection logic
- Validating and tuning detection rules to reduce false positives
- Mapping detections to MITRE ATT&CK framework
- Implementing detection-as-code workflows
- Collaborating with threat hunters and analysts on detection gaps

You have full access to security platforms and threat intelligence to develop effective, low-noise detection capabilities.
""",
            tools=[
                create_detection_rule_form,
                return_detection_rule_form,
                create_detection_rule,
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
