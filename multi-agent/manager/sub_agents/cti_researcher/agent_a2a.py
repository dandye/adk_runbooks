import json
import random
from typing import Any, AsyncIterable, Optional
from pathlib import Path
from google.adk.agents.llm_agent import LlmAgent
from google.adk.artifacts import InMemoryArtifactService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.genai import types

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


# Local cache of created research_ids for demo purposes.
research_ids = set()


def create_research_request_form(
    threat_type: Optional[str] = None,
    iocs: Optional[str] = None,
    actor_name: Optional[str] = None,
    campaign_name: Optional[str] = None,
    collection_id: Optional[str] = None,
    time_range: Optional[str] = None,
    priority: Optional[str] = None,
) -> dict[str, Any]:
    """
    Create a CTI research request form for the analyst to fill out.

    Args:
        threat_type (str): Type of threat to research (e.g., APT, malware, ransomware). Can be empty.
        iocs (str): Indicators of Compromise to investigate (comma-separated). Can be empty.
        actor_name (str): Threat actor name to research. Can be empty.
        campaign_name (str): Campaign name to investigate. Can be empty.
        collection_id (str): GTI collection ID to analyze. Can be empty.
        time_range (str): Time range for the investigation (e.g., "last 7 days"). Can be empty.
        priority (str): Priority level (high/medium/low). Can be empty.

    Returns:
        dict[str, Any]: A dictionary containing the research request form data.
    """
    research_id = 'cti_research_' + str(random.randint(1000000, 9999999))
    research_ids.add(research_id)
    return {
        'research_id': research_id,
        'threat_type': '<e.g., APT, malware, ransomware>' if not threat_type else threat_type,
        'iocs': '<comma-separated IOCs to investigate>' if not iocs else iocs,
        'actor_name': '<threat actor name>' if not actor_name else actor_name,
        'campaign_name': '<campaign name>' if not campaign_name else campaign_name,
        'collection_id': '<GTI collection ID>' if not collection_id else collection_id,
        'time_range': '<e.g., last 7 days, last month>' if not time_range else time_range,
        'priority': '<high/medium/low>' if not priority else priority,
    }


def return_research_form(
    form_request: dict[str, Any],
    tool_context: ToolContext,
    instructions: Optional[str] = None,
) -> dict[str, Any]:
    """
    Returns a structured json object indicating a CTI research form to complete.

    Args:
        form_request (dict[str, Any]): The research request form data.
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
                'threat_type': {
                    'type': 'string',
                    'description': 'Type of threat to research (e.g., APT, malware, ransomware)',
                    'title': 'Threat Type',
                    'enum': ['APT', 'Malware', 'Ransomware', 'Phishing', 'Other'],
                },
                'iocs': {
                    'type': 'string',
                    'description': 'Indicators of Compromise to investigate (comma-separated)',
                    'title': 'IOCs',
                },
                'actor_name': {
                    'type': 'string',
                    'description': 'Threat actor name to research',
                    'title': 'Actor Name',
                },
                'campaign_name': {
                    'type': 'string',
                    'description': 'Campaign name to investigate',
                    'title': 'Campaign Name',
                },
                'collection_id': {
                    'type': 'string',
                    'description': 'GTI collection ID to analyze',
                    'title': 'Collection ID',
                },
                'time_range': {
                    'type': 'string',
                    'description': 'Time range for the investigation',
                    'title': 'Time Range',
                    'enum': ['Last 24 hours', 'Last 7 days', 'Last 30 days', 'Last 90 days', 'Custom'],
                },
                'priority': {
                    'type': 'string',
                    'description': 'Priority level for this research',
                    'title': 'Priority',
                    'enum': ['High', 'Medium', 'Low'],
                },
                'research_id': {
                    'type': 'string',
                    'description': 'Research request ID',
                    'title': 'Research ID',
                    'readOnly': True,
                },
            },
            'required': ['threat_type', 'priority', 'research_id'],
        },
        'form_data': form_request,
        'instructions': instructions or 'Please fill out the CTI research request form with at least the threat type and priority.',
    }
    return json.dumps(form_dict)


def start_research(research_id: str) -> dict[str, Any]:
    """Begin CTI research for a given research_id."""
    if research_id not in research_ids:
        return {
            'research_id': research_id,
            'status': 'Error: Invalid research_id.',
        }
    return {
        'research_id': research_id,
        'status': 'Research initiated',
        'message': 'CTI research has been started. Results will be available shortly.'
    }


class CTIResearcherA2A:
    """An agent that handles CTI research requests with A2A integration."""

    SUPPORTED_CONTENT_TYPES = ['text', 'text/plain']

    def __init__(self):
        self._agent = self._build_agent()
        self._user_id = 'remote_agent'
        self._runner = Runner(
            app_name=self._agent.name,
            agent=self._agent,
            artifact_service=InMemoryArtifactService(),
            session_service=InMemorySessionService(),
            memory_service=InMemoryMemoryService(),
        )

    def get_processing_message(self) -> str:
        return 'Processing CTI research request...'

    def _build_agent(self) -> LlmAgent:
        """Builds the LLM agent for the CTI researcher with A2A capabilities."""
        # Load persona and runbooks
        BASE_DIR = Path(__file__).resolve().parent
        persona_file_path = (BASE_DIR / "../../../../rules-bank/personas/cti_researcher.md").resolve()
        runbook_files = [
            # Guidelines
            (BASE_DIR / "../../../../rules-bank/run_books/guidelines/threat_intel_workflows.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/guidelines/report_writing.md").resolve(),
            # Runbooks
            (BASE_DIR / "../../../../rules-bank/run_books/investigate_a_gti_collection_id.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/ioc_threat_hunt.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/apt_threat_hunt.md").resolve(),
            (BASE_DIR / "../../../../rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
        ]
        persona_data = load_persona_and_runbooks(
            persona_file_path,
            runbook_files,
            default_persona_description="CTI Researcher specializing in threat intelligence analysis"
        )
        
        # For now, we'll skip MCP tools in A2A agents to avoid complex import issues
        # The tools are described in the persona and the agent can reference them in responses
        mcp_tools = []
        print("Note: MCP tools are referenced in persona but not directly loaded in A2A mode")
        
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
            name='cti_researcher_a2a',
            description=persona_data,
            instruction="""
You are a CTI (Cyber Threat Intelligence) Researcher with comprehensive threat intelligence tools and A2A integration capabilities.

You have access to multiple types of tools:
1. **Threat Intelligence Tools**: GTI queries, threat actor research, IOC analysis, campaign tracking
2. **Research Forms**: For structured research project workflows  
3. **Analysis Tools**: Malware analysis, attribution research, TTPs analysis

**How to handle different requests:**

**For Formal Research Projects:**
- Use the form-based workflow (create_research_request_form → return_research_form → start_research)
- Collect research requirements systematically

**For Direct Intelligence Queries (like "research Lazarus Group", "analyze this IOC", "check GTI for campaigns"):**
- Note: In A2A mode, MCP tools are not directly available
- For complex queries requiring GTI/threat intel access, acknowledge the request and suggest:
  "I understand you need [specific research]. For direct GTI/threat intelligence access, this would be better handled by the main SOC Manager with full tool access. I can assist with research planning and structured analysis using my available tools."

**For IOC Analysis:**
- Use enrichment and analysis tools directly
- Provide comprehensive threat context and attribution

**Your expertise includes:**
- Threat actor tracking and attribution
- IOC analysis and enrichment
- Campaign investigation and tracking
- GTI collection analysis
- Threat hunting based on intelligence
- Malware family analysis
- TTPs and MITRE ATT&CK mapping

**Important**: Only use forms for formal research projects. For direct queries, analysis requests, and intelligence lookups, use your threat intelligence tools directly.
""",
            tools=[
                create_research_request_form,
                return_research_form,
                start_research,
            ] + mcp_tools,
        )

    async def stream(self, query, session_id) -> AsyncIterable[dict[str, Any]]:
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