import asyncio
from pathlib import Path

from google.adk.agents import Agent

from .sub_agents.soc_analyst_tier1 import agent as soc_analyst_tier1_agent_module
from .sub_agents.soc_analyst_tier2 import agent as soc_analyst_tier2_agent_module
from .sub_agents.cti_researcher import agent as cti_researcher_agent_module
from .sub_agents.threat_hunter import agent as threat_hunter_agent_module
from .sub_agents.soc_analyst_tier3 import agent as soc_analyst_tier3_agent_module
from .sub_agents.incident_responder import agent as incident_responder_agent_module
from .sub_agents.detection_engineer import agent as detection_engineer_agent_module

from .tools.tools import get_current_time, write_report, get_agent_tools, load_persona_and_runbooks


# This function will perform the actual asynchronous initialization of the manager Agent
async def initialize_actual_manager_agent():
    """Initializes the main Manager Agent and all its sub-agents.

    This function orchestrates the setup of shared MCP tools and then
    initializes each sub-agent, passing the shared resources. Finally,
    it configures and returns the fully initialized Manager Agent.

    The Manager Agent is responsible for delegating tasks to appropriate
    sub-agents and has its own set of tools for reporting and timekeeping.

    Returns:
        Agent: The fully configured and initialized Manager Agent instance.
    """
    # Call get_agent_tools once
    shared_tools, shared_exit_stack = await get_agent_tools()
    shared_tools += [
        get_current_time,
        write_report,
    ]
    # Initialize sub-agents that require async initialization first, passing shared tools and exit_stack
    initialized_soc_analyst_tier1, _ = await soc_analyst_tier1_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_soc_analyst_tier2, _ = await soc_analyst_tier2_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_cti_researcher, _ = await cti_researcher_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_threat_hunter, _ = await threat_hunter_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_soc_analyst_tier3, _ = await soc_analyst_tier3_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_incident_responder, _ = await incident_responder_agent_module.initialize(shared_tools, shared_exit_stack)
    initialized_detection_engineer, _ = await detection_engineer_agent_module.initialize(shared_tools, shared_exit_stack)

    # The shared_exit_stack will manage all resources. Individual stacks from sub-agents are not needed here.
    BASE_DIR = Path(__file__).resolve().parent
    persona_file_path = (BASE_DIR / "../../../rules-bank/personas/soc_manager.md").resolve()
    runbook_files = [
        # Guidelines
        (BASE_DIR / "../../../run_books/guidelines/report_writing.md").resolve(),
        # IRPs
        (BASE_DIR / "../../../rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/phishing_response.md").resolve(),
        (BASE_DIR / "../../../rules-bank/run_books/irps/ransomware_response.md").resolve(),
        # Runbooks
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/triage_alerts.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/prioritize_and_investigate_a_case.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/close_duplicate_or_similar_cases.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/basic_ioc_enrichment.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/suspicious_login_triage.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investgate_a_case_w_external_tools.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_containment.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/basic_endpoint_triage_isolation.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/advanced_threat_hunting.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
        (BASE_DIR / "../../../Users/dandye/Projects/adk_runbooks/rules-bank/run_books/create_an_investigation_report.md").resolve(),

    ]

    persona_description = load_persona_and_runbooks(
        persona_file_path,
        runbook_files,
        default_persona_description="SOC Manager: Responsible for delegating to other agents and writing reports."
    )

    return Agent(
        name="manager", # This name should match the one used in DeferredInitializationAgent
        #model="gemini-2.0-flash",
        model="gemini-2.5-pro-preview-05-06",
        description=persona_description,
        instruction="""
        You are the SOC Manager agent, responsible for overseeing and orchestrating the work of specialized sub-agents. Your primary goal is to ensure efficient and effective incident response and SOC operations.

        **Incident Response Plan (IRP) Execution:**
        When an IRP is invoked (e.g., "Start Malware IRP for CASE_ID 123"):
        1.  Your **first priority** is to understand the active IRP. The IRP details, including phases, steps, and responsible personas, are part of your contextual description.
        2.  You **MUST** meticulously follow the IRP. For each step, identify the `**Responsible Persona(s):**` as specified in the IRP.
        3.  Delegate tasks **strictly according to these IRP assignments**. For example, if the IRP says "SOC Analyst T1" is responsible for initial triage, you delegate that to the `soc_analyst_tier1` sub-agent.
        4.  Ensure that control returns to you after a sub-agent completes its delegated IRP task. You will then consult the IRP for the next step and delegate to the next responsible persona.
        5.  Provide clear context and necessary inputs (from the IRP or previous steps) to sub-agents when delegating.
        6.  If the IRP specifies "SOC Manager (Approval)" for a step, you must make an explicit approval decision (or consult the user if in an interactive session) before proceeding.

        **General Delegation:**
        For tasks not covered by a specific IRP step, use your best judgment to delegate to the most appropriate sub-agent based on their described specializations:
        - soc_analyst_tier1: Initial alert triage, basic SIEM queries, and initial data gathering.
        - soc_analyst_tier2: Deeper investigation, SOAR interactions, complex alert analysis, and initial IOC enrichment.
        - cti_researcher: In-depth threat intelligence, malware analysis, actor profiling, and advanced IOC enrichment.
        - threat_hunter: Proactive threat hunting, hypothesis-driven investigations, and advanced data analysis.
        - soc_analyst_tier3: Advanced incident response coordination for complex incidents, deep-dive forensics, and major security event leadership.
        - incident_responder: Hands-on execution of containment, eradication, and recovery phases of an incident as directed by an IRP or yourself.
        - detection_engineer: Designing, developing, testing, and tuning security detection rules and analytics.

        **Your Tools:**
        You have direct access to these tools for oversight and reporting:
        - get_current_time
        - write_report

        Always aim for clear, coordinated, and efficient execution of security operations, leveraging your sub-agents effectively according to their roles and the active IRP.
        """,
        sub_agents=[
            initialized_soc_analyst_tier1,
            initialized_soc_analyst_tier2,
            initialized_cti_researcher,
            initialized_threat_hunter,
            initialized_soc_analyst_tier3,
            initialized_incident_responder,
            initialized_detection_engineer,
        ],
        tools=[
            get_current_time,
            write_report,
        ],
    )

class DeferredInitializationAgent(Agent):
    """A wrapper agent that defers full initialization until an async method is called.

    This allows the agent's name to be available synchronously for registration
    while the potentially lengthy or asynchronous parts of its setup (like
    initializing sub-agents or tools) are delayed until actually needed.
    """
    def __init__(self, name: str, initialization_coro_func):
        """Initializes the deferred agent.

        Args:
            name (str): The name of the agent, available synchronously.
            initialization_coro_func (Callable[[], Coroutine[Any, Any, Agent]]):
                An async function (coroutine) that, when called, performs the
                full initialization and returns the actual, fully configured Agent instance.
        """
        # Initialize with minimal valid Agent attributes for synchronous access (e.g., .name)
        # and to satisfy Pydantic if it checks for Agent instance type.
        super().__init__(name=name, model="placeholder_model", tools=[]) # Provide minimal valid args
        self._initialization_coro_func = initialization_coro_func
        self._initialized_agent_delegate = None
        self._is_fully_initialized = False
        self._init_lock = asyncio.Lock()

    async def _ensure_initialized(self):
        """Ensures the agent is fully initialized, performing initialization if not already done."""
        async with self._init_lock:
            if not self._is_fully_initialized:
                # Await the coroutine that returns the fully configured Agent instance
                self._initialized_agent_delegate = await self._initialization_coro_func()
                # Copy essential attributes from the delegate to self, so this wrapper
                # behaves like the fully initialized agent.
                self.model = self._initialized_agent_delegate.model
                self.description = self._initialized_agent_delegate.description
                self.instruction = self._initialized_agent_delegate.instruction
                self.sub_agents = self._initialized_agent_delegate.sub_agents
                self.tools = self._initialized_agent_delegate.tools
                # TODO: Consider other attributes/methods that might need to be proxied or copied.
                self._is_fully_initialized = True

    async def run_async(self, invocation_context):
        """Overrides BaseAgent.run_async to ensure full initialization before running."""
        await self._ensure_initialized()
        # After _ensure_initialized, attributes like self.model, self.tools, etc.,
        # are copied to this DeferredInitializationAgent instance.
        # Now, calling super().run_async() will use these correct attributes.
        # We must iterate over the async generator returned by super().run_async()
        # and yield its events, making this method an async generator too.
        async for event in super().run_async(invocation_context):
            yield event

    # Override core Agent methods to ensure initialization and delegate.
    async def process_request(self, request, invocation_context=None, tools_code_execution_config=None):
        """Overrides Agent.process_request to ensure full initialization before processing."""
        await self._ensure_initialized()
        # Delegate to the fully initialized agent's process_request.
        return await self._initialized_agent_delegate.process_request(
            request, invocation_context, tools_code_execution_config
        )

    def get_tools_for_model(self):
        """Returns the tools appropriate for the model, ensuring initialization first."""
        # This method might be called by the framework.
        # Ensure it returns the correct tools after initialization.
        if self._is_fully_initialized: # pragma: no cover
            return self._initialized_agent_delegate.get_tools_for_model()
        # Before full initialization, it returns the placeholder tools from super().__init__
        return super().get_tools_for_model()

    # Consider other methods from BaseAgent or Agent that the ADK framework might call directly
    # on the root_agent instance and override them similarly if needed.

# root_agent is an instance of DeferredInitializationAgent.
# It *is* an Agent (satisfies Pydantic), its .name is available synchronously.
# Its async methods will trigger full initialization on first call.
root_agent = DeferredInitializationAgent(name="manager", initialization_coro_func=initialize_actual_manager_agent)

# This function can be used if other parts of the ADK or user code
# explicitly want to ensure the agent is fully initialized by awaiting something.
async def get_root_agent():
    """Ensures the root_agent is fully initialized and returns it.

    This is a convenience function for external modules that might need to
    interact with a fully initialized manager agent.

    Returns:
        Agent: The fully initialized manager agent instance.
    """
    if isinstance(root_agent, DeferredInitializationAgent): # pragma: no cover
        await root_agent._ensure_initialized()
    return root_agent
