import asyncio # Added import

from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool

from .sub_agents.soc_analyst_tier1 import agent as soc_analyst_tier1_agent_module
from .sub_agents.soc_analyst_tier2 import agent as soc_analyst_tier2_agent_module
from .sub_agents.cti_researcher import agent as cti_researcher_agent_module

from .tools.tools import get_current_time, write_report


# This function will perform the actual asynchronous initialization of the manager Agent
async def initialize_actual_manager_agent():
    # Initialize sub-agents that require async initialization first
    initialized_soc_analyst_tier1, soc_analyst_tier1_exit_stack = await soc_analyst_tier1_agent_module.initialize()
    #initialized_soc_analyst_tier2, soc_analyst_tier2_exit_stack = await soc_analyst_tier2_agent_module.initialize()
    #initialized_cti_researcher, cti_researcher_exit_stack = await cti_researcher_agent_module.initialize()
    # TODO: Properly handle the exit_stack from sub_agents if needed by the manager


    persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_manager.md"
    runbook_files = [
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investigate_a_gti_collection_id.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_threat_hunt.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/apt_threat_hunt.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
        #  "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/threat_intel_workflows.md",
        "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
        #  # `case_event_timeline_and_process_analysis.md`, `create_an_investigation_report.md`, `phishing_response.md`, or `ransomware_response.md`.
        "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/demo_manager_runbook.md",
        "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/demo_threat_intel_workflows.md",
    ]

    try:
        with open(persona_file_path, 'r') as f:
            persona_description = f.read()
    except FileNotFoundError:
        # Fallback or error handling if the persona file is not found
        persona_description = "SOC Mnaager: Responsible for delegating to other agents and writing reports."
        print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

    for runbook_file in runbook_files:
        try:
            with open(runbook_file, 'r') as f:
                runbook_content = f.read()
            persona_description += "\n\n" + runbook_content
        except FileNotFoundError:
            print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")


    return Agent(
        name="manager", # This name should match the one used in DeferredInitializationAgent
        #model="gemini-2.0-flash",
        model="gemini-2.5-pro-preview-05-06",
        description=persona_description,
        instruction="""
        You are a SOC Manager agent that is responsible for overseeing the work of the other agents.

        Always delegate the task to the appropriate agent. Use your best judgement
        to determine which agent to delegate to.

        You are responsible for delegating tasks to the following agents:
        - soc_analyst_tier1: for siem questions and tasks and tool use
        - soc_analyst_tier2: for soar questions and tasks and tool use
        - cti_researcher: for cti questions and tasks and tool use

        You also have access to the following tools:
        - get_current_time
        - write_report
        """,
        sub_agents=[
            initialized_soc_analyst_tier1,
            #initialized_soc_analyst_tier2,
            #initialized_cti_researcher,
        ],
        tools=[
            get_current_time,
            write_report,
        ],
        # enabled_mcp_servers=[],
    )

class DeferredInitializationAgent(Agent):
    def __init__(self, name: str, initialization_coro_func):
        # Initialize with minimal valid Agent attributes for synchronous access (e.g., .name)
        # and to satisfy Pydantic if it checks for Agent instance type.
        super().__init__(name=name, model="placeholder_model", tools=[]) # Provide minimal valid args
        self._initialization_coro_func = initialization_coro_func
        self._initialized_agent_delegate = None
        self._is_fully_initialized = False
        self._init_lock = asyncio.Lock()

    async def _ensure_initialized(self):
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
        """Overrides BaseAgent.run_async to ensure full initialization first."""
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
        await self._ensure_initialized()
        # Delegate to the fully initialized agent's process_request.
        return await self._initialized_agent_delegate.process_request(
            request, invocation_context, tools_code_execution_config
        )

    def get_tools_for_model(self):
        # This method might be called by the framework.
        # Ensure it returns the correct tools after initialization.
        if self._is_fully_initialized:
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
    if isinstance(root_agent, DeferredInitializationAgent):
        await root_agent._ensure_initialized()
    return root_agent
