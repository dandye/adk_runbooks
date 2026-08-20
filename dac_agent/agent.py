import asyncio
import logging
from pathlib import Path

from google.adk.agents import Agent

try:
    from .tools.tools import (
        get_dac_agent_tools,
        load_persona_with_skills_catalog,
        load_persona_and_runbooks,
    )
except ImportError:
    # Handle when run as script
    from tools.tools import (
        get_dac_agent_tools,
        load_persona_with_skills_catalog,
        load_persona_and_runbooks,
    )

# Set the root logger to output debug messages
logging.basicConfig(level=logging.ERROR)


async def initialize_actual_dac_agent():
    """Initializes the Detection-as-Code Agent for autonomous rule tuning operations.

    This function sets up the DAC agent with specialized MCP tools for SOAR case monitoring,
    GitHub operations, SIEM rule management, and progressive disclosure skills. The agent runs
    autonomously to implement the detection-as-code-rule-tuning workflow.

    Returns:
        Agent: The fully configured and initialized DAC Agent instance.
    """
    # Initialize MCP tools and skills for DAC operations
    shared_tools, _shared_exit_stack = await get_dac_agent_tools()

    BASE_DIR = Path(__file__).resolve().parent
    persona_file_path = (BASE_DIR / "../rules-bank/personas/detection_engineer.md").resolve()
    dac_skills = [
        "detection-engineering-coverage-evaluation",
        "detection-as-code-rule-tuning",
        "detection-rule-validation-tuning",
        "detection-as-code-workflows",
        "report-writing-guidelines",
        "enrich-ioc",
        "document-in-soar",
        "generate-report-file",
    ]

    persona_description = load_persona_with_skills_catalog(
        str(persona_file_path),
        skill_names=dac_skills,
        default_persona_description="Detection-as-Code Agent: Autonomous rule tuning and agentic detection engineering."
    )

    return Agent(
        name="dac_agent",
        model="gemini-3.7-flash",
        description=persona_description,
        instruction="""
        You are the Detection-as-Code (DAC) and Agentic Detection Engineering Agent. Your primary roles are:
        1. Autonomous rule tuning and lifecycle management based on SOAR feedback.
        2. Agentic detection engineering using Google SecOps MCP tools to extract threat intelligence, generate Threat Detection Opportunities (TDOs), simulate synthetic UDM events, evaluate rule coverage, and generate new YARA-L 2.0 rules to close coverage gaps.

        When executing tuning or detection engineering tasks, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics on-demand (e.g. `load_skill('detection-engineering-coverage-evaluation')`, `load_skill('detection-as-code-rule-tuning')`, or `load_skill('detection-rule-validation-tuning')`).

        **Core Capabilities & Workflow Execution:**

        **A. Agentic Detection Engineering Lifecycle (TDO & Coverage Evaluation):**
        1. **Extract Threat Intelligence**: Extract threat data from security advisories, blogs, or incident reports.
        2. **Generate TDOs**: Call `secops-1p_generate_threat_detection_opportunity` with raw threat intelligence.
        3. **Generate Synthetic Events**: Call `secops-1p_generate_synthetic_events` for each TDO to simulate attacker telemetry.
        4. **Evaluate Rule Coverage**: Call `secops-1p_evaluate_rule_coverage` (or `evaluate_rule_coverage_long_running`) to test against existing rules.
        5. **Draft Rules for Gaps**: Call `secops-1p_generate_rules` for TDOs with zero matches to draft new YARA-L 2.0 rules.
        6. **Validate Rules**: Call `secops-1p_validate_rule` to verify syntax and compilation before committing or deploying.

        **B. Autonomous Rule Tuning Pattern (SOAR Feedback Loop):**
        1. **Monitor Phase**: Search closed SOAR cases with root causes indicating tuning opportunities.
        2. **Analysis Phase**: Locate rule files, analyze rule logic, and prevent blind spots.
        3. **Modification Phase**: Generate precise rule exclusions or threshold changes on Git branches.
        4. **Validation Phase**: Test rule syntax and validate historical event impact.
        5. **Deployment Phase**: Create pull requests and track false-positive reduction metrics.

        **Key Tools Available:**
        - Google SecOps 1P Agentic Detection Engineering MCP: `generate_threat_detection_opportunity`, `generate_synthetic_events`, `evaluate_rule_coverage`, `generate_rules`, `validate_rule`
        - Progressive MCP Discovery: `search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`
        - Skill loading: `load_skill`, `list_available_skills`
        - SOAR / SIEM MCP: Case inspection, UDM searches, data tables, alert management
        - Git & GitHub tools: Branching, commits, pull requests

        Always maintain detailed logging of your decisions and actions for audit purposes.
        """,
        tools=shared_tools,
    )


class DeferredInitializationAgent(Agent):
    """A wrapper agent that defers full initialization until an async method is called.

    This allows the agent's name to be available synchronously for registration
    while the potentially lengthy or asynchronous parts of its setup (like
    initializing MCP tools) are delayed until actually needed.
    """
    def __init__(self, name: str, initialization_coro_func):
        """Initializes the deferred agent.

        Args:
            name (str): The name of the agent, available synchronously.
            initialization_coro_func (Callable[[], Coroutine[Any, Any, Agent]]):
                An async function that performs full initialization and returns
                the actual, fully configured Agent instance.
        """
        super().__init__(name=name, model="placeholder_model", tools=[])
        self._initialization_coro_func = initialization_coro_func
        self._initialized_agent_delegate = None
        self._is_fully_initialized = False
        self._init_lock = asyncio.Lock()

    async def _ensure_initialized(self):
        """Ensures the agent is fully initialized, performing initialization if not already done."""
        async with self._init_lock:
            if not self._is_fully_initialized:
                self._initialized_agent_delegate = await self._initialization_coro_func()
                self.model = self._initialized_agent_delegate.model
                self.description = self._initialized_agent_delegate.description
                self.instruction = self._initialized_agent_delegate.instruction
                self.tools = self._initialized_agent_delegate.tools
                self._is_fully_initialized = True

    async def run_async(self, invocation_context):
        """Overrides BaseAgent.run_async to ensure full initialization before running."""
        await self._ensure_initialized()
        async for event in super().run_async(invocation_context):
            yield event

    async def process_request(self, request, invocation_context=None, tools_code_execution_config=None):
        """Overrides Agent.process_request to ensure full initialization before processing."""
        await self._ensure_initialized()
        return await self._initialized_agent_delegate.process_request(
            request, invocation_context, tools_code_execution_config
        )

    def get_tools_for_model(self):
        """Returns the tools appropriate for the model, ensuring initialization first."""
        if self._is_fully_initialized:
            return self._initialized_agent_delegate.get_tools_for_model()
        return super().get_tools_for_model()


# Root agent instance for the DAC agent
root_agent = DeferredInitializationAgent(name="dac_agent", initialization_coro_func=initialize_actual_dac_agent)


async def get_root_agent():
    """Ensures the root_agent is fully initialized and returns it.

    Returns:
        Agent: The fully initialized DAC agent instance.
    """
    if isinstance(root_agent, DeferredInitializationAgent):
        await root_agent._ensure_initialized()
    return root_agent
