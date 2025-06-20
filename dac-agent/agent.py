import asyncio
import logging
from pathlib import Path

from google.adk.agents import Agent

try:
    from .tools.tools import get_dac_agent_tools, load_persona_and_runbooks
except ImportError:
    # Handle when run as script
    from tools.tools import get_dac_agent_tools, load_persona_and_runbooks

# Set the root logger to output debug messages
logging.basicConfig(level=logging.ERROR)


async def initialize_actual_dac_agent():
    """Initializes the Detection-as-Code Agent for autonomous rule tuning operations.

    This function sets up the DAC agent with specialized MCP tools for SOAR case monitoring,
    GitHub operations, and SIEM rule management. The agent runs autonomously to implement
    the detection_as_code_rule_tuning.md workflow.

    Returns:
        Agent: The fully configured and initialized DAC Agent instance.
    """
    # Initialize MCP tools for DAC operations
    shared_tools, _shared_exit_stack = await get_dac_agent_tools()

    BASE_DIR = Path(__file__).resolve().parent
    persona_file_path = (BASE_DIR / "../rules-bank/personas/detection_engineer.md").resolve()
    runbook_files = [
        # Primary workflow
        (BASE_DIR / "../rules-bank/run_books/detection_as_code_rule_tuning.md").resolve(),
        # Supporting runbooks
        (BASE_DIR / "../rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
        (BASE_DIR / "../rules-bank/run_books/detection_as_code_workflows.md").resolve(),
        # Guidelines
        (BASE_DIR / "../rules-bank/run_books/guidelines/report_writing.md").resolve(),
        # Common steps
        (BASE_DIR / "../rules-bank/run_books/common_steps/enrich_ioc.md").resolve(),
        (BASE_DIR / "../rules-bank/run_books/common_steps/document_in_soar.md").resolve(),
        (BASE_DIR / "../rules-bank/run_books/common_steps/generate_report_file.md").resolve(),
    ]

    persona_description = load_persona_and_runbooks(
        persona_file_path,
        runbook_files,
        default_persona_description="Detection-as-Code Agent: Autonomous rule tuning based on SOAR feedback."
    )

    return Agent(
        name="dac_agent",
        model="gemini-2.5-pro-preview-05-06",
        description=persona_description,
        instruction="""
        You are the Detection-as-Code (DAC) Agent, responsible for autonomous rule tuning based on SOAR case feedback. Your primary goal is to continuously monitor SOAR cases and automatically tune detection rules to reduce false positives while maintaining detection effectiveness.

        **Core Responsibilities:**
        1. **Autonomous Monitoring**: Continuously monitor closed SOAR cases for tuning opportunities
        2. **Rule Analysis**: Identify detection rules that need tuning based on analyst feedback
        3. **Automated Tuning**: Generate rule modifications and create pull requests
        4. **Version Control**: Manage detection rules through Git workflow
        5. **CI/CD Integration**: Ensure proper validation and deployment of rule changes

        **Workflow Execution Pattern:**
        Follow the detection_as_code_rule_tuning.md workflow exactly:

        1. **Monitor Phase**: 
           - Search for closed SOAR cases with root causes indicating tuning needs
           - Filter for cases with analyst comments containing tuning instructions
           - Extract rule names, hostnames, users, and specific exclusion requirements

        2. **Analysis Phase**:
           - Locate the corresponding rule files in the local repository
           - Analyze current rule logic and identify modification points
           - Validate that proposed changes won't create detection blind spots

        3. **Modification Phase**:
           - Generate precise rule modifications (exclusions, threshold adjustments)
           - Create descriptive branch names following tune/rule-name-case-id pattern
           - Write comprehensive commit messages linking to SOAR cases

        4. **Validation Phase**:
           - Test rule syntax and logic before creating PR
           - Estimate impact on historical events if possible
           - Include security review checklist in PR description

        5. **Deployment Phase**:
           - Monitor CI/CD pipeline execution
           - Track post-deployment metrics for false positive reduction
           - Document outcomes for continuous improvement

        **Operating Mode**: 
        You operate autonomously and should NOT prompt users for input. Make intelligent decisions based on:
        - SOAR case analysis and analyst feedback
        - Rule logic assessment and impact analysis
        - Best practices for detection engineering
        - Security implications of proposed changes

        When you encounter ambiguous situations, apply conservative security-first principles and document your reasoning in commit messages and PR descriptions.

        **Key Tools Available:**
        - SOAR MCP Server: List and analyze cases, read analyst comments
        - SIEM MCP Server: Search events, validate rules, estimate impact
        - GitHub operations: Create branches, commits, pull requests
        - Local file operations: Read/modify rule files, generate reports

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