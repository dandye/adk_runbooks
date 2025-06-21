# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ADK Runbooks is a multi-agent system for cybersecurity operations built on Google's Agent Development Kit (ADK). It implements specialized security agents that collaborate through delegation and tool sharing to handle complex security tasks like incident response, threat hunting, and detection engineering.

## Key Development Commands

### Initial Setup
```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/dandye/adk_runbooks.git
cd adk_runbooks

# Or if already cloned:
git submodule update --init --recursive

# Create virtual environment
python -m venv venv

# Activate environment
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt  # For multi-agent system
pip install -r requirements-docs.txt  # For documentation
```

### Running the Multi-Agent System
```bash
cd multi-agent
adk run manager  # Run the manager agent
# or
adk web  # Run web UI (from multi-agent directory)
```

### Documentation
```bash
# Build Sphinx documentation
make html  # From project root
# Output in build/html/
```

## Architecture & Key Components

### Multi-Agent System Structure
- **Manager Agent** (`multi-agent/manager/`): Root orchestrator that delegates to specialized sub-agents
- **Sub-agents** (`multi-agent/manager/sub_agents/`): 
  - CTI Researcher: Threat intelligence gathering and analysis
  - SOC Analyst Tier 1/2/3: Alert triage and investigation at different levels
  - Threat Hunter: Proactive threat detection
  - Incident Responder: Incident containment and recovery
  - Detection Engineer: Security rule development

### Agent Implementation Patterns

The system follows a **Hierarchical Multi-Agent System** pattern with these key design patterns:

1. **Deferred Initialization Pattern**: Manager uses `DeferredInitializationAgent` for lazy loading of expensive resources
2. **Delegation Pattern**: Manager orchestrates and delegates to specialized sub-agents based on expertise
3. **Shared Resource Pattern**: MCP tools initialized once and shared across all agents
4. **Configuration Loading Pattern**: Agent personas and runbooks loaded from markdown files

#### Common Agent Implementation
All sub-agents follow a consistent two-function pattern:
```python
def get_agent(tools, exit_stack):
    """Synchronous agent configuration"""
    persona, runbooks = load_persona_and_runbooks(
        'agent_persona_name',
        ['relevant', 'runbooks']
    )
    return Agent(
        name="agent_name",
        model="gemini-2.5-pro-preview-05-06",
        description=persona,
        instruction=persona + runbooks,
        tools=tools
    )

async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper"""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)
```

### Tool Integration
- **MCP Security Tools**: Configured in `multi-agent/manager/tools/tools.py`
  - Tools now use relative paths from the `external/mcp-security` git submodule
- **Shared tools** are initialized once and passed to all sub-agents to avoid redundant connections

### Configuration Requirements
1. Create `.env` file in `multi-agent/manager/` with:
   ```
   GOOGLE_API_KEY=your_api_key_here
   ```
2. Configure MCP Security tools in `external/mcp-security/.env`:
   ```
   CHRONICLE_PROJECT_ID=your_gcp_project_id
   CHRONICLE_CUSTOMER_ID=your_chronicle_customer_id
   CHRONICLE_REGION=us
   SOAR_URL=https://your-soar-instance.example.com
   SOAR_APP_KEY=your_soar_app_key
   VT_APIKEY=your_virustotal_api_key
   ```

## Important Context Files

### Rules Bank (`rules-bank/`)
- **Personas**: Define agent behaviors and responsibilities
- **Runbooks**: Step-by-step procedures for security operations
- **IRPs**: Incident Response Plans for specific scenarios (malware, phishing, ransomware)
- **Atomic Runbooks**: Reusable components for specific IOC types

### Agent Loading Pattern
Each agent loads its persona and relevant runbooks using `load_persona_and_runbooks()` from the rules-bank to configure its behavior and available procedures.

## Critical Implementation Details

1. **Agent Registration**: Each sub-agent module must export its agent instance properly for the manager to import
2. **Async Operations**: All tool initialization and agent setup uses async/await patterns
3. **Path Resolution**: Uses `pathlib` for robust cross-platform path handling
4. **Resource Management**: Uses `contextlib.ExitStack` to manage tool lifecycles
5. **Model Selection**: Currently configured for Gemini 2.5 Pro Preview models

## Common Development Tasks

### Adding a New Sub-Agent
1. Create new directory under `multi-agent/manager/sub_agents/`
2. Add `__init__.py` and `agent.py` following existing patterns
3. Import in manager's `agent.py`
4. Add to sub_agents list in manager initialization

### Modifying Tool Configuration
Edit `multi-agent/manager/tools/tools.py` to add new tools or modify tool initialization. The MCP Security tools are loaded from the `external/mcp-security` submodule with relative paths.

### Testing Individual Agents
While there's no formal test suite, you can test agents by:
1. Running `adk run manager` and selecting specific sub-agents
2. Using test prompts from the README examples
3. Checking logs in `multi-agent/adk_logs/`

## Best Practices

1. **Never use `uv` with pyproject.yaml** - causes dependency issues
2. Always run `adk web` from the `multi-agent/` directory
3. Keep agent instructions focused on their specific domain
4. Use the TodoWrite/TodoRead tools in agents for complex task management
5. Follow the IRP execution patterns defined in the manager agent's instructions
6. Never, ever use `git add -A` or `git add .`. It is dangerous. Instead, add the files individually.