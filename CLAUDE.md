# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ADK Runbooks is a multi-agent system for cybersecurity operations built on Google's Agent Development Kit (ADK). It implements specialized security agents that collaborate through delegation and tool sharing to handle complex security tasks like incident response, threat hunting, and detection engineering.

## Key Development Commands

### Initial Setup
```bash
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

### Deferred Initialization Pattern
The manager agent uses `DeferredInitializationAgent` to handle async initialization of sub-agents and MCP tools. This allows synchronous registration while deferring expensive setup operations.

### Tool Integration
- **MCP Security Tools**: Configured in `multi-agent/manager/tools/tools.py`
  - IMPORTANT: Update hardcoded paths like `/Users/dandye/Projects/mcp_security/server/...`
- **Shared tools** are initialized once and passed to all sub-agents to avoid redundant connections

### Configuration Requirements
1. Create `.env` file in `multi-agent/manager/` with:
   ```
   GOOGLE_API_KEY=your_api_key_here
   ```
2. Update MCP tool paths in `multi-agent/manager/tools/tools.py`

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
Edit `multi-agent/manager/tools/tools.py` to update MCP server paths or add new tools.

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