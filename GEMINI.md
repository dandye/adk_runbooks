---
type: Reference
title: GEMINI.md
generated:
  by: process:google-labs-jules
  at: 2025-12-20T00:15:29-05:00
---

# GEMINI.md

This file provides guidance to Gemini Code when working with code in this repository.

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
  - LLM Judge: Evaluation and scoring agent
- **Detection-as-Code Agent** (`dac-agent/`): Specialized agent for detection rule lifecycle, validation, and tuning

### Skills Progressive Disclosure Framework
- **Centralized Skills Directory** (`skills/`): Standardized repository organized into 8 taxonomy categories:
  - `skills/triage/`: Alert triage and initial investigation procedures
  - `skills/irps/`: Incident Response Plans (malware, phishing, ransomware, compromised accounts)
  - `skills/investigation/`: Case investigation, timeline analysis, IOC enrichment, and containment
  - `skills/hunting/`: Proactive threat hunting playbooks (APT, IOC, TTPs, lateral movement)
  - `skills/detection/`: Detection rule validation, tuning, and Detection-as-Code workflows
  - `skills/reporting/`: Structured reporting guidelines and standardized report generation
  - `skills/atomic/`: Atomic IOC lookups, Chronicle UDM searches, and entity enrichments
  - `skills/common/`: Reusable operational procedures (SOAR case operations, artifact closing)
- **Standard Skill Packages** (`skills/<category>/<skill_name>/SKILL.md`): Self-contained packages with YAML frontmatter metadata:
  ```yaml
  ---
  name: <skill-name>
  description: "Use when ..."
  category: <category>
  version: 1.0.0
  ---
  ```
- **SkillRegistry Engine** (`skills/registry.py`): Scans and indexes all `SKILL.md` files at startup, supports dual-key lookups (hyphen and underscore normalized), generates compact catalogs, and provides fast content retrieval.
- **Dynamic Skill Loading Tools** (`multi-agent/manager/tools/tools.py` and `dac-agent/tools/tools.py`):
  - `load_persona_with_skills_catalog(persona_file_path, skill_names=...)`: Injects a concise catalog of relevant skills (`name` and `description`) into the agent's system prompt instead of loading full runbook text upfront.
  - `load_skill(skill_name)`: Tool enabling agents to retrieve full step-by-step instructions, execution guidelines, and rubrics on demand when executing a task.
  - `list_available_skills(category=...)`: Tool for runtime skill discovery filtered optionally by category.

### Progressive MCP Tool Discovery
- **Centralized MCP Registry** (`multi-agent/manager/tools/mcp_registry.py` and `dac_agent/tools/mcp_registry.py`): Replaces 30+ static JSON parameter schemas with dynamic runtime reflection across Chronicle SIEM, Chronicle SOAR, VirusTotal/GTI, and Google SecOps 1P Detection Engineering.
- **Client Meta-Tools** (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`): Injected into agent toolsets to enable on-demand tool discovery, parameter schema inspection, and sync/async execution with zero context bloat.
- **Google SecOps 1P MCP Integration**: Connects `dac_agent` and Detection Engineer to Google Cloud SecOps 1P Agentic Detection Engineering MCP Server (`https://chronicle.{region}.rep.googleapis.com/mcp`) via dynamic Google Auth ADC bearer tokens.

### Deferred Initialization Pattern
The manager agent uses `DeferredInitializationAgent` to handle async initialization of sub-agents and MCP tools. This allows synchronous registration while deferring expensive setup operations.

### Tool Integration
- **MCP Security Tools**: Configured in `multi-agent/manager/tools/tools.py`
  - Tools use relative paths from the `external/mcp-security` git submodule
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

### Personas (`rules-bank/personas/`)
- Define agent behaviors, roles, domain responsibilities, and instructions.

### Skills Bank (`skills/`)
- Contains standard `SKILL.md` packages across 8 categories (`triage`, `irps`, `investigation`, `hunting`, `detection`, `reporting`, `atomic`, `common`).

### Evaluation and Benchmarks (`evals/`)
- `evals/datasets/`: Test dataset manifests (`core_workflows.json`, `all_36_workflows.json`, `expanded_cases_alerts.json`).
- `evals/registry.py`: Central registry mapping workflows to agents, skills, and token estimators.
- `evals/rubrics/`: 4-rubric procedural evaluation modules (triage/IRP, threat hunting, detection, reporting).
- `evals/runner.py`: CLI evaluation runner with `--report` support for Markdown and JSON benchmark scorecards.

### Model Distribution Strategy
- **Critical Thinking & Orchestration (`gemini-3.7-flash`)**: Root Manager, CTI Researcher, Threat Hunter, SOC Analyst Tier 3, Incident Responder, Detection Engineer, LLM Judge, DAC Agent, Graph Workflows.
- **High-Speed Procedural Operations (`gemini-2.5-flash-lite`)**: SOC Analyst Tier 1 and SOC Analyst Tier 2.

## Critical Implementation Details

1. **Agent Registration**: Each sub-agent module must export its agent instance properly for the manager to import
2. **Async Operations**: All tool initialization and agent setup uses async/await patterns
3. **Path Resolution**: Uses `pathlib` for robust cross-platform path handling
4. **Resource Management**: Uses `contextlib.ExitStack` to manage tool lifecycles
5. **Model Selection**: Standardized on Gemini 3.7 Flash for reasoning/orchestration and Gemini 2.5 Flash Lite for procedural triage

## Common Development Tasks

### Adding or Updating a Skill
1. Create directory `skills/<category>/<skill_name>/`
2. Add `SKILL.md` with standard YAML frontmatter:
   ```yaml
   ---
   name: <skill-name>
   description: "Use when <trigger-condition> ..."
   category: <category>
   version: 1.0.0
   ---
   ```
3. Write detailed markdown instructions, inputs, prerequisites, tool calls, and output formats.
4. Assign the skill to appropriate agent(s) in `multi-agent/manager/sub_agents/<agent>/agent.py` or `dac_agent/agent.py`.
5. (Optional) If covered by benchmarks, register the workflow in `evals/registry.py` and update datasets in `evals/datasets/`.

### Adding a New Sub-Agent
1. Create new directory under `multi-agent/manager/sub_agents/`
2. Add `__init__.py` and `agent.py` following existing patterns using `load_persona_with_skills_catalog()`
3. Import in manager's `agent.py`
4. Add to sub_agents list in manager initialization

### Modifying Tool Configuration
Edit `multi-agent/manager/tools/tools.py` to add new tools or modify tool initialization. The MCP Security tools are loaded from the `external/mcp-security` submodule with relative paths.

### Testing and Evaluation
1. Run pytest test suite:
   ```bash
   ./venv/bin/pytest tests/ evals/tests/ -v
   ```
2. Run workflow evaluation benchmarks:
   ```bash
   ./venv/bin/python -m evals.runner --dataset all_36_workflows --report -v
   ```
3. Run individual agents interactively:
   ```bash
   cd multi-agent && adk run manager
   ```

## Best Practices

1. **Never use `uv` with pyproject.yaml** - causes dependency issues
2. Always run `adk web` from the `multi-agent/` directory
3. Keep agent system prompts concise by leveraging progressive disclosure catalogs instead of dumping full runbooks
4. Ensure every skill has valid YAML frontmatter with `name`, `description` (< 250 chars), `category`, and `version`
5. Use the TodoWrite/TodoRead tools in agents for complex task management
6. Follow the IRP execution patterns defined in the manager agent's instructions