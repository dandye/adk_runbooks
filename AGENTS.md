# AGENTS.md - AI Agent Instructions & Repository Guidelines

This document defines the architecture, coding standards, workflow conventions, and operational procedures for **ADK Runbooks** (`adk_runbooks`). All AI coding assistants and contributors must follow these rules.

## Project Overview

ADK Runbooks is a multi-agent cybersecurity operations system built on Google's Agent Development Kit (ADK). It implements specialized security agents that collaborate through delegation, graph workflows, and progressive tool disclosure to handle incident response, threat hunting, alert triage, and detection engineering.

---

## Coding Standards & Conventions

### 1. Google Python Style Guide (Mandatory)
This repository strictly complies with the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html):
- **Indentation**: **2 spaces** per indentation level (`pyink-indentation = 2`), with **4 spaces** for hanging continuation indents. Never use tabs or 4-space block indentation.
- **Line Length**: **80 characters** maximum.
- **Formatter**: **Pyink** (`pyink`), Google's official Python formatter.
- **Linter**: **Ruff** (`ruff`), configured for Google docstring conventions (`convention = "google"`), import sorting (`force-single-line = true`), bugbear checks, and logging format rules (`G`).
- **Static Type Checking**: **Pytype** (`pytype`), Google's static type analyzer, alongside complete Python 3.11+ type annotations.
- **Imports**: Order alphabetically in three blocks (`future`, standard library, third-party, local application) with a single import per line.
- **Logging**: Use `%s` parameterized formatting in `logger.*` calls (`logger.info("Loaded %d skills", count)`), never f-strings (`G004`).

### 2. Strict No-Emojis Policy
- **NEVER use emojis anywhere**: Do not use emojis in chat responses, user interfaces, CLI output, code, comments, documentation, evaluation reports, or commit messages.

### 3. Shell & Code Examples
- In code and shell examples, always define environment variables first (for example, `PROJECT_ID="your-project-id"`) and then reference them as `$PROJECT_ID`.

### 4. Git & Worktree Conventions
- **Worktree Layout**: Use `<repo>__worktrees/main/` for the primary clone and `<repo>__worktrees/<branch_name>/` for feature or fix worktrees.
- **Branch Naming**: Never use `/` in branch names. Use `__` as the delimiter (for example, `upgrade__makefile-to-justfile`) and avoid meaningless prefixes like `feat`.
- **Staging Files**: Never run `git add .`, `git add -A`, or `git add --all`. Always inspect `git status` and stage specific files by explicit path (`git add <file1> <file2>`). Never stage `.env` files or credentials.

---

## Common Commands (`justfile` & `uv`)

Prefer `just <recipe>` over calling the underlying tool directly. GitHub Actions CI executes these same recipes, and `just` loads `.env` (`set dotenv-load := true`) while a bare `uv run ...` does not.

`just --list` is the authoritative command catalog (`just --show <recipe>` inspects an individual recipe body; note that `just` has no per-recipe `--help` flag).

| Task | Command | Description |
| :--- | :--- | :--- |
| **List Recipes** | `just` or `just --list` | List all available `justfile` recipes |
| **Setup** | `just setup` | Initialize submodules, create `.env` files from templates, and sync `uv` environment |
| **Sync Deps** | `just sync` | Synchronize virtual environment (`.venv`) and dependency groups via `uv sync --all-groups` |
| **Run Tests** | `just test` | Run all unit and evaluation test suites via `pytest` |
| **Test Coverage** | `just test-cov` | Run `pytest` with terminal coverage report |
| **Format** | `just format` | Format code in-place with Ruff (`--fix`) and Pyink (2 spaces, 80 columns) |
| **Format Check** | `just format-check` | Verify Pyink formatting without modifying files |
| **Lint** | `just lint` | Run Pyink format check + Ruff linter checks |
| **Typecheck** | `just typecheck` | Run Google Pytype static type analysis across packages |
| **Full CI Gate** | `just check` | Run `lint`, `typecheck`, and `test-cov` (reproduces CI locally) |
| **Build Docs** | `just html` | Build Sphinx HTML documentation from `rules-bank/` into `build/html/` |
| **Run Manager** | `just run-manager` | Run the multi-agent Manager CLI interactively (`adk run manager`) |
| **Run Web UI** | `just web` | Launch the interactive ADK Web UI from `multi-agent/` |
| **Run DAC Agent** | `just run-dac` | Execute the Detection-as-Code (DAC) agent workflow |
| **Run Evals** | `just eval` | Run the declarative workflow evaluation suite (`core_workflows` by default) |
| **Clean** | `just clean` | Remove build artifacts, caches, and temporary coverage files |

---

## Architecture & Key Components

### Multi-Agent System Structure
- **Manager Agent** (`multi-agent/manager/`): Root orchestrator that triages requests and delegates to specialized sub-agents and deterministic graph workflows.
- **Sub-agents** (`multi-agent/manager/sub_agents/`):
  - **CTI Researcher** (`cti_researcher/`): Cyber threat intelligence gathering, GTI collections, and actor profiling.
  - **SOC Analyst Tier 1/2/3** (`soc_analyst_tier1/`, `soc_analyst_tier2/`, `soc_analyst_tier3/`): Alert triage, case investigation, timeline reconstruction, and escalation.
  - **Threat Hunter** (`threat_hunter/`): Proactive hypothesis-driven hunting across APT campaigns, IOCs, and TTPs.
  - **Incident Responder** (`incident_responder/`): Containment, eradication, endpoint isolation, and full IRP execution.
  - **Detection Engineer** (`detection_engineer/`): YARA-L 2.0 rule authoring, validation, and tuning.
  - **LLM Judge** (`llm_judge/`): Rubric-based procedural compliance assessment.
- **Detection-as-Code Agent** (`dac_agent/`): Standalone agent for detection rule lifecycle, validation, and tuning integrated with the Google Cloud SecOps 1P Agentic Detection Engineering MCP Server.

### Dual-Tier Progressive Disclosure Framework
1. **Tier 1 — Skills Progressive Disclosure (`skills/`)**:
   - Standardized `SKILL.md` packages organized across 8 taxonomy categories (`triage`, `irps`, `investigation`, `hunting`, `detection`, `reporting`, `atomic`, `common`).
   - `SkillRegistry` (`skills/registry.py`) indexes skill frontmatter (`name`, `description`, `category`, `version`) and injects a compact catalog via `load_persona_with_skills_catalog()`.
   - Agents call `load_skill(skill_name)` on demand before executing domain workflows or external tools.
2. **Tier 2 — Progressive MCP Tool Discovery (`mcp_registry.py`)**:
   - `MCPToolRegistry` (`multi-agent/manager/tools/mcp_registry.py` and `dac_agent/tools/mcp_registry.py`) replaces 30+ static JSON tool schemas with 3 lightweight meta-tools: `search_mcp_tools`, `get_mcp_tool_schema`, and `execute_mcp_tool`.
3. **Runtime Compliance Gates (`multi-agent/manager/tools/compliance_gates.py`)**:
   - Enforces progressive disclosure at runtime (`load_skill_gate`, `check_tool_preconditions`, `validate_report_gate`) so agents load the relevant runbook skill before invoking SIEM/SOAR/GTI tools and execute mandatory investigation tools before writing final reports.

### Evaluation, Simulation & AQuA Flywheel (`evals/`)
- `evals/datasets/`: Declarative benchmark manifests (`core_workflows.json`, `all_36_workflows.json`, `expanded_cases_alerts.json`, `production_regressions.json`).
- `evals/rubrics/`: 4 procedural rubrics (`triage_irp_rubric.py`, `threat_hunting_rubric.py`, `detection_rubric.py`, `reporting_rubric.py`) plus categorical release gates (`categorical_rubrics.py`).
- `evals/runner.py`: CLI benchmark runner (`just eval core_workflows --report`).
- `evals/simulate_sessions.py`: Multi-turn ADK `UserSimulator` evaluation runner across analyst personas (`NOVICE`, `EXPERT`, `EVALUATOR`).
- `evals/aqua_outer_loop.py` & `evals/aqua_diagnose.py`: Longitudinal Outer-Loop AQuA trace diagnostics over ADK SQLite session stores and OpenTelemetry JSONL spans.

---

## Configuration Requirements

1. Initialize environment files and dependencies:
   ```bash
   REPO_DIR="/path/to/adk_runbooks"
   cd "$REPO_DIR"
   just setup
   ```
2. Configure `.env` and `multi-agent/manager/.env`:
   ```bash
   GOOGLE_GENAI_USE_VERTEXAI=1
   GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
   GOOGLE_CLOUD_LOCATION="global"
   ```
3. Configure MCP Security tools in `external/mcp-security/.env`:
   ```bash
   CHRONICLE_PROJECT_ID="your-gcp-project-id"
   CHRONICLE_CUSTOMER_ID="your-chronicle-customer-id"
   CHRONICLE_REGION="us"
   SOAR_URL="https://your-soar-instance.siemplify-soar.com"
   SOAR_APP_KEY="your-soar-app-key"
   VT_APIKEY="your-virustotal-or-gti-api-key"
   ```
