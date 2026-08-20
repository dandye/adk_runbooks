---
type: Reference
title: "Design Specification: Converting Runbooks to Skills with Progressive Disclosure"
description: "Design specification for migrating monolithic runbooks into standard modular SKILL.md packages with 3-tier progressive disclosure."
generated:
  by: process:google-labs-jules
  at: 2026-08-20T02:00:00-04:00
related:
  - ../plans/2026-08-20-convert-runbooks-to-skills-progressive-disclosure.md
  - ../../skills_progressive_disclosure_overview.md
---

# Architecture Design: Converting Runbooks to Skills with Progressive Disclosure

- **Date:** 2026-08-20
- **Status:** Approved / In Review
- **Author:** Antigravity & dandye
- **Target Repository:** `adk_runbooks`

---

## 1. Overview & Problem Statement

In the current ADK Runbooks multi-agent architecture, each agent (SOC Manager and specialized sub-agents: T1, T2, T3, CTI, Threat Hunter, Incident Responder, Detection Engineer, LLM Judge) initializes by statically concatenating entire Markdown runbook files into its persona description / system prompt using `load_persona_and_runbooks()`.

### The Problem:
- **Massive Context Bloat:** Concatenating dozens of runbooks results in tens of thousands of prompt tokens per turn across 9+ agents, inflating latency and token cost.
- **Context Degradation & Hallucination:** Flooding the agent's context window with irrelevant procedures degrades compliance on the specific task at hand.
- **Tight Coupling & Poor Discoverability:** Adding or updating runbooks requires editing static file arrays in Python files across multiple sub-agents.

### The Solution:
Transform runbooks into standard **Skills** (`SKILL.md` format) and implement **Progressive Disclosure**:
1. **Level 1 (System Prompt Discovery):** Agents receive only a lightweight catalog of their relevant skills containing skill names and concise triggering conditions (`"Use when..."`).
2. **Level 2 (On-Demand Loading):** Agents dynamically invoke a `load_skill(skill_name)` tool to retrieve the complete procedure into working context when a relevant task or trigger is identified.
3. **Level 3 (Supporting Sub-Skills):** Any specialized atomic actions or common sub-procedures are loaded modularly on demand.

---

## 2. Goals & Non-Goals

### Goals
- **Standardized Skills Directory:** Migrate all runbooks from `rules-bank/run_books/` to a structured top-level `skills/` directory adhering to the standard `SKILL.md` specification.
- **Skill Discovery Optimization (SDO):** Ensure every `SKILL.md` has YAML frontmatter with `name`, `description` (triggering condition starting with `"Use when..."`), and `category`.
- **Progressive Disclosure Engine (`skills/registry.py`):** Build a centralized Python module to parse, validate, index, and load skills dynamically.
- **Agent Tool Integration:** Equip the SOC Manager and all sub-agents with `load_skill` and `list_available_skills` tools, replacing monolithic prompt concatenation with lightweight catalog injection.
- **Evals & Test Harness Compatibility:** Update eval datasets and test suites in `evals/` to reference new skill paths and evaluate dynamic skill activation.

### Non-Goals
- Modifying underlying MCP security servers (`external/mcp-security`).
- Altering the ADK framework core library (`google.adk`).

---

## 3. Directory Layout & Taxonomy

All runbooks will be structured under a clean, categorized `skills/` directory:

```text
skills/
├── __init__.py
├── registry.py                       # Central skill discovery & loading engine
├── triage/
│   ├── triage-alerts/
│   │   └── SKILL.md
│   ├── suspicious-login-triage/
│   │   └── SKILL.md
│   ├── malware-triage/
│   │   └── SKILL.md
│   ├── basic-endpoint-triage-isolation/
│   │   └── SKILL.md
│   └── cloud-vulnerability-triage/
│       └── SKILL.md
├── irps/
│   ├── compromised-user-account-response/
│   │   └── SKILL.md
│   ├── phishing-response/
│   │   └── SKILL.md
│   ├── ransomware-response/
│   │   └── SKILL.md
│   └── malware-incident-response/
│       └── SKILL.md
├── investigation/
│   ├── basic-ioc-enrichment/
│   │   └── SKILL.md
│   ├── deep-dive-ioc-analysis/
│   │   └── SKILL.md
│   ├── investigate-case-external-tools/
│   │   └── SKILL.md
│   ├── prioritize-and-investigate-case/
│   │   └── SKILL.md
│   ├── close-duplicate-cases/
│   │   └── SKILL.md
│   ├── group-cases/
│   │   └── SKILL.md
│   ├── case-event-timeline-analysis/
│   │   └── SKILL.md
│   ├── investigate-gti-collection/
│   │   └── SKILL.md
│   └── compare-gti-collection/
│       └── SKILL.md
├── hunting/
│   ├── advanced-threat-hunting/
│   │   └── SKILL.md
│   ├── apt-threat-hunt/
│   │   └── SKILL.md
│   ├── ioc-threat-hunt/
│   │   └── SKILL.md
│   ├── guided-ttp-hunt-credential-access/
│   │   └── SKILL.md
│   ├── lateral-movement-hunt-psexec-wmi/
│   │   └── SKILL.md
│   └── proactive-hunt-gti-campaign/
│       └── SKILL.md
├── detection/
│   ├── detection-rule-validation-tuning/
│   │   └── SKILL.md
│   ├── detection-as-code-workflows/
│   │   └── SKILL.md
│   └── detection-as-code-rule-tuning/
│       └── SKILL.md
├── reporting/
│   ├── create-investigation-report/
│   │   └── SKILL.md
│   ├── alert-report/
│   │   └── SKILL.md
│   ├── case-report/
│   │   └── SKILL.md
│   ├── detection-report/
│   │   └── SKILL.md
│   └── guidelines-report-writing/
│       └── SKILL.md
├── atomic/
│   ├── domain-lookup-gti/
│   │   └── SKILL.md
│   ├── domain-search-chronicle/
│   │   └── SKILL.md
│   ├── ip-lookup-gti/
│   │   └── SKILL.md
│   ├── ip-search-chronicle/
│   │   └── SKILL.md
│   ├── hash-lookup-gti/
│   │   └── SKILL.md
│   ├── hash-search-chronicle/
│   │   └── SKILL.md
│   ├── url-lookup-gti/
│   │   └── SKILL.md
│   ├── user-search-activity/
│   │   └── SKILL.md
│   └── ...
└── common/
    ├── check-duplicate-cases/
    │   └── SKILL.md
    ├── enrich-ioc/
    │   └── SKILL.md
    ├── find-relevant-soar-case/
    │   └── SKILL.md
    ├── document-in-soar/
    │   └── SKILL.md
    └── close-soar-artifact/
        └── SKILL.md
```

---

## 4. SKILL.md Structure & SDO Standards

Each converted skill follows standard YAML frontmatter and markdown sections:

```markdown
---
name: triage-alerts
description: Use when assessing incoming security alerts to determine whether to escalate as a potential threat or close as a false positive / duplicate.
category: triage
version: 1.0.0
---

# Alert Triage

## Objective
...

## Inputs & Outputs
...

## Required Tools
- `soar-mcp` tools...
- `secops-mcp` tools...
- `gti-mcp` tools...

## Workflow Steps & Diagrams
...

## Completion Criteria & Rubrics
...
```

### Skill Discovery Optimization (SDO) Rules:
- **`description`**: Always starts with `"Use when..."` and states the specific triggering symptoms, inputs, or operational conditions.
- **Conciseness**: Trigger descriptions remain under 200 characters so that the injected catalog in agent instructions stays ultra-lean.
- **Active Naming**: Kebab-case identifiers matching the folder name (`triage-alerts`, `suspicious-login-triage`, `ransomware-response`).

---

## 5. Progressive Disclosure Architecture & Mechanics

### Level 1: System Prompt Skill Catalog Injection
Instead of loading thousands of lines of markdown, the agent initialization helper builds a concise Markdown catalog:

```markdown
### Available Skills (Progressive Disclosure)
You have access to the following skills. When assigned a matching task or when a trigger condition is met, call the `load_skill(skill_name)` tool to retrieve complete step-by-step procedures before execution:

- **`triage-alerts`**: Use when assessing incoming security alerts to determine escalation or closure.
- **`suspicious-login-triage`**: Use when investigating unauthorized or anomalous user authentication activity.
- **`basic-ioc-enrichment`**: Use when performing initial reputation and context lookups on IPs, domains, or hashes.
- **`close-duplicate-cases`**: Use when identifying and closing duplicate or similar SOAR cases.
```

### Level 2: On-Demand Skill Execution via `load_skill`
Each agent has access to `load_skill`:

```python
def load_skill(skill_name: str) -> str:
    """Loads the full step-by-step instructions and guidance for a specified skill.

    Args:
        skill_name: The name or identifier of the skill (e.g. 'triage-alerts', 'suspicious-login-triage').

    Returns:
        The markdown instructions for the skill, or an error message if not found.
    """
    ...
```

When an agent needs to perform an action, it executes:
`load_skill(skill_name="suspicious-login-triage")`
and receives the exact workflow, diagrams, and rubrics into its active turn context.

---

## 6. Centralized Skill Registry (`skills/registry.py`)

A centralized registry handles indexing, caching, and retrieval:

```python
class SkillRegistry:
    def __init__(self, skills_dir: Path):
        self.skills_dir = skills_dir
        self._skills_cache: dict[str, SkillMetadata] = {}
        self.scan_skills()

    def scan_skills(self) -> None:
        """Discovers all SKILL.md files and parses YAML frontmatter."""
        ...

    def get_skill_catalog(self, skill_names: list[str] | None = None) -> str:
        """Generates formatted markdown summary of available skills for prompt injection."""
        ...

    def get_skill_content(self, skill_name: str) -> str:
        """Returns the full content of the requested SKILL.md."""
        ...
```

---

## 7. Multi-Agent System Updates

### Manager (`multi-agent/manager/agent.py`):
- Catalog contains all incident response plans (IRPs) and high-level workflow skills.
- Manager uses `load_skill` when coordinating IRP phases, and instructs sub-agents with clear delegated objectives.

### Sub-Agents (`multi-agent/manager/sub_agents/*`):
- Each sub-agent defines a concise list of skill IDs relevant to its persona (e.g., Tier 1: `["triage-alerts", "suspicious-login-triage", "basic-ioc-enrichment", "close-duplicate-cases", "group-cases"]`).
- Agent initialization uses `skill_registry.get_skill_catalog(persona_skills)` to construct its description.
- All sub-agents receive `load_skill` and `list_available_skills` in their tools tuple.

---

## 8. Evals & Documentation Updates

1. **Evals Dataset Migration:** Update `evals/datasets/*.json` to reference `skills/<category>/<skill_name>/SKILL.md` instead of `rules-bank/run_books/*.md`.
2. **Evaluators & Rubrics:** Update `evals/evaluators/` to verify that agents correctly invoke `load_skill` as part of their trajectory evaluation.
3. **Documentation:** Update `README.md`, `GEMINI.md`, and Sphinx docs in `docs/` to document the skills system.

---

## 9. Verification & Testing

1. **Unit Tests:**
   - `pytest` for `skills/registry.py` (verifying parsing of all frontmatters, catalog generation, and error handling).
   - Validation that every `SKILL.md` passes structural and YAML linting.
2. **Agent Smoke Tests:**
   - Verify agent initialization for Manager and all 8 sub-agents.
   - Verify `load_skill` tool execution for each skill.
3. **Eval Benchmark Suite:**
   - Run `evals/tests/test_all_36_workflows.py` and `evals/tests/test_core_benchmarks.py` to ensure complete passing scores.
