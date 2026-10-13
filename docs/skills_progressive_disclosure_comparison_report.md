---
type: Report
title: "Skills Progressive Disclosure Architecture: Comparative Analysis & Benchmark Report"
description: "Comparative benchmark report measuring prompt character reduction, evaluation pass rates, and performance across 62 standardized skills."
generated:
  by: human:dandye
  at: 2026-08-20T04:00:00-04:00
related:
  - ./skills_progressive_disclosure_overview.md
  - ./adk_graph_workflows_overview.md
  - ./two_loop_agent_quality_flywheel_overview.md
  - ./multi_turn_user_simulation_and_scenario_generation.md
---

# Skills Progressive Disclosure Architecture: Comparative Analysis & Benchmark Report

## Executive Summary

This report evaluates the transformation of the **ADK Runbooks** multi-agent cybersecurity operations platform from a monolithic, static prompt-concatenation model into a modular, on-demand **Skills & Progressive Disclosure Framework**.

The refactoring achieves:
1. **~85% Reduction in Initial Prompt Token Overhead** per agent turn across all 9 agents.
2. **100% Evaluation Benchmark Pass Rate** maintained across all 3 benchmark suites (71 total evaluation cases).
3. **Strict SDO & Frontmatter Compliance** across all 62 modular security skills.
4. **Decoupled Architecture** allowing dynamic skill addition and runtime discovery without hardcoded Python array maintenance.

---

## 1. Architectural Comparison: Before vs. After

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ BEFORE: Monolithic Prompt Concatenation                                                 │
│                                                                                         │
│  Agent Startup:                                                                         │
│  ┌───────────────────────┐                                                              │
│  │ Persona Markdown      │                                                              │
│  │ + 10-20 Full Runbooks │ ───> [ System Prompt / Description: 50,000+ characters ]    │
│  └───────────────────────┘           │                                                  │
│                                      ▼                                                  │
│                        Every turn carries full text of all runbooks                     │
│                        (High latency, high token cost, attention dilution)              │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ AFTER: 3-Tier Progressive Disclosure Framework                                          │
│                                                                                         │
│  Level 1: System Prompt (Discovery Catalog)                                             │
│  ┌────────────────────────────────────────┐                                             │
│  │ Persona + Injected Skills Catalog      │ ───> [ Lean Description: 3k-8k chars ]      │
│  │ (- skill-name: "Use when ...")         │           │                                 │
│  └────────────────────────────────────────┘           │                                 │
│                                                       │ Matches task trigger            │
│  Level 2: On-Demand Tool Activation                   ▼                                 │
│  ┌────────────────────────────────────────┐                                             │
│  │ Agent calls `load_skill("skill-name")` │ ───> Fetches full SKILL.md into context     │
│  │                                        │      only when needed                       │
│  └────────────────────────────────────────┘           │                                 │
│                                                       │ References sub-procedure        │
│  Level 3: Supporting Sub-Skills / Atomic References   ▼                                 │
│  ┌────────────────────────────────────────┐                                             │
│  │ Agent calls `load_skill("atomic-...")` │ ───> Modular atomic lookup / common step    │
│  └────────────────────────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Quantitative System Metrics Comparison

| Metric / Dimension | Before Refactor (Prompt Concatenation) | After Refactor (Progressive Disclosure) | Impact / Delta |
| :--- | :---: | :---: | :---: |
| **Agent Prompt Length (Manager)** | ~52,400 chars | ~10,300 chars | **-80.3%** |
| **Agent Prompt Length (Tier 1)** | ~48,900 chars | ~4,800 chars | **-90.2%** |
| **Agent Prompt Length (Threat Hunter)** | ~45,200 chars | ~4,900 chars | **-89.1%** |
| **Agent Prompt Length (Detection Eng)** | ~38,700 chars | ~3,100 chars | **-92.0%** |
| **Total Standardized Skills** | 0 (Unstructured runbooks) | **62 standard `SKILL.md` packages** | **+62 modular packages** |
| **YAML Frontmatter SDO Coverage** | 0% | **100% (62/62 skills)** | **100% SDO compliant** |
| **Dynamic Skill Discovery Tools** | None (Static file arrays) | `load_skill`, `list_available_skills` | **Fully dynamic** |

---

## 3. Evaluation Benchmark Suite Results

All evaluation benchmarks were executed against the updated skills repository:

### Benchmark 1: Core Workflows (`evals/datasets/core_workflows.json`)
- **Status:** **10/10 Passed (100.0%)**
- **Average Rubric Score:** **95.5 / 100.0**
- **Tested Workflows:** Suspicious Login Triage (Low/High), Malware Triage, Basic IOC Enrichment, Endpoint Triage, IOC Containment, Case Report, Alert Report, Compromised User IRP, Detection Rule Validation.

### Benchmark 2: All 36 Workflows (`evals/datasets/all_36_workflows.json`)
- **Status:** **36/36 Passed (100.0%)**
- **Average Rubric Score:** **89.7 / 100.0**
- **Tested Categories:** Triage (15), Incident Response Plans (4), Threat Hunting (6), Detection Engineering (3), Reporting (5), Case Management (3).

### Benchmark 3: Expanded Cases & Alerts (`evals/datasets/expanded_cases_alerts.json`)
- **Status:** **25/25 Passed (100.0%)**
- **Average Rubric Score:** **90.6 / 100.0**
- **Tested Threat Scenarios:** AvosLocker, Lokibot, DarkGate, Cobalt Strike, Lateral Movement (PsExec/WMI), UEBA Data Exfiltration, and SOC Case Closures.

---

## 4. Test Suite Summary

```
============================= test session starts ==============================
platform linux -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
collected 52 items

tests/test_agents_initialization.py (9 tests) ......................... PASSED
tests/test_all_skills_validity.py (3 tests) ........................... PASSED
tests/test_dac_agent_initialization.py (4 tests) ...................... PASSED
tests/test_skill_registry.py (6 tests) ................................ PASSED
tests/test_skill_tools.py (5 tests) ................................... PASSED
evals/tests/test_all_36_workflows.py (1 test) ......................... PASSED
evals/tests/test_core_benchmarks.py (1 test) .......................... PASSED
evals/tests/test_datasets.py (3 tests) ................................ PASSED
evals/tests/test_eval_harness.py (5 tests) ............................ PASSED
evals/tests/test_evaluators.py (5 tests) .............................. PASSED
evals/tests/test_expanded_cases_alerts.py (1 test) .................... PASSED
evals/tests/test_registry.py (5 tests) ................................ PASSED
evals/tests/test_rubrics.py (4 tests) ................................. PASSED

============= 52 passed, 38 warnings, 71 subtests passed in 4.28s ==============
```

---

## 5. Summary of Copied Artifacts from Sibling Worktrees

The following prior evaluation reports and cross-experiment comparative benchmarks were copied from sibling worktrees into this worktree for direct comparison:
- [`report.md`](file://report.md): Master Evaluation & Grading Scorecard across multi-agent security experiments.
- [`TEST_PLAN.md`](file://TEST_PLAN.md): Multi-Agent security evaluation test plan.
- [`presentation/adk_graph_workflows_slide_deck.md`](file://presentation/adk_graph_workflows_slide_deck.md): Slide deck covering graph workflows vs autonomous loop paradigms.
- [`multi-agent/reports/`](file://multi-agent/reports/): 3-way benchmarks, graph vs non-graph case studies, and telemetry stats files.
- [`evals/results/`](file://evals/results/): JSON and Markdown evaluation results across prior runs.

---

## 6. 6-Way Paradigm Comparison & Two-Loop Flywheel Evaluation (Issue #79)

In GitHub Issue [#79](https://github.com/dandye/adk_runbooks/issues/79), the evaluation harness was extended to a **6-Way Paradigm Comparison** ([`evals/run_cross_experiment_benchmarks.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/run_cross_experiment_benchmarks.py)) and paired with the **Two-Loop Agent Quality Flywheel** and **Multi-Turn ADK User Simulator** ([`evals/simulate_sessions.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/simulate_sessions.py)):

| Paradigm | Turn-0 Tool Schema Bytes | Turn-1 Tool Schema Bytes | Discovery Steps | Avg Rubric Score (Exp 1, 2, 5, 6) | Progressive Disclosure Compliance |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Version A: Prompt-Only (Unguided Loop)** | ~9,345 B | ~9,345 B | 0 | 64.5 / 100 | N/A |
| **Version B: Monolithic Runbooks** | ~9,345 B | ~9,345 B | 0 | 79.8 / 100 | N/A |
| **Version C: ADK Graph Workflows (Static DAGs)** | >25,000 B | >25,000 B | 0 | 95.3 / 100 | Bypassed (`FULL_BYPASS` when static) |
| **Version D: Skills Progressive Disclosure (`skills_only`)** | ~9,345 B | ~9,345 B | 1 (`load_skill`) | 91.5 / 100 | Partial (`load_skill` only) |
| **Version E: Dual Progressive Disclosure (`dual_progressive`)** | **2,520 B (-73.0%)** | **2,758 B** | 3 (`load_skill` $\rightarrow$ `get_mcp_tool_schema` $\rightarrow$ `execute_mcp_tool`) | **94.8 / 100** | **100% (`FULL_COMPLIANCE`)** |
| **Version F: Native ADK 2.7.1 `SkillToolset` (`skill_toolset`)** | **520 B (-94.4%)** | **1,341 B** | 2 (`load_skill` auto-binds `adk_additional_tools`) | **95.5 / 100** | **100% (`FULL_COMPLIANCE`)** |

For detailed documentation on the Two-Loop Flywheel and Multi-Turn User Simulation, see:
- [`docs/two_loop_agent_quality_flywheel_overview.md`](./two_loop_agent_quality_flywheel_overview.md)
- [`docs/multi_turn_user_simulation_and_scenario_generation.md`](./multi_turn_user_simulation_and_scenario_generation.md)

