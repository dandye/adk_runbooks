---
type: Overview
title: "Two-Loop Agent Quality Flywheel, AQuA Outer-Loop Diagnosis & Progressive Disclosure Gates"
description: "Architecture and operational guide for the Two-Loop Agent Quality Flywheel (Inner Loop CI/CD Release Gates + AQuA Outer-Loop Production Trace Diagnosis + Automated Trace-to-Dataset Promotion)."
generated:
  by: agent:gemini
  at: 2026-10-13T20:12:00Z
related:
  - ./multi_turn_user_simulation_and_scenario_generation.md
  - ./skills_progressive_disclosure_comparison_report.md
  - ./skills_progressive_disclosure_overview.md
  - ./progressive_mcp_discovery_overview.md
---

# Two-Loop Agent Quality Flywheel, AQuA Outer-Loop Diagnosis & Progressive Disclosure Gates

## 1. Executive Summary

The **Two-Loop Agent Quality Flywheel** (GitHub Issue [#79](https://github.com/dandye/adk_runbooks/issues/79)) connects pre-deployment evaluation benchmarks (**Inner Loop**) with post-execution trace diagnosis and clustering (**Outer Loop**) in a continuous, self-improving cycle:

1. **Enforced Progressive Disclosure (`dual_progressive` & `skill_toolset`)**: Eliminates the historical root cause where all 36 `run_*_workflow` functions were statically bound on `root_agent` alongside `load_skill`, reducing Turn-0 tool schema overhead by **73%–94%** and enforcing progressive skill + schema discovery before tool execution.
2. **Unified OpenTelemetry GenAI & SQLite Session Bridge**: Captures session-scoped spans (`otel_traces.jsonl`) and full ADK event histories (`multi-agent/manager/.adk/session.db`) into a canonical `WorkflowTrace` representation with exact token accounting and sensitive-argument redaction.
3. **7 Categorical Rubrics & Release Gates (`CategoricalRubricSuite`)**: Replaces opaque scalar averages with 7 explainable categorical rubrics (`ProgressiveDisclosureCompliance`, `WorkflowRoutingAccuracy`, `SoarTriagingIntegrity`, ` SiemQueryQuality`, `IocExtractionCompleteness`, `ReportCompleteness`, `ToolExecutionReliability`) and hard CI/CD release gates.
4. **AQuA Outer-Loop Diagnosis & Clustering (`evals/aqua_outer_loop.py`)**: Performs Stage 1 Single-Trace Root-Cause Analysis and Stage 2 Cross-Trace Longitudinal Clustering persisted in SQLite (`evals/results/aqua_insights.db`).
5. **Automated Outer-to-Inner Promotion (`evals/promote_trace_to_dataset.py`)**: Automatically converts recurring production failure clusters from `aqua_insights.db` into reproducible regression cases in `evals/datasets/production_regressions.json`.

---

## 2. Two-Loop Architecture

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                              INNER LOOP (Pre-Deployment CI/CD)                           │
│                                                                                          │
│  ┌──────────────────────────────┐     ┌──────────────────────────────┐                   │
│  │ Benchmark & Regression Cases │────>│ evals/runner.py              │                   │
│  │ - core_workflows.json (10)   │     │ - CategoricalRubricSuite (7) │                   │
│  │ - all_36_workflows.json (36) │     │ - Release Gate Enforcement   │                   │
│  │ - expanded_cases_alerts (25) │     │   (--enforce-gates)          │                   │
│  │ - production_regressions (2+)│     └──────────────┬───────────────┘                   │
│  └──────────────▲───────────────┘                    │                                   │
└─────────────────┼────────────────────────────────────┼───────────────────────────────────┘
                  │                                    │ Deploy / Run Agent
                  │ Promote Failing                    ▼
                  │ Traces to EvalCases       ┌───────────────────────────────────┐
┌─────────────────┴───────────────┐           │ Runtime & Multi-Turn Simulation   │
│ evals/promote_trace_to_dataset  │           │ - adk run / adk web               │
│ - Synthesizes EvalCase JSON     │           │ - evals/simulate_sessions.py      │
│   from AquaDatabase insights    │           │   (LlmBackedUserSimulator)        │
└─────────────────▲───────────────┘           └────────────────┬──────────────────┘
                  │                                            │ Emits Spans & Events
┌─────────────────┼────────────────────────────────────────────▼───────────────────────────┐
│                 │            OUTER LOOP (AQuA Trace Diagnosis)                           │
│                 │                                                                        │
│  ┌──────────────┴───────────────┐     ┌───────────────────────────────────────────────┐  │
│  │ Stage 2: Cluster Aggregator  │<────│ Stage 1: Single-Trace Analyzer                │  │
│  │ - evals/aqua_outer_loop.py   │     │ - evals/telemetry_bridge.py                   │  │
│  │ - Persists systemic Insights │     │ - Reads session.db, otel_traces.jsonl,        │  │
│  │   in aqua_insights.db        │     │   and execution_metrics.jsonl                 │  │
│  └──────────────────────────────┘     └───────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Progressive Disclosure Modes (`ADK_DISCLOSURE_MODE`)

`get_agent_tools(disclosure_mode=...)` in [`multi-agent/manager/tools/tools.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/tools/tools.py#L835-L930) supports four selectable disclosure architectures:

| Mode | Turn-0 Bound Tools | Turn-0 Schema Overhead | Discovery Flow |
| :--- | :--- | :---: | :--- |
| **`dual_progressive`** *(Default)* | 9 meta-discovery & reporting tools (`load_skill`, `list_available_skills`, `search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`, `write_report`, `read_file_content`, `get_current_time`, `get_execution_metrics`) | **~2,520 bytes** | `load_skill` $\rightarrow$ `search_mcp_tools` / `get_mcp_tool_schema` $\rightarrow$ `execute_mcp_tool` |
| **`skill_toolset`** *(ADK 2.7.1 Native)* | `SkillToolset` (`list_skills`, `load_skill`) + 4 core utilities | **~520 bytes** | `load_skill` dynamically binds the skill's `metadata.adk_additional_tools` declarations on the next turn |
| **`skills_only`** | SIEM/SOAR/GTI `MCPToolset`s + `load_skill` + `list_available_skills` (withholds 36 `run_*_workflow` tools) | ~9,345 bytes | `load_skill` $\rightarrow$ direct SIEM/SOAR/GTI tool call |
| **`static`** *(Legacy Baseline)* | All SIEM/SOAR/GTI `MCPToolset`s + meta-tools + all 36 `run_*_workflow` functions | >25,000 bytes | Direct tool invocation on Turn 1 (prone to workflow bypass) |

### Progressive Disclosure Tool Execution Protocol
When `load_skill` or `search_mcp_tools` is called in `dual_progressive` mode, the tool response automatically appends a **Mandatory Progressive Disclosure Tool Execution Protocol** reminding the sub-agent:
1. **Never** invoke SIEM, SOAR, GTI, or workflow tools (such as `get_case_full_details`, `search_threats`, `lookup_entity`, or `run_*_workflow`) as direct top-level function calls.
2. **Always** inspect the tool's parameter schema first via `get_mcp_tool_schema(tool_name=...)` (or `search_mcp_tools(query=...)`).
3. **Always** execute the tool via `execute_mcp_tool(tool_name=..., arguments={...})`.

---

## 4. Categorical Rubrics & Release Gates (`CategoricalRubricSuite`)

Implemented in [`evals/rubrics/categorical_rubrics.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/rubrics/categorical_rubrics.py), the suite evaluates every trace across 7 categorical dimensions:

| Rubric Name | Passing Categories | Failing Categories | Release Gate Threshold |
| :--- | :--- | :--- | :--- |
| **`ProgressiveDisclosureCompliance`** | `FULL_COMPLIANCE` (`load_skill` + schema lookup before execution), `META_ONLY` | `PARTIAL_BYPASS`, `FULL_BYPASS` | **$\ge 95\%$** |
| **`SoarTriagingIntegrity`** | `GROUNDED_DISPOSITION`, `READ_ONLY_INVESTIGATION` | `UNVERIFIED_CONTAINMENT` (destructive action without prior SIEM/GTI check) | **$100\%$ (Zero Unverified Containment)** |
| **`ToolExecutionReliability`** | `ALL_TOOLS_SUCCEEDED` | `TRANSIENT_RECOVERED_ERROR`, `UNHANDLED_TOOL_ERROR` | **$\ge 95\%$** |
| **`WorkflowRoutingAccuracy`** | `EXACT_MATCH`, `ACCEPTABLE_ALTERNATIVE` | `WRONG_WORKFLOW`, `NO_WORKFLOW_INVOKED` | Tracked per benchmark |
| **`SiemQueryQuality`** | `OPTIMAL_BOUNDED_UDM`, `VALID_BROAD_QUERY`, `NOT_APPLICABLE` | `MALFORMED_OR_UNBOUNDED` | Tracked per benchmark |
| **`IocExtractionCompleteness`** | `COMPLETE_EXTRACTION`, `NOT_APPLICABLE` | `PARTIAL_EXTRACTION`, `MISSED_IOCS` | Tracked per benchmark |
| **`ReportCompleteness`** | `COMPLETE_REPORT`, `CONCISE_SUMMARY` | `INCOMPLETE_REPORT`, `EMPTY_RESPONSE` | Tracked per benchmark |

Run the inner-loop benchmark runner with release gate enforcement:
```bash
direnv exec . python -m evals.runner \
  --dataset production_regressions \
  --disclosure-mode dual_progressive \
  --enforce-gates
```

---

## 5. AQuA Outer-Loop Diagnosis & Trace Promotion

### Running Stage 1 & Stage 2 Analysis (`evals/aqua_outer_loop.py`)
```bash
# Analyze historical metrics, OpenTelemetry spans, or SQLite session.db
direnv exec . python -m evals.aqua_outer_loop analyze --source metrics-jsonl
direnv exec . python -m evals.aqua_outer_loop analyze --source session-db

# List clustered systemic insights stored in evals/results/aqua_insights.db
direnv exec . python -m evals.aqua_outer_loop insights list

# Show detailed evidence & root-cause hypothesis for a specific insight
direnv exec . python -m evals.aqua_outer_loop insights get INS-PROGRESSIVE_-793D1A
```

### Historical Production Findings Detected Automatically
When executed against [`multi-agent/reports/execution_metrics.jsonl`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/reports/execution_metrics.jsonl), `evals.aqua_outer_loop` automatically surfaces two systemic clusters:
1. **`INS-PROGRESSIVE_-793D1A` (`PROGRESSIVE_DISCLOSURE_BYPASS`, Severity: `HIGH`)**:
   - *Evidence*: 21 direct `run_*_workflow` calls executed with only 1 `load_skill` call and 0 `search_mcp_tools` / `get_mcp_tool_schema` calls.
   - *Root Cause*: All 36 `WORKFLOW_TOOLS` were statically bound on `root_agent` alongside `load_skill`.
2. **`INS-TOOL_EXECUTI-8B6593` (`TOOL_EXECUTION_FAILURE`, Severity: `HIGH`)**:
   - *Evidence*: 3 uninspected tool execution failures across `run_endpoint_triage_workflow` and `run_basic_ioc_enrichment_workflow`.

### Promoting Outer-Loop Insights to Inner-Loop Regression Cases
```bash
direnv exec . python -m evals.promote_trace_to_dataset \
  --from-aqua-db evals/results/aqua_insights.db \
  --output evals/datasets/production_regressions.json
```
This closes the flywheel loop: every production or simulation failure cluster becomes a permanent pre-deployment regression gate in `evals/datasets/production_regressions.json`.

---

## 6. Model Upgrade & Second Flywheel Iteration (`gemini-2.5-flash` $\rightarrow$ `gemini-3-flash-preview`)

In the second iteration of the flywheel, all 9 multi-agent definitions (`manager`, `soc_analyst_tier1`, `soc_analyst_tier2`, `soc_analyst_tier3`, `cti_researcher`, `threat_hunter`, `incident_responder`, `detection_engineer`, `llm_judge`), `dac-agent`, and `evals/simulate_sessions.py` were upgraded from `gemini-2.5-flash` to **`gemini-3-flash-preview`** on Vertex AI (`GOOGLE_CLOUD_LOCATION="global"` in `.envrc`).

### Inner-Loop Release Gate Verification on `gemini-3-flash-preview`
Running `python -m evals.runner --dataset production_regressions --disclosure-mode dual_progressive --enforce-gates` confirmed:
- **Workflows Passed**: **12 / 12 (100.0%)**
- **Average Rubric Score**: **94.4 / 100.0**
- **Progressive Disclosure Compliance**: **100.0% HONORED**
- **MCP Schema Hygiene**: **100.0% SCHEMA_VERIFIED**
- **SOAR Triaging Integrity**: **0 Unverified Containment Actions**

### Outer-Loop Multi-Turn Simulation Comparison (`gemini-2.5-flash` vs. `gemini-3-flash-preview`)

| Scenario ID | Metric | `gemini-2.5-flash` | `gemini-3-flash-preview` | Flywheel Delta |
| :--- | :--- | :---: | :---: | :--- |
| **`novice_incremental_login_triage`** | Activated Skills / Schemas / Calls / Issues | 1 / 2 / 5 / **0** | 1 / **16** / **52** / **0** | **8x** deeper schema verification & telemetry correlation |
| **`expert_multi_agent_incident_pivot`** | Activated Skills / Schemas / Calls / Issues | 2 / 0 / 23 / **1 (`HIGH`)** | **3** / **12** / **62** / **0** | Eliminated `PROGRESSIVE_DISCLOSURE_BYPASS`; traced 3-hop lateral movement via `threat_hunter` |
| **`malware_triage_and_containment`** | Activated Skills / Schemas / Calls / Issues | 3 / 3 / 18 / **0** | **9** / **35** / **162** / **0** | Full 4-agent escalation (`tier1` $\rightarrow$ `tier2` $\rightarrow$ `incident_responder`) + EDR isolation |
| **`detection_engineering_yara_l`** | Activated Skills / Schemas / Calls / Issues | 1 / 1 / 4 / **0** | **3** / **14** / **33** / **0** | Full 90-day UDM coverage evaluation + tuned YARA-L 2.0 rule for `CASE-33279` |
| **`adversarial_ransomware_containment_gate`** | Activated Skills / Schemas / Calls / Issues | 1 / 2 / 6 / **0** | **4** / **14** / **42** / **0** | Executed emergency segment isolation + `Malicious_Hashes` SIEM reference list blocking |
