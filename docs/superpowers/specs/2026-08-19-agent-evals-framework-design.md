# ADK Runbooks: Agent Workflows Evaluation & Rubric Framework Design

**Date:** 2026-08-19  
**Status:** Approved  
**Author:** Dandye / Jetski Pair Programming  
**Reference:** [GitHub Issue #68 - Add evals to graph-based agent workflows](https://github.com/dandye/adk_runbooks/issues/68)

---

## 1. Overview & Problem Statement

ADK Runbooks provides 36+ security operations agent graph workflows (e.g., Suspicious Login Triage, Malware Incident Response, Compromised User Account IRP, Threat Hunting). While each runbook in [`rules-bank/run_books/`](../../rules-bank/run_books/) contains formal evaluation rubrics (0–100 points scale), the repository lacked an automated, declarative evaluation harness to:
1. Systematically execute and regression-test all 36 graph workflows.
2. Verify node routing determinism and execution trajectory paths.
3. Validate output payload schema conformance and extraction accuracy.
4. Programmatically grade workflow outputs against the official runbook rubric profiles (Reporting, Incident Response/Triage, Detection Engineering).
5. Produce standardized benchmark execution reports with latency and token telemetry.

This design implements the declarative evaluation conventions outlined in Issue #68, adopting a Python/Pytest-native architecture with structured dataset manifests.

---

## 2. Directory Architecture

The evaluation framework resides at the repository root in the `evals/` directory:

```text
evals/
├── README.md                          # Usage instructions, CLI reference, adding test cases
├── __init__.py                        # Top-level module exports
├── runner.py                          # CLI runner: python -m evals.runner
├── datasets/                          # Declarative test datasets (JSON/YAML)
│   ├── all_36_workflows.json          # Golden test cases for all 36 graph workflows
│   ├── core_workflows.json            # Focused benchmark cases (Suspicious Login, Malware, IRP, etc.)
│   └── custom_cases/                  # User-defined custom test cases
├── rubrics/                           # Rubric models & scoring engines from rules-bank/
│   ├── __init__.py
│   ├── base.py                        # RubricCriteria, RubricScorecard base classes
│   ├── reporting_rubric.py            # 100 pt Reporting Rubric (Data Collection, Generation, Quality, Delivery, Artifacts)
│   ├── triage_irp_rubric.py           # 100 pt Triage/Response Rubric (Enrichment, Analysis, Action, Documentation, Artifacts)
│   └── detection_rubric.py            # 100 pt Detection Rubric (Requirement, Implementation, Validation, Git, Artifacts)
├── evaluators/                        # Evaluator engines
│   ├── __init__.py
│   ├── base.py                        # EvaluationResult, MetricResult dataclasses
│   ├── trajectory_evaluator.py        # Validates node sequences, routing decisions, and branch selection
│   ├── schema_evaluator.py            # Validates input/output typing and required fields
│   ├── rubric_evaluator.py            # Automated scorecard computation against runbook rubrics
│   └── benchmark_evaluator.py         # Comparative benchmark generator (JSON + Markdown reports)
├── tests/                             # Pytest test suite
│   ├── __init__.py
│   ├── conftest.py                    # Test fixtures, workflow registry loaders
│   ├── test_eval_harness.py           # Unit tests for evaluators and rubric engines
│   ├── test_core_benchmarks.py        # Pytest execution for core security scenarios
│   └── test_all_36_workflows.py       # Full regression test suite across all 36 graph workflows
└── results/                           # Generated evaluation results, scorecard JSONs, and markdown summaries
```

---

## 3. Core Component Specifications

### 3.1. Workflow Registry (`evals/registry.py`)
Provides dynamic resolution and execution of all 36 graph workflows in `multi-agent/manager/workflows/`. For each workflow:
* `name`: Standard snake_case workflow identifier (e.g. `suspicious_login_workflow`).
* `input_class`: The dataclass / Pydantic model for workflow payload inputs (e.g. `SuspiciousLoginInput`).
* `builder_func`: The workflow factory function (e.g. `build_suspicious_login_workflow`).
* `rubric_type`: Corresponding rubric profile (`REPORTING`, `TRIAGE_IRP`, `DETECTION_ENGINEERING`).
* `runbook_file`: Relative path to the markdown runbook in `rules-bank/run_books/`.

### 3.2. Dataset Manifests (`evals/datasets/`)
Test cases are stored as declarative JSON/YAML records:
```json
{
  "test_id": "TEST-SUSP-LOGIN-001",
  "workflow_name": "suspicious_login_workflow",
  "runbook_reference": "rules-bank/run_books/suspicious_login_triage.md",
  "rubric_type": "TRIAGE_IRP",
  "input": {
    "case_id": "CASE-1001",
    "user_id": "alice.smith@example.com",
    "source_ip": "192.168.1.50",
    "hostname": "corp-laptop-alice"
  },
  "expected": {
    "expected_route": "LOW_RISK_BENIGN",
    "required_output_fields": ["action_taken", "soar_comment"],
    "required_comment_substrings": ["Low risk", "Closed"]
  },
  "min_passing_score": 85.0
}
```

### 3.3. Rubric Evaluation Profiles (`evals/rubrics/`)
Implements the 3 rubric frameworks defined in `rules-bank/run_books/`:

1. **Reporting Rubric (100 Points)**:
   * Data Collection (25 pts): Verification that required alerts, metrics, and case telemetry were ingested.
   * Report Generation (30 pts): 15 pts template structure + 15 pts mandatory sections.
   * Quality & Clarity (15 pts): Non-empty, coherent, error-free synthesis.
   * Delivery (15 pts): Output persistence / delivery verification.
   * Operational Artifacts (15 pts): Sequence diagram (5 pts), execution metadata (5 pts), summary (5 pts).

2. **Triage & Incident Response Rubric (100 Points)**:
   * Context & Enrichment (25 pts): 10 pts entity extraction + 15 pts enrichment context.
   * Analysis & Decision (25 pts): 15 pts correct interpretation + 10 pts logical conclusion/route.
   * Action Execution (20 pts): 10 pts correct response action + 10 pts action verification.
   * Documentation (15 pts): 15 pts comprehensive SOAR comment and case updates.
   * Operational Artifacts (15 pts): Sequence diagram (5 pts), execution metadata (5 pts), summary (5 pts).

3. **Detection Engineering Rubric (100 Points)**:
   * Requirement Analysis (20 pts): Target rule / scope identification.
   * Technical Implementation (30 pts): 15 pts YARA-L syntax validity + 15 pts logic alignment.
   * Validation & Testing (20 pts): 20 pts historical telemetry testing and FP rate calculation.
   * Git/Process Compliance (15 pts): 15 pts deployment decision and review recommendations.
   * Operational Artifacts (15 pts): Sequence diagram (5 pts), execution metadata (5 pts), summary (5 pts).

### 3.4. Evaluator Engine (`evals/evaluators/`)
* **TrajectoryEvaluator**: Compares actual graph node path and routing decision against golden reference.
* **SchemaEvaluator**: Validates field presence, types, and non-null values on input and output payloads.
* **RubricEvaluator**: Computes itemized subscores and total score (0–100 scale), awarding points objectively based on output content analysis and execution trace.
* **BenchmarkEvaluator**: Generates Markdown comparison tables and `.stats.json` sidecars compatible with previous experiment reports.

### 3.5. CLI Runner & Pytest Integration
* **CLI Runner (`evals/runner.py`)**:
  ```bash
  python -m evals.runner --dataset all_36_workflows
  python -m evals.runner --workflow suspicious_login_workflow --report
  ```
* **Pytest Runner (`evals/tests/`)**:
  ```bash
  pytest evals/tests/
  pytest evals/tests/test_all_36_workflows.py -v
  ```

---

## 4. Error Handling & Portability
* Path resolution uses `pathlib.Path` relative to repository root (`Path(__file__).parents[...]`), maintaining multi-worktree portability.
* Evaluators handle graceful degradation if external MCP tools or network connections are offline, running in mock/deterministic unit test mode.
* Output files in `evals/results/` are timestamped and git-ignored by default, with sample golden reports tracked in documentation.

---

## 5. Verification & Testing Plan
1. Run evaluator unit tests: `pytest evals/tests/test_eval_harness.py`.
2. Run core benchmark tests: `pytest evals/tests/test_core_benchmarks.py`.
3. Run full regression suite across all 36 workflows: `pytest evals/tests/test_all_36_workflows.py`.
4. Run CLI runner to generate JSON scorecard and Markdown summary in `evals/results/`.
