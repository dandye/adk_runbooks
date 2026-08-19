# Agent Workflows Evaluation & Rubric Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a comprehensive, declarative evaluation harness (`evals/`) for all 36 ADK graph workflows in `adk_runbooks`, supporting trajectory verification, schema validation, runbook rubric scoring (0-100 pts), and automated benchmark generation.

**Architecture:** Python/Pytest-native architecture with declarative JSON/YAML dataset registries in `evals/datasets/`, programmatic rubric scoring engines in `evals/rubrics/` derived from `rules-bank/run_books/`, unified workflow registry mapping in `evals/registry.py`, evaluator engines in `evals/evaluators/`, and both CLI (`evals/runner.py`) and pytest (`evals/tests/`) execution modes.

**Tech Stack:** Python 3.11+, Pytest, Pydantic/Dataclasses, Google ADK 2.x, JSON/JSONL serialization.

**Spec:** [`docs/superpowers/specs/2026-08-19-agent-evals-framework-design.md`](../specs/2026-08-19-agent-evals-framework-design.md)

## Global Constraints
- Target workspace directory: `/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/graph_v00001`
- Multi-worktree portability: Use `pathlib.Path(__file__).parents[...]` for relative file references; never hardcode machine-specific paths.
- Zero mandatory external network dependencies during local test execution: Evaluators must operate deterministically.
- Rubric criteria must match `rules-bank/run_books/` 100-point scales (Reporting, Triage/IRP, Detection Engineering).

---

### Task 1: Core Evaluation Data Models & Rubric Profiles

**Files:**
- Create: `evals/__init__.py`
- Create: `evals/evaluators/base.py`
- Create: `evals/rubrics/__init__.py`
- Create: `evals/rubrics/base.py`
- Create: `evals/rubrics/reporting_rubric.py`
- Create: `evals/rubrics/triage_irp_rubric.py`
- Create: `evals/rubrics/detection_rubric.py`
- Test: `evals/tests/test_rubrics.py`

**Interfaces:**
- Produces:
  - `MetricResult(name: str, score: float, max_score: float, passed: bool, reason: str)`
  - `EvaluationResult(test_id: str, workflow_name: str, passed: bool, total_score: float, max_score: float, metrics: dict[str, MetricResult], duration_seconds: float, error: str | None)`
  - `RubricScorecard(profile_name: str, total_score: float, max_score: float, passed: bool, category_scores: dict[str, float], feedback: list[str])`
  - `ReportingRubric.evaluate(output_data: dict, trace: dict) -> RubricScorecard`
  - `TriageIRPRubric.evaluate(output_data: dict, trace: dict) -> RubricScorecard`
  - `DetectionRubric.evaluate(output_data: dict, trace: dict) -> RubricScorecard`

- [ ] **Step 1: Write test for rubric models and score calculations**

```python
# evals/tests/test_rubrics.py
import pytest
from evals.rubrics.reporting_rubric import ReportingRubric
from evals.rubrics.triage_irp_rubric import TriageIRPRubric
from evals.rubrics.detection_rubric import DetectionRubric

def test_reporting_rubric_evaluation():
    output = {
        "report_markdown": "# Case Report\n\n## 1. Executive Summary\nAnalysis summary.\n\n## 2. Details\nAlert details.",
        "soar_comment": "Case report generated.",
        "has_sequence_diagram": True,
        "execution_metadata": {"tokens": 1200, "duration": 0.5},
    }
    scorecard = ReportingRubric.evaluate(output)
    assert scorecard.total_score >= 85.0
    assert scorecard.passed is True
    assert "Data Collection" in scorecard.category_scores

def test_triage_irp_rubric_evaluation():
    output = {
        "user_id": "alex.kim@example.com",
        "source_ip": "146.70.171.55",
        "action_taken": "Sessions terminated and password reset.",
        "soar_comment": "Containment action documented in SOAR.",
        "enrichment_summary": "Proxy IP detected.",
    }
    scorecard = TriageIRPRubric.evaluate(output)
    assert scorecard.total_score >= 80.0
    assert "Analysis & Decision" in scorecard.category_scores

def test_detection_rubric_evaluation():
    output = {
        "rule_id": "ru_12345",
        "compilation_status": "PASSED",
        "historical_detections": 10,
        "false_positive_rate": 0.02,
        "recommendation": "DEPLOY_PRODUCTION",
    }
    scorecard = DetectionRubric.evaluate(output)
    assert scorecard.total_score >= 85.0
    assert "Technical Implementation" in scorecard.category_scores
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest evals/tests/test_rubrics.py -v`  
Expected: FAIL (No module named `evals`)

- [ ] **Step 3: Implement `evals/evaluators/base.py` and `evals/rubrics/`**

Implement `base.py` data models and `reporting_rubric.py`, `triage_irp_rubric.py`, and `detection_rubric.py` with itemized scoring logic derived from `rules-bank/run_books/`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest evals/tests/test_rubrics.py -v`  
Expected: PASS

---

### Task 2: Workflow Registry & Graph Workflow Adapter

**Files:**
- Create: `evals/registry.py`
- Test: `evals/tests/test_registry.py`

**Interfaces:**
- Consumes: `multi-agent/manager/workflows/*.py`
- Produces:
  - `WorkflowDefinition(name: str, input_cls: type, builder_func: callable, rubric_type: str, runbook_path: str)`
  - `WORKFLOW_REGISTRY: dict[str, WorkflowDefinition]` covering all 36 workflows
  - `get_workflow_definition(name: str) -> WorkflowDefinition`
  - `execute_workflow_sync(workflow_name: str, input_data: dict) -> tuple[Any, dict]`

- [ ] **Step 1: Write test for workflow registry resolution and execution**

```python
# evals/tests/test_registry.py
import pytest
from evals.registry import WORKFLOW_REGISTRY, get_workflow_definition, execute_workflow_sync

def test_registry_contains_all_36_workflows():
    assert len(WORKFLOW_REGISTRY) >= 36
    assert "suspicious_login_workflow" in WORKFLOW_REGISTRY
    assert "malware_triage_workflow" in WORKFLOW_REGISTRY
    assert "alert_report_workflow" in WORKFLOW_REGISTRY
    assert "compromised_user_irp_workflow" in WORKFLOW_REGISTRY

def test_execute_suspicious_login_sync():
    wf_def = get_workflow_definition("suspicious_login_workflow")
    assert wf_def is not None
    result, trace = execute_workflow_sync(
        "suspicious_login_workflow",
        {"case_id": "CASE-TEST-1", "user_id": "alice.smith@example.com", "source_ip": "192.168.1.50"}
    )
    assert result is not None
    assert hasattr(result, "soar_comment")
    assert "executed_nodes" in trace
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest evals/tests/test_registry.py -v`  
Expected: FAIL

- [ ] **Step 3: Implement `evals/registry.py`**

Import and register all 36 workflows from `multi-agent/manager/workflows/`, attaching their input dataclasses, rubric profile mappings, and deterministic step-by-step execution adapter `execute_workflow_sync`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest evals/tests/test_registry.py -v`  
Expected: PASS

---

### Task 3: Evaluator Engines (Trajectory, Schema, Rubric, Benchmark)

**Files:**
- Create: `evals/evaluators/__init__.py`
- Create: `evals/evaluators/trajectory_evaluator.py`
- Create: `evals/evaluators/schema_evaluator.py`
- Create: `evals/evaluators/rubric_evaluator.py`
- Create: `evals/evaluators/benchmark_evaluator.py`
- Test: `evals/tests/test_evaluators.py`

**Interfaces:**
- Produces:
  - `TrajectoryEvaluator.evaluate(actual_trace: dict, expected_trace: dict) -> MetricResult`
  - `SchemaEvaluator.evaluate(actual_output: dict, expected_fields: list[str]) -> MetricResult`
  - `RubricEvaluator.evaluate(workflow_name: str, output_data: dict, trace: dict) -> EvaluationResult`
  - `BenchmarkEvaluator.generate_markdown_report(results: list[EvaluationResult]) -> str`
  - `BenchmarkEvaluator.generate_json_summary(results: list[EvaluationResult]) -> dict`

- [ ] **Step 1: Write test for evaluators**

```python
# evals/tests/test_evaluators.py
import pytest
from evals.evaluators.trajectory_evaluator import TrajectoryEvaluator
from evals.evaluators.schema_evaluator import SchemaEvaluator
from evals.evaluators.rubric_evaluator import RubricEvaluator
from evals.evaluators.benchmark_evaluator import BenchmarkEvaluator

def test_trajectory_evaluator():
    actual_trace = {"executed_nodes": ["extract", "enrich", "route", "low_risk", "report"], "route": "LOW_RISK_BENIGN"}
    expected = {"expected_route": "LOW_RISK_BENIGN", "required_nodes": ["extract", "report"]}
    metric = TrajectoryEvaluator.evaluate(actual_trace, expected)
    assert metric.passed is True
    assert metric.score == 1.0

def test_schema_evaluator():
    output = {"action_taken": "Closed", "soar_comment": "Low risk"}
    metric = SchemaEvaluator.evaluate(output, ["action_taken", "soar_comment"])
    assert metric.passed is True

def test_benchmark_evaluator_generation():
    from evals.evaluators.base import EvaluationResult, MetricResult
    res = EvaluationResult(
        test_id="TEST-001",
        workflow_name="suspicious_login_workflow",
        passed=True,
        total_score=95.0,
        max_score=100.0,
        metrics={"trajectory": MetricResult("trajectory", 1.0, 1.0, True, "OK")},
        duration_seconds=0.05,
    )
    md = BenchmarkEvaluator.generate_markdown_report([res])
    assert "suspicious_login_workflow" in md
    assert "95.0" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest evals/tests/test_evaluators.py -v`  
Expected: FAIL

- [ ] **Step 3: Implement evaluators in `evals/evaluators/`**

Implement `trajectory_evaluator.py`, `schema_evaluator.py`, `rubric_evaluator.py`, and `benchmark_evaluator.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest evals/tests/test_evaluators.py -v`  
Expected: PASS

---

### Task 4: Declarative Test Datasets

**Files:**
- Create: `evals/datasets/core_workflows.json`
- Create: `evals/datasets/all_36_workflows.json`
- Test: `evals/tests/test_datasets.py`

**Interfaces:**
- Produces:
  - Valid JSON dataset files adhering to the test case schema.
  - `load_dataset(dataset_name: str) -> list[dict]` utility function.

- [ ] **Step 1: Write test for dataset loading and schema validation**

```python
# evals/tests/test_datasets.py
import pytest
from evals.datasets import load_dataset

def test_load_core_workflows_dataset():
    cases = load_dataset("core_workflows")
    assert len(cases) >= 6
    for case in cases:
        assert "test_id" in case
        assert "workflow_name" in case
        assert "input" in case
        assert "expected" in case

def test_load_all_36_workflows_dataset():
    cases = load_dataset("all_36_workflows")
    assert len(cases) >= 36
    workflow_names = {c["workflow_name"] for c in cases}
    assert len(workflow_names) >= 36
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest evals/tests/test_datasets.py -v`  
Expected: FAIL

- [ ] **Step 3: Implement `evals/datasets/` and dataset loader**

Write `core_workflows.json` and `all_36_workflows.json` containing valid test inputs, expected routing outcomes, and required output fields for every workflow.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest evals/tests/test_datasets.py -v`  
Expected: PASS

---

### Task 5: CLI Runner, Full Regression Pytest Suite & Documentation

**Files:**
- Create: `evals/runner.py`
- Create: `evals/tests/conftest.py`
- Create: `evals/tests/test_eval_harness.py`
- Create: `evals/tests/test_core_benchmarks.py`
- Create: `evals/tests/test_all_36_workflows.py`
- Create: `evals/README.md`

**Interfaces:**
- Produces:
  - CLI execution entrypoint: `python -m evals.runner [--dataset all_36_workflows] [--workflow <name>] [--output-dir evals/results]`
  - Pytest full test suite: `pytest evals/tests/`
  - User documentation in `evals/README.md`

- [ ] **Step 1: Write integration tests for full evaluation execution**

```python
# evals/tests/test_all_36_workflows.py
import pytest
from evals.datasets import load_dataset
from evals.runner import run_eval_case

@pytest.mark.parametrize("test_case", load_dataset("all_36_workflows"), ids=lambda c: c["test_id"])
def test_all_36_graph_workflows(test_case):
    result = run_eval_case(test_case)
    assert result.passed is True, f"Failed on {test_case['workflow_name']}: {result.error}"
    assert result.total_score >= test_case.get("min_passing_score", 80.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest evals/tests/test_all_36_workflows.py -v`  
Expected: FAIL

- [ ] **Step 3: Implement `evals/runner.py`, pytest test files, and `evals/README.md`**

Implement CLI argument parsing, execution runner, report disk writer in `evals/results/`, and comprehensive documentation.

- [ ] **Step 4: Run test suite to verify full pass**

Run: `pytest evals/tests/ -v`  
Expected: All tests PASS

- [ ] **Step 5: Run CLI runner to generate live benchmark artifact**

Run: `python -m evals.runner --dataset all_36_workflows --report`  
Expected: Output generated in `evals/results/eval_report_<timestamp>.md` and JSON sidecar.
