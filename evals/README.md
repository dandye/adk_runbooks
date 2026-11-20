# ADK Runbooks: Agent Workflows Evaluation & Rubric Framework

Automated, declarative evaluation and grading suite for all 36 Google ADK 2.x cybersecurity graph workflows in `adk_runbooks`.

Reference: [GitHub Issue #68](https://github.com/dandye/adk_runbooks/issues/68)

---

## 1. Overview

This evaluation harness allows you to:
1. **Declaratively Test Workflows**: Execute test cases defined in JSON manifests without writing repetitive test harnesses.
2. **Verify Trajectories & Routing Paths**: Assert that graph executions follow deterministic branching decisions (e.g. `LOW_RISK_BENIGN`, `HIGH_RISK_SUSPICIOUS`, `MALICIOUS_THREAT`, `EXECUTE_ISOLATION`).
3. **Validate Output Schema & Artifacts**: Verify that required attributes, entity extractions, and SOAR comment summaries are present and non-empty.
4. **Programmatically Score Runbook Rubrics (0–100 Points)**: Apply official runbook evaluation criteria from [`skills/`](../skills/):
   - **Reporting Rubric (100 pts)**: Data Collection (25), Report Gen (30), Quality/Clarity (15), Delivery (15), Operational Artifacts (15).
   - **Triage & Incident Response Rubric (100 pts)**: Context & Enrichment (25), Analysis & Decision (25), Action Execution (20), Documentation (15), Operational Artifacts (15).
   - **Threat Hunting & Deep Analysis Rubric (100 pts)**: Scope & Query (25), Data Analysis & Correlation (30), Findings Classification (15), Hunt Documentation (15), Operational Artifacts (15).
   - **Detection Engineering Rubric (100 pts)**: Requirement Analysis (20), Technical Implementation (30), Validation & Testing (20), Git/Process Compliance (15), Operational Artifacts (15).
5. **Generate Benchmark Scorecards**: Export comparative Markdown tables and JSON sidecars to `evals/results/`.

---

## 2. Directory Structure

```text
evals/
├── README.md                          # Documentation and usage guide
├── __init__.py                        # Top-level exports
├── runner.py                          # CLI runner: python -m evals.runner
├── registry.py                        # Workflow registry for all 36 ADK graph workflows
├── promptfoo/                         # Promptfoo LLM evaluation suite & custom provider
│   ├── promptfooconfig.yaml           # Declarative test scenarios & LLM-as-a-judge rubrics
│   ├── adk_agent_provider.py          # ADK 2.x agent execution provider wrapper
│   └── README.md                      # Promptfoo quick start and execution guide
├── datasets/                          # Declarative test datasets
│   ├── all_36_workflows.json          # Regression suite across all 36 workflows
│   ├── core_workflows.json            # Focused benchmark suite (10 scenarios)
│   ├── expanded_cases_alerts.json     # Comprehensive real-world case & alert scenarios
│   └── custom_cases/                  # User-defined custom test cases
├── rubrics/                           # Rubric scoring models
│   ├── base.py                        # BaseRubric interface
│   ├── reporting_rubric.py            # Reporting Runbook Rubric (100 pts)
│   ├── triage_irp_rubric.py           # Triage/IRP Rubric (100 pts)
│   ├── threat_hunting_rubric.py       # Threat Hunting & Deep Analysis Rubric (100 pts)
│   └── detection_rubric.py            # Detection Engineering Rubric (100 pts)
├── evaluators/                        # Evaluator engines
│   ├── base.py                        # MetricResult, EvaluationResult, WorkflowTrace dataclasses
│   ├── trajectory_evaluator.py        # Node path & routing assertion engine
│   ├── schema_evaluator.py            # Field and comment integrity validator
│   ├── rubric_evaluator.py            # Rubric scoring aggregator
│   └── benchmark_evaluator.py         # Markdown and JSON report generator
├── tests/                             # Pytest / unittest test suite
│   ├── conftest.py                    # Path configuration fixtures
│   ├── test_rubrics.py                # Rubric calculation unit tests
│   ├── test_registry.py               # Registry resolution unit tests
│   ├── test_evaluators.py             # Evaluator engines unit tests
│   ├── test_datasets.py               # Dataset manifest validation unit tests
│   ├── test_core_benchmarks.py        # Core security scenarios integration tests
│   ├── test_all_36_workflows.py       # 36-workflow full regression tests
│   └── test_eval_harness.py           # CLI runner & batch test verification
└── results/                           # Generated evaluation scorecards and reports
```

---

## 3. Quick Start & Execution

### Running via Pytest
```bash
# Run all evaluation tests
pytest evals/tests/ -v

# Run the 36-workflow full regression suite
pytest evals/tests/test_all_36_workflows.py -v

# Run core security benchmark scenarios
pytest evals/tests/test_core_benchmarks.py -v
```

### Running via the CLI Runner
```bash
# Evaluate all 36 workflows and generate markdown + JSON reports in evals/results/
python -m evals.runner --dataset all_36_workflows --report

# Run focused core benchmarks with verbose rubric breakdown
python -m evals.runner --dataset core_workflows --verbose

# Run with custom DAG execution step limit (default: 50)
python -m evals.runner --dataset all_36_workflows --max-steps 75 --report

# Run a single workflow
python -m evals.runner --dataset all_36_workflows --workflow suspicious_login_workflow --report
```

---

## 4. Adding New Evaluation Cases

To add a new evaluation test case, add an entry to `evals/datasets/core_workflows.json` or create a new dataset file in `evals/datasets/`:

```json
{
  "test_id": "TEST-CUSTOM-001",
  "workflow_name": "suspicious_login_workflow",
  "description": "Custom high-risk triage case.",
  "skill_reference": "skills/triage/suspicious-login-triage/SKILL.md",
  "rubric_type": "TRIAGE_IRP",
  "input": {
    "case_id": "CASE-9999",
    "user_id": "target.user@example.com",
    "source_ip": "203.0.113.10",
    "hostname": "prod-auth-node"
  },
  "expected": {
    "expected_route": "HIGH_RISK_SUSPICIOUS",
    "required_output_fields": ["action_taken", "soar_comment"],
    "required_comment_substrings": ["High Risk", "Escalate"]
  },
  "min_passing_score": 85.0
}
```

---

## 5. Promptfoo Multi-Turn LLM Agent Evaluation

For evaluating multi-turn agent procedural compliance, ASD-STE100 runbook adherence, and LLM-as-a-judge rubric scoring across Gemini models (3.7 Flash, 2.5 Flash, 2.5 Flash-Lite):

```bash
# Execute Promptfoo evaluation suite
npx promptfoo@latest eval -c evals/promptfoo/promptfooconfig.yaml

# View interactive scorecard UI
npx promptfoo@latest view
```

Full manual: [`rules-bank/ai/promptfoo_evaluation_manual.md`](../rules-bank/ai/promptfoo_evaluation_manual.md)

