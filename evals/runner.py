"""
Evaluation CLI runner for ADK Runbooks graph workflows.
Executes test cases against workflows, validates trajectories/schemas,
grades against runbook rubrics, and outputs benchmark reports.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

# Ensure multi-agent directory and root are on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"

for p in [str(REPO_ROOT), str(MULTI_AGENT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from evals.datasets import load_dataset
from evals.evaluators.base import EvaluationResult, MetricResult, WorkflowTrace
from evals.evaluators.trajectory_evaluator import TrajectoryEvaluator
from evals.evaluators.schema_evaluator import SchemaEvaluator
from evals.evaluators.rubric_evaluator import RubricEvaluator
from evals.evaluators.benchmark_evaluator import BenchmarkEvaluator
from evals.registry import execute_workflow_sync, get_workflow_definition


def run_eval_case(test_case: Dict[str, Any], max_steps: int = 50) -> EvaluationResult:
    """Execute and evaluate a single test case record."""
    test_id = test_case.get("test_id", "TEST-ANON")
    workflow_name = test_case.get("workflow_name", "")
    input_data = test_case.get("input", {})
    expected = test_case.get("expected", {})
    min_score = test_case.get("min_passing_score", 80.0)
    effective_max_steps = test_case.get("max_steps", max_steps)

    try:
        raw_output, trace = execute_workflow_sync(
            workflow_name, input_data, max_steps=effective_max_steps
        )
    except Exception as e:
        trace = WorkflowTrace(
            workflow_name=workflow_name,
            status="error",
            error=str(e),
        )
        return EvaluationResult(
            test_id=test_id,
            workflow_name=workflow_name,
            passed=False,
            total_score=0.0,
            max_score=100.0,
            trace=trace,
            duration_seconds=0.0,
            error=str(e),
        )

    # 1. Trajectory & routing evaluation
    traj_metric = TrajectoryEvaluator.evaluate(trace, expected)

    # 2. Schema and output entity integrity
    schema_metric = SchemaEvaluator.evaluate(raw_output, expected)

    # 3. Rubric evaluation
    eval_result = RubricEvaluator.evaluate(
        test_id=test_id,
        workflow_name=workflow_name,
        raw_output=raw_output,
        trace=trace,
        min_passing_score=min_score,
    )

    # Combine metrics
    eval_result.metrics["trajectory"] = traj_metric
    eval_result.metrics["schema"] = schema_metric

    # Check overall pass: rubric score + trajectory match + schema match
    overall_passed = eval_result.passed and traj_metric.passed and schema_metric.passed
    eval_result.passed = overall_passed

    return eval_result


def run_eval_dataset(
    dataset_name: str = "all_36_workflows", max_steps: int = 50
) -> List[EvaluationResult]:
    """Load and execute all test cases in a dataset."""
    test_cases = load_dataset(dataset_name)
    results: List[EvaluationResult] = []

    for case in test_cases:
        res = run_eval_case(case, max_steps=max_steps)
        results.append(res)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ADK Runbooks Graph Workflow Evaluation & Rubric Benchmark Runner"
    )
    parser.add_argument(
        "--dataset",
        type=str,
        default="all_36_workflows",
        help="Dataset name to run (default: all_36_workflows, or core_workflows)",
    )
    parser.add_argument(
        "--workflow",
        type=str,
        default=None,
        help="Filter execution to a single specific workflow name",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=50,
        help="Maximum DAG execution steps allowed per workflow (default: 50)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Save benchmark Markdown and JSON summary reports to disk",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="evals/results",
        help="Directory to save benchmark reports (default: evals/results)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print detailed scorecards and execution feedback",
    )

    args = parser.parse_args()

    print(f"=== Starting ADK Workflow Evaluation [{args.dataset}] (max_steps={args.max_steps}) ===")
    test_cases = load_dataset(args.dataset)

    if args.workflow:
        test_cases = [c for c in test_cases if c.get("workflow_name") == args.workflow]
        if not test_cases:
            print(f"Error: No test cases found matching workflow '{args.workflow}' in '{args.dataset}'.")
            return 1

    results: List[EvaluationResult] = []
    for case in test_cases:
        res = run_eval_case(case, max_steps=args.max_steps)
        results.append(res)

        badge = "✅ PASS" if res.passed else "❌ FAIL"
        print(f"[{badge}] {res.test_id} ({res.workflow_name}): {res.total_score:.1f}/100.0 in {res.duration_seconds:.4f}s")
        if args.verbose and res.scorecard:
            for cat, score in res.scorecard.category_scores.items():
                print(f"      - {cat}: {score:.1f} pts")
            for fb in res.scorecard.feedback:
                print(f"        * {fb}")

    # Summary
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    avg_score = sum(r.total_score for r in results) / total if total > 0 else 0.0
    print("\n=======================================================")
    print(f"SUMMARY: {passed}/{total} Passed ({(passed/total*100):.1f}%) | Average Rubric Score: {avg_score:.1f}/100.0")
    print("=======================================================\n")

    if args.report:
        out_dir = Path(args.output_dir)
        if not out_dir.is_absolute():
            out_dir = REPO_ROOT / out_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        md_file = out_dir / f"eval_benchmark_{args.dataset}_{timestamp}.md"
        json_file = out_dir / f"eval_benchmark_{args.dataset}_{timestamp}.json"

        md_content = BenchmarkEvaluator.generate_markdown_report(results, title=f"ADK Workflow Benchmark ({args.dataset})")
        json_content = BenchmarkEvaluator.generate_json_summary(results)

        with open(md_file, "w", encoding="utf-8") as f:
            f.write(md_content)
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(json_content, f, indent=2)

        print(f"-> Saved Markdown Report: {md_file}")
        print(f"-> Saved JSON Summary:   {json_file}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
