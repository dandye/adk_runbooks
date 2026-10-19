"""Evaluation CLI runner for ADK Runbooks graph workflows.
Executes test cases against workflows, validates trajectories/schemas,
grades against runbook rubrics and categorical compliance gates, and outputs benchmark reports.
"""

import argparse
import json
import sys
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure multi-agent directory and root are on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"

for p in [str(REPO_ROOT), str(MULTI_AGENT_DIR)]:
  if p not in sys.path:
    sys.path.insert(0, p)

from evals.datasets import load_dataset
from evals.evaluators.base import EvaluationResult
from evals.evaluators.base import WorkflowTrace
from evals.evaluators.benchmark_evaluator import BenchmarkEvaluator
from evals.evaluators.rubric_evaluator import RubricEvaluator
from evals.evaluators.schema_evaluator import SchemaEvaluator
from evals.evaluators.trajectory_evaluator import TrajectoryEvaluator
from evals.registry import execute_workflow_sync
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite


def run_eval_case(
    test_case: dict[str, Any],
    max_steps: int = 50,
    strict_eval: bool = False,
    disclosure_mode: str = "dual_progressive",
) -> EvaluationResult:
  """Execute and evaluate a single test case record."""
  test_id = test_case.get("test_id", "TEST-ANON")
  workflow_name = test_case.get("workflow_name", "")
  input_data = test_case.get("input", {})
  expected = test_case.get("expected", {})
  min_score = test_case.get("min_passing_score", 80.0)
  effective_max_steps = test_case.get("max_steps", max_steps)
  effective_mode = test_case.get("disclosure_mode", disclosure_mode)

  try:
    raw_output, trace = execute_workflow_sync(
        workflow_name,
        input_data,
        max_steps=effective_max_steps,
        strict_eval=strict_eval,
        disclosure_mode=effective_mode,
    )
  except Exception as e:
    trace = WorkflowTrace(
        workflow_name=workflow_name,
        status="error",
        error=str(e),
        disclosure_mode=effective_mode,
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

  # 4. Categorical rubric evaluation
  categorical_verdicts = CategoricalRubricSuite.evaluate_all(trace, raw_output)
  eval_result.categorical_verdicts = categorical_verdicts

  # Check if expected specifies categorical assertions
  expected_categories = expected.get("categorical_verdicts", {})
  categorical_match = True
  for r_name, exp_cat in expected_categories.items():
    actual_v = categorical_verdicts.get(r_name)
    if not actual_v or actual_v.category != exp_cat:
      categorical_match = False

  # Combine metrics
  eval_result.metrics["trajectory"] = traj_metric
  eval_result.metrics["schema"] = schema_metric

  # Check overall pass: rubric score + trajectory match + schema match + categorical match
  overall_passed = (
      eval_result.passed
      and traj_metric.passed
      and schema_metric.passed
      and categorical_match
  )
  eval_result.passed = overall_passed

  return eval_result


def run_eval_dataset(
    dataset_name: str = "all_36_workflows",
    max_steps: int = 50,
    strict_eval: bool = False,
    disclosure_mode: str = "dual_progressive",
) -> list[EvaluationResult]:
  """Load and execute all test cases in a dataset."""
  test_cases = load_dataset(dataset_name)
  results: list[EvaluationResult] = []

  for case in test_cases:
    res = run_eval_case(
        case,
        max_steps=max_steps,
        strict_eval=strict_eval,
        disclosure_mode=disclosure_mode,
    )
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
      help="Dataset name to run (default: all_36_workflows, core_workflows, or production_regressions)",
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
      "--strict",
      action="store_true",
      help="Enable strict evaluation normalization without synthetic entity/diagram injection",
  )
  parser.add_argument(
      "--disclosure-mode",
      type=str,
      default="dual_progressive",
      choices=["dual_progressive", "skill_toolset", "skills_only", "static"],
      help="Progressive disclosure mode for evaluation (default: dual_progressive)",
  )
  parser.add_argument(
      "--enforce-gates",
      action="store_true",
      help="Enforce categorical release gates (100%% PD compliance, >=95%% MCP schema verified, 0 unverified containment)",
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

  print(
      f"=== Starting ADK Workflow Evaluation [{args.dataset}] "
      f"(mode={args.disclosure_mode}, strict={args.strict}, max_steps={args.max_steps}) ==="
  )
  test_cases = load_dataset(args.dataset)

  if args.workflow:
    test_cases = [
        c for c in test_cases if c.get("workflow_name") == args.workflow
    ]
    if not test_cases:
      print(
          f"Error: No test cases found matching workflow '{args.workflow}' in '{args.dataset}'."
      )
      return 1

  results: list[EvaluationResult] = []
  for case in test_cases:
    res = run_eval_case(
        case,
        max_steps=args.max_steps,
        strict_eval=args.strict,
        disclosure_mode=args.disclosure_mode,
    )
    results.append(res)

    badge = "✅ PASS" if res.passed else "❌ FAIL"
    tokens_str = (
        f"~{res.trace.total_tokens} tokens"
        if res.trace and res.trace.total_tokens
        else "N/A tokens"
    )
    pd_cat = (
        res.categorical_verdicts["ProgressiveDisclosureCompliance"].category
        if "ProgressiveDisclosureCompliance" in res.categorical_verdicts
        else "N/A"
    )
    print(
        f"[{badge}] {res.test_id} ({res.workflow_name}): "
        f"{res.total_score:.1f}/100.0 | PD={pd_cat} | {res.duration_seconds:.4f}s | {tokens_str}"
    )
    if args.verbose and res.scorecard:
      for cat, score in res.scorecard.category_scores.items():
        print(f"      - {cat}: {score:.1f} pts")
      for r_name, v in res.categorical_verdicts.items():
        print(
            f"      - [Gate] {r_name}: {v.category} ({'PASS' if v.passed else 'FAIL'})"
        )
      for fb in res.scorecard.feedback:
        print(f"        * {fb}")

  # Summary & Release Gates
  total = len(results)
  passed = sum(1 for r in results if r.passed)
  avg_score = sum(r.total_score for r in results) / total if total > 0 else 0.0
  total_tokens = sum((r.trace.total_tokens if r.trace else 0) for r in results)
  avg_tokens = total_tokens / total if total > 0 else 0.0
  total_duration = sum(r.duration_seconds for r in results)
  gate_summary = CategoricalRubricSuite.evaluate_release_gates(results)

  print("\n=======================================================")
  print(
      f"SUMMARY: {passed}/{total} Passed ({(passed/total*100) if total else 0.0:.1f}%) | "
      f"Average Rubric Score: {avg_score:.1f}/100.0 | "
      f"Total Tokens: ~{total_tokens:,} (Avg ~{avg_tokens:.0f}/test) | "
      f"Total Run Time: {total_duration:.4f}s"
  )
  print(
      f"RELEASE GATES: {'✅ ALL PASSED' if gate_summary['all_gates_passed'] else '❌ FAILED'} | "
      f"PD Honored: {gate_summary['progressive_disclosure_honored_rate']:.1f}% | "
      f"MCP Schema Verified: {gate_summary['mcp_schema_verified_rate']:.1f}% | "
      f"Unverified Containment: {gate_summary['unverified_containment_count']}"
  )
  print("=======================================================\n")

  if args.report:
    out_dir = Path(args.output_dir)
    if not out_dir.is_absolute():
      out_dir = REPO_ROOT / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    md_file = out_dir / f"eval_benchmark_{args.dataset}_{timestamp}.md"
    json_file = out_dir / f"eval_benchmark_{args.dataset}_{timestamp}.json"

    md_content = BenchmarkEvaluator.generate_markdown_report(
        results, title=f"ADK Workflow Benchmark ({args.dataset})"
    )
    json_content = BenchmarkEvaluator.generate_json_summary(results)

    with open(md_file, "w", encoding="utf-8") as f:
      f.write(md_content)
    with open(json_file, "w", encoding="utf-8") as f:
      json.dump(json_content, f, indent=2)

    print(f"-> Saved Markdown Report: {md_file}")
    print(f"-> Saved JSON Summary:   {json_file}")

  if args.enforce_gates and not gate_summary["all_gates_passed"]:
    return 1
  return 0 if passed == total else 1


if __name__ == "__main__":
  sys.exit(main())
