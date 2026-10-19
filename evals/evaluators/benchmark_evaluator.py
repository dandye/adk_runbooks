"""Benchmark evaluator and report generator for test evaluation runs."""

from datetime import UTC
from datetime import datetime
from typing import Any

from evals.evaluators.base import EvaluationResult
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite


class BenchmarkEvaluator:
  """Generates Markdown benchmark tables and JSON summaries from evaluation results."""

  @classmethod
  def generate_json_summary(
      cls, results: list[EvaluationResult]
  ) -> dict[str, Any]:
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.passed)
    failed_tests = total_tests - passed_tests
    avg_score = (
        sum(r.total_score for r in results) / total_tests
        if total_tests > 0
        else 0.0
    )
    avg_duration = (
        sum(r.duration_seconds for r in results) / total_tests
        if total_tests > 0
        else 0.0
    )
    total_tokens = sum(
        (r.trace.total_tokens if r.trace else 0) for r in results
    )
    avg_tokens = total_tokens / total_tests if total_tests > 0 else 0.0
    release_gates = CategoricalRubricSuite.evaluate_release_gates(results)

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "summary": {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "pass_rate": (passed_tests / total_tests * 100.0)
            if total_tests > 0
            else 0.0,
            "average_score": round(avg_score, 2),
            "average_duration_seconds": round(avg_duration, 4),
            "total_estimated_tokens": total_tokens,
            "average_tokens_per_test": round(avg_tokens, 1),
            "release_gates": release_gates,
        },
        "results": [
            {
                "test_id": r.test_id,
                "workflow_name": r.workflow_name,
                "passed": r.passed,
                "total_score": r.total_score,
                "max_score": r.max_score,
                "duration_seconds": round(r.duration_seconds, 4),
                "tokens": {
                    "estimated_input": r.trace.estimated_tokens_in
                    if r.trace
                    else 0,
                    "estimated_output": r.trace.estimated_tokens_out
                    if r.trace
                    else 0,
                    "total": r.trace.total_tokens if r.trace else 0,
                    "source": r.trace.token_source if r.trace else "heuristic",
                },
                "rubric_profile": r.scorecard.profile_name
                if r.scorecard
                else None,
                "category_scores": r.scorecard.category_scores
                if r.scorecard
                else {},
                "categorical_verdicts": {
                    k: {
                        "category": v.category,
                        "passed": v.passed,
                        "reason": v.reason,
                        "exclude_from_gate": v.exclude_from_gate,
                    }
                    for k, v in (r.categorical_verdicts or {}).items()
                },
                "error": r.error,
            }
            for r in results
        ],
    }

  @classmethod
  def generate_markdown_report(
      cls,
      results: list[EvaluationResult],
      title: str = "ADK Graph Workflow Evaluation Benchmark",
  ) -> str:
    summary_data = cls.generate_json_summary(results)
    summary = summary_data["summary"]
    gates = summary.get("release_gates", {})

    lines = [
        f"# {title}",
        "",
        f"**Generated:** {summary_data['timestamp']}  ",
        f"**Total Evaluated:** {summary['total_tests']} | **Passed:** {summary['passed_tests']} | **Failed:** {summary['failed_tests']} | **Pass Rate:** {summary['pass_rate']:.1f}%  ",
        f"**Average Score:** {summary['average_score']:.1f} / 100.0 | **Average Latency:** {summary['average_duration_seconds']:.4f}s | **Total Tokens:** ~{summary['total_estimated_tokens']:,} (Avg ~{summary['average_tokens_per_test']:.0f}/test)  ",
        f"**Release Gates Passed:** {'YES' if gates.get('all_gates_passed') else 'NO'} (PD Honored: {gates.get('progressive_disclosure_honored_rate', 0.0):.1f}%, MCP Schema Verified: {gates.get('mcp_schema_verified_rate', 0.0):.1f}%, Unverified Containment: {gates.get('unverified_containment_count', 0)})",
        "",
        "---",
        "",
        "## 1. Summary Scorecard Table",
        "",
        "| Test ID | Workflow Name | Rubric Profile | Score | PD Gate | MCP Gate | Duration | Est. Tokens (In / Out / Total) | Status |",
        "|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for r in results:
      status_badge = "PASS" if r.passed else "FAIL"
      profile = r.scorecard.profile_name if r.scorecard else "N/A"
      tokens_in = r.trace.estimated_tokens_in if r.trace else 0
      tokens_out = r.trace.estimated_tokens_out if r.trace else 0
      tokens_tot = r.trace.total_tokens if r.trace else 0
      pd_verdict = (
          r.categorical_verdicts.get("ProgressiveDisclosureCompliance")
          if r.categorical_verdicts
          else None
      )
      pd_cat = pd_verdict.category if pd_verdict is not None else "N/A"
      mcp_verdict = (
          r.categorical_verdicts.get("McpSchemaHygiene")
          if r.categorical_verdicts
          else None
      )
      mcp_cat = mcp_verdict.category if mcp_verdict is not None else "N/A"
      lines.append(
          f"| `{r.test_id}` | `{r.workflow_name}` | `{profile}` | **{r.total_score:.1f}** / {r.max_score:.1f} | `{pd_cat}` | `{mcp_cat}` | {r.duration_seconds:.4f}s | {tokens_in} / {tokens_out} / **{tokens_tot}** | {status_badge} |"
      )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 2. Detailed Feedback & Category Breakdown",
            "",
        ]
    )

    for r in results:
      lines.append(f"### `{r.test_id}`: {r.workflow_name}")
      lines.append(
          f"* **Verdict:** {'PASS' if r.passed else 'FAIL'} (Score: {r.total_score:.1f}/{r.max_score:.1f})"
      )
      lines.append(f"* **Run Time:** {r.duration_seconds:.4f}s")
      if r.trace and r.trace.total_tokens:
        lines.append(
            f"* **Token Usage:** ~{r.trace.total_tokens} tokens (Input: ~{r.trace.estimated_tokens_in}, Output: ~{r.trace.estimated_tokens_out})"
        )
      if r.categorical_verdicts:
        lines.append("* **Categorical Verdicts:**")
        for r_name, v in r.categorical_verdicts.items():
          lines.append(
              f"  * **{r_name}:** `{v.category}` ({'PASS' if v.passed else 'FAIL'}) — {v.reason}"
          )
      if r.scorecard and r.scorecard.category_scores:
        lines.append("* **Category Scores:**")
        for cat, score in r.scorecard.category_scores.items():
          lines.append(f"  * **{cat}:** {score:.1f} pts")
      if r.scorecard and r.scorecard.feedback:
        lines.append("* **Rubric Feedback:**")
        for fb in r.scorecard.feedback:
          lines.append(f"  - {fb}")
      if r.error:
        lines.append(f"* **Execution Error:** `{r.error}`")
      lines.append("")

    return "\n".join(lines)
