"""
Benchmark evaluator and report generator for test evaluation runs.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List
from evals.evaluators.base import EvaluationResult


class BenchmarkEvaluator:
    """Generates Markdown benchmark tables and JSON summaries from evaluation results."""

    @classmethod
    def generate_json_summary(cls, results: List[EvaluationResult]) -> Dict[str, Any]:
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.passed)
        failed_tests = total_tests - passed_tests
        avg_score = sum(r.total_score for r in results) / total_tests if total_tests > 0 else 0.0
        avg_duration = sum(r.duration_seconds for r in results) / total_tests if total_tests > 0 else 0.0
        total_tokens = sum((r.trace.total_tokens if r.trace else 0) for r in results)
        avg_tokens = total_tokens / total_tests if total_tests > 0 else 0.0

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "pass_rate": (passed_tests / total_tests * 100.0) if total_tests > 0 else 0.0,
                "average_score": round(avg_score, 2),
                "average_duration_seconds": round(avg_duration, 4),
                "total_estimated_tokens": total_tokens,
                "average_tokens_per_test": round(avg_tokens, 1),
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
                        "estimated_input": r.trace.estimated_tokens_in if r.trace else 0,
                        "estimated_output": r.trace.estimated_tokens_out if r.trace else 0,
                        "total": r.trace.total_tokens if r.trace else 0,
                    },
                    "rubric_profile": r.scorecard.profile_name if r.scorecard else None,
                    "category_scores": r.scorecard.category_scores if r.scorecard else {},
                    "error": r.error,
                }
                for r in results
            ]
        }

    @classmethod
    def generate_markdown_report(cls, results: List[EvaluationResult], title: str = "ADK Graph Workflow Evaluation Benchmark") -> str:
        summary_data = cls.generate_json_summary(results)
        summary = summary_data["summary"]

        lines = [
            f"# {title}",
            "",
            f"**Generated:** {summary_data['timestamp']}  ",
            f"**Total Evaluated:** {summary['total_tests']} | **Passed:** {summary['passed_tests']} | **Failed:** {summary['failed_tests']} | **Pass Rate:** {summary['pass_rate']:.1f}%  ",
            f"**Average Score:** {summary['average_score']:.1f} / 100.0 | **Average Latency:** {summary['average_duration_seconds']:.4f}s | **Total Tokens:** ~{summary['total_estimated_tokens']:,} (Avg ~{summary['average_tokens_per_test']:.0f}/test)",
            "",
            "---",
            "",
            "## 1. Summary Scorecard Table",
            "",
            "| Test ID | Workflow Name | Rubric Profile | Score | Duration | Est. Tokens (In / Out / Total) | Status |",
            "|:---|:---|:---:|:---:|:---:|:---:|:---:|",
        ]

        for r in results:
            status_badge = "✅ PASS" if r.passed else "❌ FAIL"
            profile = r.scorecard.profile_name if r.scorecard else "N/A"
            tokens_in = r.trace.estimated_tokens_in if r.trace else 0
            tokens_out = r.trace.estimated_tokens_out if r.trace else 0
            tokens_tot = r.trace.total_tokens if r.trace else 0
            lines.append(
                f"| `{r.test_id}` | `{r.workflow_name}` | `{profile}` | **{r.total_score:.1f}** / {r.max_score:.1f} | {r.duration_seconds:.4f}s | {tokens_in} / {tokens_out} / **{tokens_tot}** | {status_badge} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. Detailed Feedback & Category Breakdown",
            "",
        ])

        for r in results:
            lines.append(f"### `{r.test_id}`: {r.workflow_name}")
            lines.append(f"* **Verdict:** {'PASS' if r.passed else 'FAIL'} (Score: {r.total_score:.1f}/{r.max_score:.1f})")
            lines.append(f"* **Run Time:** {r.duration_seconds:.4f}s")
            if r.trace and r.trace.total_tokens:
                lines.append(f"* **Token Usage:** ~{r.trace.total_tokens} tokens (Input: ~{r.trace.estimated_tokens_in}, Output: ~{r.trace.estimated_tokens_out})")
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
