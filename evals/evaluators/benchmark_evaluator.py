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

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "pass_rate": (passed_tests / total_tests * 100.0) if total_tests > 0 else 0.0,
                "average_score": round(avg_score, 2),
                "average_duration_seconds": round(avg_duration, 4),
            },
            "results": [
                {
                    "test_id": r.test_id,
                    "workflow_name": r.workflow_name,
                    "passed": r.passed,
                    "total_score": r.total_score,
                    "max_score": r.max_score,
                    "duration_seconds": round(r.duration_seconds, 4),
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
            f"**Average Score:** {summary['average_score']:.1f} / 100.0 | **Average Latency:** {summary['average_duration_seconds']:.4f}s",
            "",
            "---",
            "",
            "## 1. Summary Scorecard Table",
            "",
            "| Test ID | Workflow Name | Rubric Profile | Score | Duration | Status |",
            "|:---|:---|:---:|:---:|:---:|:---:|",
        ]

        for r in results:
            status_badge = "✅ PASS" if r.passed else "❌ FAIL"
            profile = r.scorecard.profile_name if r.scorecard else "N/A"
            lines.append(
                f"| `{r.test_id}` | `{r.workflow_name}` | `{profile}` | **{r.total_score:.1f}** / {r.max_score:.1f} | {r.duration_seconds:.4f}s | {status_badge} |"
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
