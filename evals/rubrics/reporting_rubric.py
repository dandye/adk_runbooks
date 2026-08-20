"""
Reporting Runbook Rubric (100 Points Total).
Applied to Case Reports, Alert Reports, Detection Reports, and UEBA/Investigation Reports.
Derived from skills/reporting/case-report/SKILL.md and skills/reporting/alert-report/SKILL.md.
"""

from typing import Any, Dict, List
from evals.evaluators.base import RubricScorecard
from evals.rubrics.base import BaseRubric


class ReportingRubric(BaseRubric):
    """Evaluator for the standard Reporting Runbook Rubric."""

    @classmethod
    def evaluate(cls, output_data: Dict[str, Any], trace: Dict[str, Any] | None = None) -> RubricScorecard:
        category_scores: Dict[str, float] = {}
        feedback: List[str] = []
        trace = trace or {}

        # 1. Data Collection (25 pts)
        data_collection_score = 0.0
        # Check if case/alert details, entities, or telemetry are present in output
        has_entities = any(k in output_data for k in ["case_id", "alert_id", "entities", "ioc_value", "user_id", "source_ip", "file_hash"])
        has_details = any(k in output_data for k in ["report_markdown", "soar_comment", "summary", "timeline", "details", "action_taken"])
        
        if has_entities and has_details:
            data_collection_score = 25.0
            feedback.append("Data Collection (25/25): Successfully collected case telemetry and alert entities.")
        elif has_details:
            data_collection_score = 20.0
            feedback.append("Data Collection (20/25): Data collected with partial entity attribution.")
        else:
            data_collection_score = 10.0
            feedback.append("Data Collection (10/25): Minimal telemetry gathered.")
        category_scores["Data Collection"] = data_collection_score

        # 2. Report Generation (30 pts: 15 format, 15 sections)
        format_score = 0.0
        sections_score = 0.0
        report_text = output_data.get("report_markdown") or output_data.get("soar_comment") or output_data.get("summary") or ""
        if isinstance(report_text, str) and len(report_text.strip()) > 50:
            format_score = 15.0
            feedback.append("Report Formatting (15/15): Properly formatted into structured Markdown.")
        elif isinstance(report_text, str) and len(report_text.strip()) > 0:
            format_score = 8.0
            feedback.append("Report Formatting (8/15): Formatted with minimal text volume.")
        else:
            format_score = 0.0
            feedback.append("Report Formatting (0/15): Missing formatted report body.")

        # Check for standard sections: Executive Summary, Details/Analysis, Recommendations/Actions
        req_sections = ["summary", "overview", "detail", "finding", "recommendation", "action", "alert", "entity"]
        found_sections = sum(1 for sec in req_sections if sec in report_text.lower())
        if found_sections >= 3:
            sections_score = 15.0
            feedback.append("Required Sections (15/15): All key reporting sections present.")
        elif found_sections >= 1:
            sections_score = 10.0
            feedback.append("Required Sections (10/15): Partial section coverage.")
        else:
            sections_score = 5.0
            feedback.append("Required Sections (5/15): Incomplete section structure.")
        category_scores["Report Generation"] = format_score + sections_score

        # 3. Quality & Clarity (15 pts)
        if isinstance(report_text, str) and len(report_text) > 100 and "error" not in report_text.lower()[:50]:
            quality_score = 15.0
            feedback.append("Quality & Clarity (15/15): Coherent, technically accurate, and professional.")
        elif isinstance(report_text, str) and len(report_text) > 0:
            quality_score = 10.0
            feedback.append("Quality & Clarity (10/15): Readable with minor content density gaps.")
        else:
            quality_score = 5.0
            feedback.append("Quality & Clarity (5/15): Low text quality or missing content.")
        category_scores["Quality & Clarity"] = quality_score

        # 4. Delivery (15 pts)
        # Check if saved to disk or delivered via SOAR comment/report path
        has_delivery = any(k in output_data for k in ["report_path", "soar_comment", "soar_comment_status", "action_taken", "action_status"])
        if has_delivery or output_data.get("report_markdown"):
            delivery_score = 15.0
            feedback.append("Delivery (15/15): Successfully written to file / SOAR documentation path.")
        else:
            delivery_score = 0.0
            feedback.append("Delivery (0/15): Report output was not delivered.")
        category_scores["Delivery"] = delivery_score

        # 5. Operational Artifacts (15 pts: 5 sequence diagram, 5 metadata, 5 summary)
        diag_score = 0.0
        meta_score = 0.0
        summary_score = 0.0

        if output_data.get("has_sequence_diagram") or "mermaid" in report_text.lower() or "sequencediagram" in report_text.lower():
            diag_score = 5.0
            feedback.append("Sequence Diagram (5/5): Included workflow sequence visualization.")
        else:
            diag_score = 0.0
            feedback.append("Sequence Diagram (0/5): Missing Mermaid sequence diagram.")

        if output_data.get("execution_metadata") or trace.get("duration_seconds") is not None or "token" in report_text.lower():
            meta_score = 5.0
            feedback.append("Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.")
        else:
            meta_score = 0.0
            feedback.append("Execution Metadata (0/5): Missing execution metadata.")

        if "summary" in report_text.lower() or output_data.get("summary") or output_data.get("action_taken"):
            summary_score = 5.0
            feedback.append("Summary Report (5/5): Provided concise action/outcome summary.")
        else:
            summary_score = 0.0
            feedback.append("Summary Report (0/5): Missing summary.")

        category_scores["Operational Artifacts"] = diag_score + meta_score + summary_score

        total_score = sum(category_scores.values())
        passed = total_score >= 80.0

        return RubricScorecard(
            profile_name="REPORTING_RUBRIC",
            total_score=total_score,
            max_score=100.0,
            passed=passed,
            category_scores=category_scores,
            feedback=feedback,
            metadata={"word_count": len(report_text.split())}
        )
