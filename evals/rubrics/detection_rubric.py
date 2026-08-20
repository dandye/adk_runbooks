"""
Detection Engineering Runbook Rubric (100 Points Total).
Applied to Detection Rule Validation & Tuning, Detection As Code Workflows, and Rule Development.
Derived from skills/detection/detection-rule-validation-tuning/SKILL.md.
"""

from typing import Any, Dict, List
from evals.evaluators.base import RubricScorecard
from evals.rubrics.base import BaseRubric


class DetectionRubric(BaseRubric):
    """Evaluator for the standard Detection Engineering Runbook Rubric."""

    @classmethod
    def evaluate(cls, output_data: Dict[str, Any], trace: Dict[str, Any] | None = None) -> RubricScorecard:
        category_scores: Dict[str, float] = {}
        feedback: List[str] = []
        trace = trace or {}

        report_text = output_data.get("report_markdown") or output_data.get("soar_comment") or str(output_data)

        # 1. Requirement Analysis (20 pts)
        has_rule = any(k in output_data for k in ["rule_id", "rule_name", "rule_display_name", "detection_scope"]) or "rule id" in report_text.lower() or "rule:" in report_text.lower()
        if has_rule:
            req_score = 20.0
            feedback.append("Requirement Analysis (20/20): Accurately identified detection rule scope and validation targets.")
        else:
            req_score = 10.0
            feedback.append("Requirement Analysis (10/20): Partial detection scope definition.")
        category_scores["Requirement Analysis"] = req_score

        # 2. Technical Implementation (30 pts: 15 syntax, 15 logic)
        syntax_score = 0.0
        logic_score = 0.0
        comp_status = output_data.get("compilation_status") or output_data.get("syntax_status")
        if (comp_status and "pass" in str(comp_status).lower()) or "compilation status: passed" in report_text.lower() or "syntax" in report_text.lower() or output_data.get("rule_syntax_valid"):
            syntax_score = 15.0
            feedback.append("Syntax Validation (15/15): Verified YARA-L / detection rule syntax compilation.")
        else:
            syntax_score = 5.0
            feedback.append("Syntax Validation (5/15): Syntax verification incomplete.")

        if output_data.get("rule_logic_valid") is not False or any(k in output_data for k in ["recommendation", "action", "tuning_decision", "action_taken"]) or "recommendation" in report_text.lower():
            logic_score = 15.0
            feedback.append("Rule Logic (15/15): Verified detection logic alignment with attack techniques.")
        else:
            logic_score = 8.0
            feedback.append("Rule Logic (8/15): Logic verification partial.")
        category_scores["Technical Implementation"] = syntax_score + logic_score

        # 3. Validation & Testing (20 pts)
        has_metrics = any(k in output_data for k in ["historical_detections", "historical_triggers", "false_positive_rate", "fp_rate", "quality_score"]) or "detections:" in report_text.lower() or "false positive" in report_text.lower()
        if has_metrics:
            val_score = 20.0
            feedback.append("Validation & Testing (20/20): Tested against historical SIEM telemetry and calculated FP ratios.")
        else:
            val_score = 10.0
            feedback.append("Validation & Testing (10/20): Limited empirical telemetry testing.")
        category_scores["Validation & Testing"] = val_score

        # 4. Git / Process Compliance (15 pts)
        has_rec = any(k in output_data for k in ["recommendation", "decision", "tuning_decision", "deployment_action", "action_taken"]) or "decision:" in report_text.lower() or "deploy" in report_text.lower()
        if has_rec:
            git_score = 15.0
            feedback.append("Process Compliance (15/15): Formulated explicit deployment/tuning recommendation.")
        else:
            git_score = 8.0
            feedback.append("Process Compliance (8/15): Missing explicit deployment recommendation.")
        category_scores["Git/Process Compliance"] = git_score

        # 5. Operational Artifacts (15 pts: 5 sequence diagram, 5 metadata, 5 summary)
        diag_score = 0.0
        meta_score = 0.0
        summary_score = 0.0

        if output_data.get("has_sequence_diagram") or "mermaid" in str(output_data).lower():
            diag_score = 5.0
            feedback.append("Sequence Diagram (5/5): Included workflow sequence visualization.")
        else:
            diag_score = 0.0
            feedback.append("Sequence Diagram (0/5): Missing Mermaid sequence diagram.")

        if output_data.get("execution_metadata") or trace.get("duration_seconds") is not None:
            meta_score = 5.0
            feedback.append("Execution Metadata (5/5): Recorded execution duration and telemetry.")
        else:
            meta_score = 0.0
            feedback.append("Execution Metadata (0/5): Missing execution metadata.")

        if output_data.get("summary") or output_data.get("recommendation") or output_data.get("action_taken") or "summary" in report_text.lower():
            summary_score = 5.0
            feedback.append("Summary Report (5/5): Produced concise validation summary.")
        else:
            summary_score = 0.0
            feedback.append("Summary Report (0/5): Missing summary.")

        category_scores["Operational Artifacts"] = diag_score + meta_score + summary_score

        total_score = sum(category_scores.values())
        passed = total_score >= 80.0

        return RubricScorecard(
            profile_name="DETECTION_ENGINEERING_RUBRIC",
            total_score=total_score,
            max_score=100.0,
            passed=passed,
            category_scores=category_scores,
            feedback=feedback,
            metadata={"decision": output_data.get("recommendation") or output_data.get("action_taken")}
        )
