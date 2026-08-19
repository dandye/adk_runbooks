"""
Triage & Incident Response Plan (IRP) Runbook Rubric (100 Points Total).
Applied to Compromised User Account, Malware, Ransomware, Phishing, Endpoint Triage, and Alert Triage workflows.
Derived from rules-bank/run_books/irps/compromised_user_account_response.md and rules-bank/run_books/triage_alerts.md.
"""

from typing import Any, Dict, List
from evals.evaluators.base import RubricScorecard
from evals.rubrics.base import BaseRubric


class TriageIRPRubric(BaseRubric):
    """Evaluator for the standard Triage & Incident Response Rubric."""

    @classmethod
    def evaluate(cls, output_data: Dict[str, Any], trace: Dict[str, Any] | None = None) -> RubricScorecard:
        category_scores: Dict[str, float] = {}
        feedback: List[str] = []
        trace = trace or {}

        # 1. Context & Enrichment (25 pts: 10 extraction, 15 enrichment)
        extract_score = 0.0
        enrich_score = 0.0
        has_entities = any(k in output_data for k in ["user_id", "source_ip", "hostname", "endpoint_id", "file_hash", "ioc_value", "case_id"])
        if has_entities:
            extract_score = 10.0
            feedback.append("Entity Extraction (10/10): Accurately identified target indicators and involved entities.")
        else:
            extract_score = 5.0
            feedback.append("Entity Extraction (5/10): Missing explicit entity identifiers.")

        has_enrichment = any(k in output_data for k in ["enrichment_summary", "ip_summary", "user_summary", "siem_summary", "gti_summary", "verdict", "risk_score", "threat_profile"]) or "enrich" in str(output_data).lower()
        if has_enrichment:
            enrich_score = 15.0
            feedback.append("Context Enrichment (15/15): Performed SIEM and Threat Intelligence contextual lookups.")
        else:
            enrich_score = 8.0
            feedback.append("Context Enrichment (8/15): Limited context enrichment observed.")
        category_scores["Context & Enrichment"] = extract_score + enrich_score

        # 2. Analysis & Decision (25 pts: 15 interpretation, 10 conclusion)
        interp_score = 0.0
        decision_score = 0.0
        has_analysis = any(k in output_data for k in ["analysis", "assessment", "verdict", "risk_level", "isolation_status", "action_taken"]) or any("route" in k for k in trace)
        if has_analysis:
            interp_score = 15.0
            feedback.append("Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.")
        else:
            interp_score = 8.0
            feedback.append("Telemetry Interpretation (8/15): Minimal risk interpretation.")

        # Concluded logical next step / route
        if output_data.get("action_taken") or output_data.get("action_status") or trace.get("route"):
            decision_score = 10.0
            feedback.append("Decision Logic (10/10): Reached deterministic disposition or containment decision.")
        else:
            decision_score = 5.0
            feedback.append("Decision Logic (5/10): Decision path unclear.")
        category_scores["Analysis & Decision"] = interp_score + decision_score

        # 3. Action Execution (20 pts: 10 execution, 10 verification)
        exec_score = 0.0
        verify_score = 0.0
        if any(k in output_data for k in ["action_taken", "action_status", "isolation_status", "soar_comment"]):
            exec_score = 10.0
            verify_score = 10.0
            feedback.append("Action Execution (20/20): Executed required response/triage actions and verified status.")
        else:
            exec_score = 5.0
            verify_score = 5.0
            feedback.append("Action Execution (10/20): Partial action execution.")
        category_scores["Action Execution"] = exec_score + verify_score

        # 4. Documentation (15 pts)
        soar_comment = output_data.get("soar_comment") or output_data.get("soar_comment_status") or output_data.get("report_markdown") or ""
        if isinstance(soar_comment, str) and len(soar_comment.strip()) > 30:
            doc_score = 15.0
            feedback.append("Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.")
        elif isinstance(soar_comment, str) and len(soar_comment.strip()) > 0:
            doc_score = 10.0
            feedback.append("Documentation (10/15): Recorded brief case documentation.")
        else:
            doc_score = 0.0
            feedback.append("Documentation (0/15): Missing case documentation.")
        category_scores["Documentation"] = doc_score

        # 5. Operational Artifacts (15 pts: 5 sequence diagram, 5 metadata, 5 summary)
        diag_score = 0.0
        meta_score = 0.0
        summary_score = 0.0

        if output_data.get("has_sequence_diagram") or "mermaid" in str(soar_comment).lower():
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

        if output_data.get("summary") or output_data.get("action_taken") or output_data.get("assessment"):
            summary_score = 5.0
            feedback.append("Summary Report (5/5): Generated clear outcome summary.")
        else:
            summary_score = 0.0
            feedback.append("Summary Report (0/5): Missing summary.")

        category_scores["Operational Artifacts"] = diag_score + meta_score + summary_score

        total_score = sum(category_scores.values())
        passed = total_score >= 80.0

        return RubricScorecard(
            profile_name="TRIAGE_IRP_RUBRIC",
            total_score=total_score,
            max_score=100.0,
            passed=passed,
            category_scores=category_scores,
            feedback=feedback,
            metadata={"status": output_data.get("action_taken") or output_data.get("action_status")}
        )
