"""
Threat Hunting & Deep Analysis Runbook Rubric (100 Points Total).
Applied to Advanced Threat Hunting, APT Threat Hunt, IOC Threat Hunt,
Credential Access Hunt, Lateral Movement Hunt, and Proactive GTI Threat Hunts.
Derived from skills/hunting/ioc-threat-hunt/SKILL.md and skills/hunting/advanced-threat-hunting/SKILL.md.
"""

from typing import Any, Dict, List
from evals.evaluators.base import RubricScorecard
from evals.rubrics.base import BaseRubric


class ThreatHuntingRubric(BaseRubric):
    """Evaluator for the Threat Hunting & Deep Analysis Runbook Rubric."""

    @classmethod
    def evaluate(cls, output_data: Dict[str, Any], trace: Dict[str, Any] | None = None) -> RubricScorecard:
        category_scores: Dict[str, float] = {}
        feedback: List[str] = []
        trace = trace or {}

        report_text = output_data.get("report_markdown") or output_data.get("soar_comment") or str(output_data)

        # 1. Scope & Query (25 pts: 10 scope definition, 15 query/search execution)
        scope_score = 0.0
        query_score = 0.0
        has_scope = any(k in output_data for k in ["hunt_scope", "target_hostname", "source_hostname", "threat_actor_name", "campaign_or_actor_name", "ioc_list", "time_range_hours", "lookback_days", "case_id"])
        if has_scope or "scope" in report_text.lower() or "lookback" in report_text.lower():
            scope_score = 10.0
            feedback.append("Hunt Scope (10/10): Defined clear time range, target entities, and hunt scope.")
        else:
            scope_score = 5.0
            feedback.append("Hunt Scope (5/10): Partial hunt scope definition.")

        has_query = any(k in output_data for k in ["events", "search_summary", "psexec_service_installs", "wmi_remote_execution_count", "suspicious_process_names", "ioc_sightings", "findings"]) or "search" in report_text.lower() or "query" in report_text.lower() or "events" in report_text.lower()
        if has_query:
            query_score = 15.0
            feedback.append("Query Execution (15/15): Constructed and executed targeted SIEM / UDM queries.")
        else:
            query_score = 8.0
            feedback.append("Query Execution (8/15): Limited empirical query results returned.")
        category_scores["Scope & Query"] = scope_score + query_score

        # 2. Data Analysis & Correlation (30 pts: 15 analysis depth, 15 correlation across logs/intel)
        analysis_score = 0.0
        correlate_score = 0.0
        has_analysis = any(k in output_data for k in ["analysis", "assessment", "threat_status", "threat_level", "lateral_movement_detected", "lsass_dump_detected", "action_taken"]) or "detected" in report_text.lower() or "analysis" in report_text.lower()
        if has_analysis:
            analysis_score = 15.0
            feedback.append("Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.")
        else:
            analysis_score = 8.0
            feedback.append("Data Analysis (8/15): Minimal log analysis depth.")

        has_correlation = any(k in output_data for k in ["gti_summary", "threat_actor", "technique", "mitre", "target_hosts_targeted", "affected_users"]) or "mitre" in report_text.lower() or "correlation" in report_text.lower() or "ttp" in report_text.lower()
        if has_correlation or "intel" in report_text.lower():
            correlate_score = 15.0
            feedback.append("Telemetry Correlation (15/15): Correlated host activity, network events, and threat intelligence.")
        else:
            correlate_score = 10.0
            feedback.append("Telemetry Correlation (10/15): Partial cross-data source correlation.")
        category_scores["Data Analysis & Correlation"] = analysis_score + correlate_score

        # 3. Findings Classification (15 pts)
        has_verdict = any(k in output_data for k in ["verdict", "threat_status", "threat_level", "findings", "action_taken", "action_status", "action_recommendation", "recommended_action"]) or "clean" in report_text.lower() or "confirmed" in report_text.lower() or "threat" in report_text.lower()
        if has_verdict:
            findings_score = 15.0
            feedback.append("Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).")
        else:
            findings_score = 8.0
            feedback.append("Findings Classification (8/15): Inconclusive finding disposition.")
        category_scores["Findings Classification"] = findings_score

        # 4. Hunt Documentation (15 pts)
        soar_comment = output_data.get("soar_comment") or output_data.get("report_markdown") or output_data.get("action_taken") or ""
        if isinstance(soar_comment, str) and len(soar_comment.strip()) > 30:
            doc_score = 15.0
            feedback.append("Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.")
        elif isinstance(soar_comment, str) and len(soar_comment.strip()) > 0:
            doc_score = 10.0
            feedback.append("Hunt Documentation (10/15): Brief hunt documentation recorded.")
        else:
            doc_score = 0.0
            feedback.append("Hunt Documentation (0/15): Missing hunt documentation.")
        category_scores["Hunt Documentation"] = doc_score

        # 5. Operational Artifacts (15 pts: 5 sequence diagram, 5 metadata, 5 summary)
        diag_score = 0.0
        meta_score = 0.0
        summary_score = 0.0

        if output_data.get("has_sequence_diagram") or "mermaid" in str(report_text).lower():
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

        if output_data.get("summary") or output_data.get("action_taken") or output_data.get("recommended_action") or output_data.get("action_recommendation"):
            summary_score = 5.0
            feedback.append("Summary Report (5/5): Generated actionable hunt lead summary.")
        else:
            summary_score = 0.0
            feedback.append("Summary Report (0/5): Missing summary.")

        category_scores["Operational Artifacts"] = diag_score + meta_score + summary_score

        total_score = sum(category_scores.values())
        passed = total_score >= 80.0

        return RubricScorecard(
            profile_name="THREAT_HUNTING_RUBRIC",
            total_score=total_score,
            max_score=100.0,
            passed=passed,
            category_scores=category_scores,
            feedback=feedback,
            metadata={"findings": output_data.get("threat_status") or output_data.get("threat_level") or output_data.get("action_taken")}
        )
