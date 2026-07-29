"""
Triage Alerts Graph Workflow for Google ADK.

Implements 'Triage Alerts Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class TriageAlertsInput(BaseModel):
    alert_ids: List[str] = Field(description="List of Alert IDs to triage")
    case_id: Optional[str] = Field(default=None, description="Associated SOAR Case ID")


class ExtractedAlertsPayload(BaseModel):
    alert_ids: List[str]
    case_id: Optional[str] = None


class AlertEnrichmentSummary(BaseModel):
    payload: ExtractedAlertsPayload
    high_severity_count: int
    malicious_entity_count: int
    overall_triage_score: int


class AlertTriageOutcome(BaseModel):
    summary: AlertEnrichmentSummary
    disposition: str  # "ESCALATE_INCIDENT", "CLOSE_FALSE_POSITIVE"
    recommended_comment: str


def extract_alerts_payload_node(inp: TriageAlertsInput) -> ExtractedAlertsPayload:
    return ExtractedAlertsPayload(
        alert_ids=[a.strip() for a in inp.alert_ids],
        case_id=inp.case_id.strip() if inp.case_id else None,
    )


def enrich_and_assess_alerts_node(payload: ExtractedAlertsPayload) -> AlertEnrichmentSummary:
    has_crit = any("crit" in a.lower() or "high" in a.lower() or "900" in a for a in payload.alert_ids)
    return AlertEnrichmentSummary(
        payload=payload,
        high_severity_count=len(payload.alert_ids) if has_crit else 0,
        malicious_entity_count=2 if has_crit else 0,
        overall_triage_score=85 if has_crit else 10,
    )


def alerts_disposition_router(summary: AlertEnrichmentSummary) -> Event:
    if summary.overall_triage_score >= 50:
        route = "ESCALATE_INCIDENT"
    else:
        route = "CLOSE_FALSE_POSITIVE"
    return Event(route=route, output=summary)


def handle_escalate_incident_branch(summary: AlertEnrichmentSummary) -> AlertTriageOutcome:
    return AlertTriageOutcome(
        summary=summary,
        disposition="ESCALATE_INCIDENT",
        recommended_comment=f"Alert Triage Complete: Escalate case {summary.payload.case_id} due to high severity alerts ({summary.payload.alert_ids}). Score: {summary.overall_triage_score}/100.",
    )


def handle_close_fp_alerts_branch(summary: AlertEnrichmentSummary) -> AlertTriageOutcome:
    return AlertTriageOutcome(
        summary=summary,
        disposition="CLOSE_FALSE_POSITIVE",
        recommended_comment=f"Alert Triage Complete: Close alerts ({summary.payload.alert_ids}) as False Positive / Low Risk.",
    )


def document_alerts_triage_report_node(outcome: AlertTriageOutcome) -> str:
    return outcome.recommended_comment


def build_triage_alerts_workflow() -> Workflow:
    return Workflow(
        name="triage_alerts_workflow",
        description="Graph-based workflow for alert triage, entity enrichment, and severity-based disposition routing",
        edges=[
            (START, extract_alerts_payload_node, enrich_and_assess_alerts_node, alerts_disposition_router),
            (alerts_disposition_router, {
                "ESCALATE_INCIDENT": handle_escalate_incident_branch,
                "CLOSE_FALSE_POSITIVE": handle_close_fp_alerts_branch,
            }),
            (handle_escalate_incident_branch, document_alerts_triage_report_node),
            (handle_close_fp_alerts_branch, document_alerts_triage_report_node),
        ],
    )
