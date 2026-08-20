"""
Post Incident Review Graph Workflow for Google ADK.

Implements 'Post Incident Review Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class PIRInput(BaseWorkflowInput):
    incident_case_id: str = Field(description="Incident SOAR Case ID for Post-Incident Review")


class ExtractedPIRPayload(BaseModel):
    incident_case_id: str


class IncidentMetricsResult(BaseModel):
    payload: ExtractedPIRPayload
    incident_severity: str
    mttd_minutes: int
    mttr_minutes: int
    lessons_learned_count: int


class PIRWorkflowOutcome(BaseModel):
    metrics: IncidentMetricsResult
    review_status: str  # "PIR_ACTION_ITEMS_CREATED", "PIR_ARCHIVED"
    report_markdown: str


def extract_pir_payload_node(inp: PIRInput) -> ExtractedPIRPayload:
    return ExtractedPIRPayload(
        incident_case_id=sanitize_entity_value(inp.incident_case_id),
    )


def compute_incident_metrics_node(payload: ExtractedPIRPayload) -> IncidentMetricsResult:
    cid = payload.incident_case_id
    is_crit = "CRIT" in cid or "900" in cid
    return IncidentMetricsResult(
        payload=payload,
        incident_severity="CRITICAL" if is_crit else "HIGH",
        mttd_minutes=14 if is_crit else 45,
        mttr_minutes=120 if is_crit else 300,
        lessons_learned_count=4 if is_crit else 1,
    )


def pir_outcome_router(metrics: IncidentMetricsResult) -> Event:
    if metrics.lessons_learned_count > 2:
        route = "PIR_ACTION_ITEMS_CREATED"
    else:
        route = "PIR_ARCHIVED"
    return Event(route=route, output=metrics)


def handle_action_items_created_branch(metrics: IncidentMetricsResult) -> PIRWorkflowOutcome:
    md = f"# Post-Incident Review (PIR): Case {metrics.payload.incident_case_id}\n\n- **MTTD:** {metrics.mttd_minutes} min | **MTTR:** {metrics.mttr_minutes} min\n- **Action Items Created:** {metrics.lessons_learned_count} Jira/SOAR remediation tasks."
    return PIRWorkflowOutcome(metrics=metrics, review_status="PIR_ACTION_ITEMS_CREATED", report_markdown=md)


def handle_pir_archived_branch(metrics: IncidentMetricsResult) -> PIRWorkflowOutcome:
    md = f"# Post-Incident Review (PIR): Case {metrics.payload.incident_case_id}\n\n- **Status:** Archived without follow-up tasks."
    return PIRWorkflowOutcome(metrics=metrics, review_status="PIR_ARCHIVED", report_markdown=md)


def document_pir_report_node(outcome: PIRWorkflowOutcome) -> str:
    return outcome.report_markdown


def build_post_incident_review_workflow() -> Workflow:
    return Workflow(
        name="post_incident_review_workflow",
        description="Graph-based workflow for post-incident review (PIR) metrics analysis and action item tracking",
        edges=[
            (START, extract_pir_payload_node, compute_incident_metrics_node, pir_outcome_router),
            (pir_outcome_router, {
                "PIR_ACTION_ITEMS_CREATED": handle_action_items_created_branch,
                "PIR_ARCHIVED": handle_pir_archived_branch,
            }),
            (handle_action_items_created_branch, document_pir_report_node),
            (handle_pir_archived_branch, document_pir_report_node),
        ],
    )
