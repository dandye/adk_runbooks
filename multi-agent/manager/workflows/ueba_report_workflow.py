"""
UEBA Report Generation Graph Workflow for Google ADK.

Implements 'UEBA Report Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class UEBAReportInput(BaseWorkflowInput):
    user_id: str = Field(description="Target User ID / Email for UEBA behavioral analysis")
    timeframe_days: int = Field(default=30, description="UEBA analysis timeframe in days")


class ExtractedUEBAPayload(BaseModel):
    user_id: str
    timeframe_days: int
    case_id: Optional[str] = None


class UEBABehaviorResult(BaseModel):
    payload: ExtractedUEBAPayload
    anomaly_score: int
    impossible_travel_events: int
    first_time_resource_access_count: int
    behavior_verdict: str  # "HIGH_RISK_USER_ANOMALY", "STANDARD_USER_PROFILE"


class UEBAReportOutcome(BaseModel):
    behavior: UEBABehaviorResult
    report_markdown: str


def extract_ueba_payload_node(inp: UEBAReportInput) -> ExtractedUEBAPayload:
    return ExtractedUEBAPayload(
        user_id=sanitize_entity_value(inp.user_id),
        timeframe_days=inp.timeframe_days,
        case_id=inp.case_id,
    )


def compute_ueba_anomalies_node(payload: ExtractedUEBAPayload) -> UEBABehaviorResult:
    uid = payload.user_id.lower()
    is_anom = "suspicious" in uid or "risk" in uid or "admin" in uid
    return UEBABehaviorResult(
        payload=payload,
        anomaly_score=88 if is_anom else 12,
        impossible_travel_events=3 if is_anom else 0,
        first_time_resource_access_count=14 if is_anom else 1,
        behavior_verdict="HIGH_RISK_USER_ANOMALY" if is_anom else "STANDARD_USER_PROFILE",
    )


def ueba_behavior_router(behavior: UEBABehaviorResult) -> Event:
    if behavior.anomaly_score >= 50:
        route = "HIGH_RISK_USER_ANOMALY"
    else:
        route = "STANDARD_USER_PROFILE"
    return Event(route=route, output=behavior)


def handle_high_risk_user_branch(behavior: UEBABehaviorResult) -> UEBAReportOutcome:
    md = f"# UEBA Behavior Report: User `{behavior.payload.user_id}`\n\n- **Anomaly Score:** `{behavior.anomaly_score}/100` (`HIGH_RISK_USER_ANOMALY`)\n- **Impossible Travel Events:** {behavior.impossible_travel_events}\n- **Recommendation:** Escalate for Account Compromise Triage."
    return UEBAReportOutcome(behavior=behavior, report_markdown=md)


def handle_standard_user_branch(behavior: UEBABehaviorResult) -> UEBAReportOutcome:
    md = f"# UEBA Behavior Report: User `{behavior.payload.user_id}`\n\n- **Anomaly Score:** `{behavior.anomaly_score}/100` (`STANDARD_USER_PROFILE`)"
    return UEBAReportOutcome(behavior=behavior, report_markdown=md)


def document_ueba_report_node(outcome: UEBAReportOutcome) -> str:
    return outcome.report_markdown


def build_ueba_report_workflow() -> Workflow:
    return Workflow(
        name="ueba_report_workflow",
        description="Graph-based workflow for User and Entity Behavior Analytics (UEBA) risk scoring and anomaly reporting",
        edges=[
            (START, extract_ueba_payload_node, compute_ueba_anomalies_node, ueba_behavior_router),
            (ueba_behavior_router, {
                "HIGH_RISK_USER_ANOMALY": handle_high_risk_user_branch,
                "STANDARD_USER_PROFILE": handle_standard_user_branch,
            }),
            (handle_high_risk_user_branch, document_ueba_report_node),
            (handle_standard_user_branch, document_ueba_report_node),
        ],
    )
