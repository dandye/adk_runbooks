"""
Alert Report Generation Graph Workflow for Google ADK.

Implements 'Alert Report Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class AlertReportInput(BaseWorkflowInput):
    alert_id: str = Field(description="Alert ID to generate report for")


class ExtractedAlertReportPayload(BaseModel):
    alert_id: str
    case_id: Optional[str] = None


class AlertDetailsResult(BaseModel):
    payload: ExtractedAlertReportPayload
    alert_title: str
    severity: str
    entities: List[str]
    rule_id: str


class AlertReportOutcome(BaseModel):
    details: AlertDetailsResult
    report_markdown: str


def extract_alert_report_payload_node(inp: AlertReportInput) -> ExtractedAlertReportPayload:
    return ExtractedAlertReportPayload(
        alert_id=sanitize_entity_value(inp.alert_id),
        case_id=inp.case_id,
    )


def fetch_alert_details_node(payload: ExtractedAlertReportPayload) -> AlertDetailsResult:
    aid = payload.alert_id
    is_high = "crit" in aid.lower() or "high" in aid.lower() or "900" in aid
    return AlertDetailsResult(
        payload=payload,
        alert_title=f"Security Alert {aid}",
        severity="HIGH" if is_high else "MEDIUM",
        entities=["alice.smith@example.com", "198.51.100.44"],
        rule_id="RULE-SUSPICIOUS-AUTH-01",
    )


def alert_report_type_router(details: AlertDetailsResult) -> Event:
    if details.severity == "HIGH":
        route = "HIGH_SEVERITY_ALERT_REPORT"
    else:
        route = "STANDARD_ALERT_REPORT"
    return Event(route=route, output=details)


def handle_high_severity_report_branch(details: AlertDetailsResult) -> AlertReportOutcome:
    md = f"# High Severity Alert Report: {details.alert_title}\n\n- **Rule ID:** `{details.rule_id}`\n- **Entities:** {details.entities}"
    return AlertReportOutcome(details=details, report_markdown=md)


def handle_standard_report_branch(details: AlertDetailsResult) -> AlertReportOutcome:
    md = f"# Standard Alert Report: {details.alert_title}\n\n- **Rule ID:** `{details.rule_id}`"
    return AlertReportOutcome(details=details, report_markdown=md)


def document_alert_report_node(outcome: AlertReportOutcome) -> str:
    return outcome.report_markdown


def build_alert_report_workflow() -> Workflow:
    return Workflow(
        name="alert_report_workflow",
        description="Graph-based workflow for generating formatted alert triage reports",
        edges=[
            (START, extract_alert_report_payload_node, fetch_alert_details_node, alert_report_type_router),
            (alert_report_type_router, {
                "HIGH_SEVERITY_ALERT_REPORT": handle_high_severity_report_branch,
                "STANDARD_ALERT_REPORT": handle_standard_report_branch,
            }),
            (handle_high_severity_report_branch, document_alert_report_node),
            (handle_standard_report_branch, document_alert_report_node),
        ],
    )
