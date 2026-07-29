"""
Case Report Generation Graph Workflow for Google ADK.

Implements 'Case Report Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class CaseReportInput(BaseWorkflowInput):
    case_id: str = Field(description="SOAR Case ID")


class ExtractedCaseReportPayload(BaseModel):
    case_id: str


class FullCaseDetailsResult(BaseModel):
    payload: ExtractedCaseReportPayload
    case_title: str
    priority: str
    stage: str
    alerts_summary: List[str]


class CaseReportOutcome(BaseModel):
    details: FullCaseDetailsResult
    report_markdown: str


def extract_case_report_payload_node(inp: CaseReportInput) -> ExtractedCaseReportPayload:
    return ExtractedCaseReportPayload(
        case_id=sanitize_entity_value(inp.case_id),
    )


def fetch_full_case_details_node(payload: ExtractedCaseReportPayload) -> FullCaseDetailsResult:
    cid = payload.case_id
    is_crit = "CRIT" in cid or "900" in cid
    return FullCaseDetailsResult(
        payload=payload,
        case_title=f"Incident Case {cid}",
        priority="HIGH" if is_crit else "MEDIUM",
        stage="INVESTIGATION",
        alerts_summary=["Suspicious Authentication Event", "Endpoint Malware Detection"],
    )


def case_report_type_router(details: FullCaseDetailsResult) -> Event:
    if details.priority == "HIGH":
        route = "EXECUTIVE_CASE_REPORT"
    else:
        route = "STANDARD_CASE_REPORT"
    return Event(route=route, output=details)


def handle_executive_case_report_branch(details: FullCaseDetailsResult) -> CaseReportOutcome:
    md = f"# Executive Case Report: {details.case_title}\n\n- **Priority:** `{details.priority}`\n- **Alerts:** {details.alerts_summary}"
    return CaseReportOutcome(details=details, report_markdown=md)


def handle_standard_case_report_branch(details: FullCaseDetailsResult) -> CaseReportOutcome:
    md = f"# Standard Case Report: {details.case_title}\n\n- **Priority:** `{details.priority}`"
    return CaseReportOutcome(details=details, report_markdown=md)


def document_case_report_node(outcome: CaseReportOutcome) -> str:
    return outcome.report_markdown


def build_case_report_workflow() -> Workflow:
    return Workflow(
        name="case_report_workflow",
        description="Graph-based workflow for generating comprehensive SOAR case summaries and reports",
        edges=[
            (START, extract_case_report_payload_node, fetch_full_case_details_node, case_report_type_router),
            (case_report_type_router, {
                "EXECUTIVE_CASE_REPORT": handle_executive_case_report_branch,
                "STANDARD_CASE_REPORT": handle_standard_case_report_branch,
            }),
            (handle_executive_case_report_branch, document_case_report_node),
            (handle_standard_case_report_branch, document_case_report_node),
        ],
    )
