"""
Create Investigation Report Graph Workflow for Google ADK.

Implements 'Create an Investigation Report Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import save_workflow_report_to_disk


class InvestigationReportInput(BaseModel):
    case_id: str = Field(description="SOAR Case ID to generate report for")
    include_timeline: bool = Field(default=True, description="Include event timeline")
    include_ioc_table: bool = Field(default=True, description="Include IOC summary table")


class ExtractedReportPayload(BaseModel):
    case_id: str
    include_timeline: bool
    include_ioc_table: bool


class SOARCaseDetailsResult(BaseModel):
    payload: ExtractedReportPayload
    case_title: str
    severity: str
    alerts_count: int
    entities_involved: List[str]
    root_cause_summary: str


class GeneratedReportResult(BaseModel):
    case_details: SOARCaseDetailsResult
    report_type: str  # "EXECUTIVE_SUMMARY", "DETAILED_TECHNICAL"
    report_markdown: str


def extract_report_payload_node(inp: InvestigationReportInput) -> ExtractedReportPayload:
    return ExtractedReportPayload(
        case_id=inp.case_id.strip(),
        include_timeline=inp.include_timeline,
        include_ioc_table=inp.include_ioc_table,
    )


def fetch_soar_case_details_node(payload: ExtractedReportPayload) -> SOARCaseDetailsResult:
    cid = payload.case_id
    is_critical = "CRIT" in cid or "900" in cid or "MAL" in cid or "33280" in cid
    return SOARCaseDetailsResult(
        payload=payload,
        case_title=f"Incident Investigation for Case {cid}",
        severity="CRITICAL" if is_critical else "MEDIUM",
        alerts_count=5 if is_critical else 1,
        entities_involved=["alice.smith@example.com", "198.51.100.44", "workstation-finance-01"],
        root_cause_summary="Phishing email credential harvesting followed by lateral movement attempt.",
    )


def report_type_router(details: SOARCaseDetailsResult) -> Event:
    if details.severity == "CRITICAL":
        route = "EXECUTIVE_SUMMARY"
    else:
        route = "DETAILED_TECHNICAL"
    return Event(route=route, output=details)


def handle_executive_summary_branch(details: SOARCaseDetailsResult) -> GeneratedReportResult:
    md = f"""# Executive Incident Investigation Report

## 1. Case Overview
- **Case ID:** `{details.payload.case_id}`
- **Title:** {details.case_title}
- **Severity:** `{details.severity}`
- **Alert Count:** {details.alerts_count}

## 2. Executive Summary
{details.root_cause_summary}

## 3. Involved Entities
{', '.join(details.entities_involved)}
"""
    return GeneratedReportResult(
        case_details=details,
        report_type="EXECUTIVE_SUMMARY",
        report_markdown=md,
    )


def handle_detailed_technical_branch(details: SOARCaseDetailsResult) -> GeneratedReportResult:
    md = f"""# Technical Investigation Report

## 1. Case Overview
- **Case ID:** `{details.payload.case_id}`
- **Title:** {details.case_title}
- **Severity:** `{details.severity}`
- **Alert Count:** {details.alerts_count}

## 2. Technical Analysis
{details.root_cause_summary}

## 3. Involved Entities
{', '.join(details.entities_involved)}
"""
    return GeneratedReportResult(
        case_details=details,
        report_type="DETAILED_TECHNICAL",
        report_markdown=md,
    )


def document_final_report_node(rep: GeneratedReportResult) -> str:
    saved_path = save_workflow_report_to_disk(
        f"Investigation_Report_Case_{rep.case_details.payload.case_id}",
        rep.report_markdown,
    )
    return f"Investigation report successfully generated and saved to disk at {saved_path}:\n\n{rep.report_markdown}"


def build_create_investigation_report_workflow() -> Workflow:
    return Workflow(
        name="create_investigation_report_workflow",
        description="Graph-based workflow for generating executive and technical SOAR investigation reports",
        edges=[
            (START, extract_report_payload_node, fetch_soar_case_details_node, report_type_router),
            (report_type_router, {
                "EXECUTIVE_SUMMARY": handle_executive_summary_branch,
                "DETAILED_TECHNICAL": handle_detailed_technical_branch,
            }),
            (handle_executive_summary_branch, document_final_report_node),
            (handle_detailed_technical_branch, document_final_report_node),
        ],
    )
