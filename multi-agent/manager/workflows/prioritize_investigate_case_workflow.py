"""
Prioritize and Investigate a Case Graph Workflow for Google ADK.

Implements 'Prioritize and Investigate a Case Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class PrioritizeCaseInput(BaseWorkflowInput):
    case_id: str = Field(description="SOAR Case ID to prioritize and investigate")


class ExtractedPrioritizationPayload(BaseModel):
    case_id: str


class CaseRiskScoreResult(BaseModel):
    payload: ExtractedPrioritizationPayload
    risk_score: int
    assigned_priority: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    critical_entities: List[str]


class PrioritizedInvestigationOutcome(BaseModel):
    score: CaseRiskScoreResult
    investigation_disposition: str  # "IMMEDIATE_ESCALATION", "STANDARD_TRIAGE"
    soar_comment_text: str


def extract_prioritization_payload_node(inp: PrioritizeCaseInput) -> ExtractedPrioritizationPayload:
    return ExtractedPrioritizationPayload(
        case_id=sanitize_entity_value(inp.case_id),
    )


def compute_case_risk_score_node(payload: ExtractedPrioritizationPayload) -> CaseRiskScoreResult:
    cid = payload.case_id
    is_crit = "900" in cid or "CRIT" in cid or "MAL" in cid
    return CaseRiskScoreResult(
        payload=payload,
        risk_score=92 if is_crit else 35,
        assigned_priority="CRITICAL" if is_crit else "MEDIUM",
        critical_entities=["vip-user@corp.com", "srv-db-prod-01"] if is_crit else [],
    )


def case_risk_router(score: CaseRiskScoreResult) -> Event:
    if score.risk_score >= 80:
        route = "IMMEDIATE_ESCALATION"
    else:
        route = "STANDARD_TRIAGE"
    return Event(route=route, output=score)


def handle_immediate_escalation_branch(score: CaseRiskScoreResult) -> PrioritizedInvestigationOutcome:
    comment = f"Priority elevated to {score.assigned_priority} (Risk Score: {score.risk_score}/100) for Case {score.payload.case_id}. Critical entities: {score.critical_entities}."
    return PrioritizedInvestigationOutcome(
        score=score,
        investigation_disposition="IMMEDIATE_ESCALATION",
        soar_comment_text=comment,
    )


def handle_standard_triage_branch(score: CaseRiskScoreResult) -> PrioritizedInvestigationOutcome:
    comment = f"Priority maintained at {score.assigned_priority} (Risk Score: {score.risk_score}/100) for Case {score.payload.case_id}."
    return PrioritizedInvestigationOutcome(
        score=score,
        investigation_disposition="STANDARD_TRIAGE",
        soar_comment_text=comment,
    )


def document_prioritization_report_node(outcome: PrioritizedInvestigationOutcome) -> str:
    return outcome.soar_comment_text


def build_prioritize_investigate_case_workflow() -> Workflow:
    return Workflow(
        name="prioritize_investigate_case_workflow",
        description="Graph-based workflow for calculating case risk scores, updating SOAR priority, and routing investigation pathways",
        edges=[
            (START, extract_prioritization_payload_node, compute_case_risk_score_node, case_risk_router),
            (case_risk_router, {
                "IMMEDIATE_ESCALATION": handle_immediate_escalation_branch,
                "STANDARD_TRIAGE": handle_standard_triage_branch,
            }),
            (handle_immediate_escalation_branch, document_prioritization_report_node),
            (handle_standard_triage_branch, document_prioritization_report_node),
        ],
    )
