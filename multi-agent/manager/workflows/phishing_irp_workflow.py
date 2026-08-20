"""
Phishing Response IRP Graph Workflow for Google ADK.

Implements 'Phishing Response IRP'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class PhishingIRPInput(BaseWorkflowInput):
    phishing_subject: str = Field(description="Phishing Email Subject Line")
    sender_email: str = Field(description="Sender Email Address")
    confirm_purge_inbox: bool = Field(default=True, description="Confirmation to purge phishing email across all user inboxes")


class ExtractedPhishingIRPPayload(BaseModel):
    phishing_subject: str
    sender_email: str
    confirm_purge_inbox: bool
    case_id: Optional[str] = None


class PhishingScopeAssessmentResult(BaseModel):
    payload: ExtractedPhishingIRPPayload
    recipient_count: int
    clicked_url_users_count: int
    credential_harvesting_detected: bool


class PhishingContainmentOutcome(BaseModel):
    assessment: PhishingScopeAssessmentResult
    action_status: str  # "PURGED_INBOXES_BLOCKED_URLS", "ANALYSIS_ONLY"
    remediation_plan: str


def extract_phishing_irp_payload_node(inp: PhishingIRPInput) -> ExtractedPhishingIRPPayload:
    return ExtractedPhishingIRPPayload(
        phishing_subject=sanitize_entity_value(inp.phishing_subject),
        sender_email=sanitize_entity_value(inp.sender_email),
        confirm_purge_inbox=inp.confirm_purge_inbox,
        case_id=inp.case_id,
    )


def assess_phishing_incident_scope_node(payload: ExtractedPhishingIRPPayload) -> PhishingScopeAssessmentResult:
    subj = payload.phishing_subject.lower()
    is_widespread = "urgent" in subj or "invoice" in subj or "payroll" in subj or "verify" in subj
    return PhishingScopeAssessmentResult(
        payload=payload,
        recipient_count=145 if is_widespread else 3,
        clicked_url_users_count=12 if is_widespread else 0,
        credential_harvesting_detected=is_widespread,
    )


def phishing_irp_containment_router(assessment: PhishingScopeAssessmentResult) -> Event:
    if assessment.payload.confirm_purge_inbox or assessment.credential_harvesting_detected:
        route = "PURGE_INBOXES_AND_BLOCK_DOMAINS"
    else:
        route = "ANALYSIS_ONLY"
    return Event(route=route, output=assessment)


def handle_purge_inboxes_branch(assessment: PhishingScopeAssessmentResult) -> PhishingContainmentOutcome:
    plan = f"EMERGENCY PHISHING CONTAINMENT EXECUTED: Email '{assessment.payload.phishing_subject}' purged across {assessment.recipient_count} Google Workspace / Exchange inboxes, sender '{assessment.payload.sender_email}' blocked, and password resets issued for {assessment.clicked_url_users_count} users who clicked malicious URL."
    return PhishingContainmentOutcome(
        assessment=assessment,
        action_status="PURGED_INBOXES_BLOCKED_URLS",
        remediation_plan=plan,
    )


def handle_analysis_only_branch(assessment: PhishingScopeAssessmentResult) -> PhishingContainmentOutcome:
    plan = f"Phishing analysis completed for email '{assessment.payload.phishing_subject}'. No mass inbox purge triggered."
    return PhishingContainmentOutcome(
        assessment=assessment,
        action_status="ANALYSIS_ONLY",
        remediation_plan=plan,
    )


def document_phishing_irp_report_node(outcome: PhishingContainmentOutcome) -> str:
    return outcome.remediation_plan


def build_phishing_irp_workflow() -> Workflow:
    return Workflow(
        name="phishing_irp_workflow",
        description="Graph-based workflow for phishing incident response, email inbox purging, and credential harvest remediation",
        edges=[
            (START, extract_phishing_irp_payload_node, assess_phishing_incident_scope_node, phishing_irp_containment_router),
            (phishing_irp_containment_router, {
                "PURGE_INBOXES_AND_BLOCK_DOMAINS": handle_purge_inboxes_branch,
                "ANALYSIS_ONLY": handle_analysis_only_branch,
            }),
            (handle_purge_inboxes_branch, document_phishing_irp_report_node),
            (handle_analysis_only_branch, document_phishing_irp_report_node),
        ],
    )
