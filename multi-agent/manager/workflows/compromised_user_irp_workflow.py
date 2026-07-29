"""
Compromised User Account Response IRP Graph Workflow for Google ADK.

Implements 'Compromised User Account Response IRP'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class CompromisedUserIRPInput(BaseWorkflowInput):
    user_id: str = Field(description="Compromised User ID / Principal Email")
    confirm_account_disable: bool = Field(default=True, description="Confirmation to disable account & revoke sessions")


class ExtractedUserIRPPayload(BaseModel):
    user_id: str
    confirm_account_disable: bool
    case_id: Optional[str] = None


class UserImpactAssessmentResult(BaseModel):
    payload: ExtractedUserIRPPayload
    user_privilege_level: str  # "DOMAIN_ADMIN", "REGULAR_USER"
    active_sessions_count: int
    data_exfiltration_risk: bool


class UserContainmentOutcome(BaseModel):
    assessment: UserImpactAssessmentResult
    account_status: str  # "ACCOUNT_DISABLED_SESSIONS_REVOKED", "MONITORING_ONLY"
    remediation_action_plan: str


def extract_user_irp_payload_node(inp: CompromisedUserIRPInput) -> ExtractedUserIRPPayload:
    return ExtractedUserIRPPayload(
        user_id=sanitize_entity_value(inp.user_id),
        confirm_account_disable=inp.confirm_account_disable,
        case_id=inp.case_id,
    )


def assess_user_compromise_impact_node(payload: ExtractedUserIRPPayload) -> UserImpactAssessmentResult:
    uid = payload.user_id.lower()
    is_admin = "admin" in uid or "vip" in uid or "root" in uid
    return UserImpactAssessmentResult(
        payload=payload,
        user_privilege_level="DOMAIN_ADMIN" if is_admin else "REGULAR_USER",
        active_sessions_count=8 if is_admin else 2,
        data_exfiltration_risk=is_admin,
    )


def user_containment_router(assessment: UserImpactAssessmentResult) -> Event:
    if assessment.payload.confirm_account_disable or assessment.user_privilege_level == "DOMAIN_ADMIN":
        route = "DISABLE_ACCOUNT_REVOKE_SESSIONS"
    else:
        route = "MONITORING_ONLY"
    return Event(route=route, output=assessment)


def handle_disable_account_branch(assessment: UserImpactAssessmentResult) -> UserContainmentOutcome:
    plan = f"EMERGENCY CONTAINMENT EXECUTED for user {assessment.payload.user_id} ({assessment.user_privilege_level}): Account disabled in IdP/Okta, all {assessment.active_sessions_count} active OAuth/SAML tokens revoked, and password reset forced."
    return UserContainmentOutcome(
        assessment=assessment,
        account_status="ACCOUNT_DISABLED_SESSIONS_REVOKED",
        remediation_action_plan=plan,
    )


def handle_monitoring_only_branch(assessment: UserImpactAssessmentResult) -> UserContainmentOutcome:
    plan = f"User {assessment.payload.user_id} placed under heightened SIEM monitoring without immediate account disablement."
    return UserContainmentOutcome(
        assessment=assessment,
        account_status="MONITORING_ONLY",
        remediation_action_plan=plan,
    )


def document_user_irp_report_node(outcome: UserContainmentOutcome) -> str:
    return outcome.remediation_action_plan


def build_compromised_user_irp_workflow() -> Workflow:
    return Workflow(
        name="compromised_user_irp_workflow",
        description="Graph-based workflow for compromised user account incident response containment and credential revocation",
        edges=[
            (START, extract_user_irp_payload_node, assess_user_compromise_impact_node, user_containment_router),
            (user_containment_router, {
                "DISABLE_ACCOUNT_REVOKE_SESSIONS": handle_disable_account_branch,
                "MONITORING_ONLY": handle_monitoring_only_branch,
            }),
            (handle_disable_account_branch, document_user_irp_report_node),
            (handle_monitoring_only_branch, document_user_irp_report_node),
        ],
    )
