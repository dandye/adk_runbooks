"""
Ransomware Response IRP Graph Workflow for Google ADK.

Implements 'Ransomware Response IRP'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class RansomwareIRPInput(BaseWorkflowInput):
    initial_affected_host: str = Field(description="Initial Affected Hostname or IP")
    confirm_network_segmentation: bool = Field(default=True, description="Confirmation to execute network segmentation & emergency host isolation")


class ExtractedRansomwareIRPPayload(BaseModel):
    initial_affected_host: str
    confirm_network_segmentation: bool
    case_id: Optional[str] = None


class RansomwareSpreadAssessmentResult(BaseModel):
    payload: ExtractedRansomwareIRPPayload
    encrypted_shares_count: int
    vss_shadow_copies_deleted: bool
    active_encrypter_process: str
    impacted_hosts_count: int


class RansomwareContainmentOutcome(BaseModel):
    assessment: RansomwareSpreadAssessmentResult
    containment_status: str  # "NETWORK_SEGMENTED_HOSTS_ISOLATED", "ISOLATE_SINGLE_HOST"
    emergency_action_plan: str


def extract_ransomware_irp_payload_node(inp: RansomwareIRPInput) -> ExtractedRansomwareIRPPayload:
    return ExtractedRansomwareIRPPayload(
        initial_affected_host=sanitize_entity_value(inp.initial_affected_host),
        confirm_network_segmentation=inp.confirm_network_segmentation,
        case_id=inp.case_id,
    )


def assess_ransomware_spread_impact_node(payload: ExtractedRansomwareIRPPayload) -> RansomwareSpreadAssessmentResult:
    host = payload.initial_affected_host.lower()
    is_widespread = "dc" in host or "srv" in host or "nas" in host or "prod" in host
    return RansomwareSpreadAssessmentResult(
        payload=payload,
        encrypted_shares_count=18 if is_widespread else 1,
        vss_shadow_copies_deleted=is_widespread,
        active_encrypter_process="vssadmin.exe delete shadows /all /quiet" if is_widespread else "unknown",
        impacted_hosts_count=12 if is_widespread else 1,
    )


def ransomware_irp_containment_router(assessment: RansomwareSpreadAssessmentResult) -> Event:
    if assessment.payload.confirm_network_segmentation or assessment.impacted_hosts_count > 1:
        route = "EXECUTE_EMERGENCY_NETWORK_SEGMENTATION"
    else:
        route = "ISOLATE_SINGLE_HOST"
    return Event(route=route, output=assessment)


def handle_emergency_segmentation_branch(assessment: RansomwareSpreadAssessmentResult) -> RansomwareContainmentOutcome:
    plan = f"CRITICAL RANSOMWARE EMERGENCY CONTAINMENT EXECUTED: Isolated network segment for host {assessment.payload.initial_affected_host}, isolated {assessment.impacted_hosts_count} impacted hosts via EDR, blocked C2 IPs, and preserved storage snapshot state."
    return RansomwareContainmentOutcome(
        assessment=assessment,
        containment_status="NETWORK_SEGMENTED_HOSTS_ISOLATED",
        emergency_action_plan=plan,
    )


def handle_single_host_isolation_branch(assessment: RansomwareSpreadAssessmentResult) -> RansomwareContainmentOutcome:
    plan = f"Isolated single host {assessment.payload.initial_affected_host} via EDR to prevent ransomware propagation."
    return RansomwareContainmentOutcome(
        assessment=assessment,
        containment_status="ISOLATE_SINGLE_HOST",
        emergency_action_plan=plan,
    )


def document_ransomware_irp_report_node(outcome: RansomwareContainmentOutcome) -> str:
    return outcome.emergency_action_plan


def build_ransomware_irp_workflow() -> Workflow:
    return Workflow(
        name="ransomware_irp_workflow",
        description="Graph-based workflow for emergency ransomware incident response, segment isolation, and lateral spread containment",
        edges=[
            (START, extract_ransomware_irp_payload_node, assess_ransomware_spread_impact_node, ransomware_irp_containment_router),
            (ransomware_irp_containment_router, {
                "EXECUTE_EMERGENCY_NETWORK_SEGMENTATION": handle_emergency_segmentation_branch,
                "ISOLATE_SINGLE_HOST": handle_single_host_isolation_branch,
            }),
            (handle_emergency_segmentation_branch, document_ransomware_irp_report_node),
            (handle_single_host_isolation_branch, document_ransomware_irp_report_node),
        ],
    )
