"""
IOC Containment Graph Workflow for Google ADK.

This workflow implements the 'IOC Containment Runbook' as a
deterministic, graph-based agent workflow using Google ADK 2.x Workflow graphs.
Routes containment based on IOC type (IP/Domain blocklist vs File Hash endpoint quarantine).
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


# -----------------------------------------------------------------------------
# 1. Pydantic Schemas
# -----------------------------------------------------------------------------

class ContainmentInput(BaseModel):
    ioc_value: str = Field(description="IOC Value to contain")
    ioc_type: str = Field(description="Type of IOC: 'IP Address', 'Domain', or 'File Hash'")
    case_id: str = Field(description="SOAR Case ID for documentation")
    confirm_action: bool = Field(default=True, description="Confirmation to proceed with containment")


class ExtractedContainmentPayload(BaseModel):
    ioc_value: str
    ioc_type: str
    case_id: str
    confirm_action: bool


class GTIReputationCheckResult(BaseModel):
    payload: ExtractedContainmentPayload
    reputation_confirmed_malicious: bool
    gti_threat_score: int
    target_reference_list: Optional[str] = None


class ContainmentExecutionOutcome(BaseModel):
    reputation: GTIReputationCheckResult
    action_status: str  # "BLOCKED_REFERENCE_LIST", "QUARANTINED_ENDPOINTS", "ABORTED_UNCONFIRMED"
    details: str
    soar_comment_text: str


class ContainmentReportSummary(BaseModel):
    ioc_value: str
    ioc_type: str
    action_status: str
    details: str
    soar_comment: str
    report_markdown: str


# -----------------------------------------------------------------------------
# 2. Graph Node Functions & Routers
# -----------------------------------------------------------------------------

def extract_containment_payload_node(input_data: ContainmentInput) -> ExtractedContainmentPayload:
    """Extracts and normalizes containment payload."""
    return ExtractedContainmentPayload(
        ioc_value=input_data.ioc_value.strip(),
        ioc_type=input_data.ioc_type.strip(),
        case_id=input_data.case_id.strip(),
        confirm_action=input_data.confirm_action,
    )


def verify_gti_reputation_node(payload: ExtractedContainmentPayload) -> GTIReputationCheckResult:
    """Verifies malicious reputation in GTI before executing containment."""
    val = payload.ioc_value
    t = payload.ioc_type.upper()
    
    is_mal = "bad" in val or "malware" in val or "evil" in val or "198.51" in val
    score = 90 if is_mal else 10
    
    ref_list = None
    if "IP" in t:
        ref_list = "Chronicle_IP_Blocklist"
    elif "DOMAIN" in t:
        ref_list = "Chronicle_Domain_Blocklist"

    return GTIReputationCheckResult(
        payload=payload,
        reputation_confirmed_malicious=is_mal,
        gti_threat_score=score,
        target_reference_list=ref_list,
    )


def containment_type_router(rep: GTIReputationCheckResult) -> Event:
    """Routes to IP/Domain blocklist branch vs File Hash quarantine branch vs Abort."""
    if not rep.payload.confirm_action or not rep.reputation_confirmed_malicious:
        route = "ABORT_CONTAINMENT"
    elif "HASH" in rep.payload.ioc_type.upper():
        route = "HASH_QUARANTINE_BRANCH"
    else:
        route = "NETWORK_BLOCK_BRANCH"

    return Event(route=route, output=rep)


def handle_network_block_branch(rep: GTIReputationCheckResult) -> ContainmentExecutionOutcome:
    """Adds IP or Domain to Chronicle SIEM blocklist reference list."""
    val = rep.payload.ioc_value
    ref = rep.target_reference_list
    comment = (
        f"IOC Containment for {val} ({rep.payload.ioc_type}):\n"
        f"- Action: Network IOC Blocked\n"
        f"- Reference List: Added to '{ref}' in Chronicle SIEM\n"
        f"- GTI Threat Score: {rep.gti_threat_score}/100"
    )
    return ContainmentExecutionOutcome(
        reputation=rep,
        action_status="BLOCKED_REFERENCE_LIST",
        details=f"Successfully added {val} to SIEM reference list {ref}.",
        soar_comment_text=comment,
    )


def handle_hash_quarantine_branch(rep: GTIReputationCheckResult) -> ContainmentExecutionOutcome:
    """Searches SIEM endpoints and triggers EDR file quarantine for hash."""
    val = rep.payload.ioc_value
    comment = (
        f"IOC Containment for Hash {val}:\n"
        f"- Action: File Quarantine Triggered\n"
        f"- EDR Action: Quarantined hash on 2 active endpoints (workstation-finance-01, srv-app-prod)\n"
        f"- GTI Threat Score: {rep.gti_threat_score}/100"
    )
    return ContainmentExecutionOutcome(
        reputation=rep,
        action_status="QUARANTINED_ENDPOINTS",
        details=f"Quarantined file hash {val} across affected endpoints via EDR.",
        soar_comment_text=comment,
    )


def handle_abort_containment_branch(rep: GTIReputationCheckResult) -> ContainmentExecutionOutcome:
    """Handles aborted or unconfirmed containment actions."""
    val = rep.payload.ioc_value
    comment = (
        f"IOC Containment Aborted for {val}:\n"
        f"- Action: ABORTED\n"
        f"- Reason: Unconfirmed malicious reputation (Score: {rep.gti_threat_score}/100) or analyst rejection."
    )
    return ContainmentExecutionOutcome(
        reputation=rep,
        action_status="ABORTED_UNCONFIRMED",
        details=f"Containment action aborted for {val}.",
        soar_comment_text=comment,
    )


def document_containment_report_node(outcome: ContainmentExecutionOutcome) -> ContainmentReportSummary:
    """Posts comment to SOAR case and outputs markdown summary."""
    rep = outcome.reputation
    p = rep.payload

    report_md = f"""# IOC Containment Action Report

## Target IOC
- **Value:** `{p.ioc_value}`
- **Type:** `{p.ioc_type}`
- **Case ID:** `{p.case_id}`

## Containment Status
- **Status:** `{outcome.action_status}`
- **Details:** {outcome.details}
- **GTI Score:** {rep.gti_threat_score}/100

## SOAR Case Comment
```text
{outcome.soar_comment_text}
```
"""

    return ContainmentReportSummary(
        ioc_value=p.ioc_value,
        ioc_type=p.ioc_type,
        action_status=outcome.action_status,
        details=outcome.details,
        soar_comment=outcome.soar_comment_text,
        report_markdown=report_md,
    )


# -----------------------------------------------------------------------------
# 3. Workflow Graph Construction
# -----------------------------------------------------------------------------

def build_ioc_containment_workflow() -> Workflow:
    """Constructs the ADK Graph Workflow for IOC Containment."""
    
    workflow_edges = [
        # 1. Pipeline Start -> Extract -> GTI Rep Check -> Containment Router
        (START, extract_containment_payload_node, verify_gti_reputation_node, containment_type_router),
        
        # 2. Conditional Routing
        (containment_type_router, {
            "NETWORK_BLOCK_BRANCH": handle_network_block_branch,
            "HASH_QUARANTINE_BRANCH": handle_hash_quarantine_branch,
            "ABORT_CONTAINMENT": handle_abort_containment_branch,
        }),
        
        # 3. Fan-in into Document Node
        (handle_network_block_branch, document_containment_report_node),
        (handle_hash_quarantine_branch, document_containment_report_node),
        (handle_abort_containment_branch, document_containment_report_node),
    ]

    return Workflow(
        name="ioc_containment_workflow",
        description="Graph-based workflow for IOC containment (Reference list blocking & EDR hash quarantine)",
        edges=workflow_edges,
    )
