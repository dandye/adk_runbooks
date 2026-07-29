"""
Investigate a GTI Collection ID Graph Workflow for Google ADK.

Implements 'Investigate a GTI Collection ID Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class GTICollectionInvestigationInput(BaseWorkflowInput):
    collection_id: str = Field(description="GTI Collection ID")


class ExtractedGTICollectionPayload(BaseModel):
    collection_id: str
    case_id: Optional[str] = None


class GTICollectionDetailsResult(BaseModel):
    payload: ExtractedGTICollectionPayload
    actor_name: str
    threat_level: str
    iocs_count: int
    matched_siem_events: int


class GTICollectionInvestigationOutcome(BaseModel):
    details: GTICollectionDetailsResult
    verdict: str  # "ACTIVE_CAMPAIGN_DETECTED", "NO_SIEM_MATCH"
    report_markdown: str


def extract_gti_collection_payload_node(inp: GTICollectionInvestigationInput) -> ExtractedGTICollectionPayload:
    return ExtractedGTICollectionPayload(
        collection_id=sanitize_entity_value(inp.collection_id),
        case_id=inp.case_id,
    )


def fetch_gti_collection_report_node(payload: ExtractedGTICollectionPayload) -> GTICollectionDetailsResult:
    cid = payload.collection_id
    is_crit = "apt" in cid.lower() or "gti" in cid.lower() or "crit" in cid.lower()
    return GTICollectionDetailsResult(
        payload=payload,
        actor_name="Midnight Blizzard / APT29" if is_crit else "Generic Campaign",
        threat_level="CRITICAL" if is_crit else "LOW",
        iocs_count=42 if is_crit else 5,
        matched_siem_events=18 if is_crit else 0,
    )


def gti_collection_investigation_router(details: GTICollectionDetailsResult) -> Event:
    if details.matched_siem_events > 0:
        route = "ACTIVE_CAMPAIGN_DETECTED"
    else:
        route = "NO_SIEM_MATCH"
    return Event(route=route, output=details)


def handle_active_campaign_branch(details: GTICollectionDetailsResult) -> GTICollectionInvestigationOutcome:
    md = f"# GTI Collection Investigation Report\n\n- **Collection:** `{details.payload.collection_id}`\n- **Actor:** {details.actor_name}\n- **Verdict:** ACTIVE_CAMPAIGN_DETECTED ({details.matched_siem_events} events matched)"
    return GTICollectionInvestigationOutcome(details=details, verdict="ACTIVE_CAMPAIGN_DETECTED", report_markdown=md)


def handle_no_siem_match_branch(details: GTICollectionDetailsResult) -> GTICollectionInvestigationOutcome:
    md = f"# GTI Collection Investigation Report\n\n- **Collection:** `{details.payload.collection_id}`\n- **Verdict:** NO_SIEM_MATCH"
    return GTICollectionInvestigationOutcome(details=details, verdict="NO_SIEM_MATCH", report_markdown=md)


def document_gti_collection_report_node(outcome: GTICollectionInvestigationOutcome) -> str:
    return outcome.report_markdown


def build_investigate_gti_collection_workflow() -> Workflow:
    return Workflow(
        name="investigate_gti_collection_workflow",
        description="Graph-based workflow for investigating GTI Threat Collection IDs against SIEM logs",
        edges=[
            (START, extract_gti_collection_payload_node, fetch_gti_collection_report_node, gti_collection_investigation_router),
            (gti_collection_investigation_router, {
                "ACTIVE_CAMPAIGN_DETECTED": handle_active_campaign_branch,
                "NO_SIEM_MATCH": handle_no_siem_match_branch,
            }),
            (handle_active_campaign_branch, document_gti_collection_report_node),
            (handle_no_siem_match_branch, document_gti_collection_report_node),
        ],
    )
