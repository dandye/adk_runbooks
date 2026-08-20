"""
Compare GTI Collection to IOCs Graph Workflow for Google ADK.

Implements 'Compare GTI Collection to IOCs and Events Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class GTICollectionInput(BaseModel):
    collection_id: str = Field(description="GTI Threat Intelligence Collection ID")
    case_id: Optional[str] = Field(default=None, description="SOAR Case ID")
    lookback_days: int = Field(default=30, description="SIEM search lookback days")


class ExtractedCollectionPayload(BaseModel):
    collection_id: str
    case_id: Optional[str] = None
    lookback_days: int


class GTICollectionIOCsResult(BaseModel):
    payload: ExtractedCollectionPayload
    actor_name: str
    collection_title: str
    extracted_iocs: List[str]
    iocs_count: int


class SIEMOverlapMatchResult(BaseModel):
    collection_iocs: GTICollectionIOCsResult
    matched_iocs: List[str]
    affected_hosts: List[str]
    threat_detected: bool


def extract_collection_node(inp: GTICollectionInput) -> ExtractedCollectionPayload:
    return ExtractedCollectionPayload(
        collection_id=inp.collection_id.strip(),
        case_id=inp.case_id.strip() if inp.case_id else None,
        lookback_days=inp.lookback_days,
    )


def fetch_gti_collection_iocs_node(payload: ExtractedCollectionPayload) -> GTICollectionIOCsResult:
    cid = payload.collection_id
    if "apt" in cid or "campaign" in cid or "gti" in cid:
        iocs = ["198.51.100.22", "bad-c2-domain.org", "c1d2e3f4hash5678"]
        actor = "APT29 / Midnight Blizzard"
    else:
        iocs = []
        actor = "Unknown Campaign"

    return GTICollectionIOCsResult(
        payload=payload,
        actor_name=actor,
        collection_title=f"GTI Collection {cid}",
        extracted_iocs=iocs,
        iocs_count=len(iocs),
    )


def match_siem_events_node(coll: GTICollectionIOCsResult) -> SIEMOverlapMatchResult:
    has_match = len(coll.extracted_iocs) > 0
    matched = coll.extracted_iocs[:2] if has_match else []
    hosts = ["srv-domain-controller-01"] if has_match else []
    
    return SIEMOverlapMatchResult(
        collection_iocs=coll,
        matched_iocs=matched,
        affected_hosts=hosts,
        threat_detected=has_match,
    )


def gti_overlap_router(match_res: SIEMOverlapMatchResult) -> Event:
    if match_res.threat_detected:
        route = "CAMPAIGN_MATCHED"
    else:
        route = "NO_MATCH"
    return Event(route=route, output=match_res)


def handle_campaign_matched_branch(match_res: SIEMOverlapMatchResult) -> str:
    coll = match_res.collection_iocs
    return (
        f"CRITICAL OVERLAP DETECTED: GTI Threat Collection '{coll.collection_title}' ({coll.actor_name}) "
        f"matches SIEM activity on host(s) {match_res.affected_hosts}. Matched IOCs: {match_res.matched_iocs}."
    )


def handle_no_match_branch(match_res: SIEMOverlapMatchResult) -> str:
    coll = match_res.collection_iocs
    return f"No SIEM overlap found for GTI Threat Collection '{coll.collection_title}' ({coll.actor_name})."


def document_gti_report_node(report_text: str) -> str:
    return report_text


def build_compare_gti_collection_workflow() -> Workflow:
    return Workflow(
        name="compare_gti_collection_workflow",
        description="Graph-based workflow for comparing GTI Threat Collections against SIEM events",
        edges=[
            (START, extract_collection_node, fetch_gti_collection_iocs_node, match_siem_events_node, gti_overlap_router),
            (gti_overlap_router, {
                "CAMPAIGN_MATCHED": handle_campaign_matched_branch,
                "NO_MATCH": handle_no_match_branch,
            }),
            (handle_campaign_matched_branch, document_gti_report_node),
            (handle_no_match_branch, document_gti_report_node),
        ],
    )
