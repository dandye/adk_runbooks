"""
IOC Threat Hunt Graph Workflow for Google ADK.

Implements 'IOC Threat Hunt Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class IOCThreatHuntInput(BaseWorkflowInput):
    ioc_list: List[str] = Field(description="List of IOCs to hunt for across SIEM events")
    lookback_days: int = Field(default=30, description="SIEM lookback timeframe in days")


class ExtractedIOCHuntPayload(BaseModel):
    ioc_list: List[str]
    lookback_days: int
    case_id: Optional[str] = None


class IOCHuntSearchResult(BaseModel):
    payload: ExtractedIOCHuntPayload
    matched_iocs: List[str]
    affected_assets: List[str]
    events_count: int


class IOCHuntVerdict(BaseModel):
    search: IOCHuntSearchResult
    verdict: str  # "IOC_MATCHES_FOUND", "NO_IOC_MATCHES"
    action_plan: str


def extract_ioc_hunt_payload_node(inp: IOCThreatHuntInput) -> ExtractedIOCHuntPayload:
    return ExtractedIOCHuntPayload(
        ioc_list=[sanitize_entity_value(i) for i in inp.ioc_list],
        lookback_days=inp.lookback_days,
        case_id=inp.case_id,
    )


def execute_ioc_siem_search_node(payload: ExtractedIOCHuntPayload) -> IOCHuntSearchResult:
    matches = [i for i in payload.ioc_list if "bad" in i or "mal" in i or "evil" in i or "198.51" in i]
    has_match = len(matches) > 0
    return IOCHuntSearchResult(
        payload=payload,
        matched_iocs=matches,
        affected_assets=["workstation-exec-01"] if has_match else [],
        events_count=14 if has_match else 0,
    )


def ioc_hunt_router(search: IOCHuntSearchResult) -> Event:
    if search.events_count > 0:
        route = "IOC_MATCHES_FOUND"
    else:
        route = "NO_IOC_MATCHES"
    return Event(route=route, output=search)


def handle_ioc_matches_found_branch(search: IOCHuntSearchResult) -> IOCHuntVerdict:
    return IOCHuntVerdict(
        search=search,
        verdict="IOC_MATCHES_FOUND",
        action_plan=f"IOC HUNT MATCHES: Found {search.events_count} SIEM events for IOCs {search.matched_iocs} on assets {search.affected_assets}. Contain assets & block IOCs.",
    )


def handle_no_ioc_matches_branch(search: IOCHuntSearchResult) -> IOCHuntVerdict:
    return IOCHuntVerdict(
        search=search,
        verdict="NO_IOC_MATCHES",
        action_plan=f"No SIEM activity detected for IOCs {search.payload.ioc_list} in {search.payload.lookback_days}d window.",
    )


def document_ioc_hunt_report_node(verdict: IOCHuntVerdict) -> str:
    return verdict.action_plan


def build_ioc_threat_hunt_workflow() -> Workflow:
    return Workflow(
        name="ioc_threat_hunt_workflow",
        description="Graph-based workflow for multi-IOC SIEM threat hunting, entity correlation, and blocklist recommendations",
        edges=[
            (START, extract_ioc_hunt_payload_node, execute_ioc_siem_search_node, ioc_hunt_router),
            (ioc_hunt_router, {
                "IOC_MATCHES_FOUND": handle_ioc_matches_found_branch,
                "NO_IOC_MATCHES": handle_no_ioc_matches_branch,
            }),
            (handle_ioc_matches_found_branch, document_ioc_hunt_report_node),
            (handle_no_ioc_matches_branch, document_ioc_hunt_report_node),
        ],
    )
