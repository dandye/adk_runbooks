"""
APT Threat Hunt Graph Workflow for Google ADK.

Implements 'APT Threat Hunt Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class APTHuntInput(BaseWorkflowInput):
    threat_actor_name: str = Field(description="APT Threat Actor Name (e.g. 'APT29', 'APT41', 'Lazarus Group')")
    timeframe_days: int = Field(default=30, description="Lookback window in days")


class ExtractedAPTPayload(BaseModel):
    threat_actor_name: str
    timeframe_days: int
    case_id: Optional[str] = None


class APTThreatIntelResult(BaseModel):
    payload: ExtractedAPTPayload
    associated_iocs: List[str]
    targeted_industries: List[str]
    mitre_ttps: List[str]


class APTSiemSearchResult(BaseModel):
    intel: APTThreatIntelResult
    matched_iocs: List[str]
    compromised_hosts: List[str]
    campaign_detected: bool


class APTHuntVerdict(BaseModel):
    siem_search: APTSiemSearchResult
    verdict: str  # "CONFIRMED_APT_CAMPAIGN", "NO_APT_ACTIVITY"
    action_plan: str


def extract_apt_payload_node(inp: APTHuntInput) -> ExtractedAPTPayload:
    return ExtractedAPTPayload(
        threat_actor_name=sanitize_entity_value(inp.threat_actor_name),
        timeframe_days=inp.timeframe_days,
        case_id=inp.case_id,
    )


def fetch_apt_threat_intel_node(payload: ExtractedAPTPayload) -> APTThreatIntelResult:
    actor = payload.threat_actor_name.lower()
    if "29" in actor or "cozy" in actor or "midnight" in actor or "apt" in actor:
        iocs = ["198.51.100.99", "evil-c2-beacon.org", "hash99001122334455"]
        ttps = ["T1071.001", "T1059.001", "T1078"]
    else:
        iocs = []
        ttps = []

    return APTThreatIntelResult(
        payload=payload,
        associated_iocs=iocs,
        targeted_industries=["Finance", "Defense", "Government"],
        mitre_ttps=ttps,
    )


def search_apt_siem_events_node(intel: APTThreatIntelResult) -> APTSiemSearchResult:
    has_match = len(intel.associated_iocs) > 0
    return APTSiemSearchResult(
        intel=intel,
        matched_iocs=intel.associated_iocs[:2] if has_match else [],
        compromised_hosts=["srv-domain-controller-01"] if has_match else [],
        campaign_detected=has_match,
    )


def apt_hunt_router(search: APTSiemSearchResult) -> Event:
    if search.campaign_detected:
        route = "CONFIRMED_APT_CAMPAIGN"
    else:
        route = "NO_APT_ACTIVITY"
    return Event(route=route, output=search)


def handle_confirmed_apt_campaign_branch(search: APTSiemSearchResult) -> APTHuntVerdict:
    return APTHuntVerdict(
        siem_search=search,
        verdict="CONFIRMED_APT_CAMPAIGN",
        action_plan=f"CRITICAL APT CAMPAIGN: Active matches for {search.intel.payload.threat_actor_name} on hosts {search.compromised_hosts}. Trigger Emergency Containment.",
    )


def handle_no_apt_activity_branch(search: APTSiemSearchResult) -> APTHuntVerdict:
    return APTHuntVerdict(
        siem_search=search,
        verdict="NO_APT_ACTIVITY",
        action_plan=f"No SIEM activity detected for APT actor '{search.intel.payload.threat_actor_name}' in {search.intel.payload.timeframe_days}d window.",
    )


def document_apt_report_node(verdict: APTHuntVerdict) -> str:
    return verdict.action_plan


def build_apt_threat_hunt_workflow() -> Workflow:
    return Workflow(
        name="apt_threat_hunt_workflow",
        description="Graph-based workflow for proactive APT threat actor campaign hunting and SIEM correlation",
        edges=[
            (START, extract_apt_payload_node, fetch_apt_threat_intel_node, search_apt_siem_events_node, apt_hunt_router),
            (apt_hunt_router, {
                "CONFIRMED_APT_CAMPAIGN": handle_confirmed_apt_campaign_branch,
                "NO_APT_ACTIVITY": handle_no_apt_activity_branch,
            }),
            (handle_confirmed_apt_campaign_branch, document_apt_report_node),
            (handle_no_apt_activity_branch, document_apt_report_node),
        ],
    )
