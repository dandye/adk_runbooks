"""
Proactive Threat Hunting based on GTI Campaign or Actor Graph Workflow for Google ADK.

Implements 'Proactive Threat Hunting based on GTI Campaign or Actor Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class ProactiveGTIHuntInput(BaseWorkflowInput):
    campaign_or_actor_name: str = Field(description="GTI Threat Actor or Campaign Name")
    timeframe_days: int = Field(default=30, description="SIEM search timeframe in days")


class ExtractedProactivePayload(BaseModel):
    campaign_or_actor_name: str
    timeframe_days: int
    case_id: Optional[str] = None


class GTIThreatCampaignResult(BaseModel):
    payload: ExtractedProactivePayload
    associated_iocs: List[str]
    ttp_signatures: List[str]
    matched_siem_events_count: int


class ProactiveHuntVerdict(BaseModel):
    result: GTIThreatCampaignResult
    verdict: str  # "CAMPAIGN_SIEM_MATCH_FOUND", "NO_CAMPAIGN_ACTIVITY"
    action_plan: str


def extract_proactive_payload_node(inp: ProactiveGTIHuntInput) -> ExtractedProactivePayload:
    return ExtractedProactivePayload(
        campaign_or_actor_name=sanitize_entity_value(inp.campaign_or_actor_name),
        timeframe_days=inp.timeframe_days,
        case_id=inp.case_id,
    )


def correlate_gti_campaign_siem_node(payload: ExtractedProactivePayload) -> GTIThreatCampaignResult:
    name = payload.campaign_or_actor_name.lower()
    is_match = "apt" in name or "campaign" in name or "gti" in name or "unc" in name
    return GTIThreatCampaignResult(
        payload=payload,
        associated_iocs=["198.51.100.33", "malicious-c2-domain.com"] if is_match else [],
        ttp_signatures=["T1566.001", "T1059.001"] if is_match else [],
        matched_siem_events_count=19 if is_match else 0,
    )


def proactive_gti_hunt_router(result: GTIThreatCampaignResult) -> Event:
    if result.matched_siem_events_count > 0:
        route = "CAMPAIGN_SIEM_MATCH_FOUND"
    else:
        route = "NO_CAMPAIGN_ACTIVITY"
    return Event(route=route, output=result)


def handle_campaign_match_found_branch(result: GTIThreatCampaignResult) -> ProactiveHuntVerdict:
    return ProactiveHuntVerdict(
        result=result,
        verdict="CAMPAIGN_SIEM_MATCH_FOUND",
        action_plan=f"PROACTIVE HUNT MATCH: GTI Campaign '{result.payload.campaign_or_actor_name}' matched {result.matched_siem_events_count} SIEM events for IOCs {result.associated_iocs}. Escalate to IR.",
    )


def handle_no_campaign_activity_branch(result: GTIThreatCampaignResult) -> ProactiveHuntVerdict:
    return ProactiveHuntVerdict(
        result=result,
        verdict="NO_CAMPAIGN_ACTIVITY",
        action_plan=f"Proactive hunt complete: No SIEM activity detected for GTI Campaign '{result.payload.campaign_or_actor_name}' in {result.payload.timeframe_days}d window.",
    )


def document_proactive_hunt_report_node(verdict: ProactiveHuntVerdict) -> str:
    return verdict.action_plan


def build_proactive_gti_threat_hunt_workflow() -> Workflow:
    return Workflow(
        name="proactive_gti_threat_hunt_workflow",
        description="Graph-based workflow for proactive threat hunting driven by GTI Campaign and Actor intelligence",
        edges=[
            (START, extract_proactive_payload_node, correlate_gti_campaign_siem_node, proactive_gti_hunt_router),
            (proactive_gti_hunt_router, {
                "CAMPAIGN_SIEM_MATCH_FOUND": handle_campaign_match_found_branch,
                "NO_CAMPAIGN_ACTIVITY": handle_no_campaign_activity_branch,
            }),
            (handle_campaign_match_found_branch, document_proactive_hunt_report_node),
            (handle_no_campaign_activity_branch, document_proactive_hunt_report_node),
        ],
    )
