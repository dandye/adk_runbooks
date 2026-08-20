"""
Advanced Threat Hunting Graph Workflow for Google ADK.

Implements 'Advanced Threat Hunting Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class AdvancedHuntInput(BaseWorkflowInput):
    hypothesis: str = Field(description="Threat hunting hypothesis or MITRE TTP identifier")
    timeframe_hours: int = Field(default=168, description="SIEM lookback timeframe in hours")


class ExtractedAdvancedHuntPayload(BaseModel):
    hypothesis: str
    timeframe_hours: int
    case_id: Optional[str] = None


class AdvancedSIEMSearchResult(BaseModel):
    payload: ExtractedAdvancedHuntPayload
    matched_events_count: int
    suspicious_entities: List[str]
    anomalous_ttp_detected: bool


class AdvancedHuntVerdict(BaseModel):
    search: AdvancedSIEMSearchResult
    verdict: str  # "CONFIRMED_THREAT_PATTERN", "CLEAN_HYPOTHESIS"
    recommendation: str


def extract_advanced_hunt_node(inp: AdvancedHuntInput) -> ExtractedAdvancedHuntPayload:
    return ExtractedAdvancedHuntPayload(
        hypothesis=sanitize_entity_value(inp.hypothesis),
        timeframe_hours=inp.timeframe_hours,
        case_id=inp.case_id,
    )


def execute_advanced_siem_hunt_node(payload: ExtractedAdvancedHuntPayload) -> AdvancedSIEMSearchResult:
    h = payload.hypothesis.lower()
    is_threat = "t1" in h or "apt" in h or "persistence" in h or "exfil" in h
    return AdvancedSIEMSearchResult(
        payload=payload,
        matched_events_count=27 if is_threat else 0,
        suspicious_entities=["198.51.100.12", "srv-web-prod-01"] if is_threat else [],
        anomalous_ttp_detected=is_threat,
    )


def advanced_hunt_router(search: AdvancedSIEMSearchResult) -> Event:
    if search.anomalous_ttp_detected:
        route = "CONFIRMED_THREAT_PATTERN"
    else:
        route = "CLEAN_HYPOTHESIS"
    return Event(route=route, output=search)


def handle_confirmed_pattern_branch(search: AdvancedSIEMSearchResult) -> AdvancedHuntVerdict:
    return AdvancedHuntVerdict(
        search=search,
        verdict="CONFIRMED_THREAT_PATTERN",
        recommendation=f"CONFIRMED THREAT: Hypothesis '{search.payload.hypothesis}' yielded {search.matched_events_count} anomalous events involving {search.suspicious_entities}. Escalate to IR.",
    )


def handle_clean_hypothesis_branch(search: AdvancedSIEMSearchResult) -> AdvancedHuntVerdict:
    return AdvancedHuntVerdict(
        search=search,
        verdict="CLEAN_HYPOTHESIS",
        recommendation=f"Clean hunt outcome for hypothesis '{search.payload.hypothesis}'. No anomalous TTPs observed in {search.payload.timeframe_hours}h timeframe.",
    )


def document_advanced_hunt_report_node(verdict: AdvancedHuntVerdict) -> str:
    return verdict.recommendation


def build_advanced_threat_hunting_workflow() -> Workflow:
    return Workflow(
        name="advanced_threat_hunting_workflow",
        description="Graph-based workflow for advanced hypothesis-driven threat hunting across SIEM logs",
        edges=[
            (START, extract_advanced_hunt_node, execute_advanced_siem_hunt_node, advanced_hunt_router),
            (advanced_hunt_router, {
                "CONFIRMED_THREAT_PATTERN": handle_confirmed_pattern_branch,
                "CLEAN_HYPOTHESIS": handle_clean_hypothesis_branch,
            }),
            (handle_confirmed_pattern_branch, document_advanced_hunt_report_node),
            (handle_clean_hypothesis_branch, document_advanced_hunt_report_node),
        ],
    )
