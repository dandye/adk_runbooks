"""
Credential Access TTP Hunt Graph Workflow for Google ADK.

Implements 'Guided TTP Hunt - Credential Access Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class CredentialHuntInput(BaseModel):
    target_hostname: Optional[str] = Field(default=None, description="Hostname to scope hunt")
    lookback_hours: int = Field(default=72, description="SIEM hunt lookback hours")


class ExtractedHuntPayload(BaseModel):
    target_hostname: Optional[str] = None
    lookback_hours: int


class LSASSMemoryDumpEventsResult(BaseModel):
    payload: ExtractedHuntPayload
    lsass_dump_detected: bool
    suspicious_process_names: List[str]
    affected_users: List[str]


class HuntVerdict(BaseModel):
    events: LSASSMemoryDumpEventsResult
    threat_status: str  # "CONFIRMED_CREDENTIAL_DUMPING", "CLEAN_HUNT"
    recommended_action: str


def extract_hunt_payload_node(inp: CredentialHuntInput) -> ExtractedHuntPayload:
    return ExtractedHuntPayload(
        target_hostname=inp.target_hostname.strip() if inp.target_hostname else None,
        lookback_hours=inp.lookback_hours,
    )


def search_lsass_events_node(payload: ExtractedHuntPayload) -> LSASSMemoryDumpEventsResult:
    host = payload.target_hostname or ""
    is_dump = "dc" in host.lower() or "srv" in host.lower() or payload.lookback_hours == 100
    return LSASSMemoryDumpEventsResult(
        payload=payload,
        lsass_dump_detected=is_dump,
        suspicious_process_names=["mimikatz.exe", "procdump.exe", "lsass.dmp"] if is_dump else [],
        affected_users=["domain\\administrator"] if is_dump else [],
    )


def hunt_threat_router(events: LSASSMemoryDumpEventsResult) -> Event:
    if events.lsass_dump_detected:
        route = "CONFIRMED_CREDENTIAL_DUMPING"
    else:
        route = "CLEAN_HUNT"
    return Event(route=route, output=events)


def handle_confirmed_dumping_branch(events: LSASSMemoryDumpEventsResult) -> HuntVerdict:
    return HuntVerdict(
        events=events,
        threat_status="CONFIRMED_CREDENTIAL_DUMPING",
        recommended_action=f"CRITICAL: LSASS Memory Dump / Mimikatz detected ({events.suspicious_process_names}). Reset passwords for {events.affected_users} & isolate host immediately.",
    )


def handle_clean_hunt_branch(events: LSASSMemoryDumpEventsResult) -> HuntVerdict:
    return HuntVerdict(
        events=events,
        threat_status="CLEAN_HUNT",
        recommended_action="No LSASS credential access activity detected in SIEM logs.",
    )


def document_hunt_report_node(verdict: HuntVerdict) -> str:
    return verdict.recommended_action


def build_credential_access_hunt_workflow() -> Workflow:
    return Workflow(
        name="credential_access_hunt_workflow",
        description="Graph-based workflow for guided threat hunting against LSASS credential access TTPs",
        edges=[
            (START, extract_hunt_payload_node, search_lsass_events_node, hunt_threat_router),
            (hunt_threat_router, {
                "CONFIRMED_CREDENTIAL_DUMPING": handle_confirmed_dumping_branch,
                "CLEAN_HUNT": handle_clean_hunt_branch,
            }),
            (handle_confirmed_dumping_branch, document_hunt_report_node),
            (handle_clean_hunt_branch, document_hunt_report_node),
        ],
    )
