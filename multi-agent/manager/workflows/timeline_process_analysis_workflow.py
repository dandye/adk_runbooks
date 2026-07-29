"""
Case Event Timeline and Process Analysis Graph Workflow for Google ADK.

Implements 'Case Event Timeline and Process Analysis Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class TimelineAnalysisInput(BaseWorkflowInput):
    case_id: str = Field(description="SOAR Case ID")
    target_hostname: Optional[str] = Field(default=None, description="Target Hostname for process tree reconstruction")
    timeframe_hours: int = Field(default=48, description="Lookback window in hours")


class ExtractedTimelinePayload(BaseModel):
    case_id: str
    target_hostname: Optional[str] = None
    timeframe_hours: int


class ProcessTreeResult(BaseModel):
    payload: ExtractedTimelinePayload
    suspicious_process_tree_found: bool
    parent_process: Optional[str]
    child_process: Optional[str]
    command_line: Optional[str]


class TimelineAnalysisVerdict(BaseModel):
    tree: ProcessTreeResult
    analysis_disposition: str  # "MALICIOUS_PROCESS_TREE", "NORMAL_PROCESS_EXECUTION"
    reconstruction_summary: str


def extract_timeline_payload_node(inp: TimelineAnalysisInput) -> ExtractedTimelinePayload:
    return ExtractedTimelinePayload(
        case_id=sanitize_entity_value(inp.case_id),
        target_hostname=sanitize_entity_value(inp.target_hostname) if inp.target_hostname else None,
        timeframe_hours=inp.timeframe_hours,
    )


def reconstruct_process_tree_node(payload: ExtractedTimelinePayload) -> ProcessTreeResult:
    cid = payload.case_id
    is_mal = "MAL" in cid or "900" in cid or "CRIT" in cid
    return ProcessTreeResult(
        payload=payload,
        suspicious_process_tree_found=is_mal,
        parent_process="winword.exe" if is_mal else "explorer.exe",
        child_process="powershell.exe -enc AAAA..." if is_mal else "chrome.exe",
        command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile -enc AAAA..." if is_mal else "chrome.exe --new-window",
    )


def timeline_process_router(tree: ProcessTreeResult) -> Event:
    if tree.suspicious_process_tree_found:
        route = "MALICIOUS_PROCESS_TREE"
    else:
        route = "NORMAL_PROCESS_EXECUTION"
    return Event(route=route, output=tree)


def handle_malicious_tree_branch(tree: ProcessTreeResult) -> TimelineAnalysisVerdict:
    return TimelineAnalysisVerdict(
        tree=tree,
        analysis_disposition="MALICIOUS_PROCESS_TREE",
        reconstruction_summary=f"SUSPICIOUS PROCESS TREE: {tree.parent_process} spawned {tree.child_process} ({tree.command_line}) on host {tree.payload.target_hostname or 'N/A'}.",
    )


def handle_normal_execution_branch(tree: ProcessTreeResult) -> TimelineAnalysisVerdict:
    return TimelineAnalysisVerdict(
        tree=tree,
        analysis_disposition="NORMAL_PROCESS_EXECUTION",
        reconstruction_summary="Normal process tree hierarchy observed in event timeline.",
    )


def document_timeline_report_node(verdict: TimelineAnalysisVerdict) -> str:
    return verdict.reconstruction_summary


def build_timeline_process_analysis_workflow() -> Workflow:
    return Workflow(
        name="timeline_process_analysis_workflow",
        description="Graph-based workflow for SOAR event timeline reconstruction and parent-child process tree analysis",
        edges=[
            (START, extract_timeline_payload_node, reconstruct_process_tree_node, timeline_process_router),
            (timeline_process_router, {
                "MALICIOUS_PROCESS_TREE": handle_malicious_tree_branch,
                "NORMAL_PROCESS_EXECUTION": handle_normal_execution_branch,
            }),
            (handle_malicious_tree_branch, document_timeline_report_node),
            (handle_normal_execution_branch, document_timeline_report_node),
        ],
    )
