"""
Group Cases V2 Graph Workflow for Google ADK.

Implements 'Group Cases V2 Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class GroupCasesV2Input(BaseWorkflowInput):
    environment_filter: str = Field(default="ALL", description="Target Environment / Tenant Filter")
    similarity_threshold: float = Field(default=0.8, description="Entity/Alert similarity threshold")


class ExtractedGroupV2Payload(BaseModel):
    environment_filter: str
    similarity_threshold: float


class CaseGroupingV2Result(BaseModel):
    payload: ExtractedGroupV2Payload
    analyzed_cases_count: int
    grouped_case_clusters: List[List[str]]
    merge_action: str  # "MERGE_HIGH_SIMILARITY_CASES", "NO_MERGE_REQUIRED"


def extract_group_v2_payload_node(inp: GroupCasesV2Input) -> ExtractedGroupV2Payload:
    return ExtractedGroupV2Payload(
        environment_filter=sanitize_entity_value(inp.environment_filter),
        similarity_threshold=inp.similarity_threshold,
    )


def compute_v2_case_clusters_node(payload: ExtractedGroupV2Payload) -> CaseGroupingV2Result:
    has_merge = payload.similarity_threshold <= 0.85
    clusters = [["CASE-101", "CASE-104", "CASE-109"]] if has_merge else []
    return CaseGroupingV2Result(
        payload=payload,
        analyzed_cases_count=20,
        grouped_case_clusters=clusters,
        merge_action="MERGE_HIGH_SIMILARITY_CASES" if has_merge else "NO_MERGE_REQUIRED",
    )


def group_cases_v2_router(result: CaseGroupingV2Result) -> Event:
    if result.merge_action == "MERGE_HIGH_SIMILARITY_CASES":
        route = "MERGE_HIGH_SIMILARITY_CASES"
    else:
        route = "NO_MERGE_REQUIRED"
    return Event(route=route, output=result)


def handle_merge_high_similarity_branch(result: CaseGroupingV2Result) -> str:
    return f"Group Cases V2: Consolidating high-similarity cases {result.grouped_case_clusters} into unified incident cases."


def handle_no_merge_required_branch(result: CaseGroupingV2Result) -> str:
    return "Group Cases V2: No case clusters exceeded similarity threshold."


def document_group_v2_report_node(report: str) -> str:
    return report


def build_group_cases_v2_workflow() -> Workflow:
    return Workflow(
        name="group_cases_v2_workflow",
        description="Graph-based workflow for V2 automated case grouping, similarity scoring, and case consolidation",
        edges=[
            (START, extract_group_v2_payload_node, compute_v2_case_clusters_node, group_cases_v2_router),
            (group_cases_v2_router, {
                "MERGE_HIGH_SIMILARITY_CASES": handle_merge_high_similarity_branch,
                "NO_MERGE_REQUIRED": handle_no_merge_required_branch,
            }),
            (handle_merge_high_similarity_branch, document_group_v2_report_node),
            (handle_no_merge_required_branch, document_group_v2_report_node),
        ],
    )
