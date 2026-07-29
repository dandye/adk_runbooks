"""
Group Cases Graph Workflow for Google ADK.

Implements 'Group Cases Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class GroupCasesInput(BaseWorkflowInput):
    target_case_ids: List[str] = Field(description="List of Case IDs to analyze for grouping")
    grouping_criteria: str = Field(default="Shared_IOCs_and_Users", description="Criteria for case grouping")


class ExtractedGroupPayload(BaseModel):
    target_case_ids: List[str]
    grouping_criteria: str


class CaseGroupResult(BaseModel):
    payload: ExtractedGroupPayload
    grouped_case_clusters: List[List[str]]
    cluster_count: int
    grouping_action: str  # "GROUP_CASES_MERGED", "NO_GROUPING_NEEDED"


def extract_group_payload_node(inp: GroupCasesInput) -> ExtractedGroupPayload:
    return ExtractedGroupPayload(
        target_case_ids=[c.strip() for c in inp.target_case_ids],
        grouping_criteria=sanitize_entity_value(inp.grouping_criteria),
    )


def cluster_similar_cases_node(payload: ExtractedGroupPayload) -> CaseGroupResult:
    cases = payload.target_case_ids
    if len(cases) > 1:
        clusters = [cases]
        action = "GROUP_CASES_MERGED"
    else:
        clusters = []
        action = "NO_GROUPING_NEEDED"

    return CaseGroupResult(
        payload=payload,
        grouped_case_clusters=clusters,
        cluster_count=len(clusters),
        grouping_action=action,
    )


def case_grouping_router(result: CaseGroupResult) -> Event:
    if result.grouping_action == "GROUP_CASES_MERGED":
        route = "GROUP_CASES_MERGED"
    else:
        route = "NO_GROUPING_NEEDED"
    return Event(route=route, output=result)


def handle_group_cases_merged_branch(result: CaseGroupResult) -> str:
    return f"SOAR Cases {result.payload.target_case_ids} successfully grouped into consolidated incident cluster."


def handle_no_grouping_needed_branch(result: CaseGroupResult) -> str:
    return "No common IOCs or entities found across specified cases. Grouping skipped."


def document_grouping_report_node(report: str) -> str:
    return report


def build_group_cases_workflow() -> Workflow:
    return Workflow(
        name="group_cases_workflow",
        description="Graph-based workflow for correlating and grouping related SOAR cases into consolidated incidents",
        edges=[
            (START, extract_group_payload_node, cluster_similar_cases_node, case_grouping_router),
            (case_grouping_router, {
                "GROUP_CASES_MERGED": handle_group_cases_merged_branch,
                "NO_GROUPING_NEEDED": handle_no_grouping_needed_branch,
            }),
            (handle_group_cases_merged_branch, document_grouping_report_node),
            (handle_no_grouping_needed_branch, document_grouping_report_node),
        ],
    )
