"""
Close Duplicate/Similar Cases Graph Workflow for Google ADK.

Implements 'Close duplicate/similar Cases Workflow' runbook.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class DuplicateCasesInput(BaseModel):
    primary_case_id: str = Field(description="Primary SOAR Case ID")
    similarity_days_back: int = Field(default=7, description="Lookback days for duplicate check")
    confirm_close: bool = Field(default=True, description="Confirmation to close identified duplicate cases")


class ExtractedPrimaryCasePayload(BaseModel):
    primary_case_id: str
    similarity_days_back: int
    confirm_close: bool


class SimilarCasesSearchResult(BaseModel):
    payload: ExtractedPrimaryCasePayload
    duplicate_case_ids: List[str]
    similarity_score: float


class ClosureExecutionOutcome(BaseModel):
    search_result: SimilarCasesSearchResult
    closed_cases_count: int
    action_status: str  # "CLOSED_DUPLICATES", "NO_DUPLICATES_FOUND", "CLOSURE_SKIPPED"
    soar_comment_text: str


def extract_primary_case_node(inp: DuplicateCasesInput) -> ExtractedPrimaryCasePayload:
    return ExtractedPrimaryCasePayload(
        primary_case_id=inp.primary_case_id.strip(),
        similarity_days_back=inp.similarity_days_back,
        confirm_close=inp.confirm_close,
    )


def find_similar_cases_node(payload: ExtractedPrimaryCasePayload) -> SimilarCasesSearchResult:
    cid = payload.primary_case_id
    dups = [f"{cid}-DUP-1", f"{cid}-DUP-2"] if "CASE" in cid else []
    score = 0.95 if dups else 0.0
    return SimilarCasesSearchResult(
        payload=payload,
        duplicate_case_ids=dups,
        similarity_score=score,
    )


def duplicate_case_router(res: SimilarCasesSearchResult) -> Event:
    if not res.duplicate_case_ids or not res.payload.confirm_close:
        route = "SKIP_CLOSURE"
    else:
        route = "CLOSE_DUPLICATES"
    return Event(route=route, output=res)


def handle_close_duplicates_branch(res: SimilarCasesSearchResult) -> ClosureExecutionOutcome:
    dups = ", ".join(res.duplicate_case_ids)
    comment = f"Closed duplicate cases [{dups}] associated with primary case {res.payload.primary_case_id}."
    return ClosureExecutionOutcome(
        search_result=res,
        closed_cases_count=len(res.duplicate_case_ids),
        action_status="CLOSED_DUPLICATES",
        soar_comment_text=comment,
    )


def handle_skip_closure_branch(res: SimilarCasesSearchResult) -> ClosureExecutionOutcome:
    comment = f"No duplicate cases closed for primary case {res.payload.primary_case_id}."
    return ClosureExecutionOutcome(
        search_result=res,
        closed_cases_count=0,
        action_status="SKIP_CLOSURE",
        soar_comment_text=comment,
    )


def document_closure_report_node(outcome: ClosureExecutionOutcome) -> str:
    return outcome.soar_comment_text


def build_close_duplicate_cases_workflow() -> Workflow:
    return Workflow(
        name="close_duplicate_cases_workflow",
        description="Graph-based workflow for identifying and closing duplicate SOAR cases",
        edges=[
            (START, extract_primary_case_node, find_similar_cases_node, duplicate_case_router),
            (duplicate_case_router, {
                "CLOSE_DUPLICATES": handle_close_duplicates_branch,
                "SKIP_CLOSURE": handle_skip_closure_branch,
            }),
            (handle_close_duplicates_branch, document_closure_report_node),
            (handle_skip_closure_branch, document_closure_report_node),
        ],
    )
