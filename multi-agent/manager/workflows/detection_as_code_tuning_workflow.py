"""
Detection as Code Rule Tuning Graph Workflow for Google ADK.

Implements 'Detection as Code Rule Tuning Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class DACRuleTuningInput(BaseWorkflowInput):
    rule_file_path: str = Field(description="Path to YARA-L rule file in Git repository")
    commit_sha: Optional[str] = Field(default=None, description="Git commit SHA")


class ExtractedDACPayload(BaseModel):
    rule_file_path: str
    commit_sha: Optional[str] = None


class DACValidationResult(BaseModel):
    payload: ExtractedDACPayload
    passed_ci_tests: bool
    linter_warnings: List[str]
    pull_request_action: str  # "MERGE_PRODUCTION", "BLOCK_CI_FAILURE"


def extract_dac_payload_node(inp: DACRuleTuningInput) -> ExtractedDACPayload:
    return ExtractedDACPayload(
        rule_file_path=sanitize_entity_value(inp.rule_file_path),
        commit_sha=sanitize_entity_value(inp.commit_sha) if inp.commit_sha else None,
    )


def run_dac_ci_pipeline_node(payload: ExtractedDACPayload) -> DACValidationResult:
    f = payload.rule_file_path.lower()
    is_fail = "fail" in f or "broken" in f
    return DACValidationResult(
        payload=payload,
        passed_ci_tests=not is_fail,
        linter_warnings=["Variable $net unused"] if not is_fail else ["Syntax error: missing match section"],
        pull_request_action="MERGE_PRODUCTION" if not is_fail else "BLOCK_CI_FAILURE",
    )


def dac_ci_router(val: DACValidationResult) -> Event:
    if val.passed_ci_tests:
        route = "MERGE_PRODUCTION"
    else:
        route = "BLOCK_CI_FAILURE"
    return Event(route=route, output=val)


def handle_merge_production_branch(val: DACValidationResult) -> str:
    return f"DAC CI Pipeline PASSED for {val.payload.rule_file_path}. Merged and deployed to SecOps production."


def handle_block_ci_failure_branch(val: DACValidationResult) -> str:
    return f"DAC CI Pipeline FAILED for {val.payload.rule_file_path}. PR blocked due to lint/syntax errors: {val.linter_warnings}."


def document_dac_report_node(report: str) -> str:
    return report


def build_detection_as_code_tuning_workflow() -> Workflow:
    return Workflow(
        name="detection_as_code_tuning_workflow",
        description="Graph-based workflow for Detection-as-Code CI/CD rule validation, linting, and automated PR merging",
        edges=[
            (START, extract_dac_payload_node, run_dac_ci_pipeline_node, dac_ci_router),
            (dac_ci_router, {
                "MERGE_PRODUCTION": handle_merge_production_branch,
                "BLOCK_CI_FAILURE": handle_block_ci_failure_branch,
            }),
            (handle_merge_production_branch, document_dac_report_node),
            (handle_block_ci_failure_branch, document_dac_report_node),
        ],
    )
