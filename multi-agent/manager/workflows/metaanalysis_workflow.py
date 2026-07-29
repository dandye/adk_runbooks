"""
Meta-Analysis Graph Workflow for Google ADK.

Implements 'Meta-Analysis Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class MetaAnalysisInput(BaseWorkflowInput):
    target_case_ids: List[str] = Field(description="List of Case IDs to perform cross-case meta-analysis on")
    timeframe_days: int = Field(default=30, description="Analysis timeframe window in days")


class ExtractedMetaAnalysisPayload(BaseModel):
    target_case_ids: List[str]
    timeframe_days: int


class MetaAnalysisSynthesisResult(BaseModel):
    payload: ExtractedMetaAnalysisPayload
    cross_case_common_entities: List[str]
    shared_attack_techniques: List[str]
    systemic_vulnerability_found: bool


class MetaAnalysisOutcome(BaseModel):
    synthesis: MetaAnalysisSynthesisResult
    meta_disposition: str  # "SYSTEMIC_RISK_IDENTIFIED", "ISOLATED_INCIDENTS"
    report_markdown: str


def extract_meta_analysis_payload_node(inp: MetaAnalysisInput) -> ExtractedMetaAnalysisPayload:
    return ExtractedMetaAnalysisPayload(
        target_case_ids=[c.strip() for c in inp.target_case_ids],
        timeframe_days=inp.timeframe_days,
    )


def synthesize_cross_case_patterns_node(payload: ExtractedMetaAnalysisPayload) -> MetaAnalysisSynthesisResult:
    has_systemic = len(payload.target_case_ids) >= 3
    return MetaAnalysisSynthesisResult(
        payload=payload,
        cross_case_common_entities=["admin-svc-account", "198.51.100.44"] if has_systemic else [],
        shared_attack_techniques=["T1059.001", "T1078.004"] if has_systemic else [],
        systemic_vulnerability_found=has_systemic,
    )


def meta_analysis_router(synthesis: MetaAnalysisSynthesisResult) -> Event:
    if synthesis.systemic_vulnerability_found:
        route = "SYSTEMIC_RISK_IDENTIFIED"
    else:
        route = "ISOLATED_INCIDENTS"
    return Event(route=route, output=synthesis)


def handle_systemic_risk_branch(synthesis: MetaAnalysisSynthesisResult) -> MetaAnalysisOutcome:
    md = f"# Meta-Analysis Report\n\n- **Target Cases:** {synthesis.payload.target_case_ids}\n- **Disposition:** `SYSTEMIC_RISK_IDENTIFIED`\n- **Common Entities:** {synthesis.cross_case_common_entities}\n- **Shared MITRE TTPs:** {synthesis.shared_attack_techniques}\n- **Recommendation:** Trigger architectural remediation & SOC detection tuning."
    return MetaAnalysisOutcome(
        synthesis=synthesis,
        meta_disposition="SYSTEMIC_RISK_IDENTIFIED",
        report_markdown=md,
    )


def handle_isolated_incidents_branch(synthesis: MetaAnalysisSynthesisResult) -> MetaAnalysisOutcome:
    md = f"# Meta-Analysis Report\n\n- **Target Cases:** {synthesis.payload.target_case_ids}\n- **Disposition:** `ISOLATED_INCIDENTS`"
    return MetaAnalysisOutcome(
        synthesis=synthesis,
        meta_disposition="ISOLATED_INCIDENTS",
        report_markdown=md,
    )


def document_meta_analysis_report_node(outcome: MetaAnalysisOutcome) -> str:
    return outcome.report_markdown


def build_metaanalysis_workflow() -> Workflow:
    return Workflow(
        name="metaanalysis_workflow",
        description="Graph-based workflow for multi-incident meta-analysis, cross-case TTP correlation, and systemic risk synthesis",
        edges=[
            (START, extract_meta_analysis_payload_node, synthesize_cross_case_patterns_node, meta_analysis_router),
            (meta_analysis_router, {
                "SYSTEMIC_RISK_IDENTIFIED": handle_systemic_risk_branch,
                "ISOLATED_INCIDENTS": handle_isolated_incidents_branch,
            }),
            (handle_systemic_risk_branch, document_meta_analysis_report_node),
            (handle_isolated_incidents_branch, document_meta_analysis_report_node),
        ],
    )
