"""
Demo SOC Tier 2 SOAR Graph Workflow for Google ADK.

Implements 'Demo SOC T2 SOAR Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class DemoSOCT2Input(BaseWorkflowInput):
    case_id: str = Field(description="Demo SOAR Case ID")


class ExtractedDemoSOCT2Payload(BaseModel):
    case_id: str


class DemoSOCT2AnalysisResult(BaseModel):
    payload: ExtractedDemoSOCT2Payload
    severity_level: str
    requires_tier3_escalation: bool


class DemoSOCT2Outcome(BaseModel):
    analysis: DemoSOCT2AnalysisResult
    t2_action_plan: str


def extract_demo_soc_t2_payload_node(inp: DemoSOCT2Input) -> ExtractedDemoSOCT2Payload:
    return ExtractedDemoSOCT2Payload(
        case_id=sanitize_entity_value(inp.case_id),
    )


def analyze_soc_t2_case_node(payload: ExtractedDemoSOCT2Payload) -> DemoSOCT2AnalysisResult:
    cid = payload.case_id
    is_crit = "900" in cid or "CRIT" in cid
    return DemoSOCT2AnalysisResult(
        payload=payload,
        severity_level="CRITICAL" if is_crit else "MEDIUM",
        requires_tier3_escalation=is_crit,
    )


def demo_soc_t2_router(analysis: DemoSOCT2AnalysisResult) -> Event:
    if analysis.requires_tier3_escalation:
        route = "ESCALATE_TIER_3"
    else:
        route = "RESOLVE_TIER_2"
    return Event(route=route, output=analysis)


def handle_escalate_tier_3_branch(analysis: DemoSOCT2AnalysisResult) -> DemoSOCT2Outcome:
    return DemoSOCT2Outcome(
        analysis=analysis,
        t2_action_plan=f"DEMO SOC T2: Case {analysis.payload.case_id} severity evaluated as {analysis.severity_level}. Escalating to SOC Tier 3 IR Team.",
    )


def handle_resolve_tier_2_branch(analysis: DemoSOCT2AnalysisResult) -> DemoSOCT2Outcome:
    return DemoSOCT2Outcome(
        analysis=analysis,
        t2_action_plan=f"DEMO SOC T2: Case {analysis.payload.case_id} severity evaluated as {analysis.severity_level}. Resolved at Tier 2.",
    )


def document_demo_soc_t2_report_node(outcome: DemoSOCT2Outcome) -> str:
    return outcome.t2_action_plan


def build_demo_soc_t2_workflow() -> Workflow:
    return Workflow(
        name="demo_soc_t2_workflow",
        description="Graph-based workflow for Tier 2 SOC alert investigation, severity assessment, and Tier 3 escalation",
        edges=[
            (START, extract_demo_soc_t2_payload_node, analyze_soc_t2_case_node, demo_soc_t2_router),
            (demo_soc_t2_router, {
                "ESCALATE_TIER_3": handle_escalate_tier_3_branch,
                "RESOLVE_TIER_2": handle_resolve_tier_2_branch,
            }),
            (handle_escalate_tier_3_branch, document_demo_soc_t2_report_node),
            (handle_resolve_tier_2_branch, document_demo_soc_t2_report_node),
        ],
    )
