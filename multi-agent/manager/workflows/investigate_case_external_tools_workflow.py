"""
Investigate Case with External Tools Graph Workflow for Google ADK.

Implements 'Investigate a Case with External Tools Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class ExternalInvestigationInput(BaseModel):
    case_id: str = Field(description="SOAR Case ID")
    external_tool: str = Field(description="External Tool identifier (e.g. 'VirusTotal', 'Shodan', 'CrowdStrike')")


class ExtractedExtPayload(BaseModel):
    case_id: str
    external_tool: str


class ExternalEnrichmentResult(BaseModel):
    payload: ExtractedExtPayload
    query_target: str
    malicious_verdict: bool
    reputation_score: int
    raw_response_summary: str


class InvestigationOutcome(BaseModel):
    enrichment: ExternalEnrichmentResult
    soar_action: str  # "ESCALATE_TIER2", "CLOSE_BENIGN"
    recommendation: str


def extract_ext_payload_node(inp: ExternalInvestigationInput) -> ExtractedExtPayload:
    return ExtractedExtPayload(
        case_id=inp.case_id.strip(),
        external_tool=inp.external_tool.strip(),
    )


def query_external_tool_node(payload: ExtractedExtPayload) -> ExternalEnrichmentResult:
    cid = payload.case_id
    is_mal = "MAL" in cid or "900" in cid
    return ExternalEnrichmentResult(
        payload=payload,
        query_target="198.51.100.77",
        malicious_verdict=is_mal,
        reputation_score=88 if is_mal else 5,
        raw_response_summary=f"External Tool '{payload.external_tool}' returned score 88/100 (Malicious C2)" if is_mal else "Clean",
    )


def external_tool_router(res: ExternalEnrichmentResult) -> Event:
    if res.malicious_verdict:
        route = "ESCALATE_TIER2"
    else:
        route = "CLOSE_BENIGN"
    return Event(route=route, output=res)


def handle_escalate_external_branch(res: ExternalEnrichmentResult) -> InvestigationOutcome:
    return InvestigationOutcome(
        enrichment=res,
        soar_action="ESCALATE_TIER2",
        recommendation=f"Escalate Case {res.payload.case_id} to Tier 2 based on {res.payload.external_tool} verdict.",
    )


def handle_close_external_branch(res: ExternalEnrichmentResult) -> InvestigationOutcome:
    return InvestigationOutcome(
        enrichment=res,
        soar_action="CLOSE_BENIGN",
        recommendation=f"Close Case {res.payload.case_id} as Benign based on {res.payload.external_tool} verdict.",
    )


def document_external_report_node(outcome: InvestigationOutcome) -> str:
    return outcome.recommendation


def build_investigate_case_external_tools_workflow() -> Workflow:
    return Workflow(
        name="investigate_case_external_tools_workflow",
        description="Graph-based workflow for SOAR case investigation enriched by external security tools",
        edges=[
            (START, extract_ext_payload_node, query_external_tool_node, external_tool_router),
            (external_tool_router, {
                "ESCALATE_TIER2": handle_escalate_external_branch,
                "CLOSE_BENIGN": handle_close_external_branch,
            }),
            (handle_escalate_external_branch, document_external_report_node),
            (handle_close_external_branch, document_external_report_node),
        ],
    )
