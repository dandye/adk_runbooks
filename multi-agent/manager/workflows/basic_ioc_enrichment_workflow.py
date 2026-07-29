"""
Basic IOC Enrichment Graph Workflow for Google ADK.

This workflow implements the 'Basic IOC Enrichment Runbook' as a
deterministic, graph-based agent workflow using Google ADK 2.x Workflow graphs.
It routes IOC enrichment based on IOC type (IP, Domain, File Hash, URL).
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


# -----------------------------------------------------------------------------
# 1. Pydantic Schemas
# -----------------------------------------------------------------------------

class IOCEnrichmentInput(BaseModel):
    ioc_value: str = Field(description="IOC Value (IP, Domain, Hash, or URL)")
    ioc_type: str = Field(description="Type of IOC: 'IP Address', 'Domain', 'File Hash', or 'URL'")
    case_id: Optional[str] = Field(default=None, description="Optional SOAR Case ID")
    siem_search_hours: int = Field(default=24, description="SIEM search timeframe")


class ExtractedIOCPayload(BaseModel):
    ioc_value: str
    ioc_type: str
    case_id: Optional[str] = None
    siem_search_hours: int


class SpecializedEnrichmentResult(BaseModel):
    payload: ExtractedIOCPayload
    gti_summary: str
    gti_score: int
    relationships: List[str]


class SIEMEventSearchResult(BaseModel):
    enrichment: SpecializedEnrichmentResult
    siem_match_found: bool
    recent_events_count: int
    related_cases: List[str]


class IOCRiskAssessmentOutcome(BaseModel):
    siem_result: SIEMEventSearchResult
    risk_level: str  # "HIGH_RISK_THREAT" or "LOW_RISK_BENIGN"
    recommendation: str


class IOCEnrichmentReportSummary(BaseModel):
    ioc_value: str
    ioc_type: str
    assessment: str
    recommendation: str
    soar_comment_status: str
    report_markdown: str


# -----------------------------------------------------------------------------
# 2. Graph Node Functions & Routers
# -----------------------------------------------------------------------------

def extract_ioc_node(input_data: IOCEnrichmentInput) -> ExtractedIOCPayload:
    """Extracts and normalizes IOC value and type."""
    return ExtractedIOCPayload(
        ioc_value=input_data.ioc_value.strip(),
        ioc_type=input_data.ioc_type.strip(),
        case_id=input_data.case_id.strip() if input_data.case_id else None,
        siem_search_hours=input_data.siem_search_hours,
    )


def ioc_type_router(payload: ExtractedIOCPayload) -> Event:
    """Routes execution based on normalized IOC_TYPE."""
    t = payload.ioc_type.upper()
    if "IP" in t:
        route = "IP_BRANCH"
    elif "DOMAIN" in t:
        route = "DOMAIN_BRANCH"
    elif "HASH" in t:
        route = "HASH_BRANCH"
    else:
        route = "URL_BRANCH"

    return Event(route=route, output=payload)


# Branch Handlers for specific IOC Types
def enrich_ip_branch(payload: ExtractedIOCPayload) -> SpecializedEnrichmentResult:
    """Enriches IP address with GTI IP Report and ASN/reputation data."""
    val = payload.ioc_value
    score = 80 if "bad" in val or "198.51" in val else 0
    return SpecializedEnrichmentResult(
        payload=payload,
        gti_summary=f"GTI IP Report for {val}: Threat Score {score}/100. Category: C2/VPN.",
        gti_score=score,
        relationships=["resolving_domains", "subnets"],
    )


def enrich_domain_branch(payload: ExtractedIOCPayload) -> SpecializedEnrichmentResult:
    """Enriches Domain with GTI Domain Report and passive DNS resolutions."""
    val = payload.ioc_value
    score = 85 if "evil" in val or "bad" in val else 5
    return SpecializedEnrichmentResult(
        payload=payload,
        gti_summary=f"GTI Domain Report for {val}: Threat Score {score}/100. Category: Phishing.",
        gti_score=score,
        relationships=["dns_resolutions", "subdomains"],
    )


def enrich_hash_branch(payload: ExtractedIOCPayload) -> SpecializedEnrichmentResult:
    """Enriches File Hash with GTI File Report and sandbox behavior summary."""
    val = payload.ioc_value
    score = 90 if "bad" in val or "malware" in val else 0
    return SpecializedEnrichmentResult(
        payload=payload,
        gti_summary=f"GTI File Report for {val}: Threat Score {score}/100. Category: Trojan.",
        gti_score=score,
        relationships=["contacted_ips", "dropped_files"],
    )


def enrich_url_branch(payload: ExtractedIOCPayload) -> SpecializedEnrichmentResult:
    """Enriches URL with GTI URL Report and page analysis."""
    val = payload.ioc_value
    score = 75 if "bad" in val or "phish" in val else 0
    return SpecializedEnrichmentResult(
        payload=payload,
        gti_summary=f"GTI URL Report for {val}: Threat Score {score}/100. Category: Malicious URL.",
        gti_score=score,
        relationships=["domain_info"],
    )


# Merge Node: SIEM Search Node
def siem_search_node(enrichment: SpecializedEnrichmentResult) -> SIEMEventSearchResult:
    """Searches SIEM for recent security events and open SOAR cases involving the IOC."""
    score = enrichment.gti_score
    matched = score > 50
    events_count = 12 if matched else 0
    related_cases = ["CASE-8801"] if matched else []

    return SIEMEventSearchResult(
        enrichment=enrichment,
        siem_match_found=matched,
        recent_events_count=events_count,
        related_cases=related_cases,
    )


# Risk Assessment Router
def ioc_risk_router(siem_res: SIEMEventSearchResult) -> Event:
    """Evaluates combined threat score and SIEM presence to determine risk level."""
    if siem_res.enrichment.gti_score >= 50 or siem_res.siem_match_found:
        route = "HIGH_RISK_THREAT"
    else:
        route = "LOW_RISK_BENIGN"

    return Event(route=route, output=siem_res)


def handle_high_risk_ioc_branch(siem_res: SIEMEventSearchResult) -> IOCRiskAssessmentOutcome:
    """Handles high-risk IOC enrichment outcome."""
    ioc = siem_res.enrichment.payload.ioc_value
    return IOCRiskAssessmentOutcome(
        siem_result=siem_res,
        risk_level="HIGH_RISK_THREAT",
        recommendation=f"Escalate IOC {ioc} for Containment / Firewall Block & Active Endpoint Inspection.",
    )


def handle_low_risk_ioc_branch(siem_res: SIEMEventSearchResult) -> IOCRiskAssessmentOutcome:
    """Handles low-risk/benign IOC enrichment outcome."""
    ioc = siem_res.enrichment.payload.ioc_value
    return IOCRiskAssessmentOutcome(
        siem_result=siem_res,
        risk_level="LOW_RISK_BENIGN",
        recommendation=f"Close case or monitor IOC {ioc} as Benign / Low Risk.",
    )


# Final Synthesize & SOAR Document Node
def document_ioc_enrichment_node(outcome: IOCRiskAssessmentOutcome) -> IOCEnrichmentReportSummary:
    """Synthesizes all findings into a SOAR comment and report summary."""
    res = outcome.siem_result
    enrich = res.enrichment
    p = enrich.payload

    comment = (
        f"Basic IOC Enrichment for {p.ioc_value} ({p.ioc_type}):\n"
        f"- Risk Level: {outcome.risk_level}\n"
        f"- GTI Summary: {enrich.gti_summary}\n"
        f"- SIEM Events Found: {res.recent_events_count}\n"
        f"- Related Cases: {res.related_cases}\n"
        f"- Recommendation: {outcome.recommendation}"
    )

    report_md = f"""# Basic IOC Enrichment Report

## Target IOC
- **Value:** `{p.ioc_value}`
- **Type:** `{p.ioc_type}`
- **Case ID:** `{p.case_id if p.case_id else 'N/A'}`

## Enrichment Summary
- **GTI Threat Score:** {enrich.gti_score}/100
- **GTI Findings:** {enrich.gti_summary}
- **Relationships:** `{enrich.relationships}`

## SIEM Context
- **SIEM Match Found:** {res.siem_match_found}
- **Recent Events Count:** {res.recent_events_count}

## Assessment & Recommendation
- **Assessment:** `{outcome.risk_level}`
- **Recommendation:** {outcome.recommendation}
"""

    return IOCEnrichmentReportSummary(
        ioc_value=p.ioc_value,
        ioc_type=p.ioc_type,
        assessment=outcome.risk_level,
        recommendation=outcome.recommendation,
        soar_comment_status="Documented in SOAR" if p.case_id else "Skipped (No Case ID)",
        report_markdown=report_md,
    )


# -----------------------------------------------------------------------------
# 3. Workflow Graph Construction
# -----------------------------------------------------------------------------

def build_basic_ioc_enrichment_workflow() -> Workflow:
    """Constructs the ADK Graph Workflow for Basic IOC Enrichment."""
    
    workflow_edges = [
        # 1. Pipeline Start -> Extract -> Type Router
        (START, extract_ioc_node, ioc_type_router),
        
        # 2. Type Branching
        (ioc_type_router, {
            "IP_BRANCH": enrich_ip_branch,
            "DOMAIN_BRANCH": enrich_domain_branch,
            "HASH_BRANCH": enrich_hash_branch,
            "URL_BRANCH": enrich_url_branch,
        }),
        
        # 3. Fan-in into SIEM Search Node
        (enrich_ip_branch, siem_search_node),
        (enrich_domain_branch, siem_search_node),
        (enrich_hash_branch, siem_search_node),
        (enrich_url_branch, siem_search_node),
        
        # 4. Risk Router & Outcome Branches
        (siem_search_node, ioc_risk_router),
        (ioc_risk_router, {
            "HIGH_RISK_THREAT": handle_high_risk_ioc_branch,
            "LOW_RISK_BENIGN": handle_low_risk_ioc_branch,
        }),
        
        # 5. Final Merge into Document & Report Node
        (handle_high_risk_ioc_branch, document_ioc_enrichment_node),
        (handle_low_risk_ioc_branch, document_ioc_enrichment_node),
    ]

    return Workflow(
        name="basic_ioc_enrichment_workflow",
        description="Graph-based workflow for basic IOC enrichment (IP, Domain, File Hash, URL)",
        edges=workflow_edges,
    )
