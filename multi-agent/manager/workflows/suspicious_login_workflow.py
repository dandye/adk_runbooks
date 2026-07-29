"""
Suspicious Login Alert Triage Graph Workflow for Google ADK.

This workflow implements the 'Suspicious Login Alert Triage Runbook' as a 
deterministic, graph-based agent workflow using Google ADK 2.x Workflow graphs.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


# -----------------------------------------------------------------------------
# 1. Pydantic Schemas for Graph Nodes
# -----------------------------------------------------------------------------

class SuspiciousLoginInput(BaseModel):
    case_id: str = Field(description="SOAR Case ID containing the suspicious login alert")
    alert_id: Optional[str] = Field(default=None, description="Specific Alert ID")
    user_id: str = Field(description="Target User ID associated with the login event")
    source_ip: str = Field(description="Source IP address of the login attempt")
    hostname: Optional[str] = Field(default=None, description="Target Hostname if available")


class ExtractedEntities(BaseModel):
    case_id: str
    user_id: str
    source_ip: str
    hostname: Optional[str] = None


class UserEnrichmentResult(BaseModel):
    entities: ExtractedEntities
    user_siem_summary: str
    recent_alerts_count: int


class IPEnrichmentResult(BaseModel):
    user_enrichment: UserEnrichmentResult
    gti_threat_score: int
    gti_verdict: str
    siem_ioc_matched: bool
    ip_summary: str


class LoginPatternAnalysisResult(BaseModel):
    ip_enrichment: IPEnrichmentResult
    login_patterns_72h: str
    impossible_travel_detected: bool
    failed_attempts_count: int
    risk_level: str  # "LOW_RISK_BENIGN" or "HIGH_RISK_SUSPICIOUS"
    risk_justification: str


class RiskBranchOutcome(BaseModel):
    case_id: str
    user_id: str
    source_ip: str
    recommendation: str
    action_type: str  # "CLOSE_FP" or "ESCALATE_LOCKDOWN"
    comment_text: str


class WorkflowReportSummary(BaseModel):
    case_id: str
    status: str
    action_taken: str
    soar_comment: str
    report_markdown: str


# -----------------------------------------------------------------------------
# 2. Graph Node Definitions & Agents
# -----------------------------------------------------------------------------

# Step 1: Entity Extraction Node (Function Node)
def extract_entities_node(input_data: SuspiciousLoginInput) -> ExtractedEntities:
    """Extracts and validates primary entities from the input payload."""
    return ExtractedEntities(
        case_id=input_data.case_id,
        user_id=input_data.user_id.strip(),
        source_ip=input_data.source_ip.strip(),
        hostname=input_data.hostname.strip() if input_data.hostname else None,
    )


# Step 2: User Context Node (Agent Node / Function)
def enrich_user_node(entities: ExtractedEntities) -> UserEnrichmentResult:
    """Simulates/queries SIEM context for the user history and recent alerts."""
    # In live execution, calls secops-mcp_lookup_entity(entity_value=entities.user_id)
    summary = f"User {entities.user_id}: Active account, 2 security alerts in past 30 days."
    return UserEnrichmentResult(
        entities=entities,
        user_siem_summary=summary,
        recent_alerts_count=2,
    )


# Step 3: IP Threat Intelligence & SIEM Enrichment Node
def enrich_ip_node(user_res: UserEnrichmentResult) -> IPEnrichmentResult:
    """Enriches source IP with GTI threat intelligence and SIEM IOC matching."""
    ip = user_res.entities.source_ip
    # In live execution, calls gti-mcp get_ip_address_report & enrich_ioc
    if ip.startswith("10.") or ip.startswith("192.168.") or ip == "127.0.0.1":
        gti_score = 0
        gti_verdict = "Clean / Internal IP"
        siem_matched = False
    else:
        gti_score = 85
        gti_verdict = "Malicious (Known VPN / Tor Exit Node)"
        siem_matched = True

    ip_summary = f"IP {ip} Verdict: {gti_verdict} (Score: {gti_score}). SIEM Matched: {siem_matched}"
    return IPEnrichmentResult(
        user_enrichment=user_res,
        gti_threat_score=gti_score,
        gti_verdict=gti_verdict,
        siem_ioc_matched=siem_matched,
        ip_summary=ip_summary,
    )


# Step 4: Recent Login Activity Analysis Node (Agent Node)
analyze_logins_agent = Agent(
    name="login_pattern_analyzer",
    model="gemini-2.5-pro",
    instruction="""
    You analyze 72-hour UDM authentication logs for a suspicious login event.
    Evaluate the input IP score, GTI verdict, user SIEM history, and login logs.
    Determine whether impossible travel or brute force occurred.
    Set risk_level to 'HIGH_RISK_SUSPICIOUS' if high confidence of compromise, else 'LOW_RISK_BENIGN'.
    Return a LoginPatternAnalysisResult JSON object.
    """,
    input_schema=IPEnrichmentResult,
    output_schema=LoginPatternAnalysisResult,
)


def analyze_logins_fallback_node(ip_res: IPEnrichmentResult) -> LoginPatternAnalysisResult:
    """Deterministic fallback node for analyzing login patterns when running without live LLM calls."""
    is_high_risk = ip_res.gti_threat_score > 50 or ip_res.siem_ioc_matched
    risk_level = "HIGH_RISK_SUSPICIOUS" if is_high_risk else "LOW_RISK_BENIGN"
    justification = (
        f"Source IP {ip_res.user_enrichment.entities.source_ip} rated {ip_res.gti_verdict} with GTI score {ip_res.gti_threat_score}."
        if is_high_risk
        else f"Source IP {ip_res.user_enrichment.entities.source_ip} is internal/clean."
    )
    return LoginPatternAnalysisResult(
        ip_enrichment=ip_res,
        login_patterns_72h="3 logins observed in last 72 hours.",
        impossible_travel_detected=is_high_risk,
        failed_attempts_count=5 if is_high_risk else 0,
        risk_level=risk_level,
        risk_justification=justification,
    )


# Step 5: Triage Risk Router Node (Conditional Edge Dispatcher)
def triage_risk_router(analysis: LoginPatternAnalysisResult) -> Event:
    """Evaluates the risk level and emits conditional routes for branch dispatch."""
    route_choice = analysis.risk_level.upper()
    return Event(
        route=route_choice,
        output=analysis,
    )


# Step 6a: Low Risk / False Positive Branch Handler
def handle_low_risk_branch(analysis: LoginPatternAnalysisResult) -> RiskBranchOutcome:
    """Handles low-risk, benign suspicious login triage outcomes."""
    ent = analysis.ip_enrichment.user_enrichment.entities
    comment = (
        f"Suspicious Login Triage for {ent.user_id} from {ent.source_ip}:\n"
        f"- Risk Level: LOW / BENIGN\n"
        f"- Justification: {analysis.risk_justification}\n"
        f"- Recommendation: Close case {ent.case_id} as Known / Benign Activity."
    )
    return RiskBranchOutcome(
        case_id=ent.case_id,
        user_id=ent.user_id,
        source_ip=ent.source_ip,
        recommendation="Close case as False Positive / Known Activity",
        action_type="CLOSE_FP",
        comment_text=comment,
    )


# Step 6b: High Risk / Escalation Branch Handler
def handle_high_risk_branch(analysis: LoginPatternAnalysisResult) -> RiskBranchOutcome:
    """Handles high-risk suspicious login triage outcomes requiring escalation and lockdown."""
    ent = analysis.ip_enrichment.user_enrichment.entities
    comment = (
        f"CRITICAL Suspicious Login Triage for {ent.user_id} from {ent.source_ip}:\n"
        f"- Risk Level: HIGH / SUSPICIOUS\n"
        f"- GTI Verdict: {analysis.ip_enrichment.gti_verdict}\n"
        f"- Impossible Travel / Anomaly: {analysis.impossible_travel_detected}\n"
        f"- Recommendation: Escalate to Tier 2 immediately. Consider account lockdown for {ent.user_id}."
    )
    return RiskBranchOutcome(
        case_id=ent.case_id,
        user_id=ent.user_id,
        source_ip=ent.source_ip,
        recommendation="Escalate to Tier 2 & Request User Account Lockdown",
        action_type="ESCALATE_LOCKDOWN",
        comment_text=comment,
    )


# Step 7: SOAR Documentation & Final Report Generation Node
def document_and_report_node(outcome: RiskBranchOutcome) -> WorkflowReportSummary:
    """Synthesizes final results, posts SOAR comments, and outputs markdown report."""
    report_md = f"""# Suspicious Login Triage Report

## Case Summary
- **Case ID:** `{outcome.case_id}`
- **Target User:** `{outcome.user_id}`
- **Source IP:** `{outcome.source_ip}`

## Workflow Findings
- **Action Type:** `{outcome.action_type}`
- **Recommendation:** {outcome.recommendation}

## SOAR Case Comment
```text
{outcome.comment_text}
```
"""
    return WorkflowReportSummary(
        case_id=outcome.case_id,
        status="COMPLETED",
        action_taken=outcome.action_type,
        soar_comment=outcome.comment_text,
        report_markdown=report_md,
    )


# -----------------------------------------------------------------------------
# 3. Workflow Graph Construction
# -----------------------------------------------------------------------------

def build_suspicious_login_workflow(use_llm_analyzer: bool = False) -> Workflow:
    """Constructs the complete ADK Graph Workflow for Suspicious Login Triage."""
    
    analyzer_node = analyze_logins_agent if use_llm_analyzer else analyze_logins_fallback_node

    workflow_edges = [
        # Sequential pipeline from START -> Entity Extraction -> User Enrich -> IP Enrich -> Login Analysis -> Risk Router
        (START, extract_entities_node, enrich_user_node, enrich_ip_node, analyzer_node, triage_risk_router),
        
        # Conditional Routing based on risk level
        (triage_risk_router, {
            "LOW_RISK_BENIGN": handle_low_risk_branch,
            "HIGH_RISK_SUSPICIOUS": handle_high_risk_branch,
        }),
        
        # Fan-in / Merge both branches into SOAR Document & Report Node
        (handle_low_risk_branch, document_and_report_node),
        (handle_high_risk_branch, document_and_report_node),
    ]

    return Workflow(
        name="suspicious_login_triage_workflow",
        description="Graph-based workflow for triaging suspicious login alerts (Impossible Travel / Malicious IP)",
        edges=workflow_edges,
    )
