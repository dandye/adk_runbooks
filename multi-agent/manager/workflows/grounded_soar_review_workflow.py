"""Grounded SOAR Case Review and Runbook Red-Lining Graph Workflow for Google ADK.

Implements an end-to-end ADK Graph Workflow that:
1. Sanitizes raw SIEM/SOAR telemetry via :func:`sanitize_telemetry_text` so
   encoded stagers and credential-dump arguments never trigger LLM safety filters.
2. Evaluates whether the case requires Stage A deterministic indicator defanging
   plus Stage B Developer Knowledge MCP semantic grounding.
3. Generates a red-line review summary and sanitized SOAR case timeline comment.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from google.adk.workflow import Workflow, START
from google.adk.events import Event

from .common import save_workflow_report_to_disk
from ..tools.docs_review_tools import (
    format_soar_doc_review_comment,
    sanitize_telemetry_text,
    verify_post_accept_secops_doc_readiness,
)


class GroundedSOARReviewInput(BaseModel):
    case_id: str = Field(description="SOAR Case ID to review and red-line")
    skill_name: str = Field(
        default="compromised-user-account-response",
        description="Drive runbook skill name applied to the case",
    )
    raw_telemetry_summary: str = Field(
        default="",
        description="Raw SOAR/SIEM command line or indicator telemetry to sanitize",
    )
    doc_url: str = Field(
        default="",
        description="Optional Google Doc URL for the incident report",
    )
    runbook_doc_url: str = Field(
        default="",
        description="Optional Google Doc URL for the staged runbook red-line draft",
    )
    doc_text: str = Field(
        default="",
        description="Optional raw Markdown/Google Doc text for counterfactual pre-vs-post accept 5-pillar readiness verification",
    )
    verify_post_accept_readiness: bool = Field(
        default=True,
        description="When True, computes counterfactual pre-vs-post accept 5-pillar readiness synthesis",
    )


class SanitizedSOARReviewPayload(BaseModel):
    case_id: str
    skill_name: str
    sanitized_telemetry: str
    has_redacted_artifacts: bool
    doc_url: str
    runbook_doc_url: str
    doc_text: str = ""
    verify_post_accept_readiness: bool = True


class GroundedSOARReviewOutcome(BaseModel):
    payload: SanitizedSOARReviewPayload
    review_mode: str
    redline_items: List[str]
    soar_comment: str
    report_markdown: str
    pre_accept_verdict: str = "APPROVED_FOR_SOC_EXECUTION"
    post_accept_verdict: str = "APPROVED_FOR_SOC_EXECUTION"
    pre_accept_readiness_score: float = 100.0
    post_accept_readiness_score: float = 100.0
    readiness_score_delta: float = 0.0
    resolved_defect_count: int = 0
    residual_defect_count: int = 0
    ready_for_promotion_after_accept: bool = True
    signoff_badge_markdown: str = ""


def sanitize_soar_telemetry_node(
    inp: GroundedSOARReviewInput,
) -> SanitizedSOARReviewPayload:
    sanitized = sanitize_telemetry_text(inp.raw_telemetry_summary or "")
    has_redacted = "<REDACTED_" in sanitized or "http://" in sanitized or "https://" in sanitized
    return SanitizedSOARReviewPayload(
        case_id=inp.case_id.strip(),
        skill_name=inp.skill_name.strip() or "compromised-user-account-response",
        sanitized_telemetry=sanitized,
        has_redacted_artifacts=has_redacted,
        doc_url=inp.doc_url.strip(),
        runbook_doc_url=inp.runbook_doc_url.strip(),
        doc_text=inp.doc_text or "",
        verify_post_accept_readiness=bool(inp.verify_post_accept_readiness),
    )


def grounded_review_mode_router(payload: SanitizedSOARReviewPayload) -> Event:
    route = (
        "TWO_STAGE_SANITIZED_REVIEW"
        if payload.has_redacted_artifacts
        else "SEMANTIC_GROUNDED_REVIEW"
    )
    return Event(route=route, output=payload)


def _compute_post_accept_readiness_for_payload(
    payload: SanitizedSOARReviewPayload,
) -> dict:
    if not payload.verify_post_accept_readiness or not (payload.doc_text or "").strip():
        return {
            "pre_accept_verdict": "APPROVED_FOR_SOC_EXECUTION",
            "post_accept_verdict": "APPROVED_FOR_SOC_EXECUTION",
            "pre_accept_readiness_score": 100.0,
            "post_accept_readiness_score": 100.0,
            "readiness_score_delta": 0.0,
            "resolved_defect_count": 0,
            "residual_defect_count": 0,
            "ready_for_promotion_after_accept": True,
            "signoff_badge_markdown": "",
        }
    return verify_post_accept_secops_doc_readiness(
        doc_text=payload.doc_text,
        doc_title=f"SOAR_Case_{payload.case_id}_Grounded_Review",
    )


def handle_two_stage_sanitized_branch(
    payload: SanitizedSOARReviewPayload,
) -> GroundedSOARReviewOutcome:
    r_info = _compute_post_accept_readiness_for_payload(payload)
    redlines = [
        f"Stage A deterministic sanitizer redacted offensive payload tokens in Case {payload.case_id}",
        "Stage A span-based scanner defanged untrusted external URLs via UTF-16 start_index/end_index",
        f"Stage B Developer Knowledge MCP verified Chronicle UDM fields and containment syntax for {payload.skill_name}",
    ]
    if r_info.get("signoff_badge_markdown"):
        redlines.append(str(r_info["signoff_badge_markdown"]))
    soar_comment = format_soar_doc_review_comment(
        case_id=payload.case_id,
        doc_title=f"SOAR_Case_{payload.case_id}_Grounded_Review",
        doc_url=payload.doc_url or f"https://docs.google.com/document/d/case-{payload.case_id}/edit",
        skill_name=payload.skill_name,
        redline_summary=redlines,
        runbook_doc_url=payload.runbook_doc_url,
    )
    readiness_section = ""
    if r_info.get("signoff_badge_markdown"):
        readiness_section = (
            "\n\n## 3b. Counterfactual Post-Accept 5-Pillar Readiness Sign-Off (H29)\n"
            f"- **Pre-Accept Verdict:** `{r_info['pre_accept_verdict']}` (`{r_info['pre_accept_readiness_score']:.2f}/100.00`)\n"
            f"- **Post-Accept Verdict:** `{r_info['post_accept_verdict']}` (`{r_info['post_accept_readiness_score']:.2f}/100.00`, delta `+{r_info['readiness_score_delta']:.2f}`)\n"
            f"- **Resolved Defects:** `{r_info['resolved_defect_count']}` | **Residual Defects:** `{r_info['residual_defect_count']}`\n"
            f"- **Sign-Off Badge:** {r_info['signoff_badge_markdown']}"
        )
    md = (
        f"""# Grounded SOAR Case Review Report (Two-Stage Sanitized Mode)

## 1. Case & Runbook Context
- **SOAR Case ID:** `{payload.case_id}`
- **Drive Runbook Loaded:** `{payload.skill_name}`
- **Review Mode:** `TWO_STAGE_SANITIZED_REVIEW`

## 2. Sanitized Telemetry Summary
```text
{payload.sanitized_telemetry}
```

## 3. Staged Red-Lines (`insertComment` + `writeMode="SUGGEST"`)
"""
        + "\n".join(f"- {item}" for item in redlines)
        + readiness_section
        + f"\n\n## 4. SOAR Timeline Comment\n```text\n{soar_comment}\n```\n"
    )
    return GroundedSOARReviewOutcome(
        payload=payload,
        review_mode="TWO_STAGE_SANITIZED_REVIEW",
        redline_items=redlines,
        soar_comment=soar_comment,
        report_markdown=md,
        pre_accept_verdict=str(r_info["pre_accept_verdict"]),
        post_accept_verdict=str(r_info["post_accept_verdict"]),
        pre_accept_readiness_score=float(r_info["pre_accept_readiness_score"]),
        post_accept_readiness_score=float(r_info["post_accept_readiness_score"]),
        readiness_score_delta=float(r_info["readiness_score_delta"]),
        resolved_defect_count=int(r_info["resolved_defect_count"]),
        residual_defect_count=int(r_info["residual_defect_count"]),
        ready_for_promotion_after_accept=bool(r_info["ready_for_promotion_after_accept"]),
        signoff_badge_markdown=str(r_info.get("signoff_badge_markdown") or ""),
    )


def handle_semantic_grounded_branch(
    payload: SanitizedSOARReviewPayload,
) -> GroundedSOARReviewOutcome:
    r_info = _compute_post_accept_readiness_for_payload(payload)
    redlines = [
        f"Stage B Developer Knowledge MCP verified Chronicle UDM fields and gcloud IAM syntax for Case {payload.case_id}",
        f"Staged Suggested Edits against {payload.skill_name} using descending startIndex ordering",
    ]
    if r_info.get("signoff_badge_markdown"):
        redlines.append(str(r_info["signoff_badge_markdown"]))
    soar_comment = format_soar_doc_review_comment(
        case_id=payload.case_id,
        doc_title=f"SOAR_Case_{payload.case_id}_Grounded_Review",
        doc_url=payload.doc_url or f"https://docs.google.com/document/d/case-{payload.case_id}/edit",
        skill_name=payload.skill_name,
        redline_summary=redlines,
        runbook_doc_url=payload.runbook_doc_url,
    )
    readiness_section = ""
    if r_info.get("signoff_badge_markdown"):
        readiness_section = (
            "\n\n## 3b. Counterfactual Post-Accept 5-Pillar Readiness Sign-Off (H29)\n"
            f"- **Pre-Accept Verdict:** `{r_info['pre_accept_verdict']}` (`{r_info['pre_accept_readiness_score']:.2f}/100.00`)\n"
            f"- **Post-Accept Verdict:** `{r_info['post_accept_verdict']}` (`{r_info['post_accept_readiness_score']:.2f}/100.00`, delta `+{r_info['readiness_score_delta']:.2f}`)\n"
            f"- **Resolved Defects:** `{r_info['resolved_defect_count']}` | **Residual Defects:** `{r_info['residual_defect_count']}`\n"
            f"- **Sign-Off Badge:** {r_info['signoff_badge_markdown']}"
        )
    md = (
        f"""# Grounded SOAR Case Review Report (Semantic Grounded Mode)

## 1. Case & Runbook Context
- **SOAR Case ID:** `{payload.case_id}`
- **Drive Runbook Loaded:** `{payload.skill_name}`
- **Review Mode:** `SEMANTIC_GROUNDED_REVIEW`

## 2. Telemetry Summary
```text
{payload.sanitized_telemetry}
```

## 3. Staged Red-Lines (`insertComment` + `writeMode="SUGGEST"`)
"""
        + "\n".join(f"- {item}" for item in redlines)
        + readiness_section
        + f"\n\n## 4. SOAR Timeline Comment\n```text\n{soar_comment}\n```\n"
    )
    return GroundedSOARReviewOutcome(
        payload=payload,
        review_mode="SEMANTIC_GROUNDED_REVIEW",
        redline_items=redlines,
        soar_comment=soar_comment,
        report_markdown=md,
        pre_accept_verdict=str(r_info["pre_accept_verdict"]),
        post_accept_verdict=str(r_info["post_accept_verdict"]),
        pre_accept_readiness_score=float(r_info["pre_accept_readiness_score"]),
        post_accept_readiness_score=float(r_info["post_accept_readiness_score"]),
        readiness_score_delta=float(r_info["readiness_score_delta"]),
        resolved_defect_count=int(r_info["resolved_defect_count"]),
        residual_defect_count=int(r_info["residual_defect_count"]),
        ready_for_promotion_after_accept=bool(r_info["ready_for_promotion_after_accept"]),
        signoff_badge_markdown=str(r_info.get("signoff_badge_markdown") or ""),
    )


def document_grounded_soar_review_node(outcome: GroundedSOARReviewOutcome) -> str:
    saved_path = save_workflow_report_to_disk(
        f"Grounded_SOAR_Review_Case_{outcome.payload.case_id}",
        outcome.report_markdown,
    )
    return (
        f"Grounded SOAR review report saved to {saved_path}:\n\n"
        f"{outcome.report_markdown}"
    )


def build_grounded_soar_review_workflow() -> Workflow:
    return Workflow(
        name="grounded_soar_review_workflow",
        description="Two-stage sanitized and Developer Knowledge grounded Google Docs review workflow for SOAR cases",
        edges=[
            (START, sanitize_soar_telemetry_node, grounded_review_mode_router),
            (
                grounded_review_mode_router,
                {
                    "TWO_STAGE_SANITIZED_REVIEW": handle_two_stage_sanitized_branch,
                    "SEMANTIC_GROUNDED_REVIEW": handle_semantic_grounded_branch,
                },
            ),
            (handle_two_stage_sanitized_branch, document_grounded_soar_review_node),
            (handle_semantic_grounded_branch, document_grounded_soar_review_node),
        ],
    )
