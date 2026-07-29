"""
Detection Report Generation Graph Workflow for Google ADK.

Implements 'Detection Report Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event

from .common import BaseWorkflowInput, CommonSOAROutcome, sanitize_entity_value, format_soar_comment


class DetectionReportInput(BaseWorkflowInput):
    rule_id: str = Field(description="Detection Rule ID")
    timeframe_days: int = Field(default=7, description="Timeframe in days for detection stats")


class ExtractedDetectionReportPayload(BaseModel):
    rule_id: str
    timeframe_days: int
    case_id: Optional[str] = None


class DetectionStatsResult(BaseModel):
    payload: ExtractedDetectionReportPayload
    rule_name: str
    total_triggers: int
    true_positives: int
    false_positives: int
    performance_verdict: str  # "OPTIMAL_PERFORMANCE", "HIGH_NOISE_LEVEL"


class DetectionReportOutcome(BaseModel):
    stats: DetectionStatsResult
    report_markdown: str


def extract_detection_report_payload_node(inp: DetectionReportInput) -> ExtractedDetectionReportPayload:
    return ExtractedDetectionReportPayload(
        rule_id=sanitize_entity_value(inp.rule_id),
        timeframe_days=inp.timeframe_days,
        case_id=inp.case_id,
    )


def fetch_detection_stats_node(payload: ExtractedDetectionReportPayload) -> DetectionStatsResult:
    rid = payload.rule_id
    is_noisy = "noise" in rid.lower() or "broad" in rid.lower()
    return DetectionStatsResult(
        payload=payload,
        rule_name=f"Detection Rule {rid}",
        total_triggers=150 if is_noisy else 12,
        true_positives=10 if is_noisy else 11,
        false_positives=140 if is_noisy else 1,
        performance_verdict="HIGH_NOISE_LEVEL" if is_noisy else "OPTIMAL_PERFORMANCE",
    )


def detection_report_router(stats: DetectionStatsResult) -> Event:
    if stats.performance_verdict == "HIGH_NOISE_LEVEL":
        route = "HIGH_NOISE_LEVEL"
    else:
        route = "OPTIMAL_PERFORMANCE"
    return Event(route=route, output=stats)


def handle_high_noise_branch(stats: DetectionStatsResult) -> DetectionReportOutcome:
    md = f"# Detection Report: {stats.rule_name}\n\n- **Verdict:** `HIGH_NOISE_LEVEL` (FP Rate: {stats.false_positives / stats.total_triggers:.0%})\n- **Recommendation:** Tune or exclude noisy filters."
    return DetectionReportOutcome(stats=stats, report_markdown=md)


def handle_optimal_performance_branch(stats: DetectionStatsResult) -> DetectionReportOutcome:
    md = f"# Detection Report: {stats.rule_name}\n\n- **Verdict:** `OPTIMAL_PERFORMANCE` (Accuracy: {stats.true_positives / stats.total_triggers:.0%})"
    return DetectionReportOutcome(stats=stats, report_markdown=md)


def document_detection_report_node(outcome: DetectionReportOutcome) -> str:
    return outcome.report_markdown


def build_detection_report_workflow() -> Workflow:
    return Workflow(
        name="detection_report_workflow",
        description="Graph-based workflow for generating detection rule effectiveness and noise metrics reports",
        edges=[
            (START, extract_detection_report_payload_node, fetch_detection_stats_node, detection_report_router),
            (detection_report_router, {
                "HIGH_NOISE_LEVEL": handle_high_noise_branch,
                "OPTIMAL_PERFORMANCE": handle_optimal_performance_branch,
            }),
            (handle_high_noise_branch, document_detection_report_node),
            (handle_optimal_performance_branch, document_detection_report_node),
        ],
    )
