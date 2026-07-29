"""
Detection Rule Validation & Tuning Graph Workflow for Google ADK.

Implements 'Detection Rule Validation and Tuning Runbook'.
"""

from typing import Optional, List
from pydantic import BaseModel, Field

from google.adk.agents import Agent
from google.adk.workflow import Workflow, START, Edge, FunctionNode
from google.adk.events import Event


class RuleValidationInput(BaseModel):
    rule_id: str = Field(description="YARA-L Detection Rule ID")
    rule_name: str = Field(description="Detection Rule Name")
    validation_days: int = Field(default=14, description="Historical validation timeframe in days")


class ExtractedRulePayload(BaseModel):
    rule_id: str
    rule_name: str
    validation_days: int


class YARAValidationResult(BaseModel):
    payload: ExtractedRulePayload
    total_detections: int
    false_positive_rate: float
    compilation_errors: List[str]
    rule_quality_score: int


class RuleTuningAction(BaseModel):
    validation: YARAValidationResult
    tuning_recommendation: str  # "DEPLOY_PRODUCTION", "TUNE_FILTER_FP", "REJECT_COMPILATION_ERROR"
    suggested_yara_l_filter: Optional[str] = None


def extract_rule_payload_node(inp: RuleValidationInput) -> ExtractedRulePayload:
    return ExtractedRulePayload(
        rule_id=inp.rule_id.strip(),
        rule_name=inp.rule_name.strip(),
        validation_days=inp.validation_days,
    )


def validate_yara_l_rule_node(payload: ExtractedRulePayload) -> YARAValidationResult:
    name = payload.rule_name.lower()
    if "err" in name or "syntax" in name:
        return YARAValidationResult(
            payload=payload,
            total_detections=0,
            false_positive_rate=0.0,
            compilation_errors=["Syntax error at line 14: invalid variable $user"],
            rule_quality_score=0,
        )
    elif "broad" in name or "noise" in name or "fp" in name:
        return YARAValidationResult(
            payload=payload,
            total_detections=1450,
            false_positive_rate=0.85,
            compilation_errors=[],
            rule_quality_score=40,
        )
    else:
        return YARAValidationResult(
            payload=payload,
            total_detections=12,
            false_positive_rate=0.02,
            compilation_errors=[],
            rule_quality_score=95,
        )


def rule_tuning_router(val: YARAValidationResult) -> Event:
    if val.compilation_errors:
        route = "REJECT_COMPILATION_ERROR"
    elif val.false_positive_rate > 0.30:
        route = "TUNE_FILTER_FP"
    else:
        route = "DEPLOY_PRODUCTION"
    return Event(route=route, output=val)


def handle_reject_syntax_branch(val: YARAValidationResult) -> RuleTuningAction:
    return RuleTuningAction(
        validation=val,
        tuning_recommendation="REJECT_COMPILATION_ERROR",
        suggested_yara_l_filter=None,
    )


def handle_tune_fp_branch(val: YARAValidationResult) -> RuleTuningAction:
    return RuleTuningAction(
        validation=val,
        tuning_recommendation="TUNE_FILTER_FP",
        suggested_yara_l_filter="Filter noise: exclude principal.user.email = 'service-account@corp.com'",
    )


def handle_deploy_prod_branch(val: YARAValidationResult) -> RuleTuningAction:
    return RuleTuningAction(
        validation=val,
        tuning_recommendation="DEPLOY_PRODUCTION",
        suggested_yara_l_filter=None,
    )


def document_rule_report_node(action: RuleTuningAction) -> str:
    return f"Rule Tuning Outcome for {action.validation.payload.rule_id}: {action.tuning_recommendation}"


def build_detection_rule_validation_workflow() -> Workflow:
    return Workflow(
        name="detection_rule_validation_workflow",
        description="Graph-based workflow for YARA-L rule validation, FP filtering, and production deployment",
        edges=[
            (START, extract_rule_payload_node, validate_yara_l_rule_node, rule_tuning_router),
            (rule_tuning_router, {
                "REJECT_COMPILATION_ERROR": handle_reject_syntax_branch,
                "TUNE_FILTER_FP": handle_tune_fp_branch,
                "DEPLOY_PRODUCTION": handle_deploy_prod_branch,
            }),
            (handle_reject_syntax_branch, document_rule_report_node),
            (handle_tune_fp_branch, document_rule_report_node),
            (handle_deploy_prod_branch, document_rule_report_node),
        ],
    )
