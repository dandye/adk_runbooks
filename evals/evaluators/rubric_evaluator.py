"""
Rubric evaluator binding workflow execution to runbook rubrics.
"""

from typing import Any, Dict
from evals.evaluators.base import EvaluationResult, MetricResult, WorkflowTrace
from evals.rubrics import RUBRIC_REGISTRY
from evals.registry import get_workflow_definition


class RubricEvaluator:
    """Evaluates a workflow output against its assigned runbook rubric."""

    @classmethod
    def evaluate(
        cls,
        test_id: str,
        workflow_name: str,
        raw_output: Any,
        trace: WorkflowTrace,
        min_passing_score: float = 80.0,
    ) -> EvaluationResult:
        wf_def = get_workflow_definition(workflow_name)
        rubric_type = wf_def.rubric_type if wf_def else "TRIAGE_IRP"

        rubric_cls = RUBRIC_REGISTRY.get(rubric_type, RUBRIC_REGISTRY["TRIAGE_IRP"])

        # Convert output to dict
        output_dict: Dict[str, Any] = {}
        if isinstance(raw_output, dict):
            output_dict = raw_output
        elif hasattr(raw_output, "__dict__"):
            output_dict = raw_output.__dict__
        else:
            output_dict = {"raw": str(raw_output)}

        trace_dict = {
            "workflow_name": trace.workflow_name,
            "executed_nodes": trace.executed_nodes,
            "route": trace.route,
            "duration_seconds": trace.duration_seconds,
            "status": trace.status,
        }

        scorecard = rubric_cls.evaluate(output_dict, trace=trace_dict)
        passed = scorecard.total_score >= min_passing_score and trace.status == "success"

        metrics: Dict[str, MetricResult] = {
            "rubric_total_score": MetricResult(
                name="rubric_total_score",
                score=scorecard.total_score,
                max_score=scorecard.max_score,
                passed=passed,
                reason=f"Scored {scorecard.total_score:.1f}/{scorecard.max_score:.1f} (min passing: {min_passing_score:.1f})",
                metadata=scorecard.category_scores,
            )
        }

        return EvaluationResult(
            test_id=test_id,
            workflow_name=workflow_name,
            passed=passed,
            total_score=scorecard.total_score,
            max_score=scorecard.max_score,
            metrics=metrics,
            scorecard=scorecard,
            trace=trace,
            duration_seconds=trace.duration_seconds,
            error=trace.error,
        )
