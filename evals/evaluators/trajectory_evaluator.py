"""
Trajectory and routing evaluator for graph workflows.
"""

from typing import Any, Dict, List, Optional
from evals.evaluators.base import MetricResult, WorkflowTrace


class TrajectoryEvaluator:
    """Evaluates whether the graph execution traversed the expected path and routing decision."""

    @classmethod
    def evaluate(cls, trace: WorkflowTrace, expected: Dict[str, Any]) -> MetricResult:
        executed_nodes = trace.executed_nodes
        actual_route = trace.route

        expected_route = expected.get("expected_route")
        required_nodes: List[str] = expected.get("required_nodes", [])
        prohibited_nodes: List[str] = expected.get("prohibited_nodes", [])

        passed = True
        reasons: List[str] = []
        score = 1.0

        # Check expected route if specified
        if expected_route is not None:
            if actual_route != expected_route:
                passed = False
                score = 0.0
                reasons.append(f"Route mismatch: expected '{expected_route}', got '{actual_route}'.")
            else:
                reasons.append(f"Route matched expected '{expected_route}'.")

        # Check required nodes
        missing_nodes = [node for node in required_nodes if node not in executed_nodes]
        if missing_nodes:
            passed = False
            score = max(0.0, score - 0.5)
            reasons.append(f"Missing required nodes: {missing_nodes}.")
        elif required_nodes:
            reasons.append("All required nodes visited.")

        # Check prohibited nodes
        hit_prohibited = [node for node in prohibited_nodes if node in executed_nodes]
        if hit_prohibited:
            passed = False
            score = 0.0
            reasons.append(f"Visited prohibited nodes: {hit_prohibited}.")

        if not reasons:
            reasons.append("Trajectory execution completed successfully.")

        return MetricResult(
            name="trajectory_and_routing",
            score=score,
            max_score=1.0,
            passed=passed,
            reason="; ".join(reasons),
            metadata={
                "actual_route": actual_route,
                "executed_nodes": executed_nodes,
                "expected_route": expected_route,
            }
        )
