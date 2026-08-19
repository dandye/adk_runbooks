"""
Schema and payload integrity evaluator for graph workflow outputs.
"""

from typing import Any, Dict, List
from evals.evaluators.base import MetricResult


class SchemaEvaluator:
    """Evaluates whether the output payload adheres to the required schema and contains key artifacts."""

    @classmethod
    def evaluate(cls, raw_output: Any, expected: Dict[str, Any]) -> MetricResult:
        # Convert output to dict representation if dataclass or object
        output_dict: Dict[str, Any] = {}
        if isinstance(raw_output, dict):
            output_dict = raw_output
        elif hasattr(raw_output, "__dict__"):
            output_dict = raw_output.__dict__
        else:
            output_dict = {"raw": str(raw_output)}

        required_fields: List[str] = expected.get("required_output_fields", [])
        required_substrings: List[str] = expected.get("required_comment_substrings", [])

        passed = True
        reasons: List[str] = []
        score = 1.0

        # Check required fields
        missing_fields = [f for f in required_fields if f not in output_dict or output_dict[f] is None]
        if missing_fields:
            passed = False
            score = max(0.0, score - 0.5)
            reasons.append(f"Missing required fields: {missing_fields}.")
        elif required_fields:
            reasons.append("All required fields present.")

        # Check required substrings in output text/comments
        all_text = " ".join(str(v) for v in output_dict.values()).lower()
        missing_substrings = [s for s in required_substrings if s.lower() not in all_text]
        if missing_substrings:
            passed = False
            score = max(0.0, score - 0.5)
            reasons.append(f"Missing expected comment keywords: {missing_substrings}.")
        elif required_substrings:
            reasons.append("All expected keyword substrings verified.")

        if not reasons:
            reasons.append("Schema and payload integrity verified.")

        return MetricResult(
            name="schema_and_payload_integrity",
            score=score,
            max_score=1.0,
            passed=passed,
            reason="; ".join(reasons),
            metadata={
                "present_fields": list(output_dict.keys()),
                "missing_fields": missing_fields,
            }
        )
