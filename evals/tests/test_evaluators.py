"""
Unit tests for evaluator engines (Trajectory, Schema, Rubric, Benchmark).
"""

import unittest
from evals.evaluators.base import EvaluationResult, MetricResult, WorkflowTrace
from evals.evaluators.trajectory_evaluator import TrajectoryEvaluator
from evals.evaluators.schema_evaluator import SchemaEvaluator
from evals.evaluators.rubric_evaluator import RubricEvaluator
from evals.evaluators.benchmark_evaluator import BenchmarkEvaluator


class TestEvaluators(unittest.TestCase):

    def test_trajectory_evaluator_matching_route(self):
        trace = WorkflowTrace(
            workflow_name="suspicious_login_workflow",
            executed_nodes=["extract_entities_node", "enrich_user_node", "handle_low_risk_branch", "document_and_report_node"],
            route="LOW_RISK_BENIGN",
        )
        expected = {
            "expected_route": "LOW_RISK_BENIGN",
            "required_nodes": ["extract_entities_node", "document_and_report_node"],
        }
        metric = TrajectoryEvaluator.evaluate(trace, expected)
        self.assertTrue(metric.passed)
        self.assertEqual(metric.score, 1.0)

    def test_trajectory_evaluator_route_mismatch(self):
        trace = WorkflowTrace(
            workflow_name="suspicious_login_workflow",
            executed_nodes=["extract_entities_node"],
            route="HIGH_RISK_SUSPICIOUS",
        )
        expected = {"expected_route": "LOW_RISK_BENIGN"}
        metric = TrajectoryEvaluator.evaluate(trace, expected)
        self.assertFalse(metric.passed)
        self.assertEqual(metric.score, 0.0)

    def test_schema_evaluator(self):
        output = {
            "action_taken": "Closed",
            "soar_comment": "User account was low risk and closed.",
        }
        expected = {
            "required_output_fields": ["action_taken", "soar_comment"],
            "required_comment_substrings": ["Low risk", "Closed"],
        }
        metric = SchemaEvaluator.evaluate(output, expected)
        self.assertTrue(metric.passed)
        self.assertEqual(metric.score, 1.0)

    def test_rubric_evaluator(self):
        raw_output = {
            "case_id": "CASE-101",
            "user_id": "alice.smith@example.com",
            "action_taken": "Low Risk Authentication Closed",
            "soar_comment": "Automated triage completed. Case closed.",
            "enrichment_summary": "Internal IP lookup confirmed.",
        }
        trace = WorkflowTrace(
            workflow_name="suspicious_login_workflow",
            executed_nodes=["extract", "enrich", "route", "document"],
            route="LOW_RISK_BENIGN",
            duration_seconds=0.05,
            status="success",
        )
        eval_result = RubricEvaluator.evaluate(
            test_id="TEST-001",
            workflow_name="suspicious_login_workflow",
            raw_output=raw_output,
            trace=trace,
            min_passing_score=80.0,
        )
        self.assertTrue(eval_result.passed)
        self.assertGreaterEqual(eval_result.total_score, 80.0)
        self.assertIsNotNone(eval_result.scorecard)

    def test_benchmark_evaluator_generation(self):
        eval_res = EvaluationResult(
            test_id="TEST-001",
            workflow_name="suspicious_login_workflow",
            passed=True,
            total_score=95.0,
            max_score=100.0,
            duration_seconds=0.0123,
        )
        json_data = BenchmarkEvaluator.generate_json_summary([eval_res])
        self.assertEqual(json_data["summary"]["total_tests"], 1)
        self.assertEqual(json_data["summary"]["passed_tests"], 1)

        md = BenchmarkEvaluator.generate_markdown_report([eval_res])
        self.assertIn("ADK Graph Workflow Evaluation Benchmark", md)
        self.assertIn("TEST-001", md)
        self.assertIn("95.0", md)


if __name__ == "__main__":
    unittest.main()
