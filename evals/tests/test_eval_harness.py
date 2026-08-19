"""
Unit tests for evaluation harness runner and CLI orchestration.
"""

import tempfile
import unittest
from pathlib import Path
from evals.datasets import load_dataset
from evals.runner import run_eval_case, run_eval_dataset
from evals.evaluators.benchmark_evaluator import BenchmarkEvaluator


class TestEvalHarness(unittest.TestCase):

    def test_run_eval_case_success(self):
        case = {
            "test_id": "TEST-UNIT-01",
            "workflow_name": "suspicious_login_workflow",
            "input": {
                "case_id": "CASE-101",
                "user_id": "alice.smith@example.com",
                "source_ip": "192.168.1.50",
            },
            "expected": {
                "expected_route": "LOW_RISK_BENIGN",
                "required_output_fields": ["action_taken", "soar_comment"],
            },
            "min_passing_score": 80.0,
        }
        res = run_eval_case(case)
        self.assertTrue(res.passed)
        self.assertGreaterEqual(res.total_score, 80.0)
        self.assertIn("trajectory", res.metrics)
        self.assertIn("schema", res.metrics)
        self.assertTrue(res.metrics["trajectory"].passed)
        self.assertTrue(res.metrics["schema"].passed)

    def test_run_eval_case_unknown_workflow(self):
        case = {
            "test_id": "TEST-UNIT-ERR",
            "workflow_name": "non_existent_workflow",
            "input": {},
        }
        res = run_eval_case(case)
        self.assertFalse(res.passed)
        self.assertEqual(res.total_score, 0.0)
        self.assertIsNotNone(res.error)

    def test_run_eval_dataset_batch(self):
        results = run_eval_dataset("core_workflows")
        self.assertGreaterEqual(len(results), 6)
        passed_count = sum(1 for r in results if r.passed)
        self.assertEqual(passed_count, len(results))

    def test_benchmark_report_file_generation(self):
        results = run_eval_dataset("core_workflows")
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir)
            md = BenchmarkEvaluator.generate_markdown_report(results)
            json_data = BenchmarkEvaluator.generate_json_summary(results)

            md_path = out_dir / "report.md"
            json_path = out_dir / "report.json"

            md_path.write_text(md, encoding="utf-8")
            json_path.write_text(str(json_data), encoding="utf-8")

            self.assertTrue(md_path.exists())
            self.assertTrue(json_path.exists())
            self.assertIn("ADK Graph Workflow Evaluation Benchmark", md)


    def test_run_eval_case_with_custom_max_steps(self):
        case = {
            "test_id": "TEST-UNIT-MAXSTEPS",
            "workflow_name": "suspicious_login_workflow",
            "input": {
                "case_id": "CASE-102",
                "user_id": "alice.smith@example.com",
                "source_ip": "192.168.1.50",
            },
            "max_steps": 100,
        }
        res = run_eval_case(case)
        self.assertTrue(res.passed)
        self.assertEqual(res.trace.status, "success")


if __name__ == "__main__":
    unittest.main()
