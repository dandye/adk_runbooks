"""
Integration test suite for core security benchmark workflows.
"""

import unittest
from evals.datasets import load_dataset
from evals.runner import run_eval_case


class TestCoreBenchmarks(unittest.TestCase):

    def setUp(self):
        self.cases = load_dataset("core_workflows")

    def test_run_all_core_benchmark_workflows(self):
        for case in self.cases:
            with self.subTest(test_id=case["test_id"], workflow=case["workflow_name"]):
                result = run_eval_case(case)
                self.assertTrue(
                    result.passed,
                    f"Test {case['test_id']} failed on {case['workflow_name']}: {result.error} (metrics: {result.metrics})"
                )
                self.assertGreaterEqual(
                    result.total_score,
                    case.get("min_passing_score", 80.0),
                    f"Test {case['test_id']} score {result.total_score} below minimum threshold."
                )
                self.assertEqual(result.trace.status, "success")


if __name__ == "__main__":
    unittest.main()
