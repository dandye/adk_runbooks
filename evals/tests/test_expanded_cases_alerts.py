"""
Integration test suite for the expanded Cases and Alerts evaluation dataset.
"""

import unittest
from evals.datasets import load_dataset
from evals.runner import run_eval_case


class TestExpandedCasesAlerts(unittest.TestCase):

    def setUp(self):
        self.cases = load_dataset("expanded_cases_alerts")

    def test_run_all_expanded_cases_and_alerts(self):
        self.assertGreaterEqual(len(self.cases), 20, "Dataset must contain at least 20 test cases.")
        failed_cases = []

        for case in self.cases:
            with self.subTest(test_id=case["test_id"], workflow=case["workflow_name"]):
                result = run_eval_case(case)
                if not result.passed:
                    failed_cases.append((case["test_id"], case["workflow_name"], result.error, result.total_score))
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

        self.assertEqual(len(failed_cases), 0, f"Failed cases: {failed_cases}")


if __name__ == "__main__":
    unittest.main()
