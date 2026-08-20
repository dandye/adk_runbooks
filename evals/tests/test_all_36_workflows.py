"""
Full regression test suite executing all 36 ADK graph workflows against declarative test manifests.
"""

import unittest
from evals.datasets import load_dataset
from evals.runner import run_eval_case


class TestAll36Workflows(unittest.TestCase):

    def setUp(self):
        self.cases = load_dataset("all_36_workflows")

    def test_run_all_36_graph_workflows(self):
        self.assertEqual(len(self.cases), 36, "Dataset must contain all 36 workflows.")
        failed_cases = []

        for case in self.cases:
            with self.subTest(test_id=case["test_id"], workflow=case["workflow_name"]):
                result = run_eval_case(case)
                if not result.passed:
                    failed_cases.append((case["test_id"], case["workflow_name"], result.error, result.total_score))
                self.assertTrue(
                    result.passed,
                    f"Test {case['test_id']} failed on {case['workflow_name']}: {result.error} (score: {result.total_score})"
                )
                self.assertGreaterEqual(
                    result.total_score,
                    case.get("min_passing_score", 80.0),
                    f"Test {case['test_id']} ({case['workflow_name']}) rubric score {result.total_score} below minimum."
                )

        self.assertEqual(len(failed_cases), 0, f"Failed workflows: {failed_cases}")


if __name__ == "__main__":
    unittest.main()
