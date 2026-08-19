"""
Unit tests for evaluation dataset loading and manifest verification.
"""

import unittest
from evals.datasets import load_dataset
from evals.registry import WORKFLOW_REGISTRY


class TestDatasets(unittest.TestCase):

    def test_load_core_workflows_dataset(self):
        cases = load_dataset("core_workflows")
        self.assertGreaterEqual(len(cases), 6)
        for case in cases:
            self.assertIn("test_id", case)
            self.assertIn("workflow_name", case)
            self.assertIn("input", case)
            self.assertIn("expected", case)
            self.assertIn(case["workflow_name"], WORKFLOW_REGISTRY)

    def test_load_all_36_workflows_dataset(self):
        cases = load_dataset("all_36_workflows")
        self.assertEqual(len(cases), 36)
        workflow_names = {c["workflow_name"] for c in cases}
        self.assertEqual(len(workflow_names), 36)
        for wf_name in workflow_names:
            self.assertIn(wf_name, WORKFLOW_REGISTRY)

    def test_load_expanded_cases_alerts_dataset(self):
        cases = load_dataset("expanded_cases_alerts")
        self.assertGreaterEqual(len(cases), 20)
        for case in cases:
            self.assertIn("test_id", case)
            self.assertIn("workflow_name", case)
            self.assertIn("input", case)
            self.assertIn("expected", case)
            self.assertIn(case["workflow_name"], WORKFLOW_REGISTRY)


if __name__ == "__main__":
    unittest.main()
