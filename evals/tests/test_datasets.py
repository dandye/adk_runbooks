"""
Unit tests for evaluation dataset loading and manifest verification.
"""

from pathlib import Path
import unittest
from evals.datasets import load_dataset
from evals.registry import WORKFLOW_REGISTRY

REPO_ROOT = Path(__file__).resolve().parents[2]


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

            # Verify skill_reference and runbook_reference point to existing skills
            skill_ref = case.get("skill_reference") or case.get("runbook_reference")
            self.assertIsNotNone(skill_ref)
            self.assertTrue(skill_ref.startswith("skills/"))
            self.assertTrue((REPO_ROOT / skill_ref).exists(), f"Skill file {skill_ref} does not exist")
            self.assertNotIn("rules-bank/run_books", skill_ref)

    def test_load_all_36_workflows_dataset(self):
        cases = load_dataset("all_36_workflows")
        self.assertEqual(len(cases), 36)
        workflow_names = {c["workflow_name"] for c in cases}
        self.assertEqual(len(workflow_names), 36)
        for case in cases:
            wf_name = case["workflow_name"]
            self.assertIn(wf_name, WORKFLOW_REGISTRY)

            skill_ref = case.get("skill_reference") or case.get("runbook_reference")
            self.assertIsNotNone(skill_ref)
            self.assertTrue(skill_ref.startswith("skills/"))
            self.assertTrue((REPO_ROOT / skill_ref).exists(), f"Skill file {skill_ref} does not exist")
            self.assertNotIn("rules-bank/run_books", skill_ref)

    def test_load_expanded_cases_alerts_dataset(self):
        cases = load_dataset("expanded_cases_alerts")
        self.assertGreaterEqual(len(cases), 20)
        for case in cases:
            self.assertIn("test_id", case)
            self.assertIn("workflow_name", case)
            self.assertIn("input", case)
            self.assertIn("expected", case)
            self.assertIn(case["workflow_name"], WORKFLOW_REGISTRY)

            skill_ref = case.get("skill_reference") or case.get("runbook_reference")
            self.assertIsNotNone(skill_ref)
            self.assertTrue(skill_ref.startswith("skills/"))
            self.assertTrue((REPO_ROOT / skill_ref).exists(), f"Skill file {skill_ref} does not exist")
            self.assertNotIn("rules-bank/run_books", skill_ref)


if __name__ == "__main__":
    unittest.main()

