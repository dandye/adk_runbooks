"""
Unit tests for workflow registry and execution adapter.
"""

import unittest
from evals.registry import WORKFLOW_REGISTRY, get_workflow_definition, execute_workflow_sync


class TestRegistry(unittest.TestCase):

    def test_registry_contains_all_36_workflows(self):
        self.assertGreaterEqual(len(WORKFLOW_REGISTRY), 36)
        self.assertIn("suspicious_login_workflow", WORKFLOW_REGISTRY)
        self.assertIn("malware_triage_workflow", WORKFLOW_REGISTRY)
        self.assertIn("alert_report_workflow", WORKFLOW_REGISTRY)
        self.assertIn("compromised_user_irp_workflow", WORKFLOW_REGISTRY)
        self.assertIn("detection_rule_validation_workflow", WORKFLOW_REGISTRY)

    def test_execute_suspicious_login_sync(self):
        wf_def = get_workflow_definition("suspicious_login_workflow")
        self.assertIsNotNone(wf_def)
        result, trace = execute_workflow_sync(
            "suspicious_login_workflow",
            {
                "case_id": "CASE-TEST-1001",
                "user_id": "alice.smith@example.com",
                "source_ip": "192.168.1.50",
                "hostname": "corp-laptop-alice"
            }
        )
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "soar_comment") or "soar_comment" in str(result))
        self.assertIn("extract_entities_node", trace.executed_nodes)
        self.assertEqual(trace.route, "LOW_RISK_BENIGN")
        self.assertEqual(trace.status, "success")

    def test_execute_malware_triage_sync(self):
        result, trace = execute_workflow_sync(
            "malware_triage_workflow",
            {
                "case_id": "CASE-TEST-MAL-1",
                "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        )
        self.assertIsNotNone(result)
        self.assertEqual(trace.status, "success")
        self.assertIn("extract_hash_node", trace.executed_nodes)

    def test_execute_workflow_configurable_max_steps(self):
        # Successful execution with explicit custom max_steps=100
        result, trace = execute_workflow_sync(
            "suspicious_login_workflow",
            {
                "case_id": "CASE-TEST-MAXSTEPS-1",
                "user_id": "alice.smith@example.com",
                "source_ip": "192.168.1.50",
                "hostname": "corp-laptop-alice"
            },
            max_steps=100
        )
        self.assertEqual(trace.status, "success")

        # Exceeding step limit should raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            execute_workflow_sync(
                "suspicious_login_workflow",
                {
                    "case_id": "CASE-TEST-MAXSTEPS-2",
                    "user_id": "alice.smith@example.com",
                    "source_ip": "192.168.1.50",
                    "hostname": "corp-laptop-alice"
                },
                max_steps=0  # Cannot execute any transition step
            )
        self.assertIn("exceeded maximum DAG step limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
