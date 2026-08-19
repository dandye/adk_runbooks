"""
Tests for rubric models and scoring engines.
Compatible with both pytest and python -m unittest.
"""

import unittest
from evals.rubrics.reporting_rubric import ReportingRubric
from evals.rubrics.triage_irp_rubric import TriageIRPRubric
from evals.rubrics.detection_rubric import DetectionRubric
from evals.rubrics.threat_hunting_rubric import ThreatHuntingRubric


class TestRubrics(unittest.TestCase):

    def test_reporting_rubric_evaluation(self):
        output = {
            "report_markdown": "# Case Report: 33279\n\n## 1. Executive Summary\nMalware C2 detected.\n\n## 2. Details & Findings\nAlert details on internal host 10.205.11.19.\n\n## 3. Recommendations\nIsolate host and block indicators.",
            "soar_comment": "Case report generated.",
            "has_sequence_diagram": True,
            "execution_metadata": {"tokens": 1200, "duration": 0.5},
            "case_id": "33279",
            "action_taken": "Report Generated",
        }
        scorecard = ReportingRubric.evaluate(output)
        self.assertGreaterEqual(scorecard.total_score, 85.0)
        self.assertTrue(scorecard.passed)
        self.assertIn("Data Collection", scorecard.category_scores)
        self.assertIn("Report Generation", scorecard.category_scores)
        self.assertIn("Operational Artifacts", scorecard.category_scores)

    def test_triage_irp_rubric_evaluation(self):
        output = {
            "user_id": "alex.kim@example.com",
            "source_ip": "146.70.171.55",
            "action_taken": "Sessions terminated and password reset.",
            "soar_comment": "Containment action documented in SOAR.",
            "enrichment_summary": "Proxy IP detected via GTI lookup.",
            "case_id": "33284",
            "has_sequence_diagram": True,
            "execution_metadata": {"tokens": 800, "duration": 0.2},
        }
        scorecard = TriageIRPRubric.evaluate(output)
        self.assertGreaterEqual(scorecard.total_score, 85.0)
        self.assertTrue(scorecard.passed)
        self.assertIn("Context & Enrichment", scorecard.category_scores)
        self.assertIn("Analysis & Decision", scorecard.category_scores)
        self.assertIn("Action Execution", scorecard.category_scores)

    def test_detection_rubric_evaluation(self):
        output = {
            "rule_id": "ru_12345",
            "rule_name": "gcp_honeytoken_secret_access_T1555",
            "compilation_status": "PASSED",
            "historical_detections": 10,
            "false_positive_rate": 0.02,
            "recommendation": "DEPLOY_PRODUCTION",
            "has_sequence_diagram": True,
            "execution_metadata": {"tokens": 600, "duration": 0.1},
        }
        scorecard = DetectionRubric.evaluate(output)
        self.assertGreaterEqual(scorecard.total_score, 85.0)
        self.assertTrue(scorecard.passed)
        self.assertIn("Requirement Analysis", scorecard.category_scores)
        self.assertIn("Technical Implementation", scorecard.category_scores)
        self.assertIn("Validation & Testing", scorecard.category_scores)

    def test_threat_hunting_rubric_evaluation(self):
        output = {
            "threat_actor_name": "APT29",
            "target_hostname": "dc-prod-01",
            "events": "Searched SIEM logs for certutil and PsExec lateral movement.",
            "threat_status": "CONFIRMED_LATERAL_MOVEMENT",
            "action_taken": "Actionable leads documented: isolate infected hosts & reset admin credentials.",
            "soar_comment": "APT29 threat hunt completed with confirmed IOC sightings.",
            "has_sequence_diagram": True,
            "execution_metadata": {"tokens": 950, "duration": 0.3},
        }
        scorecard = ThreatHuntingRubric.evaluate(output)
        self.assertGreaterEqual(scorecard.total_score, 85.0)
        self.assertTrue(scorecard.passed)
        self.assertIn("Scope & Query", scorecard.category_scores)
        self.assertIn("Data Analysis & Correlation", scorecard.category_scores)
        self.assertIn("Findings Classification", scorecard.category_scores)
        self.assertIn("Hunt Documentation", scorecard.category_scores)
        self.assertIn("Operational Artifacts", scorecard.category_scores)


if __name__ == "__main__":
    unittest.main()
