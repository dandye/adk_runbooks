"""
Rubrics package exporting rubric profiles.
"""

from evals.rubrics.base import BaseRubric
from evals.rubrics.reporting_rubric import ReportingRubric
from evals.rubrics.triage_irp_rubric import TriageIRPRubric
from evals.rubrics.detection_rubric import DetectionRubric
from evals.rubrics.threat_hunting_rubric import ThreatHuntingRubric

RUBRIC_REGISTRY = {
    "REPORTING": ReportingRubric,
    "TRIAGE_IRP": TriageIRPRubric,
    "DETECTION_ENGINEERING": DetectionRubric,
    "THREAT_HUNTING": ThreatHuntingRubric,
}

__all__ = [
    "BaseRubric",
    "ReportingRubric",
    "TriageIRPRubric",
    "DetectionRubric",
    "ThreatHuntingRubric",
    "RUBRIC_REGISTRY",
]
