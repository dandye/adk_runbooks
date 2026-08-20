"""
Base data models and interfaces for the evaluation framework.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time


@dataclass
class MetricResult:
    """Represents the score and outcome of an individual evaluation metric."""
    name: str
    score: float
    max_score: float
    passed: bool
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowTrace:
    """Tracks the execution path and telemetry of an agent workflow."""
    workflow_name: str
    executed_nodes: List[str] = field(default_factory=list)
    route: Optional[str] = None
    duration_seconds: float = 0.0
    estimated_tokens_in: int = 0
    estimated_tokens_out: int = 0
    total_tokens: int = 0
    status: str = "success"
    raw_output: Any = None
    error: Optional[str] = None


@dataclass
class RubricScorecard:
    """Itemized evaluation scorecard for a workflow execution against a runbook rubric."""
    profile_name: str
    total_score: float
    max_score: float = 100.0
    passed: bool = True
    category_scores: Dict[str, float] = field(default_factory=dict)
    feedback: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    """Overall evaluation verdict and telemetry for a test case."""
    test_id: str
    workflow_name: str
    passed: bool
    total_score: float
    max_score: float = 100.0
    metrics: Dict[str, MetricResult] = field(default_factory=dict)
    scorecard: Optional[RubricScorecard] = None
    trace: Optional[WorkflowTrace] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None
