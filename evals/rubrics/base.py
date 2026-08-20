"""
Base class for runbook-derived evaluation rubrics.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
from evals.evaluators.base import RubricScorecard


class BaseRubric(ABC):
    """Abstract base class for all runbook evaluation rubrics."""

    @classmethod
    @abstractmethod
    def evaluate(cls, output_data: Dict[str, Any], trace: Dict[str, Any] | None = None) -> RubricScorecard:
        """Evaluate a workflow execution and return an itemized RubricScorecard."""
        pass
