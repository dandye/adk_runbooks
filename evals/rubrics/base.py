"""Base class for runbook-derived evaluation rubrics."""

from abc import ABC
from abc import abstractmethod
from typing import Any

from evals.evaluators.base import RubricScorecard


class BaseRubric(ABC):
  """Abstract base class for all runbook evaluation rubrics."""

  @classmethod
  @abstractmethod
  def evaluate(
      cls, output_data: dict[str, Any], trace: dict[str, Any] | None = None
  ) -> RubricScorecard:
    """Evaluate a workflow execution and return an itemized RubricScorecard."""
    pass
