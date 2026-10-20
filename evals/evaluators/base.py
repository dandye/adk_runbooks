"""Base data models and interfaces for the evaluation framework."""

from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass
class MetricResult:
  """Represents the score and outcome of an individual evaluation metric."""

  name: str
  score: float
  max_score: float
  passed: bool
  reason: str
  metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCallRecord:
  """Structured record of a single tool invocation within an agent trajectory."""

  turn_index: int
  agent_name: str
  tool_name: str
  args: dict[str, Any] = field(default_factory=dict)
  status: str = "success"
  duration_seconds: float = 0.0
  error_message: str | None = None
  result_summary: str | None = None
  disclosure_skill_loaded: bool = False
  mcp_schema_inspected: bool = False


@dataclass
class CategoricalVerdict:
  """Discrete categorical rubric classification verdict."""

  rubric_name: str
  category: str
  passed: bool
  reason: str
  evidence: dict[str, Any] = field(default_factory=dict)
  exclude_from_gate: bool = False


@dataclass
class WorkflowTrace:
  """Tracks the execution path and telemetry of an agent workflow."""

  workflow_name: str
  executed_nodes: list[str] = field(default_factory=list)
  route: str | None = None
  duration_seconds: float = 0.0
  estimated_tokens_in: int = 0
  estimated_tokens_out: int = 0
  total_tokens: int = 0
  status: str = "success"
  raw_output: Any = None
  error: str | None = None
  # Phase 2 & 3 telemetry extensions
  session_id: str | None = None
  trace_id: str | None = None
  token_source: str = "heuristic"  # "usage_metadata" | "heuristic"
  disclosure_mode: str = "dual_progressive"
  tool_calls: list[ToolCallRecord] = field(default_factory=list)
  activated_skills: list[str] = field(default_factory=list)
  inspected_schemas: list[str] = field(default_factory=list)
  agent_delegations: list[str] = field(default_factory=list)


@dataclass
class RubricScorecard:
  """Itemized evaluation scorecard for a workflow execution against a runbook rubric."""

  profile_name: str
  total_score: float
  max_score: float = 100.0
  passed: bool = True
  category_scores: dict[str, float] = field(default_factory=dict)
  feedback: list[str] = field(default_factory=list)
  metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
  """Overall evaluation verdict and telemetry for a test case."""

  test_id: str
  workflow_name: str
  passed: bool
  total_score: float
  max_score: float = 100.0
  metrics: dict[str, MetricResult] = field(default_factory=dict)
  scorecard: RubricScorecard | None = None
  trace: WorkflowTrace | None = None
  duration_seconds: float = 0.0
  error: str | None = None
  categorical_verdicts: dict[str, CategoricalVerdict] = field(
      default_factory=dict
  )
