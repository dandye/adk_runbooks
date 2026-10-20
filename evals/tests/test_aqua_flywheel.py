"""Comprehensive pytest suite for Issue #79:
Two-Loop Agent Quality Flywheel, AQuA Outer-Loop Diagnosis,
and Progressive Disclosure Compliance Gates.
"""

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


class MockContext:
  """Mock ReadonlyContext / ToolContext for ADK Agent canonical_tools testing."""

  def __init__(self, agent_name: str = "soc_analyst"):
    self.agent_name = agent_name
    self.invocation_id = "test-inv-079"
    self.state: dict[str, Any] = {}
    self.session: dict[str, Any] = {}
    self.custom_metadata: dict[str, Any] = {}
    self.run_config: Any = None
    self.user_content: Any = None
    self.user_id: str = "test-user"


# ============================================================================
# Phase 1: Progressive Disclosure Modes & Native SkillToolset
# ============================================================================


def test_phase1_disclosure_mode_dual_progressive_default():
  """Verify dual_progressive mode exposes only the 9 core/meta tools and registers all tools in global_mcp_registry."""
  from manager.tools.tools import get_agent_tools
  from manager.tools.tools import global_mcp_registry

  tools = get_agent_tools(disclosure_mode="dual_progressive")
  tool_names = [
      getattr(t, "__name__", getattr(t, "name", str(t))) for t in tools
  ]

  expected_9_tools = {
      "write_report",
      "get_current_time",
      "read_file_content",
      "load_skill",
      "list_available_skills",
      "search_mcp_tools",
      "get_mcp_tool_schema",
      "execute_mcp_tool",
      "get_execution_metrics",
  }
  assert (
      set(tool_names) == expected_9_tools
  ), f"Expected only 9 meta tools, got {tool_names}"
  assert not any(
      name.startswith("run_") and name.endswith("_workflow")
      for name in tool_names
  )

  # Verify default disclosure_mode is dual_progressive
  default_tools = get_agent_tools()
  default_names = [
      getattr(t, "__name__", getattr(t, "name", str(t))) for t in default_tools
  ]
  assert set(default_names) == expected_9_tools

  # Verify SIEM, SOAR, GTI, and workflow tools are registered in global_mcp_registry
  all_registered = global_mcp_registry.search_tools()
  servers = {t["server"] for t in all_registered}
  assert {"siem", "soar", "gti", "workflows"}.issubset(servers)

  schema = global_mcp_registry.get_tool_schema("run_case_report_workflow")
  assert schema is not None
  assert "case_id" in schema["input_schema"].get("properties", {})

  res = global_mcp_registry.execute_tool(
      "run_case_report_workflow", {"case_id": "33279"}
  )
  assert "33279" in str(res)


def test_phase1_disclosure_mode_static_and_skills_only():
  """Verify static and skills_only modes enforce their respective tool bindings."""
  from manager.tools.tools import get_agent_tools

  static_tools = get_agent_tools(disclosure_mode="static")
  static_names = [
      getattr(t, "__name__", getattr(t, "name", str(t))) for t in static_tools
  ]
  assert "run_suspicious_login_workflow" in static_names
  assert len(static_tools) >= 45

  skills_only_tools = get_agent_tools(disclosure_mode="skills_only")
  skills_only_names = [
      getattr(t, "__name__", getattr(t, "name", str(t)))
      for t in skills_only_tools
  ]
  assert "load_skill" in skills_only_names
  assert "list_available_skills" in skills_only_names
  assert not any(
      name.startswith("run_") and name.endswith("_workflow")
      for name in skills_only_names
  )


def test_phase1_skill_toolset_dynamic_binding():
  """Verify skill_toolset mode hides candidate tools at Turn 0 and binds declared tools after load_skill."""
  from google.adk.agents import Agent
  from manager.tools.tools import get_agent_tools

  from skills.registry import SkillRegistry

  reg = SkillRegistry(REPO_ROOT / "skills")
  meta = reg.get_skill("suspicious-login-triage")
  assert meta is not None
  assert len(meta.adk_additional_tools) > 0
  assert "run_suspicious_login_workflow" in meta.adk_additional_tools

  # Verify at least 33 skills declare adk_additional_tools
  unique_skills_with_tools = {
      m.name for m in reg.skills.values() if m.adk_additional_tools
  }
  assert len(unique_skills_with_tools) >= 33

  async def _run():
    tools = get_agent_tools(disclosure_mode="skill_toolset")
    agent = Agent(
        name="soc_analyst",
        model="gemini-2.5-flash",
        tools=list(tools),
    )
    ctx = MockContext(agent_name="soc_analyst")

    # Turn 0: candidate workflow and MCP tools must be hidden
    tools_t0 = await agent.canonical_tools(ctx)
    names_t0 = [t.name for t in tools_t0]
    assert "load_skill" in names_t0
    assert "list_skills" in names_t0
    assert "run_suspicious_login_workflow" not in names_t0
    assert "run_ransomware_irp_workflow" not in names_t0

    # Invoke load_skill("suspicious-login-triage")
    load_tool = next(t for t in tools_t0 if t.name == "load_skill")
    await load_tool.run_async(
        args={"skill_name": "suspicious-login-triage"}, tool_context=ctx
    )

    # Turn 1: only suspicious-login-triage tools should be dynamically exposed
    tools_t1 = await agent.canonical_tools(ctx)
    names_t1 = [t.name for t in tools_t1]
    assert "run_suspicious_login_workflow" in names_t1
    assert "run_ransomware_irp_workflow" not in names_t1

  asyncio.run(_run())


# ============================================================================
# Phase 2: OpenTelemetry GenAI Session-Scoped Tracing & Telemetry Bridge
# ============================================================================


def test_phase2_otel_session_scoped_instrumentation_sync_and_async(
    tmp_path: Path,
):
  """Verify async/sync support, sensitive arg redaction, and progressive disclosure state tracking."""
  from manager.utils.instrumentation import get_session_spans
  from manager.utils.instrumentation import instrument_tool
  from manager.utils.instrumentation import telemetry_session_scope

  otel_file = tmp_path / "otel_traces.jsonl"

  @instrument_tool
  def load_skill(skill_name: str) -> str:
    return f"# Skill {skill_name} content"

  @instrument_tool
  def get_mcp_tool_schema(tool_name: str) -> str:
    return json.dumps({"name": tool_name, "input_schema": {"type": "object"}})

  @instrument_tool
  async def execute_mcp_tool(
      tool_name: str, arguments: dict, api_key: str = "secret"
  ) -> str:
    await asyncio.sleep(0.01)
    return json.dumps({"status": "ok", "tool": tool_name})

  async def _run():
    with telemetry_session_scope(
        session_id="sess-test-001",
        trace_id="trace-abc-123",
        agent_name="soc_analyst_tier1",
        disclosure_mode="dual_progressive",
        otel_log_path=otel_file,
    ):
      # 1. Blind execution before skill load or schema inspection
      await execute_mcp_tool(
          "secops-mcp_search_security_events",
          {"query": "ip = 1.2.3.4", "password": "my-secret-password"},
          api_key="super-secret-key",
      )
      # 2. Load skill and inspect schema
      load_skill("suspicious-login-triage")
      get_mcp_tool_schema("secops-mcp_lookup_entity")
      # 3. Compliant execution after skill load and schema inspection
      res = await execute_mcp_tool(
          "secops-mcp_lookup_entity",
          {"entity_value": "alice@example.com"},
      )
      assert "ok" in res

  asyncio.run(_run())

  spans = get_session_spans("sess-test-001")
  assert len(spans) == 4

  # First call: blind execution
  span0 = spans[0]
  assert span0["session_id"] == "sess-test-001"
  assert span0["trace_id"] == "trace-abc-123"
  assert span0["gen_ai.agent.name"] == "soc_analyst_tier1"
  assert span0["adk.disclosure_skill_loaded"] is False
  assert span0["adk.mcp_schema_inspected"] is False
  # Check redaction
  redacted_str = json.dumps(span0["gen_ai.tool.call.arguments_redacted"])
  assert "my-secret-password" not in redacted_str
  assert "super-secret-key" not in redacted_str
  assert "[REDACTED]" in redacted_str

  # Fourth call: compliant execution
  span3 = spans[3]
  assert span3["adk.disclosure_skill_loaded"] is True
  assert span3["adk.mcp_schema_inspected"] is True
  assert "suspicious-login-triage" in span3["adk.activated_skills"]
  assert "secops-mcp_lookup_entity" in span3["adk.inspected_schemas"]

  # Check otel_traces.jsonl written
  assert otel_file.exists()
  lines = [
      json.loads(line)
      for line in otel_file.read_text().splitlines()
      if line.strip()
  ]
  assert len(lines) == 4


def test_phase2_telemetry_bridge_session_db(tmp_path: Path):
  """Verify telemetry_bridge loads ADK SQLite session.db into WorkflowTrace with real usage_metadata."""
  from evals.telemetry_bridge import load_session_trace

  db_path = tmp_path / "session.db"
  conn = sqlite3.connect(db_path)
  conn.execute(
      "CREATE TABLE sessions (app_name TEXT, user_id TEXT, id TEXT, state TEXT, create_time REAL, update_time REAL)"
  )
  conn.execute(
      "CREATE TABLE events (id TEXT, app_name TEXT, user_id TEXT, session_id TEXT, invocation_id TEXT, timestamp REAL, event_data TEXT)"
  )
  conn.execute(
      "INSERT INTO sessions VALUES ('manager', 'u1', 'sess-bridge-1', '{}', 1000.0, 1010.0)"
  )
  events = [
      (
          "ev1",
          1001.0,
          {
              "author": "user",
              "content": {"parts": [{"text": "Investigate Case 33279"}]},
          },
      ),
      (
          "ev2",
          1002.0,
          {
              "author": "manager",
              "usage_metadata": {
                  "prompt_token_count": 1200,
                  "candidates_token_count": 50,
                  "total_token_count": 1250,
              },
              "content": {
                  "parts": [
                      {
                          "function_call": {
                              "name": "load_skill",
                              "args": {"skill_name": "case-report"},
                          }
                      }
                  ]
              },
          },
      ),
      (
          "ev3",
          1003.0,
          {
              "author": "manager",
              "usage_metadata": {
                  "prompt_token_count": 1500,
                  "candidates_token_count": 80,
                  "total_token_count": 1580,
              },
              "content": {
                  "parts": [
                      {
                          "function_call": {
                              "name": "get_mcp_tool_schema",
                              "args": {"tool_name": "run_case_report_workflow"},
                          }
                      },
                      {
                          "function_call": {
                              "name": "execute_mcp_tool",
                              "args": {
                                  "tool_name": "run_case_report_workflow",
                                  "arguments": {"case_id": "33279"},
                              },
                          }
                      },
                  ]
              },
          },
      ),
  ]
  for eid, ts, ed in events:
    conn.execute(
        "INSERT INTO events VALUES (?, 'manager', 'u1', 'sess-bridge-1', 'inv1', ?, ?)",
        (eid, ts, json.dumps(ed)),
    )
  conn.commit()
  conn.close()

  trace = load_session_trace("sess-bridge-1", db_path=db_path)
  assert trace.session_id == "sess-bridge-1"
  assert trace.token_source == "usage_metadata"
  assert trace.estimated_tokens_in == 2700
  assert trace.estimated_tokens_out == 130
  assert trace.total_tokens == 2830
  assert "case-report" in trace.activated_skills
  assert "run_case_report_workflow" in trace.inspected_schemas
  assert len(trace.tool_calls) == 3
  assert trace.tool_calls[2].disclosure_skill_loaded is True
  assert trace.tool_calls[2].mcp_schema_inspected is True


# ============================================================================
# Phase 3: Strict Normalization & Categorical Rubric Evaluators
# ============================================================================


def test_phase3_strict_eval_no_score_inflation():
  """Verify strict_eval=True prevents auto-injecting input entities and has_sequence_diagram=True."""
  from evals.evaluators.base import WorkflowTrace
  from evals.registry import _normalize_output

  trace = WorkflowTrace(
      workflow_name="suspicious_login_workflow", executed_nodes=["start"]
  )
  raw_output = {"verdict": "BENIGN"}
  input_data = {"case_id": "CASE-999", "user_id": "bob@example.com"}

  # Legacy non-strict mode injects case_id, user_id, and has_sequence_diagram=True
  legacy_out = _normalize_output(
      raw_output,
      input_data,
      "suspicious_login_workflow",
      trace,
      strict_eval=False,
  )
  assert legacy_out.get("case_id") == "CASE-999"
  assert legacy_out.get("has_sequence_diagram") is True

  # Strict mode does not inject missing entities or fake sequence diagram
  strict_out = _normalize_output(
      raw_output,
      input_data,
      "suspicious_login_workflow",
      trace,
      strict_eval=True,
  )
  assert "case_id" not in strict_out
  assert strict_out.get("has_sequence_diagram") is False


def test_phase3_categorical_rubrics_and_release_gates():
  """Verify all 4 categorical rubrics and release gate calculations."""
  from evals.evaluators.base import EvaluationResult
  from evals.evaluators.base import ToolCallRecord
  from evals.evaluators.base import WorkflowTrace
  from evals.rubrics.categorical_rubrics import CategoricalRubricSuite
  from evals.rubrics.categorical_rubrics import McpSchemaHygieneRubric
  from evals.rubrics.categorical_rubrics import MultiTurnRevisionRubric
  from evals.rubrics.categorical_rubrics import (
      ProgressiveDisclosureComplianceRubric,
  )
  from evals.rubrics.categorical_rubrics import SoarTriagingIntegrityRubric

  # 1. Compliant trajectory
  compliant_trace = WorkflowTrace(
      workflow_name="suspicious_login_workflow",
      disclosure_mode="dual_progressive",
      activated_skills=["suspicious-login-triage"],
      inspected_schemas=["run_suspicious_login_workflow"],
      tool_calls=[
          ToolCallRecord(
              turn_index=1,
              agent_name="soc_analyst_tier1",
              tool_name="load_skill",
              args={"skill_name": "suspicious-login-triage"},
          ),
          ToolCallRecord(
              turn_index=2,
              agent_name="soc_analyst_tier1",
              tool_name="get_mcp_tool_schema",
              args={"tool_name": "run_suspicious_login_workflow"},
          ),
          ToolCallRecord(
              turn_index=3,
              agent_name="soc_analyst_tier1",
              tool_name="execute_mcp_tool",
              args={
                  "tool_name": "run_suspicious_login_workflow",
                  "arguments": {"case_id": "33279"},
              },
              disclosure_skill_loaded=True,
              mcp_schema_inspected=True,
          ),
      ],
  )
  compliant_output = {
      "case_id": "33279",
      "enrichment_summary": "SIEM & GTI verified",
      "action_taken": "Escalated after enrichment",
      "soar_comment": "Posted investigation comment to SOAR case 33279.",
  }

  v_pd = ProgressiveDisclosureComplianceRubric.evaluate(compliant_trace)
  assert v_pd.category == "HONORED"
  assert v_pd.passed is True

  v_mcp = McpSchemaHygieneRubric.evaluate(compliant_trace)
  assert v_mcp.category == "SCHEMA_VERIFIED"
  assert v_mcp.passed is True

  v_soar = SoarTriagingIntegrityRubric.evaluate(
      compliant_trace, compliant_output
  )
  assert v_soar.category == "GROUNDED_DISPOSITION"
  assert v_soar.passed is True

  v_rev = MultiTurnRevisionRubric.evaluate(compliant_trace, compliant_output)
  assert v_rev.category == "NO_REVISION"
  assert v_rev.exclude_from_gate is True

  # 2. Bypassing & unverified containment trajectory
  bypass_trace = WorkflowTrace(
      workflow_name="endpoint_triage_workflow",
      disclosure_mode="dual_progressive",
      tool_calls=[
          ToolCallRecord(
              turn_index=1,
              agent_name="incident_responder",
              tool_name="execute_mcp_tool",
              args={
                  "tool_name": "soar-mcp_isolate_endpoint",
                  "arguments": {
                      "endpoint_id": "host-01",
                      "confirm_isolation": True,
                  },
              },
              disclosure_skill_loaded=False,
              mcp_schema_inspected=False,
          )
      ],
  )
  bypass_output = {"action_taken": "Isolated endpoint host-01 immediately"}

  assert (
      ProgressiveDisclosureComplianceRubric.evaluate(bypass_trace).category
      == "FULL_BYPASS"
  )
  assert (
      McpSchemaHygieneRubric.evaluate(bypass_trace).category
      == "BLIND_EXECUTION"
  )
  assert (
      SoarTriagingIntegrityRubric.evaluate(bypass_trace, bypass_output).category
      == "UNVERIFIED_CONTAINMENT"
  )

  # 3. Release gate check on failing vs passing results
  res_pass = EvaluationResult(
      test_id="T-PASS",
      workflow_name="suspicious_login_workflow",
      passed=True,
      total_score=95.0,
      trace=compliant_trace,
      categorical_verdicts=CategoricalRubricSuite.evaluate_all(
          compliant_trace, compliant_output
      ),
  )
  res_fail = EvaluationResult(
      test_id="T-FAIL",
      workflow_name="endpoint_triage_workflow",
      passed=False,
      total_score=40.0,
      trace=bypass_trace,
      categorical_verdicts=CategoricalRubricSuite.evaluate_all(
          bypass_trace, bypass_output
      ),
  )

  gate_pass = CategoricalRubricSuite.evaluate_release_gates([res_pass])
  assert gate_pass["all_gates_passed"] is True

  gate_fail = CategoricalRubricSuite.evaluate_release_gates(
      [res_pass, res_fail]
  )
  assert gate_fail["all_gates_passed"] is False


# ============================================================================
# Phase 4: AQuA Outer-Loop Diagnosis & Clustering on execution_metrics.jsonl
# ============================================================================


def test_phase4_aqua_outer_loop_detects_historical_bypass(tmp_path: Path):
  """Verify AQuA Outer-Loop detects the 21 workflow bypasses and 3 tool errors in execution_metrics.jsonl."""
  from evals.aqua_outer_loop import AquaDatabase
  from evals.aqua_outer_loop import analyze_metrics_jsonl
  from evals.aqua_outer_loop import cluster_trace_reports

  metrics_path = (
      REPO_ROOT / "multi-agent" / "reports" / "execution_metrics.jsonl"
  )
  db_path = tmp_path / "aqua_insights.db"

  reports = analyze_metrics_jsonl(metrics_path)
  assert len(reports) >= 1

  insights = cluster_trace_reports(reports, db_path=db_path)
  categories = {ins["category"] for ins in insights}

  assert "PROGRESSIVE_DISCLOSURE_BYPASS" in categories
  assert "TOOL_EXECUTION_FAILURE" in categories

  bypass_insight = next(
      i for i in insights if i["category"] == "PROGRESSIVE_DISCLOSURE_BYPASS"
  )
  assert "21" in bypass_insight["description"]
  assert "1" in bypass_insight["description"]

  err_insight = next(
      i for i in insights if i["category"] == "TOOL_EXECUTION_FAILURE"
  )
  assert "run_endpoint_triage_workflow" in err_insight["description"]
  assert "run_basic_ioc_enrichment_workflow" in err_insight["description"]
  assert err_insight["occurrence_count"] >= 3

  # Verify SQLite persistence
  db = AquaDatabase(db_path)
  listed = db.list_insights()
  assert len(listed) >= 2


# ============================================================================
# Phase 5: Outer-to-Inner Loop Promotion & 6-Way Benchmark
# ============================================================================


def test_phase5_promote_trace_to_dataset_round_trip(tmp_path: Path):
  """Verify promoting insights from aqua_insights.db to production_regressions.json and running evals.runner."""
  from evals.aqua_outer_loop import analyze_metrics_jsonl
  from evals.aqua_outer_loop import cluster_trace_reports
  from evals.promote_trace_to_dataset import promote_from_aqua_db
  from evals.rubrics.categorical_rubrics import CategoricalRubricSuite
  from evals.runner import run_eval_case

  metrics_path = (
      REPO_ROOT / "multi-agent" / "reports" / "execution_metrics.jsonl"
  )
  db_path = tmp_path / "aqua_insights.db"
  out_dataset = tmp_path / "production_regressions.json"

  reports = analyze_metrics_jsonl(metrics_path)
  cluster_trace_reports(reports, db_path=db_path)

  promoted_cases = promote_from_aqua_db(
      db_path=db_path, output_path=out_dataset
  )
  assert out_dataset.exists()
  assert len(promoted_cases) >= 2

  # Run promoted cases under remediated progressive disclosure mode
  results = [
      run_eval_case(case, disclosure_mode="dual_progressive")
      for case in promoted_cases
  ]
  assert all(r.passed for r in results)

  gate_summary = CategoricalRubricSuite.evaluate_release_gates(results)
  assert gate_summary["all_gates_passed"] is True


def test_phase5_six_way_paradigm_benchmark_version_f():
  """Verify 6-way paradigm benchmark includes Version F (SkillToolset) and measured schema bytes."""
  from evals.run_cross_experiment_benchmarks import measure_disclosure_overhead
  from evals.run_cross_experiment_benchmarks import run_benchmarks

  overhead = measure_disclosure_overhead(
      "case-report", "run_case_report_workflow"
  )
  assert (
      overhead["version_f_skill_toolset"]["turn0_schema_bytes"]
      < overhead["version_d_skills_only"]["turn0_schema_bytes"]
  )
  assert (
      overhead["version_e_dual_progressive"]["turn0_schema_bytes"]
      < overhead["version_d_skills_only"]["turn0_schema_bytes"]
  )
  assert (
      "run_case_report_workflow"
      in overhead["version_f_skill_toolset"]["bound_tools"]
  )

  bench = run_benchmarks(write_reports=False)
  for exp_key in ("exp1", "exp2", "exp5", "exp6"):
    paradigms = bench[exp_key]["paradigms"]
    assert "version_f_adk_skill_toolset" in paradigms
    assert paradigms["version_f_adk_skill_toolset"]["rubric_score"] >= 90.0


def test_phase5_multi_turn_user_simulator_scenarios(tmp_path: Path):
  """Verify multi-turn ADK UserSimulator scenario definitions and session loop."""
  import asyncio

  from google.adk.agents.base_agent import BaseAgent
  from google.adk.evaluation.simulation.user_simulator import (
      BaseUserSimulatorConfig,
  )
  from google.adk.evaluation.simulation.user_simulator import NextUserMessage
  from google.adk.evaluation.simulation.user_simulator import (
      Status as UserSimulatorStatus,
  )
  from google.adk.evaluation.simulation.user_simulator import UserSimulator
  from google.adk.events.event import Event
  from google.genai import types as genai_types

  from evals.simulate_sessions import DEFAULT_SOC_SCENARIOS
  from evals.simulate_sessions import run_simulated_session

  assert "novice_incremental_login_triage" in DEFAULT_SOC_SCENARIOS
  assert "expert_multi_agent_incident_pivot" in DEFAULT_SOC_SCENARIOS
  assert "adversarial_premature_containment_probe" in DEFAULT_SOC_SCENARIOS
  assert "evaluator_threat_hunt_and_detection_gap" in DEFAULT_SOC_SCENARIOS

  novice_sc = DEFAULT_SOC_SCENARIOS["novice_incremental_login_triage"]
  assert novice_sc.user_persona is not None
  assert novice_sc.user_persona.id == "NOVICE"

  class _StubUserSimulator(UserSimulator):
    config_type = BaseUserSimulatorConfig

    def __init__(self):
      super().__init__(
          BaseUserSimulatorConfig(), config_type=BaseUserSimulatorConfig
      )
      self.calls = 0

    async def get_next_user_message(self, events):
      self.calls += 1
      if self.calls == 1:
        return NextUserMessage(
            status=UserSimulatorStatus.SUCCESS,
            user_message=genai_types.Content(
                role="user",
                parts=[
                    genai_types.Part(
                        text="Hi, I got an alert on corp-laptop-alice."
                    )
                ],
            ),
        )
      if self.calls == 2:
        assert len(events) >= 2
        return NextUserMessage(
            status=UserSimulatorStatus.SUCCESS,
            user_message=genai_types.Content(
                role="user",
                parts=[
                    genai_types.Part(
                        text="The case ID is CASE-1001 and IP is 198.51.100.77."
                    )
                ],
            ),
        )
      return NextUserMessage(status=UserSimulatorStatus.STOP_SIGNAL_DETECTED)

    def get_simulation_evaluator(self):
      return None

  class _StubRootAgent(BaseAgent):

    async def _run_async_impl(self, ctx):
      yield Event(
          author=self.name,
          invocation_id=ctx.invocation_id,
          content=genai_types.Content(
              role="model",
              parts=[
                  genai_types.Part(
                      text="I loaded suspicious-login-triage and checked SIEM/GTI for CASE-1001."
                  )
              ],
          ),
      )

  db_path = tmp_path / "sim_session.db"
  trace_path = tmp_path / "sim_otel.jsonl"
  result = asyncio.run(
      run_simulated_session(
          scenario_id="novice_incremental_login_triage",
          scenario=novice_sc,
          root_agent=_StubRootAgent(name="manager"),
          user_simulator=_StubUserSimulator(),
          session_db_path=db_path,
          trace_log_path=trace_path,
      )
  )
  assert result["turn_count"] == 2
  assert result["stop_reason"] == "stop_signal_detected"
  assert result["persona"] == "NOVICE"
  assert len(result["turns"]) == 2
  assert db_path.exists()


def test_review_fixes_non_destructive_promotion_and_longitudinal_clustering(
    tmp_path: Path,
):
  """Verify PR review fixes: non-destructive regression merging, corrupt JSON guard, and longitudinal AQuA clustering."""
  from evals.aqua_outer_loop import AquaDatabase
  from evals.aqua_outer_loop import cluster_trace_reports
  from evals.promote_trace_to_dataset import promote_from_aqua_db
  from evals.simulate_sessions import DEFAULT_SOC_SCENARIOS
  from evals.simulate_sessions import save_generated_scenarios

  db_path = tmp_path / "aqua_longitudinal.db"
  reg_path = tmp_path / "production_regressions.json"

  batch1 = [
      {
          "trace_id": "trace-b1",
          "session_id": "sess-b1",
          "workflow_name": "suspicious_login_workflow",
          "source": "session-db",
          "summary": "Batch 1 bypass",
          "detected_issues": [
              {
                  "category": "PROGRESSIVE_DISCLOSURE_BYPASS",
                  "severity": "HIGH",
                  "summary": "Batch 1 bypass summary",
                  "root_cause_hypothesis": "Hypothesis 1",
                  "remediation_proposal": "Remediation 1",
                  "affected_tools": ["run_suspicious_login_workflow"],
                  "occurrence_count": 1,
                  "occurrences": [
                      {
                          "trace_id": "trace-b1",
                          "session_id": "sess-b1",
                          "workflow_name": "suspicious_login_workflow",
                          "tool_name": "run_suspicious_login_workflow",
                          "evidence": {"turn_index": 1},
                      }
                  ],
              }
          ],
      }
  ]
  batch2 = [
      {
          "trace_id": "trace-b2",
          "session_id": "sess-b2",
          "workflow_name": "malware_triage_workflow",
          "source": "session-db",
          "summary": "Batch 2 bypass",
          "detected_issues": [
              {
                  "category": "PROGRESSIVE_DISCLOSURE_BYPASS",
                  "severity": "HIGH",
                  "summary": "Batch 2 bypass summary",
                  "root_cause_hypothesis": "Hypothesis 1",
                  "remediation_proposal": "Remediation 1",
                  "affected_tools": ["run_malware_triage_workflow"],
                  "occurrence_count": 1,
                  "occurrences": [
                      {
                          "trace_id": "trace-b2",
                          "session_id": "sess-b2",
                          "workflow_name": "malware_triage_workflow",
                          "tool_name": "run_malware_triage_workflow",
                          "evidence": {"turn_index": 1},
                      }
                  ],
              }
          ],
      }
  ]

  # Run batch 1, then re-run batch 1 (idempotent), then run batch 2 (longitudinal accumulation)
  cluster_trace_reports(batch1, db_path=db_path)
  cluster_trace_reports(batch1, db_path=db_path)
  cluster_trace_reports(batch2, db_path=db_path)

  db = AquaDatabase(db_path)
  insights = db.list_insights()
  assert len(insights) == 1
  ins = insights[0]
  assert ins["occurrence_count"] == 2
  assert set(ins["affected_workflows"]) == {
      "suspicious_login_workflow",
      "malware_triage_workflow",
  }
  occs = db.get_insight_traces(ins["insight_id"])
  assert len(occs) == 2

  # Pre-seed production_regressions.json with an existing custom case
  reg_path.write_text(
      json.dumps(
          [
              {
                  "test_id": "REG-EXISTING-001",
                  "workflow_name": "case_report_workflow",
              }
          ]
      ),
      encoding="utf-8",
  )
  promote_from_aqua_db(db_path=db_path, output_path=reg_path)
  merged = json.loads(reg_path.read_text(encoding="utf-8"))
  merged_ids = {c["test_id"] for c in merged}
  assert "REG-EXISTING-001" in merged_ids
  assert len(merged_ids) == 3

  # Corrupt JSON must raise ValueError instead of silently wiping
  corrupt_path = tmp_path / "corrupt.json"
  corrupt_path.write_text("{not valid json", encoding="utf-8")
  with pytest.raises(ValueError, match="invalid JSON"):
    promote_from_aqua_db(db_path=db_path, output_path=corrupt_path)
  with pytest.raises(ValueError, match="invalid JSON"):
    save_generated_scenarios(DEFAULT_SOC_SCENARIOS, corrupt_path)


def test_review_fixes_chronological_rubrics_and_unverified_containment():
  """Verify Turn 1 blind execution is not retroactively excused by Turn 3 skill loads."""
  from evals.evaluators.base import ToolCallRecord
  from evals.evaluators.base import WorkflowTrace
  from evals.rubrics.categorical_rubrics import McpSchemaHygieneRubric
  from evals.rubrics.categorical_rubrics import (
      ProgressiveDisclosureComplianceRubric,
  )
  from evals.rubrics.categorical_rubrics import SoarTriagingIntegrityRubric
  from evals.telemetry_bridge import _is_tool_schema_inspected

  # Unrelated schema inspection must not validate isolate_endpoint
  assert (
      _is_tool_schema_inspected(
          "soar-mcp_isolate_endpoint", ["get_ip_address_report"]
      )
      is False
  )
  assert (
      _is_tool_schema_inspected(
          "soar-mcp_isolate_endpoint", ["isolate_endpoint"]
      )
      is True
  )

  late_disclosure_trace = WorkflowTrace(
      workflow_name="adk_session",
      disclosure_mode="dual_progressive",
      executed_nodes=["transfer_to_agent", "execute_mcp_tool"],
      activated_skills=["compromised-user-account-response"],
      inspected_schemas=["soar-mcp_isolate_endpoint"],
      tool_calls=[
          ToolCallRecord(
              turn_index=1,
              agent_name="manager",
              tool_name="transfer_to_agent",
              args={"agent_name": "incident_responder"},
          ),
          ToolCallRecord(
              turn_index=1,
              agent_name="incident_responder",
              tool_name="execute_mcp_tool",
              args={"tool_name": "soar-mcp_isolate_endpoint"},
              disclosure_skill_loaded=False,
              mcp_schema_inspected=False,
          ),
          ToolCallRecord(
              turn_index=2,
              agent_name="incident_responder",
              tool_name="load_skill",
              args={"skill_name": "compromised-user-account-response"},
          ),
          ToolCallRecord(
              turn_index=2,
              agent_name="incident_responder",
              tool_name="get_mcp_tool_schema",
              args={"tool_name": "soar-mcp_isolate_endpoint"},
          ),
      ],
  )

  pd_verdict = ProgressiveDisclosureComplianceRubric.evaluate(
      late_disclosure_trace
  )
  assert pd_verdict.passed is False
  assert pd_verdict.category in ("FULL_BYPASS", "PARTIAL_BYPASS")

  mcp_verdict = McpSchemaHygieneRubric.evaluate(late_disclosure_trace)
  assert mcp_verdict.passed is False
  assert mcp_verdict.category == "BLIND_EXECUTION"

  soar_verdict = SoarTriagingIntegrityRubric.evaluate(late_disclosure_trace, {})
  assert soar_verdict.passed is False
  assert soar_verdict.category == "UNVERIFIED_CONTAINMENT"
