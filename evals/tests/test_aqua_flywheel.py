"""
Comprehensive pytest suite for Issue #79:
Two-Loop Agent Quality Flywheel, AQuA Outer-Loop Diagnosis,
and Progressive Disclosure Compliance Gates.
"""

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any, Optional
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
    from manager.tools.tools import get_agent_tools, global_mcp_registry

    tools = get_agent_tools(disclosure_mode="dual_progressive")
    tool_names = [getattr(t, "__name__", getattr(t, "name", str(t))) for t in tools]

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
    assert set(tool_names) == expected_9_tools, f"Expected only 9 meta tools, got {tool_names}"
    assert not any(name.startswith("run_") and name.endswith("_workflow") for name in tool_names)

    # Verify default disclosure_mode is dual_progressive
    default_tools = get_agent_tools()
    default_names = [getattr(t, "__name__", getattr(t, "name", str(t))) for t in default_tools]
    assert set(default_names) == expected_9_tools

    # Verify SIEM, SOAR, GTI, and workflow tools are registered in global_mcp_registry
    all_registered = global_mcp_registry.search_tools()
    servers = {t["server"] for t in all_registered}
    assert {"siem", "soar", "gti", "workflows"}.issubset(servers)

    schema = global_mcp_registry.get_tool_schema("run_case_report_workflow")
    assert schema is not None
    assert "case_id" in schema["input_schema"].get("properties", {})

    res = global_mcp_registry.execute_tool("run_case_report_workflow", {"case_id": "33279"})
    assert "33279" in str(res)


def test_phase1_disclosure_mode_static_and_skills_only():
    """Verify static and skills_only modes enforce their respective tool bindings."""
    from manager.tools.tools import get_agent_tools

    static_tools = get_agent_tools(disclosure_mode="static")
    static_names = [getattr(t, "__name__", getattr(t, "name", str(t))) for t in static_tools]
    assert "run_suspicious_login_workflow" in static_names
    assert len(static_tools) >= 45

    skills_only_tools = get_agent_tools(disclosure_mode="skills_only")
    skills_only_names = [getattr(t, "__name__", getattr(t, "name", str(t))) for t in skills_only_tools]
    assert "load_skill" in skills_only_names
    assert "list_available_skills" in skills_only_names
    assert not any(name.startswith("run_") and name.endswith("_workflow") for name in skills_only_names)


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


def test_phase2_otel_session_scoped_instrumentation_sync_and_async(tmp_path: Path):
    """Verify async/sync support, sensitive arg redaction, and progressive disclosure state tracking."""
    from manager.utils.instrumentation import (
        instrument_tool,
        telemetry_session_scope,
        get_session_spans,
    )

    otel_file = tmp_path / "otel_traces.jsonl"

    @instrument_tool
    def load_skill(skill_name: str) -> str:
        return f"# Skill {skill_name} content"

    @instrument_tool
    def get_mcp_tool_schema(tool_name: str) -> str:
        return json.dumps({"name": tool_name, "input_schema": {"type": "object"}})

    @instrument_tool
    async def execute_mcp_tool(tool_name: str, arguments: dict, api_key: str = "secret") -> str:
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
    lines = [json.loads(l) for l in otel_file.read_text().splitlines() if l.strip()]
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

    trace = WorkflowTrace(workflow_name="suspicious_login_workflow", executed_nodes=["start"])
    raw_output = {"verdict": "BENIGN"}
    input_data = {"case_id": "CASE-999", "user_id": "bob@example.com"}

    # Legacy non-strict mode injects case_id, user_id, and has_sequence_diagram=True
    legacy_out = _normalize_output(raw_output, input_data, "suspicious_login_workflow", trace, strict_eval=False)
    assert legacy_out.get("case_id") == "CASE-999"
    assert legacy_out.get("has_sequence_diagram") is True

    # Strict mode does not inject missing entities or fake sequence diagram
    strict_out = _normalize_output(raw_output, input_data, "suspicious_login_workflow", trace, strict_eval=True)
    assert "case_id" not in strict_out
    assert strict_out.get("has_sequence_diagram") is False


def test_phase3_categorical_rubrics_and_release_gates():
    """Verify all 4 categorical rubrics and release gate calculations."""
    from evals.evaluators.base import EvaluationResult, ToolCallRecord, WorkflowTrace
    from evals.rubrics.categorical_rubrics import (
        ProgressiveDisclosureComplianceRubric,
        McpSchemaHygieneRubric,
        SoarTriagingIntegrityRubric,
        MultiTurnRevisionRubric,
        CategoricalRubricSuite,
    )

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

    v_soar = SoarTriagingIntegrityRubric.evaluate(compliant_trace, compliant_output)
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
                    "arguments": {"endpoint_id": "host-01", "confirm_isolation": True},
                },
                disclosure_skill_loaded=False,
                mcp_schema_inspected=False,
            )
        ],
    )
    bypass_output = {"action_taken": "Isolated endpoint host-01 immediately"}

    assert ProgressiveDisclosureComplianceRubric.evaluate(bypass_trace).category == "FULL_BYPASS"
    assert McpSchemaHygieneRubric.evaluate(bypass_trace).category == "BLIND_EXECUTION"
    assert SoarTriagingIntegrityRubric.evaluate(bypass_trace, bypass_output).category == "UNVERIFIED_CONTAINMENT"

    # 3. Release gate check on failing vs passing results
    res_pass = EvaluationResult(
        test_id="T-PASS",
        workflow_name="suspicious_login_workflow",
        passed=True,
        total_score=95.0,
        trace=compliant_trace,
        categorical_verdicts=CategoricalRubricSuite.evaluate_all(compliant_trace, compliant_output),
    )
    res_fail = EvaluationResult(
        test_id="T-FAIL",
        workflow_name="endpoint_triage_workflow",
        passed=False,
        total_score=40.0,
        trace=bypass_trace,
        categorical_verdicts=CategoricalRubricSuite.evaluate_all(bypass_trace, bypass_output),
    )

    gate_pass = CategoricalRubricSuite.evaluate_release_gates([res_pass])
    assert gate_pass["all_gates_passed"] is True

    gate_fail = CategoricalRubricSuite.evaluate_release_gates([res_pass, res_fail])
    assert gate_fail["all_gates_passed"] is False


# ============================================================================
# Phase 4: AQuA Outer-Loop Diagnosis & Clustering on execution_metrics.jsonl
# ============================================================================


def test_phase4_aqua_outer_loop_detects_historical_bypass(tmp_path: Path):
    """Verify AQuA Outer-Loop detects the 21 workflow bypasses and 3 tool errors in execution_metrics.jsonl."""
    from evals.aqua_outer_loop import analyze_metrics_jsonl, cluster_trace_reports, AquaDatabase

    metrics_path = REPO_ROOT / "multi-agent" / "reports" / "execution_metrics.jsonl"
    db_path = tmp_path / "aqua_insights.db"

    reports = analyze_metrics_jsonl(metrics_path)
    assert len(reports) >= 1

    insights = cluster_trace_reports(reports, db_path=db_path)
    categories = {ins["category"] for ins in insights}

    assert "PROGRESSIVE_DISCLOSURE_BYPASS" in categories
    assert "TOOL_EXECUTION_FAILURE" in categories

    bypass_insight = next(i for i in insights if i["category"] == "PROGRESSIVE_DISCLOSURE_BYPASS")
    assert "21" in bypass_insight["description"]
    assert "1" in bypass_insight["description"]

    err_insight = next(i for i in insights if i["category"] == "TOOL_EXECUTION_FAILURE")
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
    from evals.aqua_outer_loop import analyze_metrics_jsonl, cluster_trace_reports
    from evals.promote_trace_to_dataset import promote_from_aqua_db
    from evals.runner import run_eval_case
    from evals.rubrics.categorical_rubrics import CategoricalRubricSuite

    metrics_path = REPO_ROOT / "multi-agent" / "reports" / "execution_metrics.jsonl"
    db_path = tmp_path / "aqua_insights.db"
    out_dataset = tmp_path / "production_regressions.json"

    reports = analyze_metrics_jsonl(metrics_path)
    cluster_trace_reports(reports, db_path=db_path)

    promoted_cases = promote_from_aqua_db(db_path=db_path, output_path=out_dataset)
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
    from evals.run_cross_experiment_benchmarks import measure_disclosure_overhead, run_benchmarks

    overhead = measure_disclosure_overhead("case-report", "run_case_report_workflow")
    assert overhead["version_f_skill_toolset"]["turn0_schema_bytes"] < overhead["version_d_skills_only"]["turn0_schema_bytes"]
    assert overhead["version_e_dual_progressive"]["turn0_schema_bytes"] < overhead["version_d_skills_only"]["turn0_schema_bytes"]
    assert "run_case_report_workflow" in overhead["version_f_skill_toolset"]["bound_tools"]

    bench = run_benchmarks(write_reports=False)
    for exp_key in ("exp1", "exp2", "exp5", "exp6"):
        paradigms = bench[exp_key]["paradigms"]
        assert "version_f_adk_skill_toolset" in paradigms
        assert paradigms["version_f_adk_skill_toolset"]["rubric_score"] >= 90.0

