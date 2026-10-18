"""Tests for the Harness2 BenchmarkAdapter and Proposer integration."""

from __future__ import annotations

import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any

from harness2.core import library as harness_library
from harness2.core import schedule as harness_schedule
from harness2.core import tree as harness_tree
from harness2.core.proposer import Proposer, Reply
from harness2.substrate.opencode import OPENCODE_SURFACE

from evals.evaluators.base import ToolCallRecord, WorkflowTrace
from evals.harness2_adapter import (
    AdkRunbooksAdapter,
    _prepare_skill_for_harness,
)


def test_prepare_skill_strips_rubrics_and_jinja_braces() -> None:
    raw = (
        "---\n"
        "name: example-skill\n"
        "description: Investigate {{alert_id}} with tool steps.\n"
        "---\n"
        "# Instructions\n"
        "Check {{source_ip}} in SIEM.\n\n"
        "## Rubrics\n"
        "- Must score 100 points.\n"
    )
    cleaned = _prepare_skill_for_harness("example-skill", raw)
    assert "name: example-skill" in cleaned
    assert "## Rubrics" not in cleaned
    assert "Must score 100 points" not in cleaned
    assert "{{" not in cleaned
    assert "}}" not in cleaned
    assert "{alert_id}" in cleaned
    assert "{source_ip}" in cleaned


def test_base_harness_validates_on_opencode_surface(tmp_path: Path) -> None:
    adapter = AdkRunbooksAdapter(
        tmp_path,
        dataset_name="core_workflows",
        task_ids=["TEST-CORE-SUSP-LOGIN-002"],
    )
    tree = harness_tree.read_tree(OPENCODE_SURFACE, adapter.base_harness())

    harness_tree.validate(OPENCODE_SURFACE, tree, allow_subagents=False)
    adapter.validate_tree(tree)

    assert "systemprompt.md" in tree
    assert "guardrails.md" in tree
    assert "skills/suspicious-login-triage/SKILL.md" in tree
    skill_md = tree["skills/suspicious-login-triage/SKILL.md"]
    assert "## Rubrics" not in skill_md
    assert "suspicious-login-triage" in tree["guardrails.md"]


def test_task_prompt_hides_expected_route_and_nodes(tmp_path: Path) -> None:
    adapter = AdkRunbooksAdapter(
        tmp_path,
        dataset_name="core_workflows",
        task_ids=["TEST-CORE-SUSP-LOGIN-002"],
    )
    prompt = adapter.task_prompt("TEST-CORE-SUSP-LOGIN-002")

    assert "CASE-9002" in prompt
    assert "bob.jones@example.com" in prompt
    assert "198.51.100.44" in prompt
    assert "HIGH_RISK_SUSPICIOUS" not in prompt
    assert "handle_high_risk_branch" not in prompt
    assert "required_nodes" not in prompt
    assert "min_passing_score" not in prompt


class _ScriptedFakeProposer(Proposer):
    """Fake Proposer that edits guardrails.md in context/harness/ and emits experience tags."""

    def call(
        self,
        mission: str,
        context_dir: Path | str | None,
        label: str,
        *,
        system: str = "",
        timeout: int | None = None,
        max_attempts: int | None = None,
        harvest: str | None = None,
    ) -> Reply:
        del mission, system, timeout, max_attempts
        workspace_dir: Path | None = None
        if harvest == "context/harness" and context_dir is not None:
            src_harness = Path(context_dir) / "harness"
            workspace_dir = Path(context_dir).parent / f"ws_{label}"
            if workspace_dir.exists():
                shutil.rmtree(workspace_dir)
            shutil.copytree(src_harness, workspace_dir)
            guard_path = workspace_dir / "guardrails.md"
            text = guard_path.read_text(encoding="utf-8")
            marker = f"\n- Stage note from {label}: verify IP reputation before escalating.\n"
            if marker not in text:
                guard_path.write_text(text + marker, encoding="utf-8")
            reply_text = f"<notes>Added stage guidance in {label}.</notes>"
        elif label.startswith("experience."):
            reply_text = (
                "<edits>\n"
                "- guardrails.md: added explicit IP reputation verification rule.\n"
                "</edits>\n"
                "<experience>\n"
                "cue: Suspicious login alerts from external Tor or VPN source IPs\n"
                "lesson: Load suspicious-login-triage first and inspect tool schemas before querying GTI and SIEM.\n"
                "evidence: agg1 checked schema and correlated IP reputation with login history.\n"
                "confidence: high\n"
                "</experience>"
            )
        else:
            reply_text = "```choice\nA\n```\n<why>Candidate A correlated all telemetry.</why>"

        r = Reply(
            label=label,
            text=reply_text,
            ok=True,
            cost_usd=0.001,
            wall_s=0.1,
            attempts=1,
            channel=self.spec.kind,
            workspace=workspace_dir,
        )
        self._calls.append(r)
        return r


def test_end_to_end_k1_parallel_loop_with_fake_solver(tmp_path: Path) -> None:
    def fake_solver(
        task_id: str, harness_dir: Path, run_dir: Path
    ) -> tuple[str, str, dict[str, Any]]:
        del run_dir
        guard_text = (harness_dir / "guardrails.md").read_text(encoding="utf-8")
        improved = "Stage note from" in guard_text

        tool_calls = [
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst",
                tool_name="load_skill",
                args={"skill_name": "suspicious-login-triage"},
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=False,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="soc_analyst",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "get_ip_address_report"},
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="soc_analyst",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "get_ip_address_report",
                    "arguments": {"ip_address": "185.220.101.42"},
                },
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=4,
                agent_name="soc_analyst",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "search_security_events",
                    "arguments": {"query": "principal.user.userid = 'admin@corp.example.com'"},
                },
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ]
        trace = WorkflowTrace(
            workflow_name="suspicious_login_triage",
            executed_nodes=[
                "get_ip_address_report",
                "search_security_events",
            ],
            duration_seconds=1.2,
            estimated_tokens_in=500,
            estimated_tokens_out=250,
            total_tokens=750,
            status="success",
            disclosure_mode="dual_progressive",
            tool_calls=tool_calls,
            activated_skills=["suspicious-login-triage"],
            inspected_schemas=["get_ip_address_report", "search_security_events"],
        )
        verdict_line = "Disposition: escalate (malicious Tor exit node login)." if improved else "Disposition: suspicious."
        deliverable = (
            f"# Triage Report for {task_id}\n\n"
            "- Alert ID: ALERT-SUSP-002\n"
            "- User: admin@corp.example.com\n"
            "- Source IP: 185.220.101.42\n"
            f"- {verdict_line}\n\n"
            "## Next Steps\n"
            "Escalate case and reset credentials.\n"
        )
        trajectory = (
            "[ACTION] load_skill({'skill_name': 'suspicious-login-triage'})\n"
            "[ACTION] get_mcp_tool_schema({'tool_name': 'get_ip_address_report'})\n"
            "[ACTION] execute_mcp_tool({'tool_name': 'get_ip_address_report'})\n"
            f"[ASSISTANT] {deliverable}"
        )
        trace.raw_output = deliverable
        payload = {
            "trace": asdict(trace),
            "tool_outputs": [
                {
                    "tool_name": "get_ip_address_report",
                    "arguments": {"ip_address": "185.220.101.42"},
                    "output": {"reputation": "malicious"},
                }
            ],
            "written_reports_count": 1,
        }
        return deliverable, trajectory, payload

    adapter = AdkRunbooksAdapter(
        tmp_path,
        dataset_name="core_workflows",
        task_ids=["TEST-CORE-SUSP-LOGIN-002"],
        solver_fn=fake_solver,
    )
    prop = _ScriptedFakeProposer(
        adapter.spec.channels["proposer"],
        audit_dir=tmp_path / "audit",
    )
    lib = harness_library.Library(
        root=tmp_path / "library" / "agg",
        domain=adapter.domain_of("TEST-CORE-SUSP-LOGIN-002"),
        surface=adapter.substrate.surface(),
    )

    res = harness_schedule.run_task(
        "TEST-CORE-SUSP-LOGIN-002",
        1,
        adapter=adapter,
        prop=prop,
        runs_root=tmp_path,
        modes=("agg",),
        library=lib,
    )

    assert res.status == "ok"
    assert adapter.execution_count == 4
    sel = res.selections["agg"]
    assert sel["ok"] is True
    assert sel["chosen_label"] == "agg1"
    assert sel["trivial"] is True
    assert sel["chosen_tree_is_base"] is False
    assert sel["experience"]["cue"].startswith("Suspicious login")

    exp_file = lib.entry_dir("TEST-CORE-SUSP-LOGIN-002") / "EXPERIENCE.md"
    assert exp_file.is_file()
    assert "Suspicious login" in exp_file.read_text(encoding="utf-8")

    scored = adapter.score(Path(sel["chosen_run_dir"]), "TEST-CORE-SUSP-LOGIN-002")
    assert scored is not None
    assert scored["n_criteria"] == 100
    assert scored["rubric_score"] > 0
    assert scored["gates_passed"] is True


def test_sweep_threads_library_between_same_domain_tasks(tmp_path: Path) -> None:
    def fake_solver(
        task_id: str, harness_dir: Path, run_dir: Path
    ) -> tuple[str, str, dict[str, Any]]:
        del harness_dir, run_dir
        trace = WorkflowTrace(
            workflow_name="case_report_workflow",
            executed_nodes=["soar-mcp_get_case_full_details"],
            duration_seconds=0.5,
            estimated_tokens_in=100,
            estimated_tokens_out=100,
            total_tokens=200,
            status="success",
            disclosure_mode="dual_progressive",
            tool_calls=[
                ToolCallRecord(
                    turn_index=1,
                    agent_name="soc_analyst",
                    tool_name="load_skill",
                    args={"skill_name": "case-report"},
                    status="success",
                    disclosure_skill_loaded=True,
                    mcp_schema_inspected=True,
                )
            ],
            activated_skills=["case-report"],
            inspected_schemas=["soar-mcp_get_case_full_details"],
        )
        deliverable = (
            f"# Executive Summary for {task_id}\n\n"
            "## Overview\nCase 33279 alert de_4ee5885c details and entity findings.\n\n"
            "## Recommendations\nAction taken: documented case summary.\n"
        )
        trace.raw_output = deliverable
        return deliverable, f"[ASSISTANT] {deliverable}", {"trace": asdict(trace), "tool_outputs": []}

    adapter = AdkRunbooksAdapter(
        tmp_path,
        dataset_name="core_workflows",
        solver_fn=fake_solver,
    )
    prop = _ScriptedFakeProposer(
        adapter.spec.channels["proposer"],
        audit_dir=tmp_path / "audit",
    )

    sweep_rec = harness_schedule.run_sweep(
        1,
        adapter=adapter,
        prop=prop,
        runs_root=tmp_path,
        library_root=tmp_path / "library",
        modes=("agg",),
        only_domains=("reporting",),
    )

    assert sweep_rec["n_domains"] == 1
    dom = sweep_rec["domains"][0]
    assert dom["domain"] == "reporting"
    assert dom["done"] == 2
    assert dom["failed"] == 0
    assert dom["tasks"][0]["library_entries_before"]["agg"] == 0
    assert dom["tasks"][1]["library_entries_before"]["agg"] == 1


def test_logstory_adapter_loads_representative_cohorts_and_scores(tmp_path: Path) -> None:
    adapter = AdkRunbooksAdapter(
        tmp_path,
        dataset_name="logstory",
        logstory_suite="representative",
    )
    tasks = adapter.tasks()
    assert len(tasks) == 16
    assert adapter.reference_domain_order() == [
        "cloud_deception",
        "ransomware_edr",
        "edge_network_lotl",
        "identity_insider_detection",
        "cymbal_baselines",
    ]
    assert adapter.domain_of("GCP_HONEY_TOKENS") == "cloud_deception"
    assert adapter.domain_of("CYMBAL_BASELINE_CLOUD") == "cymbal_baselines"

    tree = harness_tree.read_tree(OPENCODE_SURFACE, adapter.base_harness())
    harness_tree.validate(OPENCODE_SURFACE, tree, allow_subagents=False)
    adapter.validate_tree(tree)
    assert "skills/cloud-honeytoken-deception-triage/SKILL.md" in tree
    assert "skills/dns-tunneling-network-beacon-hunt/SKILL.md" in tree
    assert "skills/ransomware-response/SKILL.md" in tree

    prompt = adapter.task_prompt("GCP_HONEY_TOKENS")
    assert "CASE-" in prompt
    assert "write_report" in prompt

    # Verify explicit non-representative task ID works even with default suite
    single_adapter = AdkRunbooksAdapter(
        tmp_path / "single",
        dataset_name="logstory",
        task_ids=["AWS_S3_DATA_THEFT"],
    )
    assert single_adapter.tasks() == ["AWS_S3_DATA_THEFT"]
    assert single_adapter.domain_of("AWS_S3_DATA_THEFT") == "cloud_deception"

    # Score a fake Logstory rollout for GCP_HONEY_TOKENS
    ref = adapter._cases_by_id["GCP_HONEY_TOKENS"]["reference"]
    expected_ents = list(ref.get("expected_entities") or [])
    ent_lines = "\n".join(f"- Observed entity: {e}" for e in expected_ents)
    deliverable = (
        "# GCP Honeytoken Triage Report\n\n"
        "Disposition: MALICIOUS\n\n"
        f"{ent_lines}\n"
    )
    trace = WorkflowTrace(
        workflow_name="logstory_cloud_deception",
        executed_nodes=["scc-mcp_list_scc_findings", "secops-mcp_search_security_events"],
        duration_seconds=2.5,
        estimated_tokens_in=800,
        estimated_tokens_out=300,
        total_tokens=1100,
        status="success",
        disclosure_mode="dual_progressive",
        tool_calls=[
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst",
                tool_name="load_skill",
                args={"skill_name": "cloud-honeytoken-deception-triage"},
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=False,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="soc_analyst",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "scc-mcp_list_scc_findings"},
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="soc_analyst",
                tool_name="execute_mcp_tool",
                args={"tool_name": "scc-mcp_list_scc_findings", "arguments": {}},
                status="success",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
        activated_skills=["cloud-honeytoken-deception-triage"],
        inspected_schemas=["scc-mcp_list_scc_findings"],
    )
    run_dir = tmp_path / "executions" / "fake_ls"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "deliverable.md").write_text(deliverable, encoding="utf-8")
    (run_dir / "trajectory.md").write_text("[ASSISTANT] ok", encoding="utf-8")
    import json
    (run_dir / "trace.json").write_text(
        json.dumps({"trace": asdict(trace), "tool_outputs": []}, indent=2),
        encoding="utf-8",
    )
    scored = adapter.score(run_dir, "GCP_HONEY_TOKENS")
    assert scored is not None
    assert scored["all_pass"] is True
    assert scored["n_criteria"] == 100
    assert scored["rubric_score"] >= 95.0
    assert scored["logstory_metrics"]["verdict_accuracy"] == 1.0
    assert scored["logstory_metrics"]["entity_ioc_recall"] == 1.0


def test_active_logstory_usecase_is_thread_isolated() -> None:
    import threading
    from manager.tools.logstory_corpus import active_logstory_usecase, get_logstory_corpus

    corpus = get_logstory_corpus()
    b1 = threading.Barrier(2)
    b2 = threading.Barrier(2)
    results: dict[str, set[str] | None] = {}

    def worker_a() -> None:
        with active_logstory_usecase("GCP_HONEY_TOKENS", include_baselines=False):
            b1.wait()
            results["a_before_b_exit"] = corpus.get_active_usecase_ids()
            b2.wait()
            results["a_after_b_exit"] = corpus.get_active_usecase_ids()

    def worker_b() -> None:
        with active_logstory_usecase("AKIRA_RANSOMWARE", include_baselines=False):
            b1.wait()
            results["b_inside"] = corpus.get_active_usecase_ids()
        b2.wait()

    t_a = threading.Thread(target=worker_a)
    t_b = threading.Thread(target=worker_b)
    t_a.start()
    t_b.start()
    t_a.join(timeout=5)
    t_b.join(timeout=5)

    assert results["a_before_b_exit"] == {"GCP_HONEY_TOKENS"}
    assert results["b_inside"] == {"AKIRA_RANSOMWARE"}
    assert results["a_after_b_exit"] == {"GCP_HONEY_TOKENS"}
    assert corpus.get_active_usecase_ids() is None


