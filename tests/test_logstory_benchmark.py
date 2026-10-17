"""Unit tests for the Logstory multi-cohort benchmark harness and scorer."""

from pathlib import Path

from evals.evaluators.base import ToolCallRecord, WorkflowTrace
from evals.run_logstory_benchmark import (
    COHORTS,
    REPRESENTATIVE_USECASES,
    _classify_response_disposition,
    _select_target_usecases,
    build_scenario_prompt,
    get_cohort_for_usecase,
    score_usecase_run,
)
from manager.tools.logstory_corpus import get_logstory_corpus


def test_cohorts_cover_all_47_usecases_without_duplicates():
    """Verify COHORTS covers all 47 Logstory usecases with zero omissions or duplicates."""
    corpus = get_logstory_corpus()
    all_cohort_ids = []
    for cohort_name, uids in COHORTS.items():
        assert len(uids) > 0, f"Cohort {cohort_name} is empty"
        for uid in uids:
            assert uid in corpus.usecases, f"Unknown usecase {uid} in cohort {cohort_name}"
            all_cohort_ids.append(uid)

    assert len(all_cohort_ids) == 47
    assert len(set(all_cohort_ids)) == 47
    assert set(all_cohort_ids) == set(corpus.usecases.keys())


def test_representative_suite_is_valid_subset_of_cohorts():
    """Verify REPRESENTATIVE_USECASES has 16 scenarios and is a strict subset of COHORTS."""
    rep_ids = []
    for cohort_name, uids in REPRESENTATIVE_USECASES.items():
        assert cohort_name in COHORTS
        for uid in uids:
            assert uid in COHORTS[cohort_name]
            rep_ids.append(uid)

    assert len(rep_ids) == 16
    assert len(set(rep_ids)) == 16
    assert get_cohort_for_usecase("GCP_HONEY_TOKENS") == "cloud_deception"
    assert get_cohort_for_usecase("CYMBAL_BASELINE_CLOUD") == "cymbal_baselines"
    assert get_cohort_for_usecase("NONEXISTENT_ID") == "uncategorized"


def test_build_scenario_prompt_attack_and_baseline():
    """Verify prompt construction for attack usecases and Cymbal baseline usecases."""
    corpus = get_logstory_corpus()
    uc_attack = corpus.usecases["GCP_HONEY_TOKENS"]
    prompt_atk, ref_atk = build_scenario_prompt(uc_attack, corpus, check_yaral=True)

    assert ref_atk["case_id"] in prompt_atk
    assert ref_atk["case_id"].startswith("CASE-")
    assert "validate_yaral2_rule" in prompt_atk
    assert ref_atk["expected_disposition"] == "MALICIOUS"
    assert ref_atk["is_baseline"] is False
    assert ref_atk["cohort"] == "cloud_deception"
    assert len(ref_atk["expected_entities"]) >= 1

    assert ref_atk["seed_entity"] in prompt_atk
    assert ref_atk["seed_entity"].lower() not in [e.lower() for e in ref_atk["expected_entities"]]

    uc_base = corpus.usecases["CYMBAL_BASELINE_CLOUD"]
    prompt_base, ref_base = build_scenario_prompt(uc_base, corpus, check_yaral=False)

    assert ref_base["case_id"] in prompt_base
    assert "routine telemetry check" not in prompt_base
    assert ref_base["expected_disposition"] == "BENIGN"
    assert ref_base["is_baseline"] is True
    assert ref_base["cohort"] == "cymbal_baselines"


def test_classify_response_disposition():
    """Verify verdict parser across explicit headers, plain prose, and mixed tail conclusions."""
    assert _classify_response_disposition("Verdict: **MALICIOUS**\nConfirmed canary trip.") == "MALICIOUS"
    assert _classify_response_disposition("Disposition: BENIGN\nRoutine admin activity.") == "BENIGN"
    assert _classify_response_disposition("Conclusion: False Positive. Authorized scanner.") == "BENIGN"
    assert _classify_response_disposition("Classification: SUSPICIOUS - needs Tier 2 review.") == "SUSPICIOUS"
    assert _classify_response_disposition("Verdict: INCONCLUSIVE due to missing logs.") == "INCONCLUSIVE"
    assert _classify_response_disposition("This is an active intrusion with ransomware encryption.") == "MALICIOUS"
    assert _classify_response_disposition("This matches authorized baseline expected behavior.") == "BENIGN"
    assert (
        _classify_response_disposition(
            "Checked for malicious indicators. None found. In conclusion, this activity is benign and a false positive."
        )
        == "BENIGN"
    )
    assert _classify_response_disposition("") == "UNKNOWN"


def test_score_usecase_run_attack_pass_and_yaral():
    """Verify score_usecase_run rewards grounded attack triage and valid YARA-L 2.0 rules."""
    corpus = get_logstory_corpus()
    uc = corpus.usecases["GCP_HONEY_TOKENS"]
    _, ref = build_scenario_prompt(uc, corpus, check_yaral=True)

    valid_yaral = (
        "rule gcp_canary_trip {\n"
        "  meta:\n"
        "    author = \"secops\"\n"
        "  events:\n"
        "    $e.metadata.event_type = \"USER_RESOURCE_ACCESS\"\n"
        "    $e.principal.user.email_addresses = \"canary-deployer@cymbal-investments-prod.iam.gserviceaccount.com\"\n"
        "  condition:\n"
        "    $e\n"
        "}"
    )

    trace = WorkflowTrace(
        workflow_name="GCP_HONEY_TOKENS",
        session_id="sess-ht-pass",
        trace_id="trace-ht-pass",
        disclosure_mode="dual_progressive",
        activated_skills=["alert-triage"],
        tool_calls=[
            ToolCallRecord(
                turn_index=0,
                agent_name="soc_analyst_tier1",
                tool_name="load_skill",
                args={"skill_name": "alert-triage"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst_tier1",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "secops-mcp_list_scc_findings"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst_tier1",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_list_scc_findings",
                    "arguments": {"query": "canary-deployer"},
                },
                result_summary="canary-deployer@cymbal-investments-prod.iam.gserviceaccount.com",
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="detection_engineer",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "secops-mcp_validate_yaral2_rule"},
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="detection_engineer",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_validate_yaral2_rule",
                    "arguments": {"rule_text": valid_yaral},
                },
                result_summary='{"valid": true}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )

    entities_text = " ".join(ref["expected_entities"])
    response_text = (
        f"Verdict: MALICIOUS\nConfirmed honeytoken trip on {entities_text}. "
        "Revoke canary-deployer key immediately."
    )
    score = score_usecase_run(uc, ref, trace, response_text, corpus)

    assert score["passed"] is True
    assert score["metrics"]["verdict_accuracy"] == 1.0
    assert score["metrics"]["entity_ioc_recall"] == 1.0
    assert score["metrics"]["containment_safety"] == 1.0
    assert score["metrics"]["progressive_disclosure"] == 1.0
    assert score["metrics"]["tool_grounding"] == 1.0
    assert score["metrics"]["yaral2_validity"] == 1.0
    assert score["composite_score"] == 1.0


def test_score_usecase_run_baseline_false_containment_fails():
    """Verify score_usecase_run penalizes containment on benign CYMBAL_BASELINE_* usecases."""
    corpus = get_logstory_corpus()
    uc = corpus.usecases["CYMBAL_BASELINE_CLOUD"]
    _, ref = build_scenario_prompt(uc, corpus)

    bad_trace = WorkflowTrace(
        workflow_name="CYMBAL_BASELINE_CLOUD",
        session_id="sess-base-fail",
        trace_id="trace-base-fail",
        disclosure_mode="dual_progressive",
        activated_skills=["alert-triage"],
        tool_calls=[
            ToolCallRecord(
                turn_index=0,
                agent_name="incident_responder",
                tool_name="load_skill",
                args={"skill_name": "alert-triage"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="incident_responder",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "soar-mcp_isolate_host"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="incident_responder",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "soar-mcp_isolate_host",
                    "arguments": {"hostname": "gke-prod-node-01"},
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )
    bad_score = score_usecase_run(
        uc,
        ref,
        bad_trace,
        "Verdict: MALICIOUS. Isolated host gke-prod-node-01.",
        corpus,
    )
    assert bad_score["passed"] is False
    assert bad_score["metrics"]["verdict_accuracy"] == 0.0
    assert bad_score["metrics"]["containment_safety"] == 0.0
    assert "gke-prod-node-01" in bad_score["unsafe_containment_targets"]

    # Clean baseline run with no containment and BENIGN verdict passes
    good_trace = WorkflowTrace(
        workflow_name="CYMBAL_BASELINE_CLOUD",
        session_id="sess-base-pass",
        trace_id="trace-base-pass",
        disclosure_mode="dual_progressive",
        activated_skills=["alert-triage"],
        tool_calls=[
            ToolCallRecord(
                turn_index=0,
                agent_name="soc_analyst_tier1",
                tool_name="load_skill",
                args={"skill_name": "alert-triage"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst_tier1",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "secops-mcp_search_security_events"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="soc_analyst_tier1",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_search_security_events",
                    "arguments": {"query": "cymbal"},
                },
                result_summary=" ".join(ref["expected_entities"]),
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )
    good_score = score_usecase_run(
        uc,
        ref,
        good_trace,
        f"Verdict: BENIGN. Routine activity for {' '.join(ref['expected_entities'])}.",
        corpus,
    )
    assert good_score["passed"] is True
    assert good_score["metrics"]["verdict_accuracy"] == 1.0
    assert good_score["metrics"]["containment_safety"] == 1.0


def test_select_target_usecases_filters():
    """Verify _select_target_usecases filters by suite, cohort, and explicit usecase IDs."""
    corpus = get_logstory_corpus()
    rep_all = _select_target_usecases(corpus, "representative", None, None)
    assert len(rep_all) == 16

    full_all = _select_target_usecases(corpus, "full", None, None)
    assert len(full_all) == 47

    cloud_rep = _select_target_usecases(corpus, "representative", "cloud_deception", None)
    assert cloud_rep == ["GCP_HONEY_TOKENS", "GCP_CRYPTOMINING", "GITHUB_SUPPLY_CHAIN"]

    cloud_full = _select_target_usecases(corpus, "full", "cloud_deception", None)
    assert len(cloud_full) == 7

    explicit = _select_target_usecases(corpus, "representative", None, ["gcp_honey_tokens", "invalid_id"])
    assert explicit == ["GCP_HONEY_TOKENS"]


def test_logstory_multi_turn_scenarios_file_and_usecase_ids():
    """Verify logstory_multi_turn_scenarios.json loads cleanly with valid Logstory usecase IDs."""
    from evals.simulate_sessions import (
        load_scenario_usecase_ids_from_file,
        load_scenarios_from_file,
    )

    repo_root = Path(__file__).resolve().parent.parent
    scenarios_path = repo_root / "evals" / "datasets" / "logstory_multi_turn_scenarios.json"
    assert scenarios_path.exists()

    scenarios = load_scenarios_from_file(scenarios_path)
    usecase_ids = load_scenario_usecase_ids_from_file(scenarios_path)
    corpus = get_logstory_corpus()

    assert len(scenarios) == 4
    assert set(usecase_ids.keys()) == set(scenarios.keys())
    for sid, uid in usecase_ids.items():
        assert uid in corpus.usecases, f"Scenario {sid} references unknown usecase {uid}"
        sc = scenarios[sid]
        assert sc.starting_prompt
        assert sc.conversation_plan
        assert sc.user_persona is not None


def test_get_run_metrics_is_session_scoped_and_compact(tmp_path: Path):
    """Verify get_run_metrics returns only current session spans and stays compact across runs."""
    import json
    from manager.utils.instrumentation import (
        TELEMETRY_RECORDER,
        get_run_metrics,
        telemetry_session_scope,
    )

    otel_path = tmp_path / "otel.jsonl"
    with telemetry_session_scope(session_id="sess-old-bulk", otel_log_path=otel_path):
        for i in range(60):
            TELEMETRY_RECORDER.record_span(
                {
                    "session_id": "sess-old-bulk",
                    "timestamp": "2026-10-17T00:00:00Z",
                    "tool_name": f"old_tool_{i}",
                    "effective_tool_name": f"old_tool_{i}",
                    "duration_seconds": 0.1,
                    "status": "success",
                    "estimated_tokens_in": 100,
                    "estimated_tokens_out": 2000,
                    "total_estimated_tokens": 2100,
                    "gen_ai.tool.call.result_summary": "X" * 500,
                }
            )

    with telemetry_session_scope(session_id="sess-new-clean", otel_log_path=otel_path):
        TELEMETRY_RECORDER.record_span(
            {
                "session_id": "sess-new-clean",
                "timestamp": "2026-10-17T00:01:00Z",
                "tool_name": "execute_mcp_tool",
                "effective_tool_name": "soar-mcp_get_case_full_details",
                "duration_seconds": 0.05,
                "status": "success",
                "estimated_tokens_in": 20,
                "estimated_tokens_out": 80,
                "total_estimated_tokens": 100,
                "gen_ai.tool.call.result_summary": "Y" * 500,
            }
        )
        metrics_json = get_run_metrics()
        parsed = json.loads(metrics_json)

    assert len(parsed) == 1
    assert parsed[0]["tool_name"] == "soar-mcp_get_case_full_details"
    assert "gen_ai.tool.call.result_summary" not in parsed[0]
    assert len(metrics_json) < 1000
