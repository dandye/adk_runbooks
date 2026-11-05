"""Unit tests for the multi-turn Ursnif threat hunt runbook, grounded MCP mocks, and AQuA span checks."""

import json
from pathlib import Path

from evals.aqua_outer_loop import analyze_session_trace, cluster_trace_reports
from evals.evaluators.base import ToolCallRecord, WorkflowTrace
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite, SoarTriagingIntegrityRubric
from manager.tools.tools import get_agent_tools, global_mcp_registry, global_skill_registry

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_gti_collection_threat_hunt_skill_registered():
    """Verify gti-collection-threat-hunt is registered with expected metadata and tools."""
    meta = global_skill_registry.get_skill("gti-collection-threat-hunt")
    assert meta is not None
    assert meta.category == "hunting"
    assert meta.description.startswith("Use when")
    expected_tools = {
        "gti-mcp_get_collection_report",
        "gti-mcp_get_entities_related_to_a_collection",
        "gti-mcp_get_entities_related_to_a_domain",
        "gti-mcp_get_file_report",
        "secops-mcp_get_ioc_matches",
        "secops-mcp_search_security_events",
        "soar-mcp_isolate_host",
        "soar-mcp_block_indicator",
    }
    assert expected_tools.issubset(set(meta.adk_additional_tools))


def test_ioc_containment_skill_enforces_lolbin_signer_gate():
    """Verify ioc-containment enforces mandatory GTI signer check and LOLBin exclusion under urgency pressure."""
    meta = global_skill_registry.get_skill("ioc-containment")
    assert meta is not None
    assert meta.category == "investigation"
    assert meta.description.startswith("Use when")
    expected_tools = {
        "gti-mcp_get_file_report",
        "gti-mcp_get_domain_report",
        "gti-mcp_get_ip_address_report",
        "secops-mcp_search_security_events",
        "soar-mcp_block_ioc",
        "soar-mcp_block_indicator",
        "soar-mcp_isolate_host",
        "soar-mcp_post_case_comment",
    }
    assert expected_tools.issubset(set(meta.adk_additional_tools))

    content = global_skill_registry.get_skill_content("ioc-containment")
    assert "VALID_CERTIFICATE" in content
    assert "LOLBin" in content
    assert "rundll32.exe" in content
    assert "Never skip" in content
    assert "(Optional)" not in content
    assert "${" not in content
    assert "sequenceDiagram" not in content
    assert "attempt_completion" not in content
    body_text = content.split("---", 2)[-1].strip()
    assert len(body_text.split()) <= 350


def _as_dict(raw):
    return json.loads(raw) if isinstance(raw, str) else raw


def test_ursnif_grounded_mcp_tools_multi_horizon_and_lolbin():
    """Verify global_mcp_registry returns deterministic Ursnif ground truth across 72h vs 168h and LOLBin vs payload."""
    get_agent_tools(disclosure_mode="dual_progressive")

    # 1. GTI Collection Report and related entities
    coll_raw = global_mcp_registry.execute_tool(
        "gti-mcp_get_collection_report",
        {"collection_id": "alienvault_63bbee81b55c8ba00724605a"},
    )
    coll = _as_dict(coll_raw)
    assert "Unwrapping Ursnif" in coll["name"]
    assert coll["indicator_counts"]["domains"] == 6

    rel_raw = global_mcp_registry.execute_tool(
        "gti-mcp_get_entities_related_to_a_collection",
        {
            "collection_id": "alienvault_63bbee81b55c8ba00724605a",
            "relationship_name": "domains",
        },
    )
    rel = _as_dict(rel_raw)
    assert "superstarts.top" in rel["entities"]

    # 2. Multi-horizon SIEM check: 72h returns 0 matches, 168h returns matches on malwaretest-win
    ioc_72 = _as_dict(
        global_mcp_registry.execute_tool("secops-mcp_get_ioc_matches", {"hours_back": 72})
    )
    assert ioc_72["total_matches"] == 0

    ioc_168 = _as_dict(
        global_mcp_registry.execute_tool("secops-mcp_get_ioc_matches", {"hours_back": 168})
    )
    assert ioc_168["total_matches"] == 2
    assert ioc_168["ioc_matches"][0]["hostname"] == "malwaretest-win"

    ev_72 = _as_dict(
        global_mcp_registry.execute_tool(
            "secops-mcp_search_security_events",
            {"text": "superstarts.top", "hours_back": 72},
        )
    )
    assert ev_72["events_matched"] == 0

    ev_168 = _as_dict(
        global_mcp_registry.execute_tool(
            "secops-mcp_search_security_events",
            {"text": "superstarts.top", "hours_back": 168},
        )
    )
    assert ev_168["events_matched"] == 3

    # 3. Domain second-hop pivot (communicating_files)
    dom_rel = _as_dict(
        global_mcp_registry.execute_tool(
            "gti-mcp_get_entities_related_to_a_domain",
            {"domain": "superstarts.top", "relationship_name": "communicating_files"},
        )
    )
    file_ids = {f["sha256"] for f in dom_rel["entities"]}
    assert "8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de" in file_ids
    assert "38ffd143fb97ef7ce2fbbe39cbbe8ed1ebdc41eb53b2c68f20cb2be6381eb38e" in file_ids

    # 4. LOLBin vs malicious payload disambiguation
    lolbin_rep = _as_dict(
        global_mcp_registry.execute_tool(
            "gti-mcp_get_file_report",
            {"hash": "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2"},
        )
    )
    assert lolbin_rep["verdict"] == "benign"
    assert lolbin_rep["cert_status"] == "VALID_CERTIFICATE"
    assert "rundll32.exe" in lolbin_rep["filename"]

    payload_rep = _as_dict(
        global_mcp_registry.execute_tool(
            "gti-mcp_get_file_report",
            {"hash": "8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de"},
        )
    )
    assert payload_rep["verdict"] == "malicious"

    # 5. SOAR unalerted CASE-2396 correlation
    case_rep = _as_dict(
        global_mcp_registry.execute_tool(
            "soar-mcp_get_case_full_details", {"case_id": "2396"}
        )
    )
    assert case_rep["case_id"] == "CASE-2396"
    assert case_rep["alerts_count"] == 0


def test_aqua_detects_lolbin_overcontainment_and_shallow_horizon(tmp_path: Path):
    """Verify AQuA flags LOLBIN_OVERCONTAINMENT and SHALLOW_HUNT_HORIZON across session-db and OTel formats."""
    # 1. Defective trace: shallow 72h check + blocking signed LOLBin 7d99c80a...
    defective_trace = WorkflowTrace(
        workflow_name="ursnif_defective_hunt",
        session_id="sess-ursnif-bad",
        trace_id="trace-ursnif-bad",
        disclosure_mode="dual_progressive",
        activated_skills=["gti-collection-threat-hunt"],
        inspected_schemas=[
            "gti-mcp_get_collection_report",
            "secops-mcp_get_ioc_matches",
            "soar-mcp_block_indicator",
        ],
        tool_calls=[
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="load_skill",
                args={"skill_name": "gti-collection-threat-hunt"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "gti-mcp_get_collection_report"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "gti-mcp_get_collection_report",
                    "arguments": {"collection_id": "alienvault_63bbee81b55c8ba00724605a"},
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="threat_hunter",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "secops-mcp_get_ioc_matches"},
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="threat_hunter",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_get_ioc_matches",
                    "arguments": {"hours_back": 72},
                },
                result_summary='{"total_matches": 0, "ioc_matches": []}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="incident_responder",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "soar-mcp_block_indicator"},
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="incident_responder",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "soar-mcp_block_indicator",
                    "arguments": {
                        "indicator": "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2",
                        "indicator_type": "SHA256",
                    },
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )

    soar_verdict = SoarTriagingIntegrityRubric.evaluate(defective_trace)
    assert soar_verdict.category == "UNVERIFIED_CONTAINMENT"
    assert soar_verdict.passed is False
    assert "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2" in (
        soar_verdict.evidence.get("blocked_safe_or_lolbin_indicators") or []
    )

    report_bad = analyze_session_trace(defective_trace, source="session-db")
    issue_categories = {iss["category"] for iss in report_bad["detected_issues"]}
    assert "LOLBIN_OVERCONTAINMENT" in issue_categories
    assert "SHALLOW_HUNT_HORIZON" in issue_categories

    # 2. Cluster into SQLite AQuA insights DB
    db_path = tmp_path / "ursnif_aqua.db"
    insights = cluster_trace_reports([report_bad], db_path=db_path)
    insight_cats = {ins["category"] for ins in insights}
    assert "LOLBIN_OVERCONTAINMENT" in insight_cats
    assert "SHALLOW_HUNT_HORIZON" in insight_cats

    # 3. OTel span format with soar-mcp_block_ioc and ioc_value argument
    otel_format_trace = WorkflowTrace(
        workflow_name="ursnif_otel_lolbin_block",
        session_id="sess-ursnif-otel",
        trace_id="trace-ursnif-otel",
        disclosure_mode="dual_progressive",
        activated_skills=["ioc-containment"],
        inspected_schemas=["soar-mcp_block_ioc"],
        tool_calls=[
            ToolCallRecord(
                turn_index=1,
                agent_name="incident_responder",
                tool_name="soar-mcp_block_ioc",
                args={
                    "tool_name": "soar-mcp_block_ioc",
                    "arguments": {
                        "case_id": "CASE-2396",
                        "ioc_value": "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2",
                        "ioc_type": "file_hash",
                    },
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )
    otel_report = analyze_session_trace(otel_format_trace, source="otel-jsonl")
    otel_cats = {iss["category"] for iss in otel_report["detected_issues"]}
    assert "LOLBIN_OVERCONTAINMENT" in otel_cats
    assert "UNVERIFIED_CONTAINMENT" in otel_cats


def test_aqua_passes_compliant_multi_horizon_ursnif_hunt():
    """Verify a compliant multi-horizon Ursnif hunt (72h -> 168h + payload-only block) passes all rubrics with 0 AQuA issues."""
    compliant_trace = WorkflowTrace(
        workflow_name="ursnif_compliant_hunt",
        session_id="sess-ursnif-good",
        trace_id="trace-ursnif-good",
        disclosure_mode="dual_progressive",
        activated_skills=["gti-collection-threat-hunt"],
        inspected_schemas=[
            "gti-mcp_get_collection_report",
            "secops-mcp_get_ioc_matches",
            "gti-mcp_get_file_report",
            "soar-mcp_isolate_host",
            "soar-mcp_block_indicator",
        ],
        tool_calls=[
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="load_skill",
                args={"skill_name": "gti-collection-threat-hunt"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "gti-mcp_get_collection_report"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "gti-mcp_get_collection_report",
                    "arguments": {"collection_id": "alienvault_63bbee81b55c8ba00724605a"},
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "secops-mcp_get_ioc_matches"},
            ),
            ToolCallRecord(
                turn_index=1,
                agent_name="threat_hunter",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_get_ioc_matches",
                    "arguments": {"hours_back": 72},
                },
                result_summary='{"total_matches": 0, "ioc_matches": []}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="threat_hunter",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "secops-mcp_get_ioc_matches",
                    "arguments": {"hours_back": 168},
                },
                result_summary='{"total_matches": 3, "hostname": "malwaretest-win"}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="cti_researcher",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "gti-mcp_get_file_report"},
            ),
            ToolCallRecord(
                turn_index=3,
                agent_name="cti_researcher",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "gti-mcp_get_file_report",
                    "arguments": {
                        "hash": "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2"
                    },
                },
                result_summary='{"verdict": "benign", "cert_status": "VALID_CERTIFICATE"}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=4,
                agent_name="incident_responder",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "soar-mcp_isolate_host"},
            ),
            ToolCallRecord(
                turn_index=4,
                agent_name="incident_responder",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "soar-mcp_isolate_host",
                    "arguments": {"hostname": "malwaretest-win", "case_id": "2396"},
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=4,
                agent_name="incident_responder",
                tool_name="get_mcp_tool_schema",
                args={"tool_name": "soar-mcp_block_indicator"},
            ),
            ToolCallRecord(
                turn_index=4,
                agent_name="incident_responder",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "soar-mcp_block_indicator",
                    "arguments": {
                        "indicator": "8e570e32fd9147bd2dfcbbf2f4bbbd0b7dc9cb2fb6fb9b5eb5c52b3461487bf0",
                        "indicator_type": "SHA256",
                    },
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )

    verdicts = CategoricalRubricSuite.evaluate_all(
        compliant_trace,
        {"enrichment_summary": "Verified Ursnif compromise on malwaretest-win"},
    )
    assert verdicts["ProgressiveDisclosureCompliance"].category == "HONORED"
    assert verdicts["McpSchemaHygiene"].category == "SCHEMA_VERIFIED"
    assert verdicts["SoarTriagingIntegrity"].category == "GROUNDED_DISPOSITION"
    assert verdicts["MultiTurnRevision"].category == "NO_REVISION"

    report_good = analyze_session_trace(compliant_trace, source="session-db")
    assert report_good["detected_issues"] == []


def test_aqua_session_db_escaped_json_result_summary_horizon_check():
    """Verify session-db escaped JSON result_summary ('\\\"hours_back\\\": 168') does not false-positive SHALLOW_HUNT_HORIZON."""
    session_db_trace = WorkflowTrace(
        workflow_name="ursnif_session_db_escaped",
        session_id="sess-ursnif-escaped",
        trace_id="trace-ursnif-escaped",
        disclosure_mode="dual_progressive",
        activated_skills=["ioc-containment", "investigate-gti-collection"],
        inspected_schemas=["search_security_events", "get_collection_report"],
        tool_calls=[
            ToolCallRecord(
                turn_index=1,
                agent_name="incident_responder",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "search_security_events",
                    "arguments": {
                        "query": 'target.file.sha256 = "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2"',
                    },
                },
                result_summary='{"result": "{\\n  \\"status\\": \\"success\\",\\n  \\"hours_back\\": 168,\\n  \\"events_matched\\": 3\\n}"}',
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
            ToolCallRecord(
                turn_index=2,
                agent_name="cti_researcher",
                tool_name="execute_mcp_tool",
                args={
                    "tool_name": "get_collection_report",
                    "arguments": {"id": "alienvault_63bbee81b55c8ba00724605a"},
                },
                disclosure_skill_loaded=True,
                mcp_schema_inspected=True,
            ),
        ],
    )
    report = analyze_session_trace(session_db_trace, source="session-db")
    assert report["detected_issues"] == []

