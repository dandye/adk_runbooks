"""Unit tests for LogstoryCorpus loader, active usecase replay, SCC tools, and YARA-L 2.0 validation."""

import json

import pytest

from manager.tools.logstory_corpus import (
    LogstoryCorpus,
    active_logstory_usecase,
    get_logstory_corpus,
)
from manager.tools.tools import (
    get_agent_tools,
    global_mcp_registry,
    init_shared_mcp_tools,
)


def _as_dict(raw):
    return json.loads(raw) if isinstance(raw, str) else raw


def test_logstory_corpus_loads_all_47_directories():
    """Verify all 43 attack usecases and 4 Cymbal baselines load with events, entities, and rules."""
    corpus = get_logstory_corpus()
    assert isinstance(corpus, LogstoryCorpus)

    attack_ids = corpus.list_usecases(include_baselines=False)
    baseline_ids = corpus.list_baselines()
    assert len(attack_ids) == 43
    assert len(baseline_ids) == 4
    assert set(baseline_ids) == {
        "CYMBAL_BASELINE_CLOUD",
        "CYMBAL_BASELINE_ENDPOINT",
        "CYMBAL_BASELINE_IDENTITY",
        "CYMBAL_BASELINE_NETWORK",
    }

    zero_event_usecases = [
        uid for uid, uc in corpus.usecases.items() if len(uc.events) == 0
    ]
    assert zero_event_usecases == []

    total_events = sum(len(uc.events) for uc in corpus.usecases.values())
    total_entities = sum(len(uc.entities) for uc in corpus.usecases.values())
    total_rules = sum(len(uc.rules) for uc in corpus.usecases.values())
    total_scc = len(corpus.list_scc_findings())

    assert total_events >= 1200
    assert total_entities >= 500
    assert total_rules >= 170
    assert total_scc == 8


def test_active_logstory_usecase_pins_events_and_paired_baselines():
    """Verify active_logstory_usecase scopes search, entity, SCC, IAM, and SOAR tools."""
    get_agent_tools(disclosure_mode="dual_progressive")

    with active_logstory_usecase("GCP_HONEY_TOKENS", include_baselines=True) as uc:
        assert uc.usecase_id == "GCP_HONEY_TOKENS"
        assert "CYMBAL_BASELINE_CLOUD" in uc.paired_baselines

        # 1. SIEM search returns both attack and paired baseline events
        ev_res = _as_dict(
            global_mcp_registry.execute_tool(
                "secops-mcp_search_security_events",
                {"query": "canary-deployer", "hours_back": 168, "max_events": 50},
            )
        )
        assert ev_res["status"] == "success"
        assert ev_res["events_matched"] >= 1
        assert any(
            not ev["is_baseline_noise"] for ev in ev_res["events"]
        )

        # 2. Baseline noise events are also present when querying wildcard/baseline terms
        base_res = _as_dict(
            global_mcp_registry.execute_tool(
                "secops-mcp_search_security_events",
                {"query": "*", "hours_back": 168, "max_events": 100},
            )
        )
        assert any(ev["is_baseline_noise"] for ev in base_res["events"])
        assert any(not ev["is_baseline_noise"] for ev in base_res["events"])

        # 3. SCC findings for GCP_HONEY_TOKENS
        scc_res = _as_dict(
            global_mcp_registry.execute_tool("scc-mcp_list_scc_findings", {})
        )
        assert scc_res["total_findings"] >= 1
        assert all(
            f["usecase_id"] in {"GCP_HONEY_TOKENS", "CYMBAL_BASELINE_CLOUD"}
            for f in scc_res["findings"]
        )

        # 4. Cloud IAM principal lookup identifies canary honeytoken
        iam_res = _as_dict(
            global_mcp_registry.execute_tool(
                "scc-mcp_lookup_cloud_iam_principal",
                {"principal_email": "canary-deployer"},
            )
        )
        assert iam_res["status"] == "success"
        assert iam_res["is_canary_honeytoken"] is True

        # 5. SOAR case details resolve to active usecase
        case_res = _as_dict(
            global_mcp_registry.execute_tool(
                "soar-mcp_get_case_full_details", {"case_id": "GCP_HONEY_TOKENS"}
            )
        )
        assert case_res["usecase_id"] == "GCP_HONEY_TOKENS"
        assert case_res["priority"] == "HIGH"


def test_active_logstory_usecase_without_baselines():
    """Verify include_baselines=False excludes Cymbal baseline noise."""
    corpus = get_logstory_corpus()
    with active_logstory_usecase("GCP_HONEY_TOKENS", include_baselines=False):
        events = corpus.search_events(query="*", hours_back=168, max_events=100)
        assert len(events) > 0
        assert all(not ev["is_baseline_noise"] for ev in events)


def test_validate_yaral2_rule_catches_common_chronicle_gotchas():
    """Verify YARA-L 2.0 rule validator passes corpus rules and rejects invalid syntax."""
    corpus = get_logstory_corpus()
    sample_rules = corpus.list_rules(query="gcp_honey_tokens")
    assert len(sample_rules) >= 1
    first_rule = corpus.get_rule(sample_rules[0]["rule_id"])
    assert first_rule is not None

    valid_res = corpus.validate_yaral2_rule(first_rule["rule_text"])
    assert valid_res["valid"] is True
    assert valid_res["errors"] == []

    # Invalid: inline `in (...)` tuple
    inline_tuple_rule = """
    rule test_inline_tuple {
      meta:
        author = "test"
      events:
        $e.metadata.event_type in ("PROCESS_LAUNCH", "NETWORK_CONNECTION")
      condition:
        $e
    }
    """
    tuple_res = corpus.validate_yaral2_rule(inline_tuple_rule)
    assert tuple_res["valid"] is False
    assert any("inline `in (...)`" in err for err in tuple_res["errors"])

    # Invalid: UDM search alias `$e.ip =`
    alias_rule = """
    rule test_search_alias {
      meta:
        author = "test"
      events:
        $e.ip = "198.51.100.10"
      condition:
        $e
    }
    """
    alias_res = corpus.validate_yaral2_rule(alias_rule)
    assert alias_res["valid"] is False
    assert any("UDM search alias `.ip`" in err for err in alias_res["errors"])

    # Invalid: missing condition section and unbalanced braces
    broken_rule = """
    rule broken_rule {
      meta:
        author = "test"
      events:
        $e.metadata.event_type = "USER_LOGIN"
    """
    broken_res = corpus.validate_yaral2_rule(broken_rule)
    assert broken_res["valid"] is False
    assert any("condition:" in err for err in broken_res["errors"])
    assert any("Unbalanced curly braces" in err for err in broken_res["errors"])


def test_ursnif_queries_take_precedence_and_init_shared_mcp_tools_invariant():
    """Verify init_shared_mcp_tools returns 3 toolsets and Ursnif queries remain unchanged."""
    toolsets = init_shared_mcp_tools()
    assert len(toolsets) == 3

    get_agent_tools(disclosure_mode="dual_progressive")
    ursnif_ev = _as_dict(
        global_mcp_registry.execute_tool(
            "secops-mcp_search_security_events",
            {"query": "superstarts.top", "hours_back": 168},
        )
    )
    assert ursnif_ev["events_matched"] == 3
    assert ursnif_ev["events"][0]["principal"]["hostname"] == "malwaretest-win"


def test_logstory_alerts_events_and_url_report():
    """Verify SOAR list_alerts_by_case, list_events_by_alert, and GTI get_url_report."""
    get_agent_tools(disclosure_mode="dual_progressive")

    with active_logstory_usecase("DEFENDER_MALWARE", include_baselines=True):
        alerts_res = _as_dict(
            global_mcp_registry.execute_tool(
                "soar-mcp_list_alerts_by_case", {"case_id": "DEFENDER_MALWARE"}
            )
        )
        assert alerts_res["status"] == "success"
        assert len(alerts_res["alerts"]) >= 1
        first_alert_id = alerts_res["alerts"][0]["alert_id"]

        events_res = _as_dict(
            global_mcp_registry.execute_tool(
                "soar-mcp_list_events_by_alert",
                {"case_id": "DEFENDER_MALWARE", "alert_id": first_alert_id},
            )
        )
        assert events_res["status"] == "success"
        assert len(events_res["events"]) >= 1

        url_res = _as_dict(
            global_mcp_registry.execute_tool(
                "gti-mcp_get_url_report",
                {"url": "https://cdn.invoicecloud-verify.com/gate.php"},
            )
        )
        assert url_res["status"] == "success"
        assert url_res["verdict"] == "malicious"

    with active_logstory_usecase("CYMBAL_BASELINE_ENDPOINT", include_baselines=True):
        base_alerts = _as_dict(
            global_mcp_registry.execute_tool(
                "soar-mcp_list_alerts_by_case", {"case_id": "CYMBAL_BASELINE_ENDPOINT"}
            )
        )
        assert base_alerts["status"] == "success"
        assert len(base_alerts["alerts"]) >= 1
        assert all(a["severity"] == "LOW" for a in base_alerts["alerts"])

