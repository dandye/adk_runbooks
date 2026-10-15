"""Unit tests for ``manager.tools.grounding_tools``: Developer Knowledge MCP
toolset (startup vs. runtime header provisioning) and ``AgentTool(web_search_verifier)``."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from google.adk.tools import google_search
from google.adk.tools.agent_tool import AgentTool

from manager.tools.grounding_tools import (
    DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL,
    DEFAULT_KNOWLEDGE_CATALOG_DATA_PRODUCTS_MCP_URL,
    DEFAULT_KNOWLEDGE_CATALOG_MCP_URL,
    DEVELOPER_KNOWLEDGE_TOOL_FILTER,
    DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX,
    KNOWLEDGE_CATALOG_TOOL_FILTER,
    KNOWLEDGE_CATALOG_TOOL_NAME_PREFIX,
    build_lookup_context_request_payload,
    developer_knowledge_headers,
    developer_knowledge_mcp_url,
    developer_knowledge_toolset_configured,
    init_developer_knowledge_mcp_tools,
    init_developer_knowledge_toolset,
    init_knowledge_catalog_discovery_agent_tool,
    init_knowledge_catalog_mcp_tools,
    init_knowledge_catalog_toolset,
    init_web_search_agent_tool,
    knowledge_catalog_discovery_agent,
    knowledge_catalog_headers,
    knowledge_catalog_mcp_url,
    knowledge_catalog_toolset_configured,
    web_search_verifier_agent,
)
from skills.drive_registry import StaticTokenSource
from tests.fake_devknowledge_mcp import FakeDevKnowledgeMcpServer
from tests.fake_knowledge_catalog_mcp import FakeKnowledgeCatalogMcpServer
import yaml


def test_developer_knowledge_url_defaults_and_overrides():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DEVELOPERKNOWLEDGE_MCP_URL", None)
        assert developer_knowledge_mcp_url() == DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL

    with patch.dict(
        os.environ, {"DEVELOPERKNOWLEDGE_MCP_URL": "http://127.0.0.1:9999/mcp"}, clear=False
    ):
        assert developer_knowledge_mcp_url() == "http://127.0.0.1:9999/mcp"


def test_developer_knowledge_headers_prefers_api_key():
    env = {
        "DEVELOPERKNOWLEDGE_API_KEY": "test-api-key-123",
        "GCP_PROJECT_ID": "dandye-0324-chronicle",
    }
    with patch.dict(os.environ, env, clear=False):
        headers = developer_knowledge_headers(
            readonly_context=None,
            token_source=StaticTokenSource("should-not-be-used"),
        )
    assert headers["X-Goog-Api-Key"] == "test-api-key-123"
    assert headers["X-Goog-User-Project"] == "dandye-0324-chronicle"
    assert "Authorization" not in headers


def test_developer_knowledge_headers_uses_adc_bearer_when_no_api_key():
    with patch.dict(
        os.environ, {"GCP_PROJECT_ID": "dandye-0324-chronicle"}, clear=False
    ):
        os.environ.pop("DEVELOPERKNOWLEDGE_API_KEY", None)
        headers = developer_knowledge_headers(
            readonly_context=SimpleNamespace(state={}),
            token_source=StaticTokenSource("adc-bearer-xyz"),
        )
    assert headers["Authorization"] == "Bearer adc-bearer-xyz"
    assert headers["X-Goog-User-Project"] == "dandye-0324-chronicle"


def test_developer_knowledge_toolset_configured_flag():
    with patch.dict(
        os.environ,
        {"DEVELOPERKNOWLEDGE_MCP_TOOLSET": "0", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert developer_knowledge_toolset_configured() is False

    with patch.dict(
        os.environ,
        {"DEVELOPERKNOWLEDGE_MCP_TOOLSET": "1", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert developer_knowledge_toolset_configured() is True


def test_init_developer_knowledge_toolset_startup_and_runtime_against_fake(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    """Verifies Irani (2026) startup nuance:
    1. ``get_tools(readonly_context=None)`` (called at A2A startup) succeeds even when
       the server enforces authentication headers.
    2. Runtime ``run_async`` executes ``search_documents``, ``answer_query``, and
       ``get_documents`` with the expected headers.
    """
    fake_devknowledge.store.require_auth = True
    toolset = init_developer_knowledge_toolset(
        url=fake_devknowledge.url,
        api_key="dk-api-key-abc",
        quota_project="dandye-0324-chronicle",
    )

    async def exercise():
        try:
            # 1. Startup discovery with readonly_context=None (A2A Agent Card path)
            startup_tools = await toolset.get_tools(readonly_context=None)
            names = sorted(t.name for t in startup_tools)
            assert names == sorted(DEVELOPER_KNOWLEDGE_TOOL_FILTER)
            assert fake_devknowledge.store.last_headers.get("x-goog-api-key") == "dk-api-key-abc"

            by_name = {t.name: t for t in startup_tools}

            # 2. Call search_documents
            search_res = await by_name["search_documents"].run_async(
                args={"query": "roles/aiplatform.user chronicle"}, tool_context=None
            )
            assert not search_res.get("isError")
            structured = search_res["structuredContent"]
            assert len(structured["results"]) >= 1
            first_doc_name = structured["results"][0]["parent"]
            assert first_doc_name == "documents/docs.cloud.google.com/iam/docs/understanding-roles"

            # 3. Call get_documents with parent name from search_documents
            get_res = await by_name["get_documents"].run_async(
                args={"names": [first_doc_name]}, tool_context=None
            )
            assert not get_res.get("isError")
            docs = get_res["structuredContent"]["documents"]
            assert len(docs) == 1
            assert "roles/aiplatform.user" in docs[0]["content"]

            # 4. Call answer_query
            ans_res = await by_name["answer_query"].run_async(
                args={"query": "google_search AgentTool"}, tool_context=None
            )
            assert not ans_res.get("isError")
            assert "AgentTool" in ans_res["structuredContent"]["answer_text"]
            assert (
                "documents/adk.dev/tools/google-search-grounding"
                in ans_res["structuredContent"]["references"]
            )
        finally:
            await toolset.close()

    asyncio.run(exercise())


def test_init_developer_knowledge_toolset_with_adc_bearer(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    fake_devknowledge.store.require_auth = True
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DEVELOPERKNOWLEDGE_API_KEY", None)
        toolset = init_developer_knowledge_toolset(
            url=fake_devknowledge.url,
            token_source=StaticTokenSource("adc-token-999"),
            quota_project="dandye-0324-chronicle",
        )

        async def exercise():
            try:
                tools = await toolset.get_tools(readonly_context=None)
                by_name = {t.name: t for t in tools}
                res = await by_name["search_documents"].run_async(
                    args={"query": "IAM"}, tool_context=None
                )
                assert not res.get("isError")
                assert (
                    fake_devknowledge.store.last_headers.get("authorization")
                    == "Bearer adc-token-999"
                )
                assert (
                    fake_devknowledge.store.last_headers.get("x-goog-user-project")
                    == "dandye-0324-chronicle"
                )
            finally:
                await toolset.close()

        asyncio.run(exercise())


def test_init_developer_knowledge_mcp_tools_registers_in_global_registry(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    env = {
        "DEVELOPERKNOWLEDGE_MCP_TOOLSET": "1",
        "DEVELOPERKNOWLEDGE_MCP_URL": fake_devknowledge.url,
        "DEVELOPERKNOWLEDGE_API_KEY": "reg-key",
        "GCP_PROJECT_ID": "dandye-0324-chronicle",
    }
    with patch.dict(os.environ, env, clear=False):
        ts = init_developer_knowledge_mcp_tools()
        assert ts is not None
        assert ts.tool_name_prefix == DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX


def test_web_search_verifier_agent_and_agent_tool_isolation():
    """Verifies the AgentTool pattern from Irani (2026):
    - Child agent ``web_search_verifier`` holds ONLY ``google_search`` in its tools list.
    - ``init_web_search_agent_tool()`` wraps ``web_search_verifier`` in ``AgentTool`` so
      it can sit alongside custom FunctionTools and McpToolsets on the parent agent.
    """
    child = web_search_verifier_agent()
    assert child.name == "web_search_verifier"
    assert child.tools == [google_search]

    wrapped = init_web_search_agent_tool()
    assert isinstance(wrapped, AgentTool)
    assert wrapped.agent.name == "web_search_verifier"
    assert wrapped.agent.tools == [google_search]


def test_knowledge_catalog_url_and_headers_configuration():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("KNOWLEDGE_CATALOG_MCP_URL", None)
        assert knowledge_catalog_mcp_url() == DEFAULT_KNOWLEDGE_CATALOG_MCP_URL
        assert (
            DEFAULT_KNOWLEDGE_CATALOG_DATA_PRODUCTS_MCP_URL
            == "https://dataplex.googleapis.com/mcp/data-products"
        )

    with patch.dict(
        os.environ,
        {
            "KNOWLEDGE_CATALOG_MCP_URL": "http://127.0.0.1:9998/mcp",
            "GCP_PROJECT_ID": "dandye-0324-chronicle",
        },
        clear=False,
    ):
        assert knowledge_catalog_mcp_url() == "http://127.0.0.1:9998/mcp"
        headers = knowledge_catalog_headers(
            readonly_context=None,
            token_source=StaticTokenSource("kc-adc-token-123"),
        )
        assert headers["Authorization"] == "Bearer kc-adc-token-123"
        assert headers["X-Goog-User-Project"] == "dandye-0324-chronicle"


def test_knowledge_catalog_toolset_configured_flag():
    with patch.dict(
        os.environ,
        {"KNOWLEDGE_CATALOG_MCP_TOOLSET": "0", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert knowledge_catalog_toolset_configured() is False

    with patch.dict(
        os.environ,
        {"KNOWLEDGE_CATALOG_MCP_TOOLSET": "1", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert knowledge_catalog_toolset_configured() is True


def test_build_lookup_context_request_payload_validates_bounds_and_options():
    entry_a = (
        "projects/dandye-0324-chronicle/locations/us-central1/entryGroups/@bigquery/"
        "entries/bigquery.googleapis.com/projects/dandye-0324-chronicle/datasets/secops_datalake/tables/udm_events_gold"
    )
    payload = build_lookup_context_request_payload(
        "dandye-0324-chronicle",
        "us-central1",
        [entry_a],
        fmt="yaml",
        context_budget=4000,
        all_schema_fields=True,
    )
    assert payload["name"] == "projects/dandye-0324-chronicle/locations/us-central1"
    assert payload["resources"] == [entry_a]
    assert payload["options"] == {
        "format": "yaml",
        "context_budget": "4000",
        "all_schema_fields": "true",
    }

    with pytest.raises(ValueError, match="at least 1"):
        build_lookup_context_request_payload("dandye-0324-chronicle", "us-central1", [])

    with pytest.raises(ValueError, match="at most 10"):
        build_lookup_context_request_payload(
            "dandye-0324-chronicle",
            "us-central1",
            [f"entry-{i}" for i in range(11)],
        )


def test_init_knowledge_catalog_toolset_six_dimensions_and_iam_post_filtering(
    fake_knowledge_catalog: FakeKnowledgeCatalogMcpServer,
):
    """Verifies Knowledge Catalog Remote MCP startup/runtime and lookupContext:
    1. A2A startup discovery with ``readonly_context=None`` succeeds when auth is required.
    2. ``search_entries`` discovers Context Sets (``entrygroup.type=context-set``) and
       filter-free scoped Context Set rule docs.
    3. ``lookup_context`` returns all 6 metadata dimensions (technical schema/partitioning,
       operational joins, business terms/overview/guidelines/governance_aspect, column
       data profile, data quality status, and 1-hop relatedResources).
    4. Dynamic source-system IAM post-filtering strips ``restricted_hr.compensation_records``
       both when requested directly and from ``frequent_joins`` / ``relatedResources``.
    5. ``context_budget`` truncates secondary sections when tight while ``all_schema_fields="true"``
       retains all schema columns.
    """
    fake_knowledge_catalog.store.require_auth = True
    toolset = init_knowledge_catalog_toolset(
        url=fake_knowledge_catalog.url,
        token_source=StaticTokenSource("argolis-adc-token-777"),
        quota_project="dandye-0324-chronicle",
    )

    p = "dandye-0324-chronicle"
    loc = "us-central1"
    udm_entry = (
        f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
        f"bigquery.googleapis.com/projects/{p}/datasets/secops_datalake/tables/udm_events_gold"
    )
    fin_entry = (
        f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
        f"bigquery.googleapis.com/projects/{p}/datasets/finance_mart/tables/fin_monthly_closing_internal"
    )
    restricted_hr_entry = (
        f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
        f"bigquery.googleapis.com/projects/{p}/datasets/restricted_hr/tables/compensation_records"
    )

    async def exercise():
        try:
            # 1. Startup discovery with readonly_context=None
            startup_tools = await toolset.get_tools(readonly_context=None)
            names = sorted(t.name for t in startup_tools)
            assert names == sorted(KNOWLEDGE_CATALOG_TOOL_FILTER)
            assert (
                fake_knowledge_catalog.store.last_headers.get("authorization")
                == "Bearer argolis-adc-token-777"
            )
            assert (
                fake_knowledge_catalog.store.last_headers.get("x-goog-user-project")
                == "dandye-0324-chronicle"
            )

            by_name = {t.name: t for t in startup_tools}

            # 2. Search for Context Sets and verify filter-free scoped Context Set search
            cs_res = await by_name["search_entries"].run_async(
                args={"query": "entrygroup.type=context-set", "page_size": 50, "semantic_search": True},
                tool_context=None,
            )
            assert not cs_res.get("isError")
            cs_hits = cs_res["structuredContent"]["results"]
            assert len(cs_hits) == 1
            assert cs_hits[0]["entryType"] == "context-set"

            scoped_ok = await by_name["search_entries"].run_async(
                args={
                    "query": f"entrygroup=projects/{p}/locations/{loc}/entryGroups/secops-context-set (deduplication partition)",
                },
                tool_context=None,
            )
            assert len(scoped_ok["structuredContent"]["results"]) >= 1

            scoped_bad_filter = await by_name["search_entries"].run_async(
                args={
                    "query": f"entrygroup=projects/{p}/locations/{loc}/entryGroups/secops-context-set system=bigquery",
                },
                tool_context=None,
            )
            assert scoped_bad_filter["structuredContent"]["results"] == []

            # 3. Call lookup_context across udm_entry, fin_entry, and unauthorized restricted_hr_entry
            ctx_res = await by_name["lookup_context"].run_async(
                args={
                    "name": f"projects/{p}/locations/{loc}",
                    "resources": [udm_entry, fin_entry, restricted_hr_entry],
                    "options": {
                        "format": "yaml",
                        "context_budget": "4000",
                        "all_schema_fields": "true",
                    },
                },
                tool_context=None,
            )
            assert not ctx_res.get("isError")
            raw_yaml = ctx_res["structuredContent"]["context"]
            parsed = yaml.safe_load(raw_yaml)

            # Verify unauthorized restricted_hr_entry was stripped everywhere
            assert "compensation_records" not in raw_yaml
            returned_names = [r["simpleName"] for r in parsed["resources"]]
            assert returned_names == [
                "secops_datalake.udm_events_gold",
                "finance_mart.fin_monthly_closing_internal",
            ]

            # Verify all 6 dimensions on udm_events_gold
            udm_block = parsed["resources"][0]
            assert udm_block["usage"]["partitionBy"] == ["event_date"]
            assert "principal_hostname" in udm_block["usage"]["clusterBy"]
            assert "QUALIFY ROW_NUMBER()" in udm_block["guidelines"]
            assert udm_block["data_quality"]["status"] == "PASSED"
            assert udm_block["governance_aspect"]["product_tier"] == "GOLD_CRITICAL"
            assert len(udm_block["schema"]) == 6
            assert udm_block["schema"][3]["sample_values"] == [
                "PROCESS_LAUNCH",
                "USER_LOGIN",
                "NETWORK_CONNECTION",
                "NETWORK_DNS",
            ]
            # Cross-resource join between udm_events_gold and fin_monthly_closing_internal
            assert parsed["joins"][0]["source"] == "secops_datalake.udm_events_gold"
            assert parsed["joins"][0]["target"] == "finance_mart.fin_monthly_closing_internal"

            # 4. Tight budget with all_schema_fields="true" vs "false"
            tight_keep_schema = await by_name["lookup_context"].run_async(
                args={
                    "name": f"projects/{p}/locations/{loc}",
                    "resources": [udm_entry],
                    "options": {
                        "format": "yaml",
                        "context_budget": "500",
                        "all_schema_fields": "true",
                    },
                },
                tool_context=None,
            )
            parsed_keep = yaml.safe_load(tight_keep_schema["structuredContent"]["context"])
            assert len(parsed_keep["resources"][0]["schema"]) == 6

            tight_truncate_schema = await by_name["lookup_context"].run_async(
                args={
                    "name": f"projects/{p}/locations/{loc}",
                    "resources": [udm_entry],
                    "options": {
                        "format": "yaml",
                        "context_budget": "500",
                        "all_schema_fields": "false",
                    },
                },
                tool_context=None,
            )
            parsed_trunc = yaml.safe_load(tight_truncate_schema["structuredContent"]["context"])
            assert len(parsed_trunc["resources"][0]["schema"]) == 1

            # 5. Requesting ONLY an unauthorized entry returns empty context
            unauth_only = await by_name["lookup_context"].run_async(
                args={
                    "name": f"projects/{p}/locations/{loc}",
                    "resources": [restricted_hr_entry],
                    "options": {"format": "yaml"},
                },
                tool_context=None,
            )
            assert unauth_only["structuredContent"]["context"] == ""
        finally:
            await toolset.close()

    asyncio.run(exercise())


def test_knowledge_catalog_discovery_agent_tool_isolation_and_registry(
    fake_knowledge_catalog: FakeKnowledgeCatalogMcpServer,
):
    """Verifies that ``knowledge_catalog_discovery_agent`` isolates wide-net
    catalog search inside an ``AgentTool`` and registers under ``kcatalog``."""
    env = {
        "KNOWLEDGE_CATALOG_MCP_TOOLSET": "1",
        "KNOWLEDGE_CATALOG_MCP_URL": fake_knowledge_catalog.url,
        "GCP_PROJECT_ID": "dandye-0324-chronicle",
    }
    with patch.dict(os.environ, env, clear=False):
        ts = init_knowledge_catalog_mcp_tools(
            token_source=StaticTokenSource("kc-reg-token"),
        )
        assert ts is not None
        assert ts.tool_name_prefix == KNOWLEDGE_CATALOG_TOOL_NAME_PREFIX

        child = knowledge_catalog_discovery_agent(toolset=ts)
        assert child.name == "knowledge_catalog_discovery_agent"
        assert "entrygroup.type=context-set" in child.instruction
        assert "lookup_context" in child.instruction
        assert "Source Contract" in child.instruction

        wrapped = init_knowledge_catalog_discovery_agent_tool(toolset=ts)
        assert isinstance(wrapped, AgentTool)
        assert wrapped.agent.name == "knowledge_catalog_discovery_agent"


def test_select_active_case_store_postgres_to_alloydb_zero_redeploy_cutover():
    """Verifies that ``select_active_case_store`` routes to the certified
    ``GOLD_CRITICAL`` store and switches from Cloud SQL PostgreSQL to AlloyDB
    ``pgvector`` purely via Knowledge Catalog aspect updates."""
    from manager.tools.catalog_enrichment_tools import select_active_case_store

    day1_entries = [
        {
            "name": "projects/dandye-0324-chronicle/locations/us-central1/entryGroups/secops-investigation-stores/entries/postgres_secops_soar_cases",
            "entrySource": {
                "displayName": "postgres.secops.soar_case_reports",
                "system": "CLOUD_SQL_POSTGRESQL",
            },
            "aspects": {
                "1002894625780.us-central1.secops-store-governance": {
                    "data": {
                        "engine_family": "CLOUD_SQL_POSTGRESQL",
                        "connection_uri": "host=10.128.0.15:5432, db=soar_cases",
                        "governance_tier": "GOLD_CRITICAL",
                        "is_certified": True,
                        "retrieval_modality": "SQL_FTS_TSVECTOR",
                        "markdown_column_or_property": "case_body_md",
                        "cross_engine_join_key": "case_id",
                    }
                },
                "655216118709.global.schema": {
                    "data": {
                        "fields": [
                            {"name": "case_id"},
                            {"name": "case_body_md"},
                        ]
                    }
                },
            },
        },
        {
            "name": "projects/dandye-0324-chronicle/locations/us-central1/entryGroups/secops-investigation-stores/entries/alloydb_secops_detection_reports",
            "entrySource": {
                "displayName": "alloydb.secops.detection_reports",
                "system": "ALLOYDB_POSTGRESQL",
            },
            "aspects": {
                "1002894625780.us-central1.secops-store-governance": {
                    "data": {
                        "engine_family": "ALLOYDB_POSTGRESQL",
                        "connection_uri": "host=alloydb-primary.secops.internal:5432, db=postgres",
                        "governance_tier": "BRONZE_ADHOC",
                        "is_certified": False,
                        "retrieval_modality": "PGVECTOR_COSINE",
                        "markdown_column_or_property": "markdown_report",
                        "cross_engine_join_key": "id, alert_ids",
                    }
                },
                "655216118709.global.schema": {
                    "data": {
                        "fields": [
                            {"name": "id"},
                            {"name": "markdown_report"},
                            {"name": "embedding"},
                        ]
                    }
                },
            },
        },
    ]

    day1_selected = select_active_case_store(day1_entries)
    assert day1_selected["display_name"] == "postgres.secops.soar_case_reports"
    assert day1_selected["engine_family"] == "CLOUD_SQL_POSTGRESQL"
    assert day1_selected["retrieval_modality"] == "SQL_FTS_TSVECTOR"
    assert day1_selected["markdown_column"] == "case_body_md"

    # Day 2 cutover: demote Cloud SQL Postgres to DEPRECATED and promote AlloyDB to GOLD_CRITICAL
    day1_entries[0]["aspects"]["1002894625780.us-central1.secops-store-governance"]["data"][
        "governance_tier"
    ] = "DEPRECATED"
    day1_entries[0]["aspects"]["1002894625780.us-central1.secops-store-governance"]["data"][
        "is_certified"
    ] = False
    day1_entries[1]["aspects"]["1002894625780.us-central1.secops-store-governance"]["data"][
        "governance_tier"
    ] = "GOLD_CRITICAL"
    day1_entries[1]["aspects"]["1002894625780.us-central1.secops-store-governance"]["data"][
        "is_certified"
    ] = True

    day2_selected = select_active_case_store(day1_entries)
    assert day2_selected["display_name"] == "alloydb.secops.detection_reports"
    assert day2_selected["engine_family"] == "ALLOYDB_POSTGRESQL"
    assert day2_selected["retrieval_modality"] == "PGVECTOR_COSINE"
    assert day2_selected["markdown_column"] == "markdown_report"
    assert "embedding" in day2_selected["schema_fields"]


