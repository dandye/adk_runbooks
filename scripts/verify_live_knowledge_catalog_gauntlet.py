#!/usr/bin/env python3
"""Live end-to-end gauntlet for Google Cloud Knowledge Catalog Remote MCP,
AgentTool Sub-Agent Isolation, Multi-Engine SecOps Investigation Stores
(AlloyDB pgvector, Neo4j, Elasticsearch, BigQuery), Closed-Loop Metadata
Enrichment, and Stage A/B Governance Red-Lining in Argolis (dandye-0324-chronicle).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in (str(REPO_ROOT), str(MULTI_AGENT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from google.adk.agents import Agent  # noqa: E402
from google.adk.runners import InMemoryRunner  # noqa: E402
from google.genai import types as genai_types  # noqa: E402

from manager.tools.catalog_enrichment_tools import (  # noqa: E402
    MULTI_ENGINE_SECOPS_INVESTIGATION_STORE_ENTRIES,
    diff_and_audit_catalog_enrichment,
    download_catalog_entry_to_markdown,
    enrich_catalog_entry_markdown,
    publish_enriched_markdown_to_catalog,
)
from manager.tools.docs_review_tools import (  # noqa: E402
    audit_and_redline_catalog_context_in_doc,
    inspect_catalog_context_and_source_contract_in_text,
)
from manager.tools.grounding_tools import (  # noqa: E402
    init_knowledge_catalog_discovery_agent_tool,
    init_knowledge_catalog_toolset,
)

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "dandye-0324-chronicle")
LOCATION = "us-central1"
ENTRY_GROUP_ID = "secops-investigation-stores"


def _extract_mcp_text(result: Any) -> str:
    """Extracts text from an ADK McpTool CallToolResult or dict."""
    if isinstance(result, dict):
        content = result.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and "text" in item:
                    parts.append(str(item["text"]))
            if parts:
                return "\n".join(parts)
        return json.dumps(result)
    content = getattr(result, "content", None)
    if isinstance(content, list):
        parts = []
        for item in content:
            txt = getattr(item, "text", None)
            if txt is not None:
                parts.append(str(txt))
        if parts:
            return "\n".join(parts)
    return str(result)


async def run_gauntlet() -> dict[str, Any]:
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
    os.environ["GOOGLE_CLOUD_PROJECT"] = PROJECT_ID
    # Gemini 3 preview models require Vertex AI location="global"
    os.environ["GOOGLE_CLOUD_LOCATION"] = "global"

    summary: dict[str, Any] = {
        "project_id": PROJECT_ID,
        "dataplex_location": LOCATION,
        "vertex_location": "global",
        "model": "gemini-3-flash-preview",
        "stages": {},
    }

    # =========================================================================
    # STAGE 1: Live ADK McpToolset Startup Discovery & Multi-Engine Search
    # =========================================================================
    print("\n" + "=" * 78)
    print("STAGE 1: Live ADK McpToolset Startup Discovery & Multi-Engine Search")
    print("=" * 78)
    t0 = time.monotonic()
    toolset = init_knowledge_catalog_toolset(quota_project=PROJECT_ID)
    tools = await toolset.get_tools(readonly_context=None)
    tool_map = {t.name: t for t in tools}
    discovered_names = sorted(tool_map.keys())
    print(f"Discovered MCP tools (readonly_context=None): {discovered_names}")
    assert discovered_names == [
        "lookup_context",
        "lookup_entry",
        "search_entries",
    ], f"Unexpected tools: {discovered_names}"

    search_tool = tool_map["search_entries"]
    search_queries = {
        "entrygroup_secops_stores": f"entrygroup={ENTRY_GROUP_ID}",
        "alloydb_pgvector_reports": "alloydb.secops.detection_reports",
        "neo4j_knowledge_graph": "neo4j.secops.knowledge_graph",
        "elasticsearch_runbooks": "elasticsearch.secops.agentic_soc_runbooks",
        "bigquery_chatops": "system=BIGQUERY chatops_warehouse",
    }
    search_results_summary: dict[str, Any] = {}
    for label, q in search_queries.items():
        raw_res = await search_tool.run_async(
            args={"projectId": PROJECT_ID, "query": q, "pageSize": 20},
            tool_context=None,
        )
        parsed = json.loads(_extract_mcp_text(raw_res))
        entries = parsed.get("results", [])
        names = [
            e.get("dataplexEntry", {})
            .get("entrySource", {})
            .get("displayName")
            or e.get("dataplexEntry", {}).get("name", "").rsplit("/", 1)[-1]
            for e in entries
        ]
        search_results_summary[label] = {
            "query": q,
            "hit_count": len(entries),
            "display_names": names,
        }
        print(f"  - [{label}] query={q!r} -> {len(entries)} hits: {names}")

    assert search_results_summary["entrygroup_secops_stores"]["hit_count"] >= 5
    assert "alloydb.secops.detection_reports" in search_results_summary["alloydb_pgvector_reports"]["display_names"]
    assert "neo4j.secops.knowledge_graph" in search_results_summary["neo4j_knowledge_graph"]["display_names"]
    assert "elasticsearch.secops.agentic_soc_runbooks" in search_results_summary["elasticsearch_runbooks"]["display_names"]
    assert "channel_events" in search_results_summary["bigquery_chatops"]["display_names"]

    summary["stages"]["stage1_mcp_discovery_and_search"] = {
        "status": "PASS",
        "elapsed_sec": round(time.monotonic() - t0, 2),
        "discovered_tools": discovered_names,
        "searches": search_results_summary,
    }

    # =========================================================================
    # STAGE 2: Live Multi-Engine lookup_context & lookup_entry Synthesis
    # =========================================================================
    print("\n" + "=" * 78)
    print("STAGE 2: Live Multi-Engine lookup_context & lookup_entry Synthesis")
    print("=" * 78)
    t1 = time.monotonic()
    lookup_context_tool = tool_map["lookup_context"]
    lookup_entry_tool = tool_map["lookup_entry"]

    multi_engine_resources = [
        f"projects/{PROJECT_ID}/locations/{LOCATION}/entryGroups/{ENTRY_GROUP_ID}/entries/{spec['entry_id']}"
        for spec in MULTI_ENGINE_SECOPS_INVESTIGATION_STORE_ENTRIES
    ] + [
        f"projects/{PROJECT_ID}/locations/{LOCATION}/entryGroups/@bigquery/entries/"
        f"bigquery.googleapis.com/projects/{PROJECT_ID}/datasets/chatops_warehouse/tables/channel_events"
    ]

    raw_ctx = await lookup_context_tool.run_async(
        args={
            "projectId": PROJECT_ID,
            "location": LOCATION,
            "resources": multi_engine_resources,
        },
        tool_context=None,
    )
    ctx_json = json.loads(_extract_mcp_text(raw_ctx))
    yaml_context_str = ctx_json.get("context", "")
    parsed_yaml = yaml.safe_load(yaml_context_str)
    ctx_resources = parsed_yaml.get("resources", [])
    ctx_names = [
        r.get("simpleName") or r.get("catalogEntry") or r.get("name")
        for r in ctx_resources
    ]
    print(f"lookup_context returned {len(ctx_resources)} synthesized resources: {ctx_names}")
    assert len(ctx_resources) == 6, f"Expected 6 resources in lookup_context, got {len(ctx_resources)}"

    reports_entry_name = (
        f"projects/{PROJECT_ID}/locations/{LOCATION}/entryGroups/"
        f"{ENTRY_GROUP_ID}/entries/alloydb_secops_detection_reports"
    )
    raw_entry = await lookup_entry_tool.run_async(
        args={
            "projectId": PROJECT_ID,
            "location": LOCATION,
            "entry": reports_entry_name,
            "view": "ALL",
        },
        tool_context=None,
    )
    entry_obj = json.loads(_extract_mcp_text(raw_entry)).get("entry", {})
    aspect_keys = sorted((entry_obj.get("aspects") or {}).keys())
    print(f"lookup_entry(view='ALL') on alloydb_secops_detection_reports returned aspects: {aspect_keys}")
    assert "655216118709.global.schema" in aspect_keys
    assert "655216118709.global.overview" in aspect_keys
    assert any(k.endswith(".secops-store-governance") for k in aspect_keys)

    summary["stages"]["stage2_multi_engine_lookup_context"] = {
        "status": "PASS",
        "elapsed_sec": round(time.monotonic() - t1, 2),
        "resource_count": len(ctx_resources),
        "synthesized_resource_names": ctx_names,
        "yaml_byte_length": len(yaml_context_str),
        "reports_entry_aspects": aspect_keys,
    }

    # =========================================================================
    # STAGE 3: Live Closed-Loop Agentic Metadata Enrichment (Download -> Enrich
    #          -> Diff & Leakage Critic -> Live Publish -> Real-Time MCP Check)
    # =========================================================================
    print("\n" + "=" * 78)
    print("STAGE 3: Live Closed-Loop Metadata Enrichment & Leakage Critic Gate")
    print("=" * 78)
    t2 = time.monotonic()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # 3.1 Download live entry to baseline Markdown
        dl_res = download_catalog_entry_to_markdown(
            reports_entry_name,
            output_dir=tmp_path,
            live_dataplex=True,
            quota_project=PROJECT_ID,
        )
        baseline_md = dl_res["markdown_content"]
        if "## Enriched Agentic Data Context" in baseline_md:
            baseline_md = (
                baseline_md.split("## Enriched Agentic Data Context", 1)[0].rstrip()
                + "\n"
            )
        print(
            f"  - Downloaded live entry to {dl_res['short_table_name']}.md "
            f"({len(baseline_md)} chars)"
        )
        assert "alloydb.secops.detection_reports" in baseline_md
        assert "embedding" in baseline_md

        # 3.2 Enrich baseline Markdown with verified cross-engine join rules
        enrich_res = enrich_catalog_entry_markdown(
            baseline_md,
            context_notes=[
                "Primary grain is one row per Markdown investigation report (`report_id`) generated for a Chronicle detection alert (`alert_id`).",
                "Use `<TARGET_HOST>`, `<PRINCIPAL_EMAIL>`, and `<ALERT_ID>` placeholders in reusable query templates.",
            ],
            frequent_joins=[
                {
                    "table": "alloydb.secops.detection_alerts",
                    "join_key": "detection_reports.alert_id = detection_alerts.alert_id",
                },
                {
                    "table": "neo4j.secops.knowledge_graph",
                    "join_key": "MATCH (r:Report {report_id: $report_id})-[:INVESTIGATES]->(a:Alert {alert_id: $alert_id})-[:OBSERVED_ENTITY]->(e:Entity)",
                },
                {
                    "table": "elasticsearch.secops.agentic_soc_runbooks",
                    "join_key": "mitre_techniques overlap on BM25 multi_match query",
                },
            ],
            partition_keys=["created_at"],
            quality_rules=[
                "Completeness check on report_id, alert_id, summary, and 768-dim embedding (100.0%).",
                "Cosine similarity threshold (`1 - (embedding <=> $query_vec::vector) >= 0.78`) enforced before context injection.",
            ],
            output_path=tmp_path / "alloydb.secops.detection_reports.enriched.md",
        )
        enriched_md = enrich_res["enriched_markdown"]

        # 3.3 Adversarial Leakage Critic Check (Simulated IoC leak MUST be blocked)
        leaked_draft = (
            enriched_md
            + "\n### Analyst Note\nCorrelated SOAR Case 33269 on workstation 10.42.88.19 for user bruce.wayne@the.org.\n"
        )
        leaked_audit = diff_and_audit_catalog_enrichment(baseline_md, leaked_draft)
        leaked_pub = publish_enriched_markdown_to_catalog(
            reports_entry_name,
            baseline_md,
            leaked_draft,
            human_approved=True,
            live_dataplex=True,
            quota_project=PROJECT_ID,
        )
        print(
            f"  - Adversarial leakage test: status={leaked_pub['status']!r}, "
            f"violations={len(leaked_audit['leakage_violations'])}"
        )
        assert leaked_pub["status"] == "blocked"
        assert len(leaked_audit["leakage_violations"]) == 3

        # 3.4 Unapproved Check (human_approved=False MUST be blocked)
        unapproved_pub = publish_enriched_markdown_to_catalog(
            reports_entry_name,
            baseline_md,
            enriched_md,
            human_approved=False,
            live_dataplex=True,
            quota_project=PROJECT_ID,
        )
        assert unapproved_pub["status"] == "blocked"

        # 3.5 Clean Audit + Human-Approved Live Publish to Dataplex
        clean_audit = diff_and_audit_catalog_enrichment(baseline_md, enriched_md)
        assert clean_audit["ready_for_human_review"] is True
        assert clean_audit["leakage_violations"] == []

        live_pub = publish_enriched_markdown_to_catalog(
            reports_entry_name,
            baseline_md,
            enriched_md,
            human_approved=True,
            live_dataplex=True,
            quota_project=PROJECT_ID,
        )
        print(
            f"  - Clean human-approved live publish: status={live_pub['status']!r}, "
            f"updated_aspects={live_pub['updated_aspect_keys']}"
        )
        assert live_pub["status"] == "published"

        # 3.6 Verify immediately via live MCP lookup_context that the enriched
        # cross-engine joins are now served in real time!
        verify_ctx_raw = await lookup_context_tool.run_async(
            args={
                "projectId": PROJECT_ID,
                "location": LOCATION,
                "resources": [reports_entry_name],
            },
            tool_context=None,
        )
        verify_ctx_text = json.loads(_extract_mcp_text(verify_ctx_raw)).get("context", "")
        assert "Enriched Agentic Data Context" in verify_ctx_text
        assert "elasticsearch.secops.agentic_soc_runbooks" in verify_ctx_text
        print("  - Verified via live MCP lookup_context: enriched cross-engine join notes are live!")

    summary["stages"]["stage3_closed_loop_enrichment"] = {
        "status": "PASS",
        "elapsed_sec": round(time.monotonic() - t2, 2),
        "adversarial_leakage_violations_caught": len(leaked_audit["leakage_violations"]),
        "diff_line_count": len(clean_audit["unified_diff"].splitlines()),
        "published_aspect_keys": live_pub["updated_aspect_keys"],
        "verified_in_live_mcp_lookup_context": True,
    }

    # =========================================================================
    # STAGE 4: Live ADK AgentTool(knowledge_catalog_discovery_agent) Sub-Agent
    #          Execution on Vertex AI (gemini-3-flash-preview, location=global)
    # =========================================================================
    print("\n" + "=" * 78)
    print("STAGE 4: Live ADK AgentTool(knowledge_catalog_discovery_agent) on Vertex AI (gemini-3-flash-preview)")
    print("=" * 78)
    t3 = time.monotonic()
    kc_agent_toolset = init_knowledge_catalog_toolset(quota_project=PROJECT_ID)
    kc_discovery_tool = init_knowledge_catalog_discovery_agent_tool(
        model="gemini-3-flash-preview",
        toolset=kc_agent_toolset,
    )

    parent_orchestrator = Agent(
        name="secops_multi_engine_orchestrator",
        model="gemini-3-flash-preview",
        description="Parent SecOps orchestrator that delegates data/store discovery to knowledge_catalog_discovery_agent.",
        instruction=(
            "You are the Lead SecOps Architecture & Investigation Orchestrator.\n"
            "Before proposing any SQL, pgvector, Cypher, or Elasticsearch queries, ALWAYS "
            "invoke your `knowledge_catalog_discovery_agent` tool to discover the registered "
            "assets in GCP project `dandye-0324-chronicle` (location `us-central1`, including "
            "`entrygroup=secops-investigation-stores` and `system=BIGQUERY`) and obtain the "
            "verified 6-item Pre-SQL Source Contract.\n"
            "Then present the 6-item Source Contract and the cross-engine query plan linking "
            "AlloyDB (`alloydb.secops.detection_reports`), Neo4j (`neo4j.secops.knowledge_graph`), "
            "Elasticsearch (`elasticsearch.secops.agentic_soc_runbooks`), and BigQuery "
            "(`chatops_warehouse.channel_events`)."
        ),
        tools=[kc_discovery_tool],
    )

    runner = InMemoryRunner(
        agent=parent_orchestrator,
        app_name="kc_live_gauntlet",
    )
    session = await runner.session_service.create_session(
        app_name="kc_live_gauntlet",
        user_id="dandye",
    )
    user_prompt = (
        "We need to correlate Markdown investigation reports by 768-dim pgvector cosine "
        "similarity with multi-hop Neo4j entity Blast Radius paths, Elasticsearch BM25 "
        "MITRE ATT&CK runbooks, and BigQuery ChatOps channel events in project "
        "`dandye-0324-chronicle` (`us-central1`). Use `knowledge_catalog_discovery_agent` "
        "to discover these assets in Knowledge Catalog (`entrygroup=secops-investigation-stores` "
        "and `system=BIGQUERY`) and return the complete 6-item Source Contract."
    )

    parent_tool_calls: list[str] = []
    final_response_parts: list[str] = []
    async for event in runner.run_async(
        user_id="dandye",
        session_id=session.id,
        new_message=genai_types.Content(
            role="user",
            parts=[genai_types.Part.from_text(text=user_prompt)],
        ),
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.function_call and part.function_call.name:
                    parent_tool_calls.append(part.function_call.name)
                    print(f"  - Parent Orchestrator invoked tool: {part.function_call.name}")
                if part.text and event.is_final_response():
                    final_response_parts.append(part.text)

    final_text = "\n".join(final_response_parts).strip()
    print(f"  - Final Orchestrator Response ({len(final_text)} chars):")
    print("-" * 78)
    print(final_text[:1500] + ("\n...[truncated]..." if len(final_text) > 1500 else ""))
    print("-" * 78)
    assert "knowledge_catalog_discovery_agent" in parent_tool_calls
    assert "alloydb.secops.detection_reports" in final_text
    assert "neo4j.secops.knowledge_graph" in final_text
    assert "elasticsearch.secops.agentic_soc_runbooks" in final_text

    summary["stages"]["stage4_live_adk_agent_tool_subagent"] = {
        "status": "PASS",
        "elapsed_sec": round(time.monotonic() - t3, 2),
        "parent_tool_calls": parent_tool_calls,
        "response_char_length": len(final_text),
        "response_preview": final_text[:1200],
    }

    # =========================================================================
    # STAGE 5: Stage A/B Knowledge Catalog Governance Audit & Red-Lining
    #          (KC-01..KC-05)
    # =========================================================================
    print("\n" + "=" * 78)
    print("STAGE 5: Stage A/B Knowledge Catalog Governance Audit (KC-01..KC-05)")
    print("=" * 78)
    t4 = time.monotonic()
    flawed_runbook_doc = (
        "# Multi-Engine SecOps Lakehouse & Investigation Store Runbook\n\n"
        "## 1. Executive Metric Selection\n"
        "For the quarterly Board of Directors security briefing, query `analyst_sandbox.tmp_data_dump_v2_final_real` "
        "and export internal rows from `finance_mart.fin_monthly_closing_internal` to external partners.\n\n"
        "## 2. Unpartitioned Telemetry Scan\n"
        "Execute `SELECT event_id, principal_hostname FROM secops_datalake.udm_events_gold WHERE metadata_event_type = 'PROCESS_LAUNCH'` "
        "across all historical data without a partition filter.\n\n"
        "## 3. Ad-Hoc Join & Un-Deduplicated Streaming Aggregation\n"
        "Join `secops_datalake.udm_events_gold` to `secops_datalake.entity_graph_gold` using `ON udm.raw_host_uuid = eg.asset_tag` "
        "and count streaming rows directly without a `QUALIFY ROW_NUMBER()` deduplication CTE.\n\n"
        "## 4. High-Null Column Predicate & Failed Quality Check\n"
        "Filter UDM telemetry with `WHERE legacy_unpopulated_tag = 'Completed'` despite `null_ratio` of 0.88 and `data_quality.status` of `FAILED`.\n\n"
        "## 5. Discovery Protocol & Context Budget Violation\n"
        "Run scoped Context Set search with `entrygroup=secops-context-set system=bigquery column:event_id`, pass 25 entry names "
        "into a single `lookup_context` call, and run SQL without emitting a 6-item Source Contract.\n\n"
        "## 6. Certified Multi-Engine Negative Control\n"
        "Use `knowledge_catalog_discovery_agent` to run two-pass `lookup_context` (`options={'format': 'yaml', 'context_budget': '4000', 'all_schema_fields': 'true'}`) "
        "on `entryGroups/secops-investigation-stores` (`alloydb.secops.detection_reports`, `neo4j.secops.knowledge_graph`, "
        "`elasticsearch.secops.agentic_soc_runbooks`) and certified `GOLD_CRITICAL` BigQuery tables (`is_certified: true`), "
        "emit the 6-item Source Contract, filter by `event_date`, and deduplicate with "
        "`QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY ingested_timestamp DESC) = 1`.\n"
    )
    inspection = inspect_catalog_context_and_source_contract_in_text(flawed_runbook_doc)
    redline = audit_and_redline_catalog_context_in_doc(
        document_id="doc-live-kc-gauntlet",
        mode="DRY_RUN",
        doc_text_override=flawed_runbook_doc,
    )
    defect_ids = [d["rule_id"] for d in inspection["defects"]]
    print(f"  - Detected governance defects: {defect_ids}")
    print(f"  - Negative controls preserved: {len(inspection['negative_controls_preserved'])}")
    assert defect_ids == ["KC-01", "KC-02", "KC-03", "KC-04", "KC-05"]
    assert redline["defect_count"] == 5

    summary["stages"]["stage5_governance_redline_audit"] = {
        "status": "PASS",
        "elapsed_sec": round(time.monotonic() - t4, 2),
        "defect_ids": defect_ids,
        "negative_controls_preserved": len(inspection["negative_controls_preserved"]),
        "staged_comments_count": len(redline["staged_comments"]),
        "staged_suggested_edits_count": len(redline["staged_suggested_edits"]),
    }

    await toolset.close()
    await kc_agent_toolset.close()
    return summary


if __name__ == "__main__":
    result = asyncio.run(run_gauntlet())
    print("\n" + "=" * 78)
    print("ALL 5 LIVE KNOWLEDGE CATALOG GAUNTLET STAGES PASSED")
    print("=" * 78)
    print(json.dumps(result, indent=2))
