"""Unit tests for Closed-Loop Agentic Metadata Enrichment
(``manager.tools.catalog_enrichment_tools``) and Stage A/B Knowledge Catalog
Google Docs Audit & Redlining (``KC-01``..``KC-05`` in ``docs_review_tools.py``)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from manager.tools.catalog_enrichment_tools import (
    diff_and_audit_catalog_enrichment,
    download_catalog_entry_to_markdown,
    enrich_catalog_entry_markdown,
    publish_enriched_markdown_to_catalog,
)
from manager.tools.docs_review_tools import (
    CANONICAL_KNOWLEDGE_CATALOG_GROUNDING_CATALOG,
    audit_and_redline_catalog_context_in_doc,
    find_catalog_context_and_source_contract_spans,
    inspect_catalog_context_and_source_contract_in_text,
)
from tests.fake_knowledge_catalog_mcp import FakeKnowledgeCatalogStore


def test_download_enrich_diff_and_publish_closed_loop(
    knowledge_catalog_store: FakeKnowledgeCatalogStore,
    tmp_path: Path,
):
    """Verifies the 4-stage human-in-the-loop metadata enrichment pipeline:
    1. ``download_catalog_entry_to_markdown`` exports ``lookup_entry(view='FULL')``
       into ``<project>.<dataset>.<table>.md``.
    2. ``enrich_catalog_entry_markdown`` synthesizes ``<table.enriched.md>`` with
       business definitions, ``frequent_joins``, partition pruning ``guidelines``,
       and quality rules.
    3. ``diff_and_audit_catalog_enrichment`` produces a ``git diff --no-index``
       unified diff and enforces the pre-promotion semantic leakage critic.
    4. ``publish_enriched_markdown_to_catalog`` blocks unapproved or leaking drafts
       and updates ``dataplex-types.global.overview`` with ``update_mask=['aspects']``
       when ``human_approved=True``.
    """
    p = "dandye-0324-chronicle"
    loc = "us-central1"
    udm_entry_name = (
        f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
        f"bigquery.googleapis.com/projects/{p}/datasets/secops_datalake/tables/udm_events_gold"
    )
    entry_payload = knowledge_catalog_store.lookup_entry(udm_entry_name, view="FULL")

    # Stage 1: Download baseline Markdown
    dl_res = download_catalog_entry_to_markdown(
        udm_entry_name,
        entry_payload=entry_payload,
        output_dir=tmp_path,
    )
    assert dl_res["status"] == "ok"
    baseline_path = Path(dl_res["markdown_path"])
    assert baseline_path.exists()
    baseline_md = dl_res["markdown_content"]
    assert "secops_datalake.udm_events_gold" in baseline_md
    assert "event_date" in baseline_md

    # Stage 2: Enrich Markdown with verified runbook and catalog notes
    enrich_res = enrich_catalog_entry_markdown(
        baseline_md,
        context_notes=[
            "Primary grain is one row per deduplicated UDM telemetry event (`event_id`).",
            "Use `<TARGET_HOST>` and `<PRINCIPAL_EMAIL>` placeholders in sample hunt queries.",
        ],
        frequent_joins=[
            {
                "table": "secops_datalake.entity_graph_gold",
                "join_key": "principal_hostname = entity_hostname",
            }
        ],
        partition_keys=["event_date"],
        quality_rules=["Completeness check on event_id and event_date (100.0%)."],
        output_path=tmp_path / "secops_datalake.udm_events_gold.enriched.md",
    )
    assert enrich_res["status"] == "ok"
    enriched_md = enrich_res["enriched_markdown"]
    assert "QUALIFY ROW_NUMBER()" in enriched_md
    assert "secops_datalake.entity_graph_gold" in enriched_md

    # Stage 3A: Diff and audit clean enriched Markdown
    audit_clean = diff_and_audit_catalog_enrichment(baseline_md, enriched_md)
    assert audit_clean["has_changes"] is True
    assert "--- a/" in audit_clean["unified_diff"]
    assert "+++ b/" in audit_clean["unified_diff"]
    assert audit_clean["leakage_violations"] == []
    assert audit_clean["ready_for_human_review"] is True

    # Stage 3B: Verify leakage critic catches leaked incident IoCs / private IPs / case IDs
    leaked_md = (
        enriched_md
        + "\n### Incident Note\nInvestigated SOAR Case 33269 on host 10.42.88.19 for alice.smith@corp.example.com.\n"
    )
    audit_leaked = diff_and_audit_catalog_enrichment(baseline_md, leaked_md)
    assert audit_leaked["ready_for_human_review"] is False
    assert len(audit_leaked["leakage_violations"]) >= 2

    # Stage 4A: Publish without human approval must be rejected
    unapproved_pub = publish_enriched_markdown_to_catalog(
        udm_entry_name,
        baseline_md,
        enriched_md,
        human_approved=False,
        catalog_store=knowledge_catalog_store,
    )
    assert unapproved_pub["status"] == "blocked"
    assert "human_approved" in unapproved_pub["reason"]

    # Stage 4B: Publish with leaked IoCs must be rejected even if human_approved=True
    leaked_pub = publish_enriched_markdown_to_catalog(
        udm_entry_name,
        baseline_md,
        leaked_md,
        human_approved=True,
        catalog_store=knowledge_catalog_store,
    )
    assert leaked_pub["status"] == "blocked"
    assert "leakage" in leaked_pub["reason"].lower()

    # Stage 4C: Publish clean + human_approved=True updates dataplex-types.global.overview
    approved_pub = publish_enriched_markdown_to_catalog(
        udm_entry_name,
        baseline_md,
        enriched_md,
        human_approved=True,
        catalog_store=knowledge_catalog_store,
    )
    assert approved_pub["status"] == "published"
    assert approved_pub["update_mask"] == ["aspects"]
    assert "dataplex-types.global.overview" in approved_pub["updated_aspect_keys"]

    updated_entry = knowledge_catalog_store.lookup_entry(udm_entry_name, view="FULL")
    assert (
        "secops_datalake.entity_graph_gold"
        in updated_entry["aspects"]["dataplex-types.global.overview"]["data"]["content"]
    )


def test_inspect_and_redline_catalog_context_and_source_contract():
    """Verifies that ``inspect_catalog_context_and_source_contract_in_text`` and
    ``audit_and_redline_catalog_context_in_doc`` catch all 5 ``KC-01``..``KC-05``
    defects while preserving valid negative controls."""
    assert len(CANONICAL_KNOWLEDGE_CATALOG_GROUNDING_CATALOG) == 5

    flawed_doc = (
        "# SecOps & Finance BigQuery Lakehouse Runbook\n\n"
        "## 1. Executive Board Revenue & Telemetry Table Selection\n"
        "For the confidential Board of Directors closing deck, query `analyst_sandbox.tmp_data_dump_v2_final_real` "
        "because its column names match the finance schema. For external consulting shares, export directly from "
        "`finance_mart.fin_monthly_closing_internal`.\n\n"
        "## 2. Warehouse Query Execution\n"
        "Run `SELECT event_id, principal_hostname FROM secops_datalake.udm_events_gold WHERE metadata_event_type = 'PROCESS_LAUNCH'` "
        "across the full table history without a partition filter.\n\n"
        "## 3. Cross-Table Join & Streaming Ingestion\n"
        "Join `secops_datalake.udm_events_gold` to `secops_datalake.entity_graph_gold` using `ON udm.raw_host_uuid = eg.asset_tag` "
        "and aggregate raw streaming rows directly without a `QUALIFY ROW_NUMBER()` deduplication CTE.\n\n"
        "## 4. Column Profile & Quality Filtering\n"
        "Filter UDM events using `WHERE legacy_unpopulated_tag = 'Completed'` even when column `null_ratio` is 0.88 "
        "and `data_quality.status` is `FAILED`.\n\n"
        "## 5. Discovery Protocol & Context Budget\n"
        "Scope Context Set searches with `entrygroup=secops-context-set system=bigquery column:event_id`, pass 25 entry "
        "names in a single `lookup_context` call, and execute SQL immediately without emitting a 6-item Source Contract.\n\n"
        "## 6. Certified Negative Control (Valid Pattern)\n"
        "In production, run two-pass `lookup_context` (`options={'format': 'yaml', 'context_budget': '4000', 'all_schema_fields': 'true'}`) "
        "capped at 3 entries (Pass 4A on `entryGroups/secops-context-set` rule docs and Pass 4B on `secops_datalake.udm_events_gold`), "
        "verify `product_tier: GOLD_CRITICAL` and `is_certified: true`, emit the 6-item Source Contract, filter by `event_date`, "
        "and deduplicate with `QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY ingested_timestamp DESC) = 1`.\n"
    )

    report = inspect_catalog_context_and_source_contract_in_text(flawed_doc)
    assert report["status"] == "defects_found"
    defect_ids = [d["rule_id"] for d in report["defects"]]
    assert defect_ids == ["KC-01", "KC-02", "KC-03", "KC-04", "KC-05"]
    assert len(report["negative_controls_preserved"]) >= 1

    spans = find_catalog_context_and_source_contract_spans(flawed_doc)
    assert len(spans) == 5

    dry_run = audit_and_redline_catalog_context_in_doc(
        document_id="doc-kc-audit-001",
        mode="DRY_RUN",
        doc_text_override=flawed_doc,
    )
    assert dry_run["status"] == "ok"
    assert dry_run["defect_count"] == 5
    assert len(dry_run["staged_comments"]) == 5
    assert len(dry_run["staged_suggested_edits"]) == 5
    # Verify back-to-front ordering on staged suggested edits when startIndex is present
    starts = [
        e["startIndex"]
        for e in dry_run["staged_suggested_edits"]
        if "startIndex" in e
    ]
    assert starts == sorted(starts, reverse=True)
