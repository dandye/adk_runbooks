---
type: Skill
title: "Skill: knowledge-catalog-governance"
name: knowledge-catalog-governance
description: "Use when discovering BigQuery or Chronicle datalake tables in Google Cloud Knowledge Catalog, verifying governance aspects and lookupContext metadata, or generating a Pre-SQL Source Contract before executing warehouse queries."
category: hunting
version: 1.0.0
generated:
  by: okf-agent/gemini-2.5-pro
  at: "2026-10-13T19:50:00Z"
metadata:
  adk_additional_tools:
    - kcatalog_search_entries
    - kcatalog_lookup_context
    - kcatalog_lookup_entry
---

# Knowledge Catalog Governance and Two-Pass Context Grounding

## Overview

Before generating or executing any BigQuery SQL or Chronicle datalake query, you MUST ground table selection, schema fields, join paths, partitioning keys, and deduplication rules against **Google Cloud Knowledge Catalog** (`https://dataplex.googleapis.com/mcp`).

Never guess table names or rely on raw `INFORMATION_SCHEMA` column names when certified data products and unverified sandbox tables share identical schemas.

---

## Phase 1: Five-Step Two-Pass Discovery Protocol

1. **Step 1 — Three-Way Semantic Decomposition**:
   - Decompose the analytical or hunting question into three distinct semantic search variations:
     - *Variation 1 (Core Entities)*: Primary telemetry objects or business entities (e.g., `UDM process launch endpoint`).
     - *Variation 2 (Metrics & Grain)*: Target aggregations, grain, or compliance scope (e.g., `monthly closing revenue GAAP` or `deduplicated event_id`).
     - *Variation 3 (Domain Synonyms)*: Alternate catalog terminology and glossary synonyms.

2. **Step 2 — Four-Way Parallel Discovery Search**:
   - Invoke `search_entries` (`semantic_search=True`, `page_size=50`) across the 3 semantic variations plus a 4th dedicated query for `entrygroup.type=context-set`.

3. **Step 3 — Filter-Free Scoped Context Set Search**:
   - When a relevant Context Set entry group (`projects/{project}/locations/{location}/entryGroups/{context_set_id}`) is discovered, execute 3 scoped `search_entries` calls using `entrygroup=projects/{project}/locations/{location}/entryGroups/{context_set_id} (<variation>)`.
   - **CRITICAL**: Do NOT include `system=`, `type=`, or `column:` filters in scoped Context Set searches, as those table-specific qualifiers filter out unstructured rule documents and golden SQL entries inside the Context Set.

4. **Step 4 — Two-Pass `lookup_context` (Hard Cap of 3 Entries)**:
   - Always pass `options={"format": "yaml", "context_budget": "4000", "all_schema_fields": "true"}` (and never exceed 10 resources in any single `lookupContext` request).
   - **Pass 4A (Rules Pass)**: Call `lookup_context` on up to 2 Context Set child rule entries (`entryGroups/{context_set_id}/entries/{doc_id}`) to extract golden SQL templates, mandatory `WHERE` filters, and deduplication rules.
   - **Pass 4B (Candidate Pass)**: Call `lookup_context` on the single highest-scoring candidate table entry (`entryGroups/@bigquery/entries/...`) and verify all 6 metadata dimensions:
     1. *Technical metadata*: Column names, types, modes, `usage.partitionBy`, and `usage.clusterBy`.
     2. *Operational metadata*: `frequent_joins` (`EntryLinks` mined from `Query history` or `Data insights`).
     3. *Business descriptions & Governance Aspects*: Glossary `terms`, `overview`, `guidelines`, and custom governance aspect fields (`product_tier`: `GOLD_CRITICAL` / `SILVER_STANDARD` / `BRONZE_ADHOC`, `usage_scope`: `INTERNAL_ONLY` / `EXTERNAL_READY`, `update_frequency`: `DAILY_BATCH` / `REALTIME_STREAMING`, `is_certified`: `true` / `false`).
     4. *Data profile*: Column `null_ratio`, `distinct_values`, and `sample_values`.
     5. *Data quality*: Automated scan `data_quality.status` (`PASSED` vs. `FAILED`) and rule descriptions.
     6. *Related data assets*: 1-hop `relatedResources` (respecting dynamic source-system IAM post-filtering).

5. **Step 5 — Mandatory 6-Item Pre-SQL Source Contract**:
   - Before outputting or executing any SQL statement, emit the following 6-item **Source Contract**:
     1. **Selected Table & Certification Tier**: Full resource name, `product_tier`, `usage_scope`, `update_frequency`, and `is_certified` status.
     2. **Grain & Primary Key**: Exact row grain and primary key column(s).
     3. **Join Path & Origin**: Verified `join_key` and relationship origin (`Query history` or `Data insights`).
     4. **Partitioning & Deduplication Rules**: Mandatory partition pruning filter (`WHERE <partition_col> >= ...`) and inline deduplication CTE (`QUALIFY ROW_NUMBER() OVER (PARTITION BY <pk> ORDER BY <updated_at> DESC) = 1`).
     5. **Metric / Hunt Formula**: Exact aggregation or detection logic grounded in Context Set rules.
     6. **Data Quality & Null-Ratio Caveats**: Confirmation that `data_quality.status == PASSED` and filtered columns have acceptable `null_ratio` and matching `sample_values`.

---

## Phase 2: Query Execution & Closed-Loop Metadata Enrichment

- Execute SQL only after Phase 1 verification succeeds and all governance constraints match the user's intent (never use `BRONZE_ADHOC` / `is_certified: false` tables for executive or production reporting, and never expose `INTERNAL_ONLY` tables in external outputs).
- When tribal knowledge or new query guidelines are validated during an investigation, stage updates through the 4-stage human-gated metadata enrichment loop (`download_catalog_entry_to_markdown` -> `enrich_catalog_entry_markdown` -> `diff_and_audit_catalog_enrichment` -> `publish_enriched_markdown_to_catalog` with `update_mask=["aspects"]` onto `dataplex-types.global.overview`).
