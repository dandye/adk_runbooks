"""Closed-loop agentic metadata enrichment tools for Google Cloud Knowledge Catalog.

Implements the 4-stage human-in-the-loop (HITL) enrichment lifecycle from
Google Cloud's ``dataplex-SavedQueries-to-Catalog`` workflow combined with a
Pre-Promotion Semantic Leakage Critic:

1. ``download_catalog_entry_to_markdown`` — Exports a Knowledge Catalog entry
   (``lookup_entry(view='FULL')``) into a local ``<dataset>.<table>.md`` baseline.
2. ``enrich_catalog_entry_markdown`` — Synthesizes ``<dataset>.<table>.enriched.md``
   combining existing entry metadata with verified join keys, partition pruning
   guidelines, deduplication idioms, and data quality expectations.
3. ``diff_and_audit_catalog_enrichment`` — Computes a ``git diff --no-index``
   unified diff and enforces the pre-promotion semantic leakage critic to ensure
   no incident-specific IoCs (SOAR case IDs, private IPs, unparameterized user
   emails, or bearer tokens) leak into shared catalog aspects.
4. ``publish_enriched_markdown_to_catalog`` — Updates ``dataplex-types.global.overview``
   with ``update_mask=['aspects']`` only when ``human_approved=True`` and zero
   leakage violations exist.
"""

from __future__ import annotations

import difflib
from pathlib import Path
import re
from typing import Any


_LEAKED_CASE_ID_RE = re.compile(
    r"(?i)\b(?:soar\s+case|case|incident|ticket)\s*#?\s*\d{3,}\b"
)
_LEAKED_RFC1918_IPV4_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)
_LEAKED_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_LEAKED_TOKEN_RE = re.compile(
    r"\b(?:ya29\.[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{35})\b"
)


def _derive_short_table_name(
    entry_name: str, entry_payload: dict[str, Any] | None = None
) -> str:
    """Extracts ``<dataset>.<table>`` from ``fully_qualified_name``, ``displayName``, or ``entry_name``."""
    fqn = ""
    display_name = ""
    if isinstance(entry_payload, dict):
        fqn = str(
            entry_payload.get("fully_qualified_name")
            or entry_payload.get("fullyQualifiedName")
            or ""
        ).strip()
        es = dict(
            entry_payload.get("entry_source")
            or entry_payload.get("entrySource")
            or {}
        )
        display_name = str(
            es.get("display_name") or es.get("displayName") or ""
        ).strip()
    if fqn.startswith("bigquery:"):
        raw = fqn.split("bigquery:", 1)[1]
        parts = [p for p in raw.split(".") if p]
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return raw
    if "." in display_name and " " not in display_name:
        return display_name
    m = re.search(r"/datasets/([^/]+)/tables/([^/]+)$", str(entry_name or ""))
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    tail = str(entry_name or "catalog_entry").rstrip("/").split("/")[-1]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", tail) or "catalog_entry"


def _find_aspect_data(aspects: dict[str, Any], suffix: str) -> dict[str, Any]:
    """Finds aspect ``data`` by exact key or suffix (handling both ``dataplex-types.global.*``
    and live project-number ``655216118709.global.*`` aspect keys)."""
    for key, val in aspects.items():
        if key == suffix or key.endswith(f".{suffix}"):
            if isinstance(val, dict):
                return dict(val.get("data") or {})
    return {}


def download_catalog_entry_to_markdown(
    entry_name: str,
    *,
    entry_payload: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
    catalog_store: Any = None,
    live_dataplex: bool = False,
    quota_project: str | None = None,
) -> dict[str, Any]:
    """Stage 1: Exports a Knowledge Catalog entry (``view='FULL'`` / ``view='ALL'``)
    to a structured baseline Markdown file ``<dataset>.<table>.md``.
    """
    payload = entry_payload
    if payload is None and catalog_store is not None and hasattr(catalog_store, "lookup_entry"):
        payload = catalog_store.lookup_entry(entry_name, view="FULL")
    elif payload is None and live_dataplex:
        import httpx  # pylint: disable=import-outside-toplevel
        from .grounding_tools import knowledge_catalog_headers  # pylint: disable=import-outside-toplevel

        headers = knowledge_catalog_headers(quota_project=quota_project)
        resp = httpx.get(
            f"https://dataplex.googleapis.com/v1/{entry_name}",
            params={"view": "ALL"},
            headers=headers,
            timeout=30.0,
        )
        resp.raise_for_status()
        payload = resp.json()
    payload = dict(payload or {})

    short_name = _derive_short_table_name(entry_name, payload)
    entry_source = dict(
        payload.get("entry_source") or payload.get("entrySource") or {}
    )
    description = str(
        entry_source.get("description")
        or payload.get("description")
        or "Curated Knowledge Catalog asset."
    )
    aspects = dict(payload.get("aspects") or {})

    overview_content = _find_aspect_data(aspects, "global.overview").get("content", "")
    schema_fields = _find_aspect_data(aspects, "global.schema").get("fields", [])
    bq_table_spec = _find_aspect_data(aspects, "global.bigquery-table-spec")
    gov_data = (
        _find_aspect_data(aspects, "secops-store-governance")
        or _find_aspect_data(aspects, "official-data-product-spec")
    )

    lines: list[str] = [
        f"# {short_name}",
        "",
        f"- **Entry Resource Name**: `{entry_name}`",
        f"- **Description**: {description}",
        "",
        "## Overview",
        overview_content or description,
        "",
        "## Schema Fields",
    ]
    if schema_fields:
        for field in schema_fields:
            f_name = field.get("name", "unknown")
            f_type = field.get("dataType") or field.get("type") or "STRING"
            f_mode = field.get("mode", "NULLABLE")
            f_desc = field.get("description", "")
            lines.append(f"- `{f_name}` ({f_type}, {f_mode}): {f_desc}")
    else:
        lines.append("- *(No schema fields recorded)*")

    if gov_data:
        lines.extend(["", "## Governance & Store Aspect"])
        for k, v in sorted(gov_data.items()):
            lines.append(f"- **{k}**: `{v}`")

    if bq_table_spec:
        lines.extend(
            [
                "",
                "## Table Specification",
                f"- **Time Partitioning**: `{bq_table_spec.get('time_partitioning', {})}`",
                f"- **Clustering Fields**: `{bq_table_spec.get('clustering_fields', [])}`",
                f"- **Guidelines**: {bq_table_spec.get('guidelines', '')}",
            ]
        )

    markdown_content = "\n".join(lines).rstrip() + "\n"
    markdown_path: Path | None = None
    if output_dir is not None:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        markdown_path = out_dir / f"{short_name}.md"
        markdown_path.write_text(markdown_content, encoding="utf-8")

    return {
        "status": "ok",
        "entry_name": entry_name,
        "short_table_name": short_name,
        "markdown_path": str(markdown_path) if markdown_path else None,
        "markdown_content": markdown_content,
    }


def enrich_catalog_entry_markdown(
    baseline_markdown: str,
    *,
    context_notes: list[str] | None = None,
    frequent_joins: list[dict[str, Any]] | None = None,
    partition_keys: list[str] | None = None,
    quality_rules: list[str] | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Stage 2: Synthesizes an enriched Markdown draft combining the baseline catalog
    entry with verified domain notes, ``frequent_joins``, partition pruning &
    deduplication guidelines, and data quality assertions.
    """
    base = str(baseline_markdown or "").rstrip()
    section_lines: list[str] = [
        base,
        "",
        "## Enriched Agentic Data Context",
        "",
        "### Business Definitions & Context Notes",
    ]
    for note in context_notes or []:
        section_lines.append(f"- {note}")
    if not context_notes:
        section_lines.append("- Parameterized semantic context verified for agent grounding.")

    section_lines.extend(["", "### Recommended Frequent Joins"])
    for join_spec in frequent_joins or []:
        target_tbl = join_spec.get("table", "unknown_table")
        join_key = join_spec.get("join_key", "")
        section_lines.append(f"- Join `{target_tbl}` on `{join_key}`")
    if not frequent_joins:
        section_lines.append("- *(No frequent joins specified)*")

    part_list = list(partition_keys or [])
    section_lines.extend(["", "### Partition Pruning & Deduplication Guidelines"])
    if part_list:
        section_lines.append(
            f"- **Mandatory Partition Filter**: Always include a `WHERE` predicate on `{', '.join(part_list)}`."
        )
    section_lines.append(
        "- **Streaming Deduplication CTE**: Deduplicate raw streaming rows with "
        "`QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY ingested_timestamp DESC) = 1`."
    )

    section_lines.extend(["", "### Data Quality Rules"])
    for rule in quality_rules or []:
        section_lines.append(f"- {rule}")
    if not quality_rules:
        section_lines.append("- Verify `data_quality.status == 'PASSED'` prior to production reporting.")

    enriched_markdown = "\n".join(section_lines).rstrip() + "\n"
    out_file: Path | None = None
    if output_path is not None:
        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(enriched_markdown, encoding="utf-8")

    return {
        "status": "ok",
        "enriched_markdown": enriched_markdown,
        "output_path": str(out_file) if out_file else None,
    }


def diff_and_audit_catalog_enrichment(
    baseline_markdown: str,
    enriched_markdown: str,
    *,
    filename: str = "catalog_entry.md",
) -> dict[str, Any]:
    """Stage 3: Generates a ``git diff --no-index``-compatible unified diff between
    ``baseline_markdown`` and ``enriched_markdown`` and executes the Pre-Promotion
    Semantic Leakage Critic.
    """
    base_lines = str(baseline_markdown or "").splitlines(keepends=True)
    enriched_lines = str(enriched_markdown or "").splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            base_lines,
            enriched_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )
    unified_diff = "".join(diff_lines)
    has_changes = bool(unified_diff.strip())

    leakage_violations: list[dict[str, str]] = []
    text_to_scan = str(enriched_markdown or "")

    for m in _LEAKED_CASE_ID_RE.finditer(text_to_scan):
        leakage_violations.append(
            {
                "violation_type": "leaked_incident_or_case_id",
                "matched_text": m.group(0),
                "remediation": "Replace specific SOAR case/ticket numbers with parameterized placeholders such as `<CASE_ID>`.",
            }
        )
    for m in _LEAKED_RFC1918_IPV4_RE.finditer(text_to_scan):
        leakage_violations.append(
            {
                "violation_type": "leaked_private_ipv4_ioc",
                "matched_text": m.group(0),
                "remediation": "Replace customer-specific RFC1918 IP addresses with `<TARGET_IP>` or `<PRINCIPAL_IP>`.",
            }
        )
    for m in _LEAKED_EMAIL_RE.finditer(text_to_scan):
        leakage_violations.append(
            {
                "violation_type": "leaked_user_email_pii",
                "matched_text": m.group(0),
                "remediation": "Replace literal user email addresses with `<PRINCIPAL_EMAIL>`.",
            }
        )
    for m in _LEAKED_TOKEN_RE.finditer(text_to_scan):
        leakage_violations.append(
            {
                "violation_type": "leaked_credential_token",
                "matched_text": m.group(0),
                "remediation": "Never embed bearer tokens or API keys in Knowledge Catalog aspects.",
            }
        )

    ready_for_human_review = bool(has_changes and len(leakage_violations) == 0)
    return {
        "status": "ok",
        "has_changes": has_changes,
        "unified_diff": unified_diff,
        "leakage_violations": leakage_violations,
        "ready_for_human_review": ready_for_human_review,
    }


def publish_enriched_markdown_to_catalog(
    entry_name: str,
    baseline_markdown: str,
    enriched_markdown: str,
    *,
    human_approved: bool = False,
    catalog_store: Any = None,
    live_dataplex: bool = False,
    quota_project: str | None = None,
) -> dict[str, Any]:
    """Stage 4: Publishes the enriched Markdown into the Knowledge Catalog entry's
    ``dataplex-types.global.overview`` / ``655216118709.global.overview`` aspect
    using ``update_mask=['aspects']`` only after passing the Pre-Promotion
    Semantic Leakage Critic and verifying ``human_approved=True``.
    """
    audit = diff_and_audit_catalog_enrichment(baseline_markdown, enriched_markdown)
    if audit["leakage_violations"]:
        return {
            "status": "blocked",
            "entry_name": entry_name,
            "reason": (
                "Blocked by Pre-Promotion Semantic Leakage Critic: enriched Markdown "
                f"contains {len(audit['leakage_violations'])} leaked IoC/PII token(s)."
            ),
            "leakage_violations": audit["leakage_violations"],
        }

    if not human_approved:
        return {
            "status": "blocked",
            "entry_name": entry_name,
            "reason": (
                "Publishing to Knowledge Catalog requires explicit human_approved=True "
                "after reviewing the unified diff."
            ),
            "unified_diff": audit["unified_diff"],
        }

    aspect_key = "dataplex-types.global.overview"
    aspect_patch = {
        aspect_key: {
            "aspect_type": "projects/dataplex-types/locations/global/aspectTypes/overview",
            "data": {
                "content": str(enriched_markdown),
            },
        }
    }
    update_mask = ["aspects"]

    updated_entry: dict[str, Any] = {}
    if catalog_store is not None:
        if hasattr(catalog_store, "update_entry"):
            updated_entry = catalog_store.update_entry(
                entry_name=entry_name,
                overview_content=str(enriched_markdown),
                update_mask=update_mask,
            )
        elif hasattr(catalog_store, "update_entry_aspects"):
            updated_entry = catalog_store.update_entry_aspects(
                entry_name=entry_name,
                aspects=aspect_patch,
                update_mask=update_mask,
            )
    elif live_dataplex:
        import httpx  # pylint: disable=import-outside-toplevel
        from .grounding_tools import knowledge_catalog_headers  # pylint: disable=import-outside-toplevel

        live_aspect_key = "655216118709.global.overview"
        headers = knowledge_catalog_headers(quota_project=quota_project)
        headers["Content-Type"] = "application/json"
        resp = httpx.patch(
            f"https://dataplex.googleapis.com/v1/{entry_name}",
            params={
                "updateMask": "aspects",
                "aspectKeys": live_aspect_key,
            },
            headers=headers,
            json={
                "name": entry_name,
                "aspects": {
                    live_aspect_key: {
                        "aspectType": "projects/655216118709/locations/global/aspectTypes/overview",
                        "data": {
                            "content": str(enriched_markdown),
                        },
                    }
                },
            },
            timeout=30.0,
        )
        resp.raise_for_status()
        updated_entry = resp.json()
        return {
            "status": "published",
            "entry_name": entry_name,
            "update_mask": update_mask,
            "updated_aspect_keys": [aspect_key, live_aspect_key],
            "unified_diff": audit["unified_diff"],
            "entry": updated_entry,
        }

    return {
        "status": "published",
        "entry_name": entry_name,
        "update_mask": update_mask,
        "updated_aspect_keys": [aspect_key],
        "unified_diff": audit["unified_diff"],
        "entry": updated_entry,
    }


MULTI_ENGINE_SECOPS_INVESTIGATION_STORE_ENTRIES: tuple[dict[str, Any], ...] = (
    {
        "entry_id": "alloydb_secops_detection_reports",
        "entry_type_id": "alloydb-pgvector-table",
        "display_name": "alloydb.secops.detection_reports",
        "system": "ALLOYDB_POSTGRESQL",
        "resource": "//alloydb.googleapis.com/projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary/databases/postgres/tables/detection_reports",
        "description": "Primary AlloyDB for PostgreSQL (pgvector) table storing harvested Markdown security investigation reports, 768-dim Vertex AI embeddings, verdicts, entities, and triage steps.",
        "connection_uri": "projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary (host=34.70.211.60:5432, db=postgres)",
        "guidelines": "Use HNSW cosine distance (`embedding <=> $1::vector`) combined with GIN FTS (`to_tsvector`) and relational joins to `detection_alerts` and `detection_entities`.",
        "overview": (
            "# alloydb.secops.detection_reports\n\n"
            "Primary AlloyDB for PostgreSQL (`pgvector`) table storing full **Markdown security investigation reports** (`markdown_report`), "
            "768-dimensional Vertex AI dense embeddings (`embedding vector(768)`), structured JSONB entities/steps, and verdicts.\n\n"
            "## Multi-Modal Similarity Profiles\n"
            "- `balanced`: `semantic=0.35, entity=0.30, ttp=0.20, flow=0.10, time=0.05`\n"
            "- `threat-hunt`: `ttp=0.45, semantic=0.35, flow=0.10, time=0.05, entity=0.05`\n"
            "- `compromise-pivot`: `entity=0.45, time=0.30, semantic=0.15, flow=0.05, ttp=0.05`\n"
            "- `false-positive`: `entity=0.40, ttp=0.25, semantic=0.20, flow=0.10, time=0.05`\n"
            "- `semantic`: `semantic=0.60, flow=0.15, ttp=0.15, entity=0.05, time=0.05`\n\n"
            "## Frequent Joins\n"
            "- Join `alloydb.secops.detection_alerts` on `detection_reports.id = detection_alerts.investigation_id`\n"
            "- Join `alloydb.secops.detection_entities` on `detection_reports.id = detection_entities.investigation_id`\n"
        ),
        "schema": [
            {"name": "id", "dataType": "VARCHAR(64)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Primary key investigation report ID."},
            {"name": "display_name", "dataType": "TEXT", "metadataType": "STRING", "mode": "REQUIRED", "description": "Human-readable investigation title (indexed in GIN FTS)."},
            {"name": "verdict", "dataType": "VARCHAR(32)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Analyst/agent verdict (TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, SUSPICIOUS)."},
            {"name": "confidence", "dataType": "VARCHAR(32)", "metadataType": "STRING", "mode": "NULLABLE", "description": "Confidence level (HIGH, MEDIUM, LOW)."},
            {"name": "summary", "dataType": "TEXT", "metadataType": "STRING", "mode": "NULLABLE", "description": "Executive summary of the investigation (indexed in GIN FTS)."},
            {"name": "alert_ids", "dataType": "TEXT[]", "metadataType": "STRING", "mode": "REPEATED", "description": "Array of linked Chronicle/SOAR alert IDs (GIN indexed)."},
            {"name": "investigation_steps", "dataType": "JSONB", "metadataType": "STRING", "mode": "NULLABLE", "description": "Structured JSONB array of executed investigation steps."},
            {"name": "entities", "dataType": "JSONB", "metadataType": "STRING", "mode": "NULLABLE", "description": "GIN-indexed JSONB array of involved hosts, users, IPs, files, and domains."},
            {"name": "markdown_report", "dataType": "TEXT", "metadataType": "STRING", "mode": "NULLABLE", "description": "Full Markdown investigation report text."},
            {"name": "embedding", "dataType": "VECTOR(768)", "metadataType": "NUMBER", "mode": "REPEATED", "description": "768-dimensional Vertex AI text embedding indexed with HNSW (vector_cosine_ops)."},
        ],
    },
    {
        "entry_id": "alloydb_secops_detection_alerts",
        "entry_type_id": "alloydb-pgvector-table",
        "display_name": "alloydb.secops.detection_alerts",
        "system": "ALLOYDB_POSTGRESQL",
        "resource": "//alloydb.googleapis.com/projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary/databases/postgres/tables/detection_alerts",
        "description": "AlloyDB relational child table linking Chronicle SIEM / SOAR alerts and MITRE ATT&CK tactics/techniques to Markdown investigation reports.",
        "connection_uri": "projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary (host=34.70.211.60:5432, db=postgres)",
        "guidelines": "Join to `detection_reports` on `detection_alerts.investigation_id = detection_reports.id`. Filter by `alert_id` or `mitre_techniques` overlap (`&&`).",
        "overview": (
            "# alloydb.secops.detection_alerts\n\n"
            "Relational child table linking Chronicle SIEM / SOAR alerts (`alert_id`) and MITRE ATT&CK arrays (`mitre_tactics`, `mitre_techniques`) "
            "to parent Markdown investigation reports in `detection_reports` via `investigation_id`."
        ),
        "schema": [
            {"name": "id", "dataType": "SERIAL", "metadataType": "NUMBER", "mode": "REQUIRED", "description": "Surrogate primary key."},
            {"name": "alert_id", "dataType": "VARCHAR(128)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Chronicle SIEM or SOAR alert identifier (indexed)."},
            {"name": "investigation_id", "dataType": "VARCHAR(64)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Foreign key referencing detection_reports(id) ON DELETE CASCADE."},
            {"name": "severity", "dataType": "VARCHAR(32)", "metadataType": "STRING", "mode": "NULLABLE", "description": "Alert severity (CRITICAL, HIGH, MEDIUM, LOW)."},
            {"name": "mitre_tactics", "dataType": "TEXT[]", "metadataType": "STRING", "mode": "REPEATED", "description": "Array of MITRE ATT&CK tactic names/IDs."},
            {"name": "mitre_techniques", "dataType": "TEXT[]", "metadataType": "STRING", "mode": "REPEATED", "description": "Array of MITRE ATT&CK technique IDs (e.g. T1059.001)."},
        ],
    },
    {
        "entry_id": "alloydb_secops_detection_entities",
        "entry_type_id": "alloydb-pgvector-table",
        "display_name": "alloydb.secops.detection_entities",
        "system": "ALLOYDB_POSTGRESQL",
        "resource": "//alloydb.googleapis.com/projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary/databases/postgres/tables/detection_entities",
        "description": "AlloyDB relational child table indexing extracted entities (Host, User, IP, File, Domain) and GTI threat intelligence per Markdown investigation report.",
        "connection_uri": "projects/secops-demo-env/locations/us-central1/clusters/secops-alloydb-cluster/instances/secops-alloydb-primary (host=34.70.211.60:5432, db=postgres)",
        "guidelines": "Use composite index `(entity_type, entity_value)` for compromise-pivot lookups and join `investigation_id = detection_reports.id`.",
        "overview": (
            "# alloydb.secops.detection_entities\n\n"
            "Relational child table storing normalized indicators and entities (`entity_type`, `entity_value`) and GTI enrichment (`threat_intel`) "
            "extracted from harvested Markdown investigation reports."
        ),
        "schema": [
            {"name": "id", "dataType": "SERIAL", "metadataType": "NUMBER", "mode": "REQUIRED", "description": "Surrogate primary key."},
            {"name": "investigation_id", "dataType": "VARCHAR(64)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Foreign key referencing detection_reports(id) ON DELETE CASCADE."},
            {"name": "entity_type", "dataType": "VARCHAR(32)", "metadataType": "STRING", "mode": "REQUIRED", "description": "Entity domain type (HOST, USER, IP, FILE, DOMAIN)."},
            {"name": "entity_value", "dataType": "TEXT", "metadataType": "STRING", "mode": "REQUIRED", "description": "Normalized entity identifier (indexed with entity_type)."},
            {"name": "threat_intel", "dataType": "JSONB", "metadataType": "STRING", "mode": "NULLABLE", "description": "GTI / VirusTotal enrichment JSONB object."},
        ],
    },
    {
        "entry_id": "neo4j_secops_knowledge_graph",
        "entry_type_id": "neo4j-knowledge-graph",
        "display_name": "neo4j.secops.knowledge_graph",
        "system": "NEO4J",
        "resource": "//neo4j.secops.internal/instances/34.85.131.164:7687/databases/neo4j/graphs/knowledge_graph",
        "description": "Neo4j 5.20 Cypher property graph linking Investigation reports, Alerts, Cases, Hosts, Users, Files, Domains, and NetworkAddresses.",
        "connection_uri": "bolt://34.85.131.164:7687 (container: neo4j_soc, image: neo4j:5.20.0-community)",
        "guidelines": "Query `Host`, `User`, `File`, `Domain`, and `NetworkAddress` nodes by `.name` (without `user:`/`host:` prefix) and `Investigation`/`Alert`/`Case` nodes by `.id`.",
        "overview": (
            "# neo4j.secops.knowledge_graph\n\n"
            "Neo4j 5.20 Cypher property graph ingested from `investigations/knowledge_graph.json` (`manage_neo4j.py`).\n\n"
            "## Node Labels & Uniqueness Keys\n"
            "- `(:Investigation {id})`, `(:Alert {id})`, `(:Case {id})`\n"
            "- `(:Host {name})`, `(:User {name})`, `(:File {name})`, `(:Domain {name})`, `(:NetworkAddress {name})`\n"
        ),
        "schema": [
            {"name": "Investigation", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "Investigation node constrained on unique `id` (`investigation_id_unique`)."},
            {"name": "Alert", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "Alert node constrained on unique `id` (`alert_id_unique`)."},
            {"name": "Case", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "SOAR Case node constrained on unique `id` (`case_id_unique`)."},
            {"name": "Host", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "Endpoint/server node constrained on unique `name` (`host_id_unique`)."},
            {"name": "User", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "Identity/account node constrained on unique `name` (`user_id_unique`)."},
            {"name": "File", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "File/hash artifact node constrained on unique `name` (`file_id_unique`)."},
            {"name": "Domain", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "DNS domain node constrained on unique `name` (`domain_id_unique`)."},
            {"name": "NetworkAddress", "dataType": "NODE_LABEL", "metadataType": "STRING", "mode": "REQUIRED", "description": "IPv4/IPv6 address node constrained on unique `name` (`networkaddress_id_unique`)."},
            {"name": "INVOLVES", "dataType": "RELATIONSHIP_TYPE", "metadataType": "STRING", "mode": "NULLABLE", "description": "Directed edge connecting (`Investigation` | `Alert` | `Case`) -> (`Host` | `User` | `File` | `Domain` | `NetworkAddress`)."},
        ],
    },
    {
        "entry_id": "elasticsearch_agentic_soc_runbooks",
        "entry_type_id": "elasticsearch-bm25-index",
        "display_name": "elasticsearch.secops.agentic_soc_runbooks",
        "system": "ELASTICSEARCH",
        "resource": "//elasticsearch.secops.internal/clusters/34.145.140.152:9200/indices/agentic-soc-runbooks",
        "description": "Elasticsearch BM25 full-text index storing section-chunked Markdown investigation reports (`investigations/*.md`) and operational SOC runbooks (`rules_bank/run_books/**`).",
        "connection_uri": "http://34.145.140.152:9200/agentic-soc-runbooks",
        "guidelines": "Use `multi_match` on `['title^2', 'content']` for BM25 retrieval and filter or group by `doc_path` (`keyword`) to reconstruct full Markdown documents ordered by `chunk_index`.",
        "overview": (
            "# elasticsearch.secops.agentic_soc_runbooks\n\n"
            "Elasticsearch BM25 index (`agentic-soc-runbooks`) managed by `manage_elasticsearch.py`, indexing section-aware chunks (`max_chunk_size=3000`, `overlap=300`) "
            "from `investigations/*.md` and `rules_bank/run_books/`."
        ),
        "schema": [
            {"name": "title", "dataType": "TEXT", "metadataType": "STRING", "mode": "REQUIRED", "description": "Markdown section heading title (`standard` analyzer)."},
            {"name": "doc_name", "dataType": "KEYWORD", "metadataType": "STRING", "mode": "REQUIRED", "description": "Exact Markdown filename (`keyword` mapping)."},
            {"name": "doc_path", "dataType": "KEYWORD", "metadataType": "STRING", "mode": "REQUIRED", "description": "Relative repository path to the Markdown report or runbook (`keyword` mapping)."},
            {"name": "content", "dataType": "TEXT", "metadataType": "STRING", "mode": "REQUIRED", "description": "Section-chunked Markdown body (`max_chunk_size=3000`, `overlap=300`, `standard` analyzer)."},
            {"name": "chunk_index", "dataType": "INTEGER", "metadataType": "NUMBER", "mode": "REQUIRED", "description": "0-based sequential chunk index within `doc_path`."},
        ],
    },
)


def register_multi_engine_investigation_stores_in_catalog(
    *,
    project_id: str = "dandye-0324-chronicle",
    location: str = "us-central1",
    entry_group_id: str = "secops-investigation-stores",
    catalog_store: Any = None,
) -> dict[str, Any]:
    """Registers the 5 multi-engine SecOps investigation & runbook stores
    (AlloyDB ``detection_reports`` / ``detection_alerts`` / ``detection_entities``,
    Neo4j ``knowledge_graph``, and Elasticsearch ``agentic_soc_runbooks``) in a
    Knowledge Catalog custom entry group.
    """
    registered_entry_names: list[str] = []
    for spec in MULTI_ENGINE_SECOPS_INVESTIGATION_STORE_ENTRIES:
        entry_name = (
            f"projects/{project_id}/locations/{location}/entryGroups/"
            f"{entry_group_id}/entries/{spec['entry_id']}"
        )
        registered_entry_names.append(entry_name)
        if catalog_store is not None and hasattr(catalog_store, "upsert_custom_entry"):
            catalog_store.upsert_custom_entry(
                entry_name=entry_name,
                spec=spec,
            )

    return {
        "status": "ok",
        "project_id": project_id,
        "location": location,
        "entry_group": f"projects/{project_id}/locations/{location}/entryGroups/{entry_group_id}",
        "registered_count": len(registered_entry_names),
        "registered_entries": registered_entry_names,
    }


__all__ = [
    "MULTI_ENGINE_SECOPS_INVESTIGATION_STORE_ENTRIES",
    "diff_and_audit_catalog_enrichment",
    "download_catalog_entry_to_markdown",
    "enrich_catalog_entry_markdown",
    "publish_enriched_markdown_to_catalog",
    "register_multi_engine_investigation_stores_in_catalog",
]
