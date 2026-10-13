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
    """Extracts ``<dataset>.<table>`` from ``fully_qualified_name`` or ``entry_name``."""
    fqn = ""
    if isinstance(entry_payload, dict):
        fqn = str(entry_payload.get("fully_qualified_name") or "").strip()
    if fqn.startswith("bigquery:"):
        raw = fqn.split("bigquery:", 1)[1]
        parts = [p for p in raw.split(".") if p]
        if len(parts) >= 2:
            return f"{parts[-2]}.{parts[-1]}"
        return raw
    m = re.search(r"/datasets/([^/]+)/tables/([^/]+)$", str(entry_name or ""))
    if m:
        return f"{m.group(1)}.{m.group(2)}"
    tail = str(entry_name or "catalog_entry").rstrip("/").split("/")[-1]
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", tail) or "catalog_entry"


def download_catalog_entry_to_markdown(
    entry_name: str,
    *,
    entry_payload: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
    catalog_store: Any = None,
) -> dict[str, Any]:
    """Stage 1: Exports a Knowledge Catalog entry (``view='FULL'``) to a structured
    baseline Markdown file ``<dataset>.<table>.md``.
    """
    payload = entry_payload
    if payload is None and catalog_store is not None and hasattr(catalog_store, "lookup_entry"):
        payload = catalog_store.lookup_entry(entry_name, view="FULL")
    payload = dict(payload or {})

    short_name = _derive_short_table_name(entry_name, payload)
    entry_source = dict(payload.get("entry_source") or {})
    description = str(
        entry_source.get("description")
        or payload.get("description")
        or "Curated Knowledge Catalog asset."
    )
    aspects = dict(payload.get("aspects") or {})

    overview_content = (
        aspects.get("dataplex-types.global.overview", {})
        .get("data", {})
        .get("content", "")
    )
    schema_fields = (
        aspects.get("dataplex-types.global.schema", {})
        .get("data", {})
        .get("fields", [])
    )
    bq_table_spec = (
        aspects.get("dataplex-types.global.bigquery-table-spec", {}).get("data", {})
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
            f_type = field.get("dataType", "STRING")
            f_mode = field.get("mode", "NULLABLE")
            f_desc = field.get("description", "")
            lines.append(f"- `{f_name}` ({f_type}, {f_mode}): {f_desc}")
    else:
        lines.append("- *(No schema fields recorded)*")

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
) -> dict[str, Any]:
    """Stage 4: Publishes the enriched Markdown into the Knowledge Catalog entry's
    ``dataplex-types.global.overview`` aspect using ``update_mask=['aspects']`` only
    after passing the Pre-Promotion Semantic Leakage Critic and verifying
    ``human_approved=True``.
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

    return {
        "status": "published",
        "entry_name": entry_name,
        "update_mask": update_mask,
        "updated_aspect_keys": [aspect_key],
        "unified_diff": audit["unified_diff"],
        "entry": updated_entry,
    }


__all__ = [
    "diff_and_audit_catalog_enrichment",
    "download_catalog_entry_to_markdown",
    "enrich_catalog_entry_markdown",
    "publish_enriched_markdown_to_catalog",
]
