"""In-process fake of the Google Cloud Knowledge Catalog remote MCP server for tests.

The real server (``https://dataplex.googleapis.com/mcp``) is a stateless
Streamable HTTP MCP server exposing:

* ``search_entries(query: str, name: str = "", page_size: int = 50, semantic_search: bool = True)``
* ``lookup_context(name: str, resources: list[str], options: dict[str, str] | None = None)``
* ``lookup_entry(name: str, view: str = "FULL")``

This fake also exposes ``update_entry`` and data-product tools
(``search_data_products``, ``lookup_data_product``, ``list_data_assets``,
``get_data_asset``) so tests can exercise:
1. A2A startup discovery (``McpToolset.get_tools(readonly_context=None)``) and
   per-turn tool execution with ``BearerTokenAuth(AdcTokenSource)`` and
   ``X-Goog-User-Project``.
2. All 6 metadata dimensions of ``lookupContext`` (technical schema/partitioning,
   operational query-history joins, business glossary terms/overviews/guidelines
   and custom governance aspects, column statistical data profiles, automated
   data quality statuses, and 1-hop related assets).
3. Dynamic source-system IAM post-filtering (stripping unauthorized entries and
   hiding ``EntryLinks`` touching unauthorized tables).
4. ``format`` (``yaml``, ``xml``, ``json``), ``context_budget`` / ``budget``
   truncation, ``all_schema_fields="true"`` schema preservation override, and the
   10-resource cap on ``LookupContextRequest.resources``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import socket
import threading
import time
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
import uvicorn
import yaml


@dataclass
class FakeColumnSchema:
    """One column definition with data profile metrics."""

    name: str
    col_type: str
    mode: str = "NULLABLE"
    description: str = ""
    terms: str = ""
    null_ratio: float = 0.0
    distinct_values: int = 0
    sample_values: list[Any] = field(default_factory=list)

    def to_dict(self, *, include_profile: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "type": self.col_type,
            "mode": self.mode,
            "description": self.description,
        }
        if self.terms:
            payload["terms"] = self.terms
        if include_profile:
            payload["null_ratio"] = self.null_ratio
            payload["distinct_values"] = self.distinct_values
            payload["sample_values"] = list(self.sample_values)
        return payload


@dataclass
class FakeCatalogEntry:
    """One Knowledge Catalog entry (BigQuery table, Context Set, or rule doc)."""

    entry_name: str
    resource: str
    simple_name: str
    entry_type: str = "bigquery-table"
    entry_group_type: str = "bigquery"
    system: str = "bigquery"
    description: str = ""
    overview: str = ""
    guidelines: str = ""
    terms: str = ""
    partition_by: list[str] = field(default_factory=list)
    cluster_by: list[str] = field(default_factory=list)
    schema: list[FakeColumnSchema] = field(default_factory=list)
    frequent_joins: list[dict[str, Any]] = field(default_factory=list)
    data_quality: dict[str, Any] = field(default_factory=dict)
    governance_aspect: dict[str, Any] = field(default_factory=dict)
    related_entry_names: list[str] = field(default_factory=list)
    sample_queries: list[dict[str, str]] = field(default_factory=list)
    required_permission: str = "bigquery.tables.get"


class FakeKnowledgeCatalogStore:
    """In-memory Knowledge Catalog corpus with IAM post-filtering and header tracking."""

    def __init__(self, *, seed_defaults: bool = True) -> None:
        self.entries: dict[str, FakeCatalogEntry] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.last_headers: dict[str, str] = {}
        self.header_history: list[dict[str, str]] = []
        self.require_auth: bool = False
        self.denied_entries: set[str] = set()
        self._lock = threading.Lock()
        if seed_defaults:
            self._seed_default_entries()

    def _seed_default_entries(self) -> None:
        p = "dandye-0324-chronicle"
        loc = "us-central1"

        # 1. Certified Gold Internal Finance Table
        fin_internal_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/finance_mart/tables/fin_monthly_closing_internal"
        )
        # 2. Certified Gold External Finance Table
        fin_public_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/finance_mart/tables/fin_quarterly_public_report"
        )
        # 3. Realtime Streaming Marketing Table
        mkt_realtime_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/marketing_prod/tables/mkt_realtime_campaign_performance"
        )
        # 4. Uncertified Bronze Sandbox Table
        sandbox_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/analyst_sandbox/tables/tmp_data_dump_v2_final_real"
        )
        # 5. Certified Gold SecOps BigQuery UDM Datalake Table
        udm_gold_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/secops_datalake/tables/udm_events_gold"
        )
        # 6. Restricted HR Compensation Table (denied by default for IAM post-filtering tests)
        restricted_hr_name = (
            f"projects/{p}/locations/{loc}/entryGroups/@bigquery/entries/"
            f"bigquery.googleapis.com/projects/{p}/datasets/restricted_hr/tables/compensation_records"
        )
        self.denied_entries.add(restricted_hr_name)

        # 7. Context Set Entry Group & Child Rule Entry
        context_set_entry_name = (
            f"projects/{p}/locations/{loc}/entryGroups/secops-context-set/entries/context_set_root"
        )
        context_set_rule_doc_name = (
            f"projects/{p}/locations/{loc}/entryGroups/secops-context-set/entries/udm_dedup_and_partition_rules"
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=fin_internal_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/finance_mart/tables/fin_monthly_closing_internal",
                simple_name="finance_mart.fin_monthly_closing_internal",
                description="Official finalized monthly closing revenue and margin metrics for internal executive reporting.",
                overview="Certified GOLD_CRITICAL finance mart table audited by Finance Controllership.",
                guidelines=(
                    "Always filter by 'closing_date' to optimize query costs due to partitioning. "
                    "Strictly INTERNAL_ONLY; never expose in external consulting exports."
                ),
                terms="Monthly Closing Revenue, Net Margin, GAAP Recognized Revenue",
                partition_by=["closing_date"],
                cluster_by=["business_unit", "region"],
                schema=[
                    FakeColumnSchema(
                        name="closing_id",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Primary key for the monthly closing record.",
                        null_ratio=0.0,
                        distinct_values=125000,
                        sample_values=["CLS-2026-01-001", "CLS-2026-02-001"],
                    ),
                    FakeColumnSchema(
                        name="closing_date",
                        col_type="DATE",
                        mode="REQUIRED",
                        description="Accounting period closing date (partition key).",
                        null_ratio=0.0,
                        distinct_values=36,
                        sample_values=["2026-01-31", "2026-02-28", "2026-03-31"],
                    ),
                    FakeColumnSchema(
                        name="business_unit",
                        col_type="STRING",
                        mode="NULLABLE",
                        description="Reporting business unit code.",
                        null_ratio=0.01,
                        distinct_values=12,
                        sample_values=["CLOUD_SECOPS", "WORKSPACE", "AI_INFRA"],
                    ),
                    FakeColumnSchema(
                        name="net_revenue_usd",
                        col_type="NUMERIC",
                        mode="REQUIRED",
                        description="Recognized GAAP net revenue in USD.",
                        null_ratio=0.0,
                        distinct_values=98400,
                        sample_values=[1250000.00, 3400000.50],
                    ),
                ],
                frequent_joins=[
                    {
                        "table": "finance_mart.fin_quarterly_public_report",
                        "target_entry": fin_public_name,
                        "join_key": "business_unit = business_unit",
                        "origin": "Query history",
                    },
                    {
                        "table": "restricted_hr.compensation_records",
                        "target_entry": restricted_hr_name,
                        "join_key": "business_unit = cost_center_bu",
                        "origin": "Query history",
                    },
                ],
                data_quality={
                    "status": "PASSED",
                    "rules": [
                        "Completeness check on closing_id and closing_date (>99.9%).",
                        "Reconciliation check on net_revenue_usd (>= 0).",
                    ],
                },
                governance_aspect={
                    "product_tier": "GOLD_CRITICAL",
                    "data_domain": "FINANCE",
                    "usage_scope": "INTERNAL_ONLY",
                    "update_frequency": "DAILY_BATCH",
                    "is_certified": True,
                },
                related_entry_names=[fin_public_name, restricted_hr_name],
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=fin_public_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/finance_mart/tables/fin_quarterly_public_report",
                simple_name="finance_mart.fin_quarterly_public_report",
                description="Scrubbed quarterly financial summary approved for external sharing and consulting partners.",
                overview="Certified EXTERNAL_READY quarterly revenue aggregation with all internal margin details removed.",
                guidelines="Use for all external reporting and third-party consulting shares. Filter by 'fiscal_quarter'.",
                terms="Public Quarterly Revenue, External Financial Summary",
                partition_by=["quarter_end_date"],
                cluster_by=["fiscal_quarter"],
                schema=[
                    FakeColumnSchema(
                        name="fiscal_quarter",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Fiscal quarter identifier (e.g. 2026-Q1).",
                        null_ratio=0.0,
                        distinct_values=16,
                        sample_values=["2025-Q4", "2026-Q1", "2026-Q2"],
                    ),
                    FakeColumnSchema(
                        name="quarter_end_date",
                        col_type="DATE",
                        mode="REQUIRED",
                        description="Quarter end date (partition key).",
                        null_ratio=0.0,
                        distinct_values=16,
                        sample_values=["2026-03-31", "2026-06-30"],
                    ),
                    FakeColumnSchema(
                        name="business_unit",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Public reporting segment.",
                        null_ratio=0.0,
                        distinct_values=4,
                        sample_values=["CLOUD", "SERVICES"],
                    ),
                    FakeColumnSchema(
                        name="public_revenue_usd",
                        col_type="NUMERIC",
                        mode="REQUIRED",
                        description="Scrubbed public segment revenue in USD.",
                        null_ratio=0.0,
                        distinct_values=64,
                        sample_values=[45000000.00, 82000000.00],
                    ),
                ],
                data_quality={
                    "status": "PASSED",
                    "rules": ["External disclosure scrub verification (100% pass)."],
                },
                governance_aspect={
                    "product_tier": "GOLD_CRITICAL",
                    "data_domain": "FINANCE",
                    "usage_scope": "EXTERNAL_READY",
                    "update_frequency": "DAILY_BATCH",
                    "is_certified": True,
                },
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=mkt_realtime_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/marketing_prod/tables/mkt_realtime_campaign_performance",
                simple_name="marketing_prod.mkt_realtime_campaign_performance",
                description="Real-time streaming ad spend and campaign conversion telemetry.",
                overview="Low-latency streaming table updated continuously for live operational dashboards.",
                guidelines="Always filter by 'event_date' partition and deduplicate using QUALIFY ROW_NUMBER() OVER (PARTITION BY campaign_event_id ORDER BY ingested_at DESC) = 1.",
                terms="Realtime Ad Spend, Campaign Impressions",
                partition_by=["event_date"],
                cluster_by=["campaign_id"],
                schema=[
                    FakeColumnSchema(
                        name="campaign_event_id",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Unique streaming event ID.",
                        null_ratio=0.0,
                        distinct_values=500000,
                        sample_values=["EVT-9001", "EVT-9002"],
                    ),
                    FakeColumnSchema(
                        name="event_date",
                        col_type="DATE",
                        mode="REQUIRED",
                        description="UTC event date partition column.",
                        null_ratio=0.0,
                        distinct_values=90,
                        sample_values=["2026-10-12", "2026-10-13"],
                    ),
                    FakeColumnSchema(
                        name="ingested_at",
                        col_type="TIMESTAMP",
                        mode="REQUIRED",
                        description="Streaming ingestion timestamp for deduplication.",
                        null_ratio=0.0,
                        distinct_values=480000,
                        sample_values=["2026-10-13T17:00:00Z"],
                    ),
                    FakeColumnSchema(
                        name="ad_spend_usd",
                        col_type="FLOAT64",
                        mode="NULLABLE",
                        description="Incremental ad spend in USD.",
                        null_ratio=0.02,
                        distinct_values=12000,
                        sample_values=[14.25, 89.50, 250.00],
                    ),
                ],
                data_quality={
                    "status": "PASSED",
                    "rules": ["Streaming freshness SLA (<5 minutes lag)."],
                },
                governance_aspect={
                    "product_tier": "SILVER_STANDARD",
                    "data_domain": "MARKETING",
                    "usage_scope": "INTERNAL_ONLY",
                    "update_frequency": "REALTIME_STREAMING",
                    "is_certified": True,
                },
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=sandbox_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/analyst_sandbox/tables/tmp_data_dump_v2_final_real",
                simple_name="analyst_sandbox.tmp_data_dump_v2_final_real",
                description="Uncertified ad-hoc sandbox dump for exploratory ML experiments.",
                overview="Raw unverified scratchpad table; contains duplicate rows and unvalidated revenue estimates.",
                guidelines="Experimental ML sandbox only. Never use for executive, board, or production SecOps reporting.",
                terms="Sandbox Dump, Experimental Scratchpad",
                partition_by=[],
                cluster_by=[],
                schema=[
                    FakeColumnSchema(
                        name="closing_id",
                        col_type="STRING",
                        mode="NULLABLE",
                        description="Unverified closing ID.",
                        null_ratio=0.35,
                        distinct_values=1200,
                        sample_values=["TMP-1", "TMP-2"],
                    ),
                    FakeColumnSchema(
                        name="net_revenue_usd",
                        col_type="FLOAT64",
                        mode="NULLABLE",
                        description="Unverified revenue estimate.",
                        null_ratio=0.62,
                        distinct_values=800,
                        sample_values=[999999.99, -42.0],
                    ),
                ],
                data_quality={
                    "status": "FAILED",
                    "rules": ["Completeness check on net_revenue_usd FAILED (62% null ratio)."],
                },
                governance_aspect={
                    "product_tier": "BRONZE_ADHOC",
                    "data_domain": "FINANCE",
                    "usage_scope": "INTERNAL_ONLY",
                    "update_frequency": "ADHOC",
                    "is_certified": False,
                },
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=udm_gold_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/secops_datalake/tables/udm_events_gold",
                simple_name="secops_datalake.udm_events_gold",
                description="Certified Gold Chronicle SIEM UDM telemetry export table in BigQuery.",
                overview="Canonical UDM events lakehouse table for threat hunting, statistical outlier analysis, and detection coverage validation.",
                guidelines=(
                    "Always filter by 'event_date' partition to prevent full-table scans. "
                    "Deduplicate streaming export rows with QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY ingested_timestamp DESC) = 1. "
                    "Join with secops_datalake.entity_graph_gold on principal_hostname = entity_hostname."
                ),
                terms="Chronicle UDM Events, Security Telemetry Lakehouse, Endpoint Process Execution",
                partition_by=["event_date"],
                cluster_by=["metadata_event_type", "principal_hostname"],
                schema=[
                    FakeColumnSchema(
                        name="event_id",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Unique Chronicle UDM event identifier.",
                        null_ratio=0.0,
                        distinct_values=2500000,
                        sample_values=["udm-evt-001", "udm-evt-002"],
                    ),
                    FakeColumnSchema(
                        name="event_date",
                        col_type="DATE",
                        mode="REQUIRED",
                        description="UTC event partition date derived from metadata.event_timestamp.",
                        null_ratio=0.0,
                        distinct_values=365,
                        sample_values=["2026-10-12", "2026-10-13"],
                    ),
                    FakeColumnSchema(
                        name="ingested_timestamp",
                        col_type="TIMESTAMP",
                        mode="REQUIRED",
                        description="BigQuery export ingestion timestamp used for QUALIFY ROW_NUMBER() deduplication.",
                        null_ratio=0.0,
                        distinct_values=2400000,
                        sample_values=["2026-10-13T17:15:00Z"],
                    ),
                    FakeColumnSchema(
                        name="metadata_event_type",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Canonical UDM event type enum.",
                        null_ratio=0.0,
                        distinct_values=24,
                        sample_values=[
                            "PROCESS_LAUNCH",
                            "USER_LOGIN",
                            "NETWORK_CONNECTION",
                            "NETWORK_DNS",
                        ],
                    ),
                    FakeColumnSchema(
                        name="principal_hostname",
                        col_type="STRING",
                        mode="NULLABLE",
                        description="Normalized hostname of the principal endpoint.",
                        null_ratio=0.03,
                        distinct_values=4200,
                        sample_values=["wkstn-fin-01", "srv-dc-01", "build-runner-04"],
                    ),
                    FakeColumnSchema(
                        name="legacy_unpopulated_tag",
                        col_type="STRING",
                        mode="NULLABLE",
                        description="Deprecated collector tag; 88% null.",
                        null_ratio=0.88,
                        distinct_values=3,
                        sample_values=["LEGACY"],
                    ),
                ],
                frequent_joins=[
                    {
                        "table": "finance_mart.fin_monthly_closing_internal",
                        "target_entry": fin_internal_name,
                        "join_key": "event_date = closing_date",
                        "origin": "Data insights",
                    },
                    {
                        "table": "restricted_hr.compensation_records",
                        "target_entry": restricted_hr_name,
                        "join_key": "principal_hostname = assigned_laptop_hostname",
                        "origin": "Query history",
                    },
                ],
                data_quality={
                    "status": "PASSED",
                    "rules": [
                        "Completeness check on event_id and event_date (100.0%).",
                        "Valid UDM enum check on metadata_event_type (>99.9%).",
                    ],
                },
                governance_aspect={
                    "product_tier": "GOLD_CRITICAL",
                    "data_domain": "SECOPS",
                    "usage_scope": "INTERNAL_ONLY",
                    "update_frequency": "REALTIME_STREAMING",
                    "is_certified": True,
                },
                related_entry_names=[fin_internal_name, restricted_hr_name],
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=restricted_hr_name,
                resource=f"//bigquery.googleapis.com/projects/{p}/datasets/restricted_hr/tables/compensation_records",
                simple_name="restricted_hr.compensation_records",
                description="Restricted employee compensation and SSN records.",
                overview="Confidential HR table; requires bigquery.tables.get on restricted_hr.",
                guidelines="Restricted HR access only.",
                partition_by=["effective_date"],
                schema=[
                    FakeColumnSchema(
                        name="employee_id",
                        col_type="STRING",
                        mode="REQUIRED",
                        description="Employee ID.",
                    )
                ],
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=context_set_entry_name,
                resource=f"//dataplex.googleapis.com/projects/{p}/locations/{loc}/entryGroups/secops-context-set",
                simple_name="secops-context-set",
                entry_type="context-set",
                entry_group_type="context-set",
                system="dataplex",
                description="Curated Context Set for SecOps UDM BigQuery analytics, deduplication rules, and finance mart governance.",
                overview="Authoritative Context Set containing golden SQL rules and Source Contract templates.",
                guidelines="Scope secondary search_entries calls to entrygroup=projects/dandye-0324-chronicle/locations/us-central1/entryGroups/secops-context-set without system= or column: filters.",
            )
        )

        self.add_entry(
            FakeCatalogEntry(
                entry_name=context_set_rule_doc_name,
                resource=f"//dataplex.googleapis.com/projects/{p}/locations/{loc}/entryGroups/secops-context-set/entries/udm_dedup_and_partition_rules",
                simple_name="secops-context-set.udm_dedup_and_partition_rules",
                entry_type="context-rule-doc",
                entry_group_type="context-set",
                system="dataplex",
                description="Mandatory deduplication and partition pruning rules for SecOps and Finance BigQuery tables.",
                overview=(
                    "Rule 1: Always filter secops_datalake.udm_events_gold by event_date and finance_mart.fin_monthly_closing_internal by closing_date.\n"
                    "Rule 2: Wrap streaming tables in a cleaning CTE with QUALIFY ROW_NUMBER() OVER (PARTITION BY event_id ORDER BY ingested_timestamp DESC) = 1.\n"
                    "Rule 3: Never use analyst_sandbox.tmp_data_dump_v2_final_real (BRONZE_ADHOC, is_certified: false) for production or executive queries."
                ),
                guidelines="Emit a 6-item Source Contract before executing any BigQuery SQL statement.",
            )
        )

    def add_entry(self, entry: FakeCatalogEntry) -> None:
        with self._lock:
            self.entries[entry.entry_name] = entry

    def _record(self, tool_name: str, arguments: dict[str, Any]) -> None:
        with self._lock:
            self.calls.append((tool_name, arguments))
            headers = dict(self.last_headers)
        if self.require_auth:
            has_api_key = bool(headers.get("x-goog-api-key"))
            has_bearer = headers.get("authorization", "").lower().startswith("bearer ")
            if not (has_api_key or has_bearer):
                raise ToolError(
                    "UNAUTHENTICATED: Request is missing required authentication credential. "
                    "Expected Authorization Bearer token or X-Goog-Api-Key."
                )

    def search_entries(
        self,
        query: str,
        name: str = "",
        page_size: int = 50,
        semantic_search: bool = True,
    ) -> dict[str, Any]:
        self._record(
            "search_entries",
            {
                "query": query,
                "name": name,
                "page_size": page_size,
                "semantic_search": semantic_search,
            },
        )
        q_lower = query.lower()
        results: list[dict[str, Any]] = []

        # Context-set discovery query: entrygroup.type=context-set
        if "entrygroup.type=context-set" in q_lower:
            for entry in self.entries.values():
                if entry.entry_name in self.denied_entries:
                    continue
                if entry.entry_type == "context-set":
                    results.append(self._to_search_hit(entry))
            return {"results": results[:page_size]}

        # Scoped context-set query: entrygroup=...
        if "entrygroup=" in q_lower and "secops-context-set" in q_lower:
            # Real Knowledge Catalog behavior: passing system=, type=, or column:
            # filters inside a scoped context-set search excludes rule documents.
            if any(bad in q_lower for bad in ("system=", "type=", "column:")):
                return {"results": []}
            for entry in self.entries.values():
                if entry.entry_name in self.denied_entries:
                    continue
                if entry.entry_group_type == "context-set":
                    results.append(self._to_search_hit(entry))
            return {"results": results[:page_size]}

        tokens = [
            tok
            for tok in q_lower.replace("_", " ").replace(".", " ").replace("-", " ").split()
            if len(tok) >= 2
        ]
        scored: list[tuple[int, FakeCatalogEntry]] = []
        for entry in self.entries.values():
            if entry.entry_name in self.denied_entries:
                continue
            haystack = (
                f"{entry.entry_name} {entry.simple_name} {entry.description} "
                f"{entry.overview} {entry.guidelines} {entry.terms} "
                f"{json.dumps(entry.governance_aspect)}"
            ).lower()
            score = sum(1 for tok in tokens if tok in haystack) if tokens else 1
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda pair: (-pair[0], pair[1].simple_name))
        return {"results": [self._to_search_hit(e) for _, e in scored[:page_size]]}

    def lookup_context(
        self,
        name: str,
        resources: list[str],
        options: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        opts = dict(options or {})
        self._record(
            "lookup_context",
            {"name": name, "resources": list(resources), "options": opts},
        )
        if not resources:
            raise ToolError("INVALID_ARGUMENT: resources must contain at least 1 entry name.")
        if len(resources) > 10:
            raise ToolError(
                f"INVALID_ARGUMENT: LookupContext supports at most 10 resources per request; got {len(resources)}."
            )

        fmt = opts.get("format", "yaml").strip().lower()
        if fmt not in {"yaml", "xml", "json"}:
            raise ToolError(f"INVALID_ARGUMENT: Unsupported format {fmt!r}; expected yaml, xml, or json.")

        budget_raw = opts.get("context_budget") or opts.get("budget")
        budget = int(budget_raw) if budget_raw and str(budget_raw).isdigit() else None
        all_schema_fields = str(opts.get("all_schema_fields", "false")).strip().lower() == "true"

        permitted_entries: list[FakeCatalogEntry] = []
        for res_name in resources:
            if res_name in self.denied_entries:
                continue
            entry = self.entries.get(res_name)
            if entry is not None:
                permitted_entries.append(entry)

        if not permitted_entries:
            return {"context": ""}

        # Build structured context payload across the 6 dimensions, applying
        # dynamic IAM post-filtering on frequent_joins and relatedResources.
        resource_blocks: list[dict[str, Any]] = []
        related_blocks: list[dict[str, Any]] = []
        cross_joins: list[dict[str, Any]] = []
        requested_set = {e.entry_name for e in permitted_entries}
        seen_related: set[str] = set()

        # If budget is tight (< 900 chars), truncate optional secondary sections
        # while honoring all_schema_fields for schema columns.
        tight_budget = budget is not None and budget < 900

        for entry in permitted_entries:
            filtered_joins = [
                {
                    "table": j["table"],
                    "join_key": j["join_key"],
                    "origin": j.get("origin", "Query history"),
                }
                for j in entry.frequent_joins
                if j.get("target_entry") not in self.denied_entries
            ]
            for j in entry.frequent_joins:
                target_entry = j.get("target_entry")
                if target_entry in requested_set and target_entry not in self.denied_entries:
                    cross_joins.append(
                        {
                            "source": entry.simple_name,
                            "target": j["table"],
                            "joinKeys": [j["join_key"]],
                        }
                    )

            schema_cols = (
                entry.schema
                if (all_schema_fields or not tight_budget)
                else entry.schema[:1]
            )
            entry_dict: dict[str, Any] = {
                "catalogEntry": entry.entry_name,
                "resource": entry.resource,
                "simpleName": entry.simple_name,
                "type": entry.entry_type,
                "description": entry.description,
                "terms": entry.terms,
                "overview": entry.overview,
                "guidelines": entry.guidelines,
                "usage": {
                    "partitionBy": list(entry.partition_by),
                    "clusterBy": list(entry.cluster_by),
                },
                "schema": [
                    col.to_dict(include_profile=not tight_budget) for col in schema_cols
                ],
            }
            if entry.governance_aspect:
                entry_dict["governance_aspect"] = dict(entry.governance_aspect)
            if not tight_budget:
                entry_dict["data_quality"] = dict(entry.data_quality)
                entry_dict["frequent_joins"] = filtered_joins
            resource_blocks.append(entry_dict)

            if not tight_budget:
                for rel_name in entry.related_entry_names:
                    if rel_name in self.denied_entries or rel_name in seen_related:
                        continue
                    rel_entry = self.entries.get(rel_name)
                    if rel_entry is not None:
                        seen_related.add(rel_name)
                        related_blocks.append(
                            {
                                "catalogEntry": rel_entry.entry_name,
                                "resource": rel_entry.resource,
                                "simpleName": rel_entry.simple_name,
                                "type": rel_entry.entry_type,
                                "description": rel_entry.description,
                            }
                        )

        payload: dict[str, Any] = {"resources": resource_blocks}
        if related_blocks:
            payload["relatedResources"] = related_blocks
        if cross_joins:
            payload["joins"] = cross_joins

        if fmt == "json":
            text = json.dumps(payload, indent=2)
        elif fmt == "xml":
            text = self._to_xml(payload)
        else:
            text = yaml.safe_dump(payload, sort_keys=False)

        return {"context": text}

    def lookup_entry(self, name: str, view: str = "FULL") -> dict[str, Any]:
        self._record("lookup_entry", {"name": name, "view": view})
        if name in self.denied_entries:
            raise ToolError(f"PERMISSION_DENIED: Caller lacks bigquery.tables.get on {name}")
        entry = self.entries.get(name)
        if entry is None:
            raise ToolError(f"NOT_FOUND: Entry not found: {name}")
        return {
            "name": entry.entry_name,
            "fullyQualifiedName": f"{entry.system}:{entry.simple_name}",
            "entryType": entry.entry_type,
            "entrySource": {
                "resource": entry.resource,
                "displayName": entry.simple_name,
                "description": entry.description,
                "system": entry.system,
            },
            "aspects": {
                "dataplex-types.global.overview": {
                    "aspectType": "projects/dataplex-types/locations/global/aspectTypes/overview",
                    "data": {"content": entry.overview},
                },
                "dataplex-types.global.guidelines": {
                    "aspectType": "projects/dataplex-types/locations/global/aspectTypes/guidelines",
                    "data": {"content": entry.guidelines},
                },
                "dataplex-types.global.schema": {
                    "aspectType": "projects/dataplex-types/locations/global/aspectTypes/schema",
                    "data": {
                        "fields": [c.to_dict(include_profile=True) for c in entry.schema]
                    },
                },
                "dandye-0324-chronicle.us-central1.official-data-product-spec": {
                    "aspectType": "projects/dandye-0324-chronicle/locations/us-central1/aspectTypes/official-data-product-spec",
                    "data": dict(entry.governance_aspect),
                },
            },
        }

    def update_entry(
        self,
        entry_name: str,
        overview_content: str,
        guidelines_content: str = "",
        update_mask: list[str] | None = None,
    ) -> dict[str, Any]:
        self._record(
            "update_entry",
            {
                "entry_name": entry_name,
                "overview_content": overview_content,
                "guidelines_content": guidelines_content,
                "update_mask": list(update_mask or []),
            },
        )
        if not update_mask or "aspects" not in update_mask:
            raise ToolError("INVALID_ARGUMENT: update_mask must include 'aspects'.")
        entry = self.entries.get(entry_name)
        if entry is None:
            raise ToolError(f"NOT_FOUND: Entry not found: {entry_name}")
        with self._lock:
            entry.overview = overview_content
            if guidelines_content:
                entry.guidelines = guidelines_content
        return self.lookup_entry(entry_name, view="FULL")

    @staticmethod
    def _to_search_hit(entry: FakeCatalogEntry) -> dict[str, Any]:
        return {
            "name": entry.entry_name,
            "linkedResource": entry.resource,
            "displayName": entry.simple_name,
            "entryType": entry.entry_type,
            "description": entry.description,
            "governance_aspect": dict(entry.governance_aspect),
        }

    @staticmethod
    def _to_xml(payload: dict[str, Any]) -> str:
        lines = ["<context>"]
        for r in payload.get("resources", []):
            lines.append(f'  <resource catalogEntry="{r["catalogEntry"]}" simpleName="{r["simpleName"]}">')
            lines.append(f'    <description>{r.get("description", "")}</description>')
            lines.append(f'    <guidelines>{r.get("guidelines", "")}</guidelines>')
            lines.append("    <schema>")
            for col in r.get("schema", []):
                lines.append(f'      <field name="{col["name"]}" type="{col["type"]}" />')
            lines.append("    </schema>")
            lines.append("  </resource>")
        lines.append("</context>")
        return "\n".join(lines)


def build_fastmcp(
    store: FakeKnowledgeCatalogStore, *, json_response: bool = True, host: str, port: int
) -> FastMCP:
    """Builds the FastMCP app exposing Knowledge Catalog tools over ``store``."""
    server = FastMCP(
        "fake-knowledge-catalog-mcp",
        host=host,
        port=port,
        stateless_http=True,
        json_response=json_response,
        log_level="WARNING",
    )

    @server.tool(name="search_entries")
    def search_entries(
        query: str,
        name: str = "",
        page_size: int = 50,
        semantic_search: bool = True,
    ) -> dict[str, Any]:
        return store.search_entries(
            query=query, name=name, page_size=page_size, semantic_search=semantic_search
        )

    @server.tool(name="lookup_context")
    def lookup_context(
        name: str,
        resources: list[str],
        options: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return store.lookup_context(name=name, resources=resources, options=options)

    @server.tool(name="lookup_entry")
    def lookup_entry(name: str, view: str = "FULL") -> dict[str, Any]:
        return store.lookup_entry(name=name, view=view)

    @server.tool(name="update_entry")
    def update_entry(
        entry_name: str,
        overview_content: str,
        guidelines_content: str = "",
        update_mask: list[str] | None = None,
    ) -> dict[str, Any]:
        return store.update_entry(
            entry_name=entry_name,
            overview_content=overview_content,
            guidelines_content=guidelines_content,
            update_mask=update_mask,
        )

    return server


class _HeaderRecorder:
    """ASGI wrapper that records the headers of every HTTP request."""

    def __init__(self, app, store: FakeKnowledgeCatalogStore) -> None:
        self._app = app
        self._store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers", [])
            }
            self._store.last_headers = headers
            self._store.header_history.append(headers)
        await self._app(scope, receive, send)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeKnowledgeCatalogMcpServer:
    """Runs the fake Knowledge Catalog MCP server on a background thread."""

    def __init__(
        self,
        store: FakeKnowledgeCatalogStore | None = None,
        *,
        json_response: bool = True,
    ) -> None:
        self.store = store or FakeKnowledgeCatalogStore()
        self.json_response = json_response
        self.host = "127.0.0.1"
        self.port = _free_port()
        self.url = f"http://{self.host}:{self.port}/mcp"
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "FakeKnowledgeCatalogMcpServer":
        fastmcp = build_fastmcp(
            self.store, json_response=self.json_response, host=self.host, port=self.port
        )
        app = _HeaderRecorder(fastmcp.streamable_http_app(), self.store)
        config = uvicorn.Config(
            app, host=self.host, port=self.port, log_level="warning", lifespan="on"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, name="fake-knowledge-catalog-mcp", daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("fake Knowledge Catalog MCP server exited during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("fake Knowledge Catalog MCP server did not start in time")
            time.sleep(0.01)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)

    def __enter__(self) -> "FakeKnowledgeCatalogMcpServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
