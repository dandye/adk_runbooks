"""Developer Knowledge Remote MCP Server and ``AgentTool(web_search_verifier)`` grounding tools.

Implements the two-source grounding architecture from Irani (2026)
(*Grounding Google Docs Suggested Edits with Developer Knowledge MCP and Google Search*):

1. **Google Developer Knowledge Remote MCP Server**
   (``https://developerknowledge.googleapis.com/mcp``) -- Exposes ``answer_query``,
   ``search_documents``, and ``get_documents`` over official Google documentation
   (Google Cloud, Chronicle / SecOps, Vertex AI, Gemini, ADK, Firebase, Android,
   Go, Flutter, Chrome). Handles the ADK A2A startup discovery nuance where
   ``McpToolset.get_tools(readonly_context=None)`` is called before any user
   request exists, requiring authentication headers in both static connection
   params/httpx client factory and ``header_provider``.

2. **Isolated Google Search Grounding Sub-Agent (``AgentTool`` Pattern)** --
   Because Gemini's built-in ``google_search`` grounding primitive cannot be mixed
   directly in the same ``tools=[...]`` list with custom ``FunctionTool``s or
   ``McpToolset``s, ``web_search_verifier`` is defined as a dedicated child
   :class:`google.adk.agents.Agent` whose only tool is ``google_search``, and
   exposed to parent agents via :class:`google.adk.tools.agent_tool.AgentTool`.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from google.adk.agents import Agent  # noqa: E402
from google.adk.tools import google_search  # noqa: E402
from google.adk.tools.agent_tool import AgentTool  # noqa: E402

from skills.drive_registry import (  # noqa: E402
    AdcTokenSource,
    DriveMcpError,
    DriveRegistryConfigError,
    TokenSource,
)
from .drive_tools import (  # noqa: E402
    TOOLSET_CONNECT_TIMEOUT_SECONDS,
    TOOLSET_SSE_READ_TIMEOUT_SECONDS,
    drive_quota_project,
    make_drive_httpx_client_factory,
)

logger = logging.getLogger(__name__)

DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL = "https://developerknowledge.googleapis.com/mcp"
DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX = "devknowledge"
DEVELOPER_KNOWLEDGE_TOOL_FILTER = [
    "answer_query",
    "search_documents",
    "get_documents",
]
DEFAULT_WEB_SEARCH_VERIFIER_MODEL = "gemini-3-flash-preview"

DEFAULT_KNOWLEDGE_CATALOG_MCP_URL = "https://dataplex.googleapis.com/mcp"
DEFAULT_KNOWLEDGE_CATALOG_DATA_PRODUCTS_MCP_URL = (
    "https://dataplex.googleapis.com/mcp/data-products"
)
KNOWLEDGE_CATALOG_TOOL_NAME_PREFIX = "kcatalog"
KNOWLEDGE_CATALOG_TOOL_FILTER = [
    "search_entries",
    "lookup_context",
    "lookup_entry",
]
KNOWLEDGE_CATALOG_DATA_PRODUCTS_TOOL_FILTER = [
    "search_data_products",
    "lookup_data_product",
    "get_data_asset",
    "list_data_assets",
    "lookup_context",
]
DEFAULT_KNOWLEDGE_CATALOG_DISCOVERY_MODEL = "gemini-3-flash-preview"


def developer_knowledge_mcp_url() -> str:
    """Returns the Developer Knowledge MCP endpoint URL."""
    return (
        os.environ.get("DEVELOPERKNOWLEDGE_MCP_URL", "").strip()
        or DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL
    )


def developer_knowledge_api_key() -> str:
    """Returns ``DEVELOPERKNOWLEDGE_API_KEY`` when configured."""
    return os.environ.get("DEVELOPERKNOWLEDGE_API_KEY", "").strip()


def developer_knowledge_quota_project() -> str:
    """Returns the consumer GCP project ID for ``X-Goog-User-Project``."""
    return (
        os.environ.get("DEVELOPERKNOWLEDGE_QUOTA_PROJECT", "").strip()
        or drive_quota_project()
    )


def developer_knowledge_toolset_configured() -> bool:
    """True when the Developer Knowledge MCP toolset is enabled and has credentials/project."""
    flag = os.environ.get("DEVELOPERKNOWLEDGE_MCP_TOOLSET", "1").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    return bool(
        developer_knowledge_api_key()
        or developer_knowledge_quota_project()
        or os.environ.get("DEVELOPERKNOWLEDGE_MCP_URL", "").strip()
    )


def developer_knowledge_headers(
    readonly_context: Any = None,
    *,
    api_key: str | None = None,
    quota_project: str | None = None,
    token_source: TokenSource | None = None,
) -> dict[str, str]:
    """Builds authentication headers for the Developer Knowledge MCP server.

    Supports two authentication modes:
    1. ``X-Goog-Api-Key`` when ``DEVELOPERKNOWLEDGE_API_KEY`` (or ``api_key``) is set.
    2. ``Authorization: Bearer <token>`` + ``X-Goog-User-Project`` using the
       worktree's Application Default Credentials (or injected ``token_source``).

    Can be invoked both with ``readonly_context=None`` (during A2A Agent Card
    startup discovery) and with an active ``ReadonlyContext`` during agent turns.
    """
    _ = readonly_context
    resolved_key = api_key if api_key is not None else developer_knowledge_api_key()
    resolved_project = (
        quota_project if quota_project is not None else developer_knowledge_quota_project()
    )

    headers: dict[str, str] = {}
    if resolved_project:
        headers["X-Goog-User-Project"] = resolved_project

    if resolved_key:
        headers["X-Goog-Api-Key"] = resolved_key
        return headers

    source = token_source or AdcTokenSource()
    try:
        token = source()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    except (DriveRegistryConfigError, DriveMcpError) as err:
        logger.debug("Developer Knowledge ADC token unavailable during header build: %s", err)
    return headers


def init_developer_knowledge_toolset(
    *,
    url: str | None = None,
    api_key: str | None = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    tool_filter: list[str] | None = None,
    use_header_provider: bool = False,
):
    """Builds the ADK ``McpToolset`` for the Google Developer Knowledge MCP server.

    Handles two ADK 2.7.1 nuances:
    1. **Startup Discovery (``readonly_context=None``)**: When FastAPI builds an
       A2A Agent Card at startup, it calls ``McpToolset.get_tools(readonly_context=None)``.
       ``McpToolset(header_provider=...)`` is skipped when ``readonly_context`` is
       ``None``, so static headers (``X-Goog-Api-Key``, ``X-Goog-User-Project``)
       and ``httpx.Auth`` bearer injection must live on
       ``StreamableHTTPConnectionParams``.
    2. **Direct ``McpTool.run_async(tool_context=None)`` Bug**: In ADK 2.7.1,
       ``mcp_tool.py:L434`` unconditionally evaluates
       ``ReadonlyContext(tool_context._invocation_context)`` whenever
       ``header_provider`` is non-null, raising ``AttributeError`` when
       ``tool_context`` is ``None`` (and hashing rotating tokens into the session
       pool key). Therefore ``use_header_provider`` defaults to ``False`` while
       still supporting ``use_header_provider=True`` when a caller requires
       ``ReadonlyContext``-driven headers.
    """
    from google.adk.tools.mcp_tool.mcp_session_manager import (  # pylint: disable=import-outside-toplevel
        StreamableHTTPConnectionParams,
    )
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset  # pylint: disable=import-outside-toplevel

    resolved_key = api_key if api_key is not None else developer_knowledge_api_key()
    resolved_project = (
        quota_project if quota_project is not None else developer_knowledge_quota_project()
    )
    resolved_token_source = token_source or AdcTokenSource()

    static_headers: dict[str, str] = {}
    if resolved_project:
        static_headers["X-Goog-User-Project"] = resolved_project
    if resolved_key:
        static_headers["X-Goog-Api-Key"] = resolved_key

    def _header_provider(readonly_context: Any = None) -> dict[str, str]:
        return developer_knowledge_headers(
            readonly_context,
            api_key=resolved_key,
            quota_project=resolved_project,
            token_source=resolved_token_source,
        )

    conn_kwargs: dict[str, Any] = {
        "url": url or developer_knowledge_mcp_url(),
        "headers": static_headers or None,
        "timeout": TOOLSET_CONNECT_TIMEOUT_SECONDS,
        "sse_read_timeout": TOOLSET_SSE_READ_TIMEOUT_SECONDS,
    }
    if not resolved_key:
        conn_kwargs["httpx_client_factory"] = make_drive_httpx_client_factory(
            resolved_token_source
        )

    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(**conn_kwargs),
        tool_filter=list(tool_filter or DEVELOPER_KNOWLEDGE_TOOL_FILTER),
        tool_name_prefix=DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX,
        header_provider=_header_provider if use_header_provider else None,
    )


def init_developer_knowledge_mcp_tools(mcp_registry: Any = None):
    """Builds and registers the Developer Knowledge MCP toolset when configured."""
    if not developer_knowledge_toolset_configured():
        return None
    try:
        dk_toolset = init_developer_knowledge_toolset()
    except (DriveRegistryConfigError, DriveMcpError, ImportError) as err:
        logger.warning("Developer Knowledge MCP toolset unavailable: %s", err)
        return None

    if mcp_registry is None:
        from .tools import global_mcp_registry  # pylint: disable=import-outside-toplevel

        mcp_registry = global_mcp_registry
    mcp_registry.register_mcp_toolset(dk_toolset, server_name="devknowledge")
    return dk_toolset


def web_search_verifier_agent(model: str | None = None) -> Agent:
    """Builds the isolated child ``Agent`` whose sole tool is ``google_search``.

    In the Gemini API, built-in ``google_search`` is a server-side grounding
    primitive that cannot be mixed in the same ``tools=[...]`` list with custom
    ``FunctionTool``s or ``McpToolset``s. Isolating ``google_search`` inside this
    dedicated sub-agent and wrapping it in :class:`AgentTool` exposes web search
    grounding as a standard callable tool on the parent orchestrator.
    """
    resolved_model = (
        model
        or os.environ.get("WEB_SEARCH_VERIFIER_MODEL", "").strip()
        or DEFAULT_WEB_SEARCH_VERIFIER_MODEL
    )
    return Agent(
        name="web_search_verifier",
        model=resolved_model,
        description=(
            "Fact-checks and verifies non-Google technical claims, external CVEs, "
            "third-party vendor advisories (AWS, Azure, FortiOS, Ivanti, Palo Alto), "
            "and general web facts using Google Search Grounding."
        ),
        instruction=(
            "You are a technical fact-checking specialist.\n"
            "Given a technical claim, CVE identifier, vendor advisory, command, or "
            "factual statement, use `google_search` to verify whether it is accurate "
            "and current.\n"
            "Return a concise report containing:\n"
            "1. Verdict: ACCURATE, OUTDATED, or INACCURATE.\n"
            "2. The verified current fact, syntax, version, or remediation command.\n"
            "3. Authoritative source URLs backing your finding."
        ),
        tools=[google_search],
    )


def init_web_search_agent_tool(model: str | None = None) -> AgentTool:
    """Wraps :func:`web_search_verifier_agent` in an ADK :class:`AgentTool`."""
    return AgentTool(agent=web_search_verifier_agent(model=model))


# ---------------------------------------------------------------------------
# Google Cloud Knowledge Catalog Remote MCP & AgentTool Discovery Sub-Agent
# ---------------------------------------------------------------------------


def knowledge_catalog_mcp_url() -> str:
    """Returns the Knowledge Catalog Remote MCP discovery endpoint URL."""
    return (
        os.environ.get("KNOWLEDGE_CATALOG_MCP_URL", "").strip()
        or DEFAULT_KNOWLEDGE_CATALOG_MCP_URL
    )


def knowledge_catalog_quota_project() -> str:
    """Returns the consumer GCP project ID for ``X-Goog-User-Project``."""
    return (
        os.environ.get("KNOWLEDGE_CATALOG_QUOTA_PROJECT", "").strip()
        or os.environ.get("DATAPLEX_PROJECT", "").strip()
        or drive_quota_project()
    )


def knowledge_catalog_toolset_configured() -> bool:
    """True when the Knowledge Catalog MCP toolset is explicitly enabled."""
    flag = os.environ.get("KNOWLEDGE_CATALOG_MCP_TOOLSET", "").strip().lower()
    if flag in {"0", "false", "no", "off"}:
        return False
    if flag in {"1", "true", "yes", "on"}:
        return True
    return bool(
        os.environ.get("KNOWLEDGE_CATALOG_MCP_URL", "").strip()
        or os.environ.get("DATAPLEX_PROJECT", "").strip()
    )


def knowledge_catalog_headers(
    readonly_context: Any = None,
    *,
    quota_project: str | None = None,
    token_source: TokenSource | None = None,
) -> dict[str, str]:
    """Builds authentication headers for the Knowledge Catalog Remote MCP server.

    Injects ``X-Goog-User-Project`` and ``Authorization: Bearer <token>`` from
    the isolated worktree Application Default Credentials (or injected
    ``token_source``). Works both at A2A Agent Card startup discovery
    (``readonly_context=None``) and during active agent turns.
    """
    _ = readonly_context
    resolved_project = (
        quota_project if quota_project is not None else knowledge_catalog_quota_project()
    )
    headers: dict[str, str] = {}
    if resolved_project:
        headers["X-Goog-User-Project"] = resolved_project

    source = token_source or AdcTokenSource()
    try:
        token = source()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    except (DriveRegistryConfigError, DriveMcpError) as err:
        logger.debug("Knowledge Catalog ADC token unavailable during header build: %s", err)
    return headers


def build_lookup_context_request_payload(
    project_id: str,
    location: str,
    resources: list[str],
    *,
    fmt: str = "yaml",
    context_budget: int = 4000,
    all_schema_fields: bool = True,
) -> dict[str, Any]:
    """Builds and validates a ``LookupContextRequest`` payload.

    Enforces the Dataplex ``CatalogService.LookupContext`` contract:
    - ``1 <= len(resources) <= 10``
    - ``format`` in ``{"yaml", "xml", "json"}``
    - ``context_budget`` and ``all_schema_fields`` serialized as strings in ``options``
    """
    if not resources:
        raise ValueError(
            "LookupContextRequest requires at least 1 entry resource name in 'resources'."
        )
    if len(resources) > 10:
        raise ValueError(
            f"LookupContextRequest supports at most 10 entry resource names; got {len(resources)}."
        )
    norm_fmt = fmt.strip().lower()
    if norm_fmt not in {"yaml", "xml", "json"}:
        raise ValueError(
            f"Unsupported lookup_context format {fmt!r}; expected 'yaml', 'xml', or 'json'."
        )
    return {
        "name": f"projects/{project_id}/locations/{location}",
        "resources": list(resources),
        "options": {
            "format": norm_fmt,
            "context_budget": str(int(context_budget)),
            "all_schema_fields": "true" if all_schema_fields else "false",
        },
    }


def init_knowledge_catalog_toolset(
    *,
    url: str | None = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    tool_filter: list[str] | None = None,
    tool_name_prefix: str = KNOWLEDGE_CATALOG_TOOL_NAME_PREFIX,
    use_header_provider: bool = False,
):
    """Builds the ADK ``McpToolset`` for the Google Cloud Knowledge Catalog MCP server.

    Uses ``StreamableHTTPConnectionParams`` with ``make_drive_httpx_client_factory``
    (``BearerTokenAuth``) so rotating OAuth tokens are injected per HTTP request
    without invalidating ADK's header-hashed MCP session pool, and A2A startup
    discovery (``get_tools(readonly_context=None)``) succeeds seamlessly.
    """
    from google.adk.tools.mcp_tool.mcp_session_manager import (  # pylint: disable=import-outside-toplevel
        StreamableHTTPConnectionParams,
    )
    from google.adk.tools.mcp_tool.mcp_toolset import McpToolset  # pylint: disable=import-outside-toplevel

    resolved_project = (
        quota_project if quota_project is not None else knowledge_catalog_quota_project()
    )
    resolved_token_source = token_source or AdcTokenSource()

    static_headers: dict[str, str] = {}
    if resolved_project:
        static_headers["X-Goog-User-Project"] = resolved_project

    def _header_provider(readonly_context: Any = None) -> dict[str, str]:
        return knowledge_catalog_headers(
            readonly_context,
            quota_project=resolved_project,
            token_source=resolved_token_source,
        )

    conn_kwargs: dict[str, Any] = {
        "url": url or knowledge_catalog_mcp_url(),
        "headers": static_headers or None,
        "timeout": TOOLSET_CONNECT_TIMEOUT_SECONDS,
        "sse_read_timeout": TOOLSET_SSE_READ_TIMEOUT_SECONDS,
        "httpx_client_factory": make_drive_httpx_client_factory(resolved_token_source),
    }

    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(**conn_kwargs),
        tool_filter=list(tool_filter or KNOWLEDGE_CATALOG_TOOL_FILTER),
        tool_name_prefix=tool_name_prefix,
        header_provider=_header_provider if use_header_provider else None,
    )


def init_knowledge_catalog_mcp_tools(
    mcp_registry: Any = None,
    *,
    token_source: TokenSource | None = None,
):
    """Builds and registers the Knowledge Catalog MCP toolset when configured."""
    if not knowledge_catalog_toolset_configured():
        return None
    try:
        kc_toolset = init_knowledge_catalog_toolset(token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError, ImportError) as err:
        logger.warning("Knowledge Catalog MCP toolset unavailable: %s", err)
        return None

    if mcp_registry is None:
        from .tools import global_mcp_registry  # pylint: disable=import-outside-toplevel

        mcp_registry = global_mcp_registry
    mcp_registry.register_mcp_toolset(kc_toolset, server_name="kcatalog")
    return kc_toolset


def knowledge_catalog_discovery_agent(
    model: str | None = None,
    toolset: Any = None,
) -> Agent:
    """Builds the isolated ADK child ``Agent`` for Knowledge Catalog discovery.

    Isolates wide-net ``search_entries(semantic_search=True, page_size=50)``
    fan-out and two-pass ``lookup_context`` calls inside a dedicated child
    context window so 50-entry search payloads never bloat the parent
    orchestrator's reasoning trajectory.
    """
    resolved_model = (
        model
        or os.environ.get("KNOWLEDGE_CATALOG_DISCOVERY_MODEL", "").strip()
        or DEFAULT_KNOWLEDGE_CATALOG_DISCOVERY_MODEL
    )
    tools_list = [toolset] if toolset is not None else []
    return Agent(
        name="knowledge_catalog_discovery_agent",
        model=resolved_model,
        description=(
            "Discovers enterprise BigQuery, AlloyDB (pgvector), Neo4j (property graph), "
            "Elasticsearch (BM25), and Chronicle datalake assets, Context Sets, and "
            "governance aspects in Google Cloud Knowledge Catalog using semantic "
            "search_entries and two-pass lookup_context, returning a verified 6-item "
            "Pre-SQL Source Contract."
        ),
        instruction=(
            "You are the Knowledge Catalog Discovery & Governance Specialist.\n"
            "Execute the 5-step Two-Pass Discovery Protocol before any SQL, Cypher, Elasticsearch DSL, or YARA-L query is written:\n"
            "1. Semantic Decomposition: Decompose the request into 3 variations (Core Entities, Metrics & Grain, Domain Synonyms).\n"
            "2. Parallel Discovery Search: Call `kcatalog_search_entries` (passing `projectId` e.g. `'dandye-0324-chronicle'`, `query`, `pageSize=50`, `semanticSearch=True`) across your variations plus `entrygroup.type=context-set` or `entrygroup=secops-investigation-stores`.\n"
            "3. Scoped Context Set Search: When a Context Set or custom EntryGroup is found, query `entrygroup=<entry_group> (<variation>)` WITHOUT `system=`, `type=`, or `column:` filters.\n"
            "4. Two-Pass `kcatalog_lookup_context` (Hard Cap <= 10 entries, recommended <= 5 entries per call; pass `projectId` e.g. `'dandye-0324-chronicle'`, `location` e.g. `'us-central1'`, and `resources=[...]` containing full `projects/.../locations/.../entryGroups/.../entries/...` resource names):\n"
            "   - Pass 4A (Rules Pass): Inspect Context Set child rule entries.\n"
            "   - Pass 4B (Candidate Pass): Inspect the top candidate table/graph/index entries across all 6 metadata dimensions (technical schema/partitionBy/clusterBy, frequent_joins, business terms/overview/guidelines/governance_aspect, column null_ratio/sample_values, data_quality status, and relatedResources).\n"
            "5. Emit a mandatory 6-item Pre-SQL Source Contract:\n"
            "   - Selected Asset(s) & Governance Tier (`GOLD_CRITICAL` vs `BRONZE_ADHOC`, `usage_scope`, `update_frequency`, `is_certified`)\n"
            "   - Grain & Primary Key\n"
            "   - Cross-Table / Cross-Engine Join Path & Origin (`Query history` vs `Data insights`)\n"
            "   - Partitioning & Deduplication Rules (`QUALIFY ROW_NUMBER() OVER (PARTITION BY <pk> ORDER BY <updated_at> DESC) = 1`)\n"
            "   - Metric / Similarity / Detection Formula\n"
            "   - Data Quality & Null-Ratio Caveats"
        ),
        tools=tools_list,
    )


def init_knowledge_catalog_discovery_agent_tool(
    model: str | None = None,
    toolset: Any = None,
) -> AgentTool:
    """Wraps :func:`knowledge_catalog_discovery_agent` in an ADK :class:`AgentTool`."""
    return AgentTool(
        agent=knowledge_catalog_discovery_agent(model=model, toolset=toolset)
    )
