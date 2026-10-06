"""Google Drive remote MCP integration for the SOC multi-agent.

Two concerns live here:

1. **Runbook source selection** -- :func:`build_skill_registry` decides where
   runbooks come from using ``RUNBOOK_SOURCE``. ``drive`` (the default on this
   branch) serves ``text/markdown`` runbooks from the Drive folder named by
   ``DRIVE_RUNBOOKS_FOLDER_ID`` through the Drive MCP server; ``local`` uses the
   checked-in ``skills/`` tree. Any Drive problem (missing folder id, missing
   ADC, access denied) degrades to the local tree with a warning so importing
   the agents never fails in CI or offline.

2. **Drive as a tool for agents** -- :func:`init_drive_toolset` builds an ADK
   ``McpToolset`` for the Drive MCP server so agents can call
   ``drive_search_files`` / ``drive_read_file_content`` / ``drive_create_file``
   directly, and :func:`publish_report_to_drive` lets ``write_report`` publish
   finished reports into ``DRIVE_REPORTS_FOLDER_ID`` as native Markdown files.

Authentication is the gcloud Application Default Credentials of the isolated
worktree (``gcloud auth login <ACCOUNT> --enable-gdrive-access --update-adc``)
plus ``X-Goog-User-Project`` for the project that has ``drivemcp.googleapis.com``
enabled.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Callable

import httpx

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from skills.drive_registry import (  # noqa: E402  pylint: disable=wrong-import-position
    DEFAULT_DRIVE_MCP_URL,
    AdcTokenSource,
    DriveMcpClient,
    DriveMcpError,
    DriveRegistryConfigError,
    DriveSkillRegistry,
    TokenSource,
)
from skills.registry import SkillRegistry  # noqa: E402  pylint: disable=wrong-import-position

logger = logging.getLogger(__name__)

RUNBOOK_SOURCE_DRIVE = "drive"
RUNBOOK_SOURCE_LOCAL = "local"
DEFAULT_RUNBOOK_SOURCE = RUNBOOK_SOURCE_DRIVE

DRIVE_TOOL_NAME_PREFIX = "drive"
# Read-mostly subset of the public /mcp/v1 toolset; create_file is the only
# write so agents can publish reports without being able to copy or share.
DRIVE_TOOL_FILTER = [
    "search_files",
    "read_file_content",
    "download_file_content",
    "get_file_metadata",
    "create_file",
]
TOOLSET_CONNECT_TIMEOUT_SECONDS = 30.0
TOOLSET_SSE_READ_TIMEOUT_SECONDS = 300.0

_client_lock = threading.Lock()
_shared_client: DriveMcpClient | None = None


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def runbook_source() -> str:
    """Returns the normalized ``RUNBOOK_SOURCE`` (``drive`` or ``local``)."""
    return (os.environ.get("RUNBOOK_SOURCE") or DEFAULT_RUNBOOK_SOURCE).strip().lower()


def drive_mcp_url() -> str:
    return os.environ.get("DRIVE_MCP_URL") or DEFAULT_DRIVE_MCP_URL


def drive_quota_project() -> str:
    return (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or ""
    )


def runbooks_folder_id() -> str:
    return os.environ.get("DRIVE_RUNBOOKS_FOLDER_ID", "").strip()


def reports_folder_id() -> str:
    return os.environ.get("DRIVE_REPORTS_FOLDER_ID", "").strip()


def drive_toolset_configured() -> bool:
    """True when Drive is configured well enough to hand agents the Drive tools.

    ``DRIVE_MCP_TOOLSET=0`` disables the toolset even when folders are set,
    which is handy for evals that must not touch Drive.
    """
    if os.environ.get("DRIVE_MCP_TOOLSET", "1").strip().lower() in {"0", "false", "no", "off"}:
        return False
    return bool(runbooks_folder_id() or reports_folder_id())


def get_drive_client() -> DriveMcpClient:
    """Returns a process-wide synchronous Drive MCP client (ADC-authenticated)."""
    global _shared_client  # pylint: disable=global-statement
    with _client_lock:
        if _shared_client is None:
            _shared_client = DriveMcpClient()
        return _shared_client


def reset_drive_client() -> None:
    """Drops the shared client (tests and credential rotation)."""
    global _shared_client  # pylint: disable=global-statement
    with _client_lock:
        if _shared_client is not None:
            _shared_client.close()
        _shared_client = None


# ---------------------------------------------------------------------------
# Runbook registry selection
# ---------------------------------------------------------------------------


def build_skill_registry(
    source: str | None = None,
    *,
    drive_registry_factory: Callable[[], SkillRegistry] = DriveSkillRegistry,
    local_registry_factory: Callable[[], SkillRegistry] = SkillRegistry,
) -> SkillRegistry:
    """Builds the runbook registry selected by ``RUNBOOK_SOURCE``.

    Args:
        source: Overrides ``RUNBOOK_SOURCE``; ``drive`` or ``local``.
        drive_registry_factory: Builds the Drive registry (injectable for tests).
        local_registry_factory: Builds the local registry (injectable for tests).

    Returns:
        A :class:`skills.registry.SkillRegistry`. When ``drive`` is requested
        but unusable the local registry is returned and a warning is logged.
    """
    selected = (source or runbook_source()).strip().lower()
    if selected == RUNBOOK_SOURCE_DRIVE:
        try:
            registry = drive_registry_factory()
            logger.info(
                "Runbook source: Google Drive folder %s (%d skills)",
                getattr(registry, "folder_id", "?"),
                len({id(meta) for meta in registry.skills.values()}),
            )
            return registry
        except DriveRegistryConfigError as err:
            logger.warning(
                "RUNBOOK_SOURCE=drive but Drive is not configured (%s); "
                "falling back to the local skills/ tree.",
                err,
            )
        except DriveMcpError as err:
            logger.warning(
                "RUNBOOK_SOURCE=drive but the Drive MCP server rejected the request "
                "(%s); falling back to the local skills/ tree.",
                err,
            )
    elif selected != RUNBOOK_SOURCE_LOCAL:
        logger.warning(
            "Unknown RUNBOOK_SOURCE=%r; expected 'drive' or 'local'. Using local skills/.",
            selected,
        )
    return local_registry_factory()


# ---------------------------------------------------------------------------
# ADK McpToolset for the Drive MCP server
# ---------------------------------------------------------------------------


class BearerTokenAuth(httpx.Auth):
    """httpx auth hook that stamps a fresh OAuth bearer token on every request.

    The token is deliberately not placed in the static connection ``headers``:
    ADK pools MCP sessions keyed by a hash of those headers, so a rotating
    access token there would open a new session every time ADC refreshed.
    """

    requires_request_body = False
    requires_response_body = False

    def __init__(self, token_source: TokenSource) -> None:
        self._token_source = token_source

    def auth_flow(self, request: httpx.Request):
        request.headers["Authorization"] = f"Bearer {self._token_source()}"
        yield request


def make_drive_httpx_client_factory(token_source: TokenSource):
    """Returns an ``httpx_client_factory`` for ``StreamableHTTPConnectionParams``.

    The MCP SDK calls the factory as ``factory(headers=..., timeout=..., auth=...)``
    and expects an ``httpx.AsyncClient``.
    """

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            auth=auth or BearerTokenAuth(token_source),
            follow_redirects=True,
        )

    return factory


def init_drive_toolset(
    *,
    url: str | None = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    tool_filter: list[str] | None = None,
):
    """Builds the ADK ``McpToolset`` for the Google Drive remote MCP server.

    Args:
        url: Drive MCP endpoint; defaults to ``DRIVE_MCP_URL``.
        token_source: Callable returning a bearer token; defaults to ADC.
        quota_project: Value for ``X-Goog-User-Project``; defaults to
            ``DRIVE_MCP_QUOTA_PROJECT`` / ``GCP_PROJECT_ID``.
        tool_filter: Drive tool names to expose; defaults to ``DRIVE_TOOL_FILTER``.

    Returns:
        google.adk.tools.mcp_tool.mcp_toolset.MCPToolset
    """
    # Imported lazily so the registry half of this module works without ADK's
    # optional ``mcp`` extra installed.
    from google.adk.tools.mcp_tool.mcp_session_manager import (  # pylint: disable=import-outside-toplevel
        StreamableHTTPConnectionParams,
    )
    from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset  # pylint: disable=import-outside-toplevel

    project = drive_quota_project() if quota_project is None else quota_project
    headers = {"X-Goog-User-Project": project} if project else None
    return MCPToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=url or drive_mcp_url(),
            headers=headers,
            timeout=TOOLSET_CONNECT_TIMEOUT_SECONDS,
            sse_read_timeout=TOOLSET_SSE_READ_TIMEOUT_SECONDS,
            httpx_client_factory=make_drive_httpx_client_factory(token_source or AdcTokenSource()),
        ),
        tool_filter=list(tool_filter or DRIVE_TOOL_FILTER),
        tool_name_prefix=DRIVE_TOOL_NAME_PREFIX,
    )


# ---------------------------------------------------------------------------
# Report publishing
# ---------------------------------------------------------------------------


def publish_report_to_drive(
    report_name: str,
    report_contents: str,
    *,
    folder_id: str | None = None,
    client: DriveMcpClient | None = None,
) -> dict[str, Any]:
    """Creates ``report_name`` as a native ``text/markdown`` file in Drive.

    Args:
        report_name: File title, e.g. ``incident_report_20260101_120000.md``.
        report_contents: Markdown body.
        folder_id: Destination folder; defaults to ``DRIVE_REPORTS_FOLDER_ID``.
        client: Drive MCP client; defaults to the shared ADC client.

    Returns:
        ``{"id", "title", "viewUrl", "parentId"}`` of the created file.

    Raises:
        DriveRegistryConfigError: when no reports folder is configured.
        DriveMcpError: when the Drive MCP server rejects the upload.
    """
    destination = (folder_id or reports_folder_id()).strip()
    if not destination:
        raise DriveRegistryConfigError(
            "DRIVE_REPORTS_FOLDER_ID is not set; cannot publish the report to Drive."
        )
    drive = client or get_drive_client()
    created = drive.create_markdown_file(
        title=report_name, text=report_contents, parent_id=destination
    )
    return {
        "id": created.get("id", ""),
        "title": created.get("title", report_name),
        "viewUrl": created.get("viewUrl", ""),
        "parentId": created.get("parentId", destination),
    }
