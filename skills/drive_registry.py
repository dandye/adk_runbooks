"""Drive-backed skill registry.

Serves Markdown runbooks (``text/markdown`` files) from a Google Drive folder
through the Google Drive remote MCP server instead of the local ``skills/``
tree. It keeps the :class:`skills.registry.SkillRegistry` contract so the
``load_skill`` / ``list_available_skills`` tools and the persona catalog work
unchanged; only the source of truth moves to Drive.

Design notes:

* The Drive MCP server at ``https://drivemcp.googleapis.com/mcp/v1`` is a
    stateless Streamable HTTP server, so each tool call is a single JSON-RPC
    ``POST`` (no ``initialize`` handshake, no session id). That keeps this module
    synchronous, which matters because ADK function tools such as ``load_skill``
    are plain synchronous callables.
* ``search_files`` lists the folder (``parentId = '<id>' and
    mimeType = 'text/markdown'``) and ``download_file_content`` returns the exact
    bytes, so YAML frontmatter and fenced code blocks survive untouched.
    ``read_file_content`` is deliberately not used for runbooks because it
    returns a verbalized representation.
* Runbook content is cached per file id and invalidated by ``modifiedTime``.
    A short TTL re-lists the folder so an analyst editing a runbook in Drive is
    picked up on the next ``load_skill`` without a redeploy.
"""

from __future__ import annotations

import base64
import itertools
import json
import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import yaml

from skills.registry import SkillMetadata, SkillRegistry

logger = logging.getLogger(__name__)

DEFAULT_DRIVE_MCP_URL = "https://drivemcp.googleapis.com/mcp/v1"
MARKDOWN_MIME_TYPE = "text/markdown"
DEFAULT_CACHE_TTL_SECONDS = 60.0
DEFAULT_PAGE_SIZE = 100
_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

TokenSource = Callable[[], str]


class DriveMcpError(RuntimeError):
    """Raised when the Drive MCP server rejects or fails a request."""


class DriveRegistryConfigError(ValueError):
    """Raised when the Drive registry is enabled but not configured."""


def local_adc_path() -> str:
    """Returns the ADC file google-auth will read, honoring direnv isolation."""
    explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if explicit:
        return explicit
    config_dir = os.environ.get("CLOUDSDK_CONFIG") or os.path.expanduser("~/.config/gcloud")
    return os.path.join(config_dir, "application_default_credentials.json")


class AdcTokenSource:
    """Thread-safe OAuth 2.0 access tokens from Application Default Credentials.

    The token must carry a Drive scope. Inside a direnv-isolated worktree that is
    ``gcloud auth login <ACCOUNT> --enable-gdrive-access --update-adc``.
    """

    def __init__(self) -> None:
        self._credentials: Any = None
        self._lock = threading.Lock()

    def __call__(self) -> str:
        import google.auth.exceptions  # pylint: disable=g-import-not-at-top

        with self._lock:
            try:
                if self._credentials is None:
                    self._credentials = self._load_credentials()
                if not self._credentials.valid:
                    from google.auth.transport.requests import Request  # pylint: disable=g-import-not-at-top

                    self._credentials.refresh(Request())
            except google.auth.exceptions.GoogleAuthError as err:
                raise DriveRegistryConfigError(
                        f"ADC authentication failed ({err}). Run: gcloud auth login <ACCOUNT> "
                        "--enable-gdrive-access --update-adc inside the worktree."
                ) from err
            token = self._credentials.token
        if not token:
            raise DriveMcpError("ADC refresh produced an empty access token.")
        return token

    @staticmethod
    def _load_credentials() -> Any:
        import google.auth  # pylint: disable=g-import-not-at-top

        adc_path = local_adc_path()
        if os.environ.get("CLOUDSDK_CONFIG") and not os.path.exists(adc_path):
            # Without this guard google-auth silently falls back to the Cloudtop VM's
            # metadata-server service account, which is the wrong identity entirely.
            raise DriveRegistryConfigError(
                    f"No ADC file at {adc_path}. Run: gcloud auth login <ACCOUNT> "
                    "--enable-gdrive-access --update-adc inside the worktree."
            )
        credentials, _ = google.auth.default()
        return credentials


class StaticTokenSource:
    """Token source for tests and pre-minted tokens."""

    def __init__(self, token: str) -> None:
        self._token = token

    def __call__(self) -> str:
        return self._token


def parse_jsonrpc_response(response: httpx.Response) -> dict[str, Any]:
    """Extracts the JSON-RPC message from a JSON or SSE Streamable HTTP response."""
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/event-stream"):
        last_message: dict[str, Any] | None = None
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if not data:
                continue
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict) and ("result" in message or "error" in message):
                last_message = message
        if last_message is None:
            raise DriveMcpError("SSE response contained no JSON-RPC result.")
        return last_message

    try:
        message = response.json()
    except json.JSONDecodeError as err:
        raise DriveMcpError(f"Non-JSON response: {response.text[:300]}") from err
    if isinstance(message, list):
        for item in message:
            if isinstance(item, dict) and ("result" in item or "error" in item):
                return item
        raise DriveMcpError("Batch response contained no JSON-RPC result.")
    if not isinstance(message, dict):
        raise DriveMcpError(f"Unexpected JSON-RPC payload: {str(message)[:300]}")
    return message


def unwrap_tool_result(result: dict[str, Any]) -> Any:
    """Returns a tool call's structured payload, raising on ``isError`` results."""
    texts = [
            part.get("text", "")
            for part in result.get("content", []) or []
            if isinstance(part, dict) and part.get("type") == "text"
    ]
    joined = "\n".join(t for t in texts if t)
    if result.get("isError"):
        raise DriveMcpError(joined or "Tool call failed without an error message.")
    structured = result.get("structuredContent")
    if structured is not None:
        return structured
    if not joined:
        return {}
    try:
        return json.loads(joined)
    except json.JSONDecodeError:
        return joined


class DriveMcpClient:
    """Minimal synchronous client for the stateless Drive MCP server."""

    def __init__(
            self,
            *,
            url: str | None = None,
            token_source: TokenSource | None = None,
            quota_project: str | None = None,
            timeout: float = 60.0,
            transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.url = url or os.environ.get("DRIVE_MCP_URL") or DEFAULT_DRIVE_MCP_URL
        if quota_project is None:
            quota_project = (
                    os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
                    or os.environ.get("GCP_PROJECT_ID")
                    or os.environ.get("GOOGLE_CLOUD_PROJECT")
                    or ""
            )
        self.quota_project = quota_project
        self._token_source = token_source or AdcTokenSource()
        self._http = httpx.Client(timeout=timeout, transport=transport)
        self._ids = itertools.count(1)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> DriveMcpClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        headers = {
                "Authorization": f"Bearer {self._token_source()}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
        }
        if self.quota_project:
            # gcloud's OAuth client is Google-owned, so the project with
            # drivemcp.googleapis.com enabled (and allowlisted) must be named here.
            headers["X-Goog-User-Project"] = self.quota_project
        return headers

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Invokes ``tools/call`` and returns the unwrapped structured result."""
        payload = {
                "jsonrpc": "2.0",
                "id": next(self._ids),
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
        }
        try:
            response = self._http.post(self.url, json=payload, headers=self._headers())
        except httpx.HTTPError as err:
            raise DriveMcpError(f"HTTP transport error calling {name}: {err}") from err
        if response.status_code >= 400:
            raise DriveMcpError(
                    f"HTTP {response.status_code} calling {name}: {response.text[:300]}"
            )
        message = parse_jsonrpc_response(response)
        if "error" in message:
            error = message["error"]
            raise DriveMcpError(
                    f"{name} failed: {error.get('message', error)} (code {error.get('code')})"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise DriveMcpError(f"{name} returned no result object: {str(message)[:300]}")
        return unwrap_tool_result(result)

    # Convenience wrappers mirroring the public /mcp/v1 toolset.

    def search_files(
            self,
            query: str,
            *,
            page_size: int = DEFAULT_PAGE_SIZE,
            page_token: str | None = None,
            exclude_content_snippets: bool = True,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
                "query": query,
                "pageSize": page_size,
                "excludeContentSnippets": exclude_content_snippets,
        }
        if page_token:
            arguments["pageToken"] = page_token
        payload = self.call_tool("search_files", arguments)
        return payload if isinstance(payload, dict) else {}

    def iter_files(self, query: str, *, page_size: int = DEFAULT_PAGE_SIZE) -> Iterator[dict[str, Any]]:
        """Yields every file matching ``query`` across result pages."""
        page_token: str | None = None
        while True:
            page = self.search_files(query, page_size=page_size, page_token=page_token)
            for item in page.get("files", []) or []:
                yield item
            page_token = page.get("nextPageToken")
            if not page_token:
                return

    def download_text(self, file_id: str) -> str:
        """Returns the exact UTF-8 text of a blob file via ``download_file_content``."""
        payload = self.call_tool("download_file_content", {"fileId": file_id})
        encoded = payload.get("content", "") if isinstance(payload, dict) else ""
        if not encoded:
            return ""
        try:
            return base64.b64decode(encoded).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as err:
            raise DriveMcpError(f"Could not decode content of {file_id}: {err}") from err

    def read_file_content(self, file_id: str) -> str:
        """Returns the verbalized text of a file via ``read_file_content``."""
        payload = self.call_tool("read_file_content", {"fileId": file_id})
        if isinstance(payload, dict):
            return str(payload.get("fileContent", ""))
        return str(payload)

    def get_file_metadata(self, file_id: str) -> dict[str, Any]:
        payload = self.call_tool(
                "get_file_metadata", {"fileId": file_id, "excludeContentSnippets": True}
        )
        return payload if isinstance(payload, dict) else {}

    def create_markdown_file(
            self, *, title: str, text: str, parent_id: str
    ) -> dict[str, Any]:
        """Creates a native ``text/markdown`` file (no Google Doc conversion)."""
        payload = self.call_tool(
                "create_file",
                {
                        "title": title,
                        "contentMimeType": MARKDOWN_MIME_TYPE,
                        "textContent": text,
                        "parentId": parent_id,
                        # Without this the server converts text uploads into Google Docs.
                        "disableConversionToGoogleType": True,
                },
        )
        return payload if isinstance(payload, dict) else {}


def build_runbook_query(folder_id: str, mime_type: str = MARKDOWN_MIME_TYPE) -> str:
    """Builds the Drive MCP query for runbooks in a folder.

    The Drive MCP grammar uses ``parentId = '<id>'`` rather than the Drive API
    v3 ``'<id>' in parents`` form.
    """
    if not folder_id:
        raise DriveRegistryConfigError("A Drive folder id is required.")
    return f"parentId = '{folder_id}' and mimeType = '{mime_type}'"


def skill_name_from_title(title: str) -> str:
    """Derives a skill name from a Drive file title such as ``triage-alerts.md``."""
    stem = title.rsplit(".", 1)[0] if title.lower().endswith(".md") else title
    stem = stem.strip().lower()
    stem = re.sub(r"[\s_]+", "-", stem)
    stem = re.sub(r"[^a-z0-9-]", "", stem)
    return stem.strip("-") or title


@dataclass
class DriveSkillMetadata(SkillMetadata):
    """Skill metadata for a runbook stored in Google Drive."""

    file_id: str = ""
    title: str = ""
    modified_time: str = ""
    view_url: str = ""
    content: str | None = field(default=None, repr=False)


class DriveSkillRegistry(SkillRegistry):
    """Skill registry whose runbooks live in a Google Drive folder."""

    def __init__(
            self,
            *,
            folder_id: str | None = None,
            client: DriveMcpClient | None = None,
            cache_ttl_seconds: float | None = None,
            clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.folder_id = folder_id or os.environ.get("DRIVE_RUNBOOKS_FOLDER_ID", "")
        if not self.folder_id:
            raise DriveRegistryConfigError(
                    "DRIVE_RUNBOOKS_FOLDER_ID is not set; cannot build DriveSkillRegistry."
            )
        if cache_ttl_seconds is None:
            cache_ttl_seconds = float(
                    os.environ.get("DRIVE_RUNBOOKS_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS)
            )
        self.cache_ttl_seconds = cache_ttl_seconds
        self.client = client or DriveMcpClient()
        self._clock = clock
        self._last_scan: float | None = None
        self._lock = threading.RLock()
        # SkillRegistry.__init__ would scan a local directory; emulate its state
        # instead and run our own scan.
        self.skills_dir = Path("googledrive") / self.folder_id
        self.skills: dict[str, SkillMetadata] = {}
        self.scan_skills()

    def close(self) -> None:
        """Closes the underlying DriveMcpClient HTTP connection pool."""
        if hasattr(self.client, "close"):
            self.client.close()

    def __enter__(self) -> DriveSkillRegistry:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # -- scanning -----------------------------------------------------------

    def scan_skills(self) -> dict[str, SkillMetadata]:
        """Lists the Drive folder and (re)downloads runbooks whose modifiedTime changed."""
        with self._lock:
            previous: dict[str, DriveSkillMetadata] = {
                    meta.file_id: meta
                    for meta in self.skills.values()
                    if isinstance(meta, DriveSkillMetadata)
            }
            discovered: dict[str, SkillMetadata] = {}
            query = build_runbook_query(self.folder_id)
            for item in self.client.iter_files(query):
                file_id = item.get("id", "")
                if not file_id:
                    continue
                title = item.get("title", file_id)
                modified = item.get("modifiedTime", "")
                cached = previous.get(file_id)
                if cached is not None and cached.modified_time == modified and cached.content is not None:
                    meta = cached
                else:
                    try:
                        content = self.client.download_text(file_id)
                    except DriveMcpError as err:
                        logger.warning("Skipping Drive runbook %s (%s): %s", title, file_id, err)
                        continue
                    meta = self._build_metadata(item, content)
                self._register(discovered, meta)
            self.skills = discovered
            self._last_scan = self._clock()
            unique_skills = len({id(meta) for meta in discovered.values()})
            logger.info(
                "Drive runbook registry scanned folder %s: %d skills",
                self.folder_id,
                unique_skills,
            )
            return self.skills

    def _build_metadata(self, item: dict[str, Any], content: str) -> DriveSkillMetadata:
        title = item.get("title", item.get("id", ""))
        fm_data = parse_frontmatter(content)
        name = str(fm_data.get("name") or skill_name_from_title(title))
        description = str(fm_data.get("description", "")).strip() or f"Runbook {title}"
        category = str(fm_data.get("category", "") or "drive")
        version = str(fm_data.get("version", "1.0.0"))
        return DriveSkillMetadata(
                name=name,
                description=description,
                category=category,
                path=self.skills_dir / title,
                version=version,
                file_id=item.get("id", ""),
                title=title,
                modified_time=item.get("modifiedTime", ""),
                view_url=item.get("viewUrl", ""),
                content=content,
        )

    @staticmethod
    def _register(target: dict[str, SkillMetadata], meta: SkillMetadata) -> None:
        target[meta.name] = meta
        alt_hyphen = meta.name.replace("_", "-")
        if alt_hyphen != meta.name:
            target[alt_hyphen] = meta
        alt_underscore = meta.name.replace("-", "_")
        if alt_underscore != meta.name:
            target[alt_underscore] = meta

    def _refresh_if_stale(self) -> None:
        if self._last_scan is None:
            self.scan_skills()
            return
        if self.cache_ttl_seconds >= 0 and (self._clock() - self._last_scan) > self.cache_ttl_seconds:
            try:
                self.scan_skills()
            except DriveMcpError as err:
                # Serve the last good catalog rather than failing a live investigation.
                logger.warning("Drive runbook refresh failed; serving cached catalog: %s", err)

    # -- SkillRegistry contract ---------------------------------------------

    def get_skill(self, name: str) -> SkillMetadata | None:
        self._refresh_if_stale()
        return super().get_skill(name)

    def get_skill_content(self, name: str) -> str:
        """Returns the exact Markdown of a Drive runbook, refreshing when stale."""
        meta = self.get_skill(name)
        if not isinstance(meta, DriveSkillMetadata):
            return f"Error: Skill '{name}' not found in Drive runbook registry."
        if meta.content is None:
            try:
                meta.content = self.client.download_text(meta.file_id)
            except DriveMcpError as err:
                return f"Error: could not download skill '{name}' from Drive: {err}"
        return meta.content

    def get_skill_catalog(self, skill_names: list[str] | None = None) -> str:
        self._refresh_if_stale()
        return super().get_skill_catalog(skill_names)

    def list_skills_by_category(self, category: str) -> list[SkillMetadata]:
        self._refresh_if_stale()
        return super().list_skills_by_category(category)


def parse_frontmatter(content: str) -> dict[str, Any]:
    """Returns the YAML frontmatter mapping of a Markdown document, or ``{}``."""
    match = _FRONTMATTER_RE.match(content)
    if not match:
        return {}
    try:
        data = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}
