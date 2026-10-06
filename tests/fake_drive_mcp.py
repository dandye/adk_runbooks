"""In-process fake of the Google Drive remote MCP server for tests.

The real server (``https://drivemcp.googleapis.com/mcp/v1``) is a stateless
Streamable HTTP MCP server. This fake runs the official ``mcp`` FastMCP server
in the same mode (``stateless_http=True``) behind uvicorn on an ephemeral
localhost port, so the production client code path (plain JSON-RPC ``POST``
without ``initialize``, JSON or SSE responses) is exercised for real.

Tool names and the request/response field names mirror the public ``/mcp/v1``
toolset exactly (``fileId``, ``title``, ``parentId``, ``modifiedTime``,
base64 ``content`` from ``download_file_content``, ``fileContent`` from
``read_file_content`` ...) so a test that passes here would have sent a valid
request to the real server.
"""

from __future__ import annotations

import base64
import itertools
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"
GOOGLE_DOC_MIME_TYPE = "application/vnd.google-apps.document"
MARKDOWN_MIME_TYPE = "text/markdown"
DEFAULT_MODIFIED_TIME = "2026-01-01T00:00:00.000Z"
PERMISSION_DENIED_MESSAGE = "The caller does not have permission"

_CLAUSE_RE = re.compile(
    r"^\s*(?P<field>[A-Za-z]+)\s+(?P<op>=|!=|contains)\s+"
    r"(?:'(?P<quoted>[^']*)'|(?P<bare>true|false))\s*$"
)


@dataclass
class FakeDriveFile:
    """One file in the fake Drive."""

    id: str
    title: str
    parent_id: str
    mime_type: str
    data: bytes
    modified_time: str

    def to_api(self) -> dict[str, Any]:
        """Serializes to the ``File`` shape returned by the Drive MCP tools."""
        extension = self.title.rsplit(".", 1)[1] if "." in self.title else ""
        return {
            "id": self.id,
            "title": self.title,
            "parentId": self.parent_id,
            "mimeType": self.mime_type,
            "fileSize": str(len(self.data)),
            "description": "",
            "fileExtension": extension,
            "viewUrl": f"https://drive.google.com/file/d/{self.id}/view",
            "createdTime": self.modified_time,
            "modifiedTime": self.modified_time,
            "owner": "fake-user@example.com",
            "canAddChildren": self.mime_type == FOLDER_MIME_TYPE,
        }


class FakeDriveStore:
    """In-memory Drive contents plus a record of every tool call received."""

    def __init__(self) -> None:
        self.files: dict[str, FakeDriveFile] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.last_headers: dict[str, str] = {}
        self.deny_message: str | None = None
        self._ids = itertools.count(1)
        self._lock = threading.Lock()

    # -- population helpers used by tests ------------------------------------

    def add_folder(self, title: str, parent_id: str = "root") -> str:
        return self._add(title, parent_id, FOLDER_MIME_TYPE, b"", DEFAULT_MODIFIED_TIME)

    def add_markdown(
        self,
        title: str,
        text: str,
        parent_id: str,
        *,
        modified_time: str = DEFAULT_MODIFIED_TIME,
        mime_type: str = MARKDOWN_MIME_TYPE,
    ) -> str:
        return self._add(title, parent_id, mime_type, text.encode("utf-8"), modified_time)

    def update_markdown(self, file_id: str, text: str, *, modified_time: str) -> None:
        with self._lock:
            current = self.files[file_id]
            self.files[file_id] = FakeDriveFile(
                id=current.id,
                title=current.title,
                parent_id=current.parent_id,
                mime_type=current.mime_type,
                data=text.encode("utf-8"),
                modified_time=modified_time,
            )

    def calls_for(self, tool_name: str) -> list[dict[str, Any]]:
        return [args for name, args in self.calls if name == tool_name]

    def _add(self, title: str, parent_id: str, mime_type: str, data: bytes, modified_time: str) -> str:
        with self._lock:
            file_id = f"fake-{next(self._ids):04d}"
            self.files[file_id] = FakeDriveFile(
                id=file_id,
                title=title,
                parent_id=parent_id,
                mime_type=mime_type,
                data=data,
                modified_time=modified_time,
            )
            return file_id

    # -- tool implementations -------------------------------------------------

    def _record(self, tool_name: str, arguments: dict[str, Any]) -> None:
        with self._lock:
            self.calls.append((tool_name, arguments))
        if self.deny_message:
            raise ToolError(self.deny_message)

    def _get(self, file_id: str) -> FakeDriveFile:
        try:
            return self.files[file_id]
        except KeyError as err:
            raise ToolError(f"File not found: {file_id}") from err

    def search(
        self,
        query: str,
        page_size: int,
        page_token: str | None,
        exclude_content_snippets: bool,
    ) -> dict[str, Any]:
        self._record(
            "search_files",
            {
                "query": query,
                "pageSize": page_size,
                "pageToken": page_token,
                "excludeContentSnippets": exclude_content_snippets,
            },
        )
        predicates = [_compile_clause(clause) for clause in re.split(r"\s+and\s+", query.strip())]
        matches = [
            f for f in sorted(self.files.values(), key=lambda f: f.id)
            if all(pred(f) for pred in predicates)
        ]
        start = int(page_token) if page_token else 0
        page = matches[start : start + page_size]
        result: dict[str, Any] = {"files": []}
        for f in page:
            item = f.to_api()
            if not exclude_content_snippets and f.mime_type != FOLDER_MIME_TYPE:
                item["contentSnippet"] = f.data[:80].decode("utf-8", errors="replace")
            result["files"].append(item)
        if start + page_size < len(matches):
            result["nextPageToken"] = str(start + page_size)
        return result

    def download(self, file_id: str, export_mime_type: str | None) -> dict[str, Any]:
        self._record("download_file_content", {"fileId": file_id, "exportMimeType": export_mime_type})
        f = self._get(file_id)
        if f.mime_type == FOLDER_MIME_TYPE:
            raise ToolError("Folders cannot be downloaded")
        return {
            "id": f.id,
            "title": f.title,
            "mimeType": export_mime_type or f.mime_type,
            "content": base64.b64encode(f.data).decode("ascii"),
        }

    def read(self, file_id: str, include_comments: bool) -> dict[str, Any]:
        self._record("read_file_content", {"fileId": file_id, "includeComments": include_comments})
        f = self._get(file_id)
        text = f.data.decode("utf-8", errors="replace")
        # The real tool returns a verbalized rendering, not the raw bytes;
        # collapsing Markdown fences is enough to make that distinction testable.
        verbalized = text.replace("```", "")
        return {
            "fileContent": verbalized,
            "textFormattingNotSupported": False,
            "contentAnchoredComments": [],
            "unanchoredComments": [],
        }

    def metadata(self, file_id: str, exclude_content_snippets: bool) -> dict[str, Any]:
        self._record(
            "get_file_metadata",
            {"fileId": file_id, "excludeContentSnippets": exclude_content_snippets},
        )
        return self._get(file_id).to_api()

    def create(
        self,
        title: str,
        content_mime_type: str | None,
        text_content: str | None,
        base64_content: str | None,
        parent_id: str | None,
        disable_conversion: bool,
    ) -> dict[str, Any]:
        self._record(
            "create_file",
            {
                "title": title,
                "contentMimeType": content_mime_type,
                "textContent": text_content,
                "base64Content": base64_content,
                "parentId": parent_id,
                "disableConversionToGoogleType": disable_conversion,
            },
        )
        if text_content is not None and base64_content is not None:
            raise ToolError("Provide either textContent or base64Content, not both")
        if base64_content is not None:
            data = base64.b64decode(base64_content)
        else:
            data = (text_content or "").encode("utf-8")
        mime_type = content_mime_type or "application/octet-stream"
        if not disable_conversion and mime_type.startswith("text/"):
            # Mirrors the real server: text uploads become Google Docs unless
            # the caller opts out of conversion.
            mime_type = GOOGLE_DOC_MIME_TYPE
        file_id = self._add(title, parent_id or "root", mime_type, data, _now_rfc3339())
        return self.files[file_id].to_api()


def _compile_clause(clause: str):
    match = _CLAUSE_RE.match(clause)
    if not match:
        raise ToolError(f"Invalid query clause: {clause!r}")
    field_name = match.group("field")
    op = match.group("op")
    value = match.group("quoted") if match.group("quoted") is not None else match.group("bare")

    def getter(f: FakeDriveFile) -> str:
        if field_name == "parentId":
            return f.parent_id
        if field_name == "mimeType":
            return f.mime_type
        if field_name == "title":
            return f.title
        if field_name == "fullText":
            return f.title + "\n" + f.data.decode("utf-8", errors="replace")
        if field_name == "trashed":
            return "false"
        raise ToolError(f"Unsupported query field: {field_name}")

    if op == "=":
        return lambda f: getter(f) == value
    if op == "!=":
        return lambda f: getter(f) != value
    return lambda f: value.lower() in getter(f).lower()


def _now_rfc3339() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def build_fastmcp(store: FakeDriveStore, *, json_response: bool, host: str, port: int) -> FastMCP:
    """Builds the FastMCP app exposing the Drive tool surface over ``store``."""
    server = FastMCP(
        "fake-drive-mcp",
        host=host,
        port=port,
        stateless_http=True,
        json_response=json_response,
        log_level="WARNING",
    )

    # Parameter names are camelCase on purpose: FastMCP derives the JSON schema
    # property names from them and they must match the real tool contracts.

    @server.tool(name="search_files")
    def search_files(  # pylint: disable=invalid-name
        query: str,
        pageSize: int = 20,
        pageToken: str | None = None,
        excludeContentSnippets: bool = False,
    ) -> dict[str, Any]:
        return store.search(query, pageSize, pageToken, excludeContentSnippets)

    @server.tool(name="download_file_content")
    def download_file_content(fileId: str, exportMimeType: str | None = None) -> dict[str, Any]:  # pylint: disable=invalid-name
        return store.download(fileId, exportMimeType)

    @server.tool(name="read_file_content")
    def read_file_content(fileId: str, includeComments: bool = False) -> dict[str, Any]:  # pylint: disable=invalid-name
        return store.read(fileId, includeComments)

    @server.tool(name="get_file_metadata")
    def get_file_metadata(fileId: str, excludeContentSnippets: bool = False) -> dict[str, Any]:  # pylint: disable=invalid-name
        return store.metadata(fileId, excludeContentSnippets)

    @server.tool(name="create_file")
    def create_file(  # pylint: disable=invalid-name
        title: str,
        contentMimeType: str | None = None,
        textContent: str | None = None,
        base64Content: str | None = None,
        parentId: str | None = None,
        disableConversionToGoogleType: bool = False,
    ) -> dict[str, Any]:
        return store.create(
            title, contentMimeType, textContent, base64Content, parentId, disableConversionToGoogleType
        )

    return server


class _HeaderRecorder:
    """ASGI wrapper that records the headers of the most recent HTTP request."""

    def __init__(self, app, store: FakeDriveStore) -> None:
        self._app = app
        self._store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self._store.last_headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers", [])
            }
        await self._app(scope, receive, send)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeDriveMcpServer:
    """Runs the fake Drive MCP server on a background thread.

    Usage::

        with FakeDriveMcpServer() as server:
            client = DriveMcpClient(url=server.url, token_source=StaticTokenSource("t"))
    """

    def __init__(self, store: FakeDriveStore | None = None, *, json_response: bool = True) -> None:
        self.store = store or FakeDriveStore()
        self.json_response = json_response
        self.host = "127.0.0.1"
        self.port = _free_port()
        self.url = f"http://{self.host}:{self.port}/mcp"
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "FakeDriveMcpServer":
        fastmcp = build_fastmcp(
            self.store, json_response=self.json_response, host=self.host, port=self.port
        )
        app = _HeaderRecorder(fastmcp.streamable_http_app(), self.store)
        config = uvicorn.Config(
            app, host=self.host, port=self.port, log_level="warning", lifespan="on"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, name="fake-drive-mcp", daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("fake Drive MCP server thread exited during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("fake Drive MCP server did not start in time")
            time.sleep(0.01)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)

    def __enter__(self) -> "FakeDriveMcpServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
