"""In-process fake of the Google Developer Knowledge remote MCP server for tests.

The real server (``https://developerknowledge.googleapis.com/mcp``) is a
stateless Streamable HTTP MCP server exposing three tools:

* ``answer_query(query: str)``
* ``search_documents(query: str)``
* ``get_documents(names: list[str])``

This fake runs the official ``mcp`` FastMCP server in stateless Streamable HTTP
mode (``stateless_http=True``) behind uvicorn on an ephemeral localhost port
and records incoming HTTP headers on every request so tests can verify both:

1. Startup tool discovery (``McpToolset.get_tools(readonly_context=None)``)
   using static ``StreamableHTTPConnectionParams(headers=...)`` or
   ``httpx_client_factory``.
2. Per-turn tool execution (``readonly_context`` present) using
   ``McpToolset(header_provider=...)`` and ``X-Goog-Api-Key`` or OAuth bearer
   tokens.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError


@dataclass
class FakeKnowledgeDoc:
    """One canonical developer documentation entry in the fake corpus."""

    name: str
    url: str
    title: str
    content: str

    def to_chunk(self) -> dict[str, Any]:
        return {
            "parent": self.name,
            "url": self.url,
            "title": self.title,
            "content": self.content[:400],
        }

    def to_document(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "title": self.title,
            "content": self.content,
        }


class FakeDevKnowledgeStore:
    """In-memory Developer Knowledge corpus plus request/header recording."""

    def __init__(self, *, seed_defaults: bool = True) -> None:
        self.docs: dict[str, FakeKnowledgeDoc] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.last_headers: dict[str, str] = {}
        self.header_history: list[dict[str, str]] = []
        self.require_auth: bool = False
        self._lock = threading.Lock()
        if seed_defaults:
            self._seed_default_corpus()

    def _seed_default_corpus(self) -> None:
        self.add_doc(
            name="documents/docs.cloud.google.com/iam/docs/understanding-roles",
            url="https://docs.cloud.google.com/iam/docs/understanding-roles",
            title="Understanding IAM predefined roles",
            content=(
                "Grant predefined roles such as roles/aiplatform.user for Vertex AI "
                "runtime access and roles/chronicle.viewer for read-only Chronicle SIEM "
                "investigations. Avoid granting primitive roles/owner or roles/editor "
                "to service accounts."
            ),
        )
        self.add_doc(
            name="documents/adk.dev/tools/google-search-grounding",
            url="https://adk.dev/tools/google-search-grounding",
            title="Using Google Search Grounding with Custom Tools in ADK",
            content=(
                "In Gemini, the built-in google_search grounding tool cannot be combined "
                "directly in the same tools list with custom FunctionTools or McpToolsets. "
                "Wrap a dedicated Agent(tools=[google_search]) inside AgentTool to expose "
                "web search grounding to a parent orchestrator."
            ),
        )

    def add_doc(self, *, name: str, url: str, title: str, content: str) -> None:
        with self._lock:
            self.docs[name] = FakeKnowledgeDoc(
                name=name, url=url, title=title, content=content
            )

    def calls_for(self, tool_name: str) -> list[dict[str, Any]]:
        return [args for name, args in self.calls if name == tool_name]

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
                    "Expected X-Goog-Api-Key or Authorization Bearer token."
                )

    def answer_query(self, query: str) -> dict[str, Any]:
        self._record("answer_query", {"query": query})
        matches = self._match_docs(query)
        if not matches:
            return {
                "answer_text": f"No official Google developer documentation matched: {query}",
                "references": [],
            }
        synthesized = " ".join(doc.content for doc in matches)
        return {
            "answer_text": synthesized,
            "references": [doc.name for doc in matches],
        }

    def search_documents(self, query: str) -> dict[str, Any]:
        self._record("search_documents", {"query": query})
        matches = self._match_docs(query)
        return {
            "results": [doc.to_chunk() for doc in matches],
        }

    def get_documents(self, names: list[str]) -> dict[str, Any]:
        self._record("get_documents", {"names": list(names)})
        if len(names) > 20:
            raise ToolError("A maximum of 20 documents can be retrieved in one call.")
        found: list[dict[str, Any]] = []
        for name in names:
            doc = self.docs.get(name)
            if doc is None:
                raise ToolError(f"Document not found: {name}")
            found.append(doc.to_document())
        return {"documents": found}

    def _match_docs(self, query: str) -> list[FakeKnowledgeDoc]:
        tokens = [
            tok.lower()
            for tok in query.replace("/", " ").replace("-", " ").split()
            if len(tok) >= 2
        ]
        if not tokens:
            return list(self.docs.values())
        scored: list[tuple[int, FakeKnowledgeDoc]] = []
        for doc in self.docs.values():
            haystack = f"{doc.name} {doc.title} {doc.content}".lower()
            score = sum(1 for tok in tokens if tok in haystack)
            if score > 0:
                scored.append((score, doc))
        scored.sort(key=lambda pair: (-pair[0], pair[1].name))
        return [doc for _, doc in scored]


def build_fastmcp(
    store: FakeDevKnowledgeStore, *, json_response: bool = True, host: str, port: int
) -> FastMCP:
    """Builds the FastMCP app exposing the Developer Knowledge toolset over ``store``."""
    server = FastMCP(
        "fake-devknowledge-mcp",
        host=host,
        port=port,
        stateless_http=True,
        json_response=json_response,
        log_level="WARNING",
    )

    @server.tool(name="answer_query")
    def answer_query(query: str) -> dict[str, Any]:
        return store.answer_query(query)

    @server.tool(name="search_documents")
    def search_documents(query: str) -> dict[str, Any]:
        return store.search_documents(query)

    @server.tool(name="get_documents")
    def get_documents(names: list[str]) -> dict[str, Any]:
        return store.get_documents(names)

    return server


class _HeaderRecorder:
    """ASGI wrapper that records the headers of every HTTP request."""

    def __init__(self, app, store: FakeDevKnowledgeStore) -> None:
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


class FakeDevKnowledgeMcpServer:
    """Runs the fake Developer Knowledge MCP server on a background thread."""

    def __init__(
        self, store: FakeDevKnowledgeStore | None = None, *, json_response: bool = True
    ) -> None:
        self.store = store or FakeDevKnowledgeStore()
        self.json_response = json_response
        self.host = "127.0.0.1"
        self.port = _free_port()
        self.url = f"http://{self.host}:{self.port}/mcp"
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "FakeDevKnowledgeMcpServer":
        fastmcp = build_fastmcp(
            self.store, json_response=self.json_response, host=self.host, port=self.port
        )
        app = _HeaderRecorder(fastmcp.streamable_http_app(), self.store)
        config = uvicorn.Config(
            app, host=self.host, port=self.port, log_level="warning", lifespan="on"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, name="fake-devknowledge-mcp", daemon=True
        )
        self._thread.start()
        deadline = time.monotonic() + 15
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("fake Developer Knowledge MCP server exited during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("fake Developer Knowledge MCP server did not start in time")
            time.sleep(0.01)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=15)

    def __enter__(self) -> "FakeDevKnowledgeMcpServer":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
