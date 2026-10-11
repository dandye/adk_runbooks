"""Unit tests for ``manager.tools.grounding_tools``: Developer Knowledge MCP
toolset (startup vs. runtime header provisioning) and ``AgentTool(web_search_verifier)``."""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from google.adk.tools import google_search
from google.adk.tools.agent_tool import AgentTool

from manager.tools.grounding_tools import (
    DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL,
    DEVELOPER_KNOWLEDGE_TOOL_FILTER,
    DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX,
    developer_knowledge_headers,
    developer_knowledge_mcp_url,
    developer_knowledge_toolset_configured,
    init_developer_knowledge_mcp_tools,
    init_developer_knowledge_toolset,
    init_web_search_agent_tool,
    web_search_verifier_agent,
)
from skills.drive_registry import StaticTokenSource
from tests.fake_devknowledge_mcp import FakeDevKnowledgeMcpServer


def test_developer_knowledge_url_defaults_and_overrides():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DEVELOPERKNOWLEDGE_MCP_URL", None)
        assert developer_knowledge_mcp_url() == DEFAULT_DEVELOPER_KNOWLEDGE_MCP_URL

    with patch.dict(
        os.environ, {"DEVELOPERKNOWLEDGE_MCP_URL": "http://127.0.0.1:9999/mcp"}, clear=False
    ):
        assert developer_knowledge_mcp_url() == "http://127.0.0.1:9999/mcp"


def test_developer_knowledge_headers_prefers_api_key():
    env = {
        "DEVELOPERKNOWLEDGE_API_KEY": "test-api-key-123",
        "GCP_PROJECT_ID": "dandye-0324-chronicle",
    }
    with patch.dict(os.environ, env, clear=False):
        headers = developer_knowledge_headers(
            readonly_context=None,
            token_source=StaticTokenSource("should-not-be-used"),
        )
    assert headers["X-Goog-Api-Key"] == "test-api-key-123"
    assert headers["X-Goog-User-Project"] == "dandye-0324-chronicle"
    assert "Authorization" not in headers


def test_developer_knowledge_headers_uses_adc_bearer_when_no_api_key():
    with patch.dict(
        os.environ, {"GCP_PROJECT_ID": "dandye-0324-chronicle"}, clear=False
    ):
        os.environ.pop("DEVELOPERKNOWLEDGE_API_KEY", None)
        headers = developer_knowledge_headers(
            readonly_context=SimpleNamespace(state={}),
            token_source=StaticTokenSource("adc-bearer-xyz"),
        )
    assert headers["Authorization"] == "Bearer adc-bearer-xyz"
    assert headers["X-Goog-User-Project"] == "dandye-0324-chronicle"


def test_developer_knowledge_toolset_configured_flag():
    with patch.dict(
        os.environ,
        {"DEVELOPERKNOWLEDGE_MCP_TOOLSET": "0", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert developer_knowledge_toolset_configured() is False

    with patch.dict(
        os.environ,
        {"DEVELOPERKNOWLEDGE_MCP_TOOLSET": "1", "GCP_PROJECT_ID": "dandye-0324-chronicle"},
        clear=False,
    ):
        assert developer_knowledge_toolset_configured() is True


def test_init_developer_knowledge_toolset_startup_and_runtime_against_fake(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    """Verifies Irani (2026) startup nuance:
    1. ``get_tools(readonly_context=None)`` (called at A2A startup) succeeds even when
       the server enforces authentication headers.
    2. Runtime ``run_async`` executes ``search_documents``, ``answer_query``, and
       ``get_documents`` with the expected headers.
    """
    fake_devknowledge.store.require_auth = True
    toolset = init_developer_knowledge_toolset(
        url=fake_devknowledge.url,
        api_key="dk-api-key-abc",
        quota_project="dandye-0324-chronicle",
    )

    async def exercise():
        try:
            # 1. Startup discovery with readonly_context=None (A2A Agent Card path)
            startup_tools = await toolset.get_tools(readonly_context=None)
            names = sorted(t.name for t in startup_tools)
            assert names == sorted(DEVELOPER_KNOWLEDGE_TOOL_FILTER)
            assert fake_devknowledge.store.last_headers.get("x-goog-api-key") == "dk-api-key-abc"

            by_name = {t.name: t for t in startup_tools}

            # 2. Call search_documents
            search_res = await by_name["search_documents"].run_async(
                args={"query": "roles/aiplatform.user chronicle"}, tool_context=None
            )
            assert not search_res.get("isError")
            structured = search_res["structuredContent"]
            assert len(structured["results"]) >= 1
            first_doc_name = structured["results"][0]["parent"]
            assert first_doc_name == "documents/docs.cloud.google.com/iam/docs/understanding-roles"

            # 3. Call get_documents with parent name from search_documents
            get_res = await by_name["get_documents"].run_async(
                args={"names": [first_doc_name]}, tool_context=None
            )
            assert not get_res.get("isError")
            docs = get_res["structuredContent"]["documents"]
            assert len(docs) == 1
            assert "roles/aiplatform.user" in docs[0]["content"]

            # 4. Call answer_query
            ans_res = await by_name["answer_query"].run_async(
                args={"query": "google_search AgentTool"}, tool_context=None
            )
            assert not ans_res.get("isError")
            assert "AgentTool" in ans_res["structuredContent"]["answer_text"]
            assert (
                "documents/adk.dev/tools/google-search-grounding"
                in ans_res["structuredContent"]["references"]
            )
        finally:
            await toolset.close()

    asyncio.run(exercise())


def test_init_developer_knowledge_toolset_with_adc_bearer(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    fake_devknowledge.store.require_auth = True
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DEVELOPERKNOWLEDGE_API_KEY", None)
        toolset = init_developer_knowledge_toolset(
            url=fake_devknowledge.url,
            token_source=StaticTokenSource("adc-token-999"),
            quota_project="dandye-0324-chronicle",
        )

        async def exercise():
            try:
                tools = await toolset.get_tools(readonly_context=None)
                by_name = {t.name: t for t in tools}
                res = await by_name["search_documents"].run_async(
                    args={"query": "IAM"}, tool_context=None
                )
                assert not res.get("isError")
                assert (
                    fake_devknowledge.store.last_headers.get("authorization")
                    == "Bearer adc-token-999"
                )
                assert (
                    fake_devknowledge.store.last_headers.get("x-goog-user-project")
                    == "dandye-0324-chronicle"
                )
            finally:
                await toolset.close()

        asyncio.run(exercise())


def test_init_developer_knowledge_mcp_tools_registers_in_global_registry(
    fake_devknowledge: FakeDevKnowledgeMcpServer,
):
    env = {
        "DEVELOPERKNOWLEDGE_MCP_TOOLSET": "1",
        "DEVELOPERKNOWLEDGE_MCP_URL": fake_devknowledge.url,
        "DEVELOPERKNOWLEDGE_API_KEY": "reg-key",
        "GCP_PROJECT_ID": "dandye-0324-chronicle",
    }
    with patch.dict(os.environ, env, clear=False):
        ts = init_developer_knowledge_mcp_tools()
        assert ts is not None
        assert ts.tool_name_prefix == DEVELOPER_KNOWLEDGE_TOOL_NAME_PREFIX


def test_web_search_verifier_agent_and_agent_tool_isolation():
    """Verifies the AgentTool pattern from Irani (2026):
    - Child agent ``web_search_verifier`` holds ONLY ``google_search`` in its tools list.
    - ``init_web_search_agent_tool()`` wraps ``web_search_verifier`` in ``AgentTool`` so
      it can sit alongside custom FunctionTools and McpToolsets on the parent agent.
    """
    child = web_search_verifier_agent()
    assert child.name == "web_search_verifier"
    assert child.tools == [google_search]

    wrapped = init_web_search_agent_tool()
    assert isinstance(wrapped, AgentTool)
    assert wrapped.agent.name == "web_search_verifier"
    assert wrapped.agent.tools == [google_search]
