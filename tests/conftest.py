"""Shared pytest fixtures for the adk_runbooks test-suite."""

from __future__ import annotations

import pytest

from tests.fake_devknowledge_mcp import FakeDevKnowledgeMcpServer, FakeDevKnowledgeStore
from tests.fake_drive_mcp import FakeDriveMcpServer, FakeDriveStore
from tests.fake_knowledge_catalog_mcp import (
    FakeKnowledgeCatalogMcpServer,
    FakeKnowledgeCatalogStore,
)


@pytest.fixture
def drive_store() -> FakeDriveStore:
    """An empty in-memory fake Drive."""
    return FakeDriveStore()


@pytest.fixture
def fake_drive(drive_store: FakeDriveStore):
    """A running fake Drive MCP server that answers with ``application/json``."""
    with FakeDriveMcpServer(drive_store, json_response=True) as server:
        yield server


@pytest.fixture
def fake_drive_sse(drive_store: FakeDriveStore):
    """A running fake Drive MCP server that answers with ``text/event-stream``."""
    with FakeDriveMcpServer(drive_store, json_response=False) as server:
        yield server


@pytest.fixture
def devknowledge_store() -> FakeDevKnowledgeStore:
    """An in-memory fake Developer Knowledge corpus with default seeded docs."""
    return FakeDevKnowledgeStore(seed_defaults=True)


@pytest.fixture
def fake_devknowledge(devknowledge_store: FakeDevKnowledgeStore):
    """A running fake Developer Knowledge MCP server."""
    with FakeDevKnowledgeMcpServer(devknowledge_store, json_response=True) as server:
        yield server


@pytest.fixture
def knowledge_catalog_store() -> FakeKnowledgeCatalogStore:
    """An in-memory fake Knowledge Catalog corpus with default seeded entries."""
    return FakeKnowledgeCatalogStore(seed_defaults=True)


@pytest.fixture
def fake_knowledge_catalog(knowledge_catalog_store: FakeKnowledgeCatalogStore):
    """A running fake Knowledge Catalog MCP server."""
    with FakeKnowledgeCatalogMcpServer(
        knowledge_catalog_store, json_response=True
    ) as server:
        yield server
