"""Unit tests for Centralized MCPToolRegistry Engine."""

import pytest
import asyncio
from typing import Any
from manager.tools.mcp_registry import MCPToolMetadata, MCPToolRegistry


def test_mcp_tool_metadata_dataclass():
    """Verify MCPToolMetadata attributes and defaults."""
    schema = {
        "type": "object",
        "properties": {
            "case_id": {"type": "string", "description": "The case ID"}
        },
        "required": ["case_id"],
    }
    meta = MCPToolMetadata(
        name="soar_get_case",
        server="soar",
        description="Fetch complete case details from SOAR.",
        input_schema=schema,
    )
    assert meta.name == "soar_get_case"
    assert meta.server == "soar"
    assert meta.description == "Fetch complete case details from SOAR."
    assert meta.input_schema == schema
    assert meta.executor is None
    assert meta.version == "1.0.0"


def test_registry_register_and_get_tool_dual_key_normalization():
    """Verify dual-key normalization (snake_case and kebab-case) and whitespace trimming."""
    registry = MCPToolRegistry()
    meta = MCPToolMetadata(
        name="soar_get_case_details",
        server="soar",
        description="Retrieve SOAR case details.",
        input_schema={"type": "object", "properties": {"id": {"type": "string"}}},
    )
    registry.register_tool(meta)

    # Retrieval by exact name
    assert registry.get_tool("soar_get_case_details") is not None
    assert registry.get_tool("soar_get_case_details").name == "soar_get_case_details"

    # Retrieval by kebab-case
    assert registry.get_tool("soar-get-case-details") is not None
    assert registry.get_tool("soar-get-case-details").name == "soar_get_case_details"

    # Retrieval with whitespace
    assert registry.get_tool("  soar_get_case_details  ") is not None
    assert registry.get_tool("  soar-get-case-details \n") is not None

    # Registering a kebab-case tool directly
    kebab_meta = MCPToolMetadata(
        name="siem-search-events",
        server="siem",
        description="Search Chronicle SIEM events.",
        input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
    )
    registry.register_tool(kebab_meta)
    assert registry.get_tool("siem-search-events") is not None
    assert registry.get_tool("siem_search_events") is not None

    # Non-existent tool returns None
    assert registry.get_tool("unknown_tool") is None


def test_registry_search_tools():
    """Verify keyword and server-based searching and deduplication."""
    registry = MCPToolRegistry()
    registry.register_tool(
        MCPToolMetadata(
            name="soar_get_case",
            server="soar",
            description="Retrieve case from SOAR.",
            input_schema={},
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="soar_close_case",
            server="soar",
            description="Close SOAR case with root cause.",
            input_schema={},
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Query Chronicle UDM security events.",
            input_schema={},
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="gti_lookup_ioc",
            server="gti",
            description="Enrich threat intelligence and IP reputation.",
            input_schema={},
        )
    )

    # Search all
    all_tools = registry.search_tools()
    assert len(all_tools) == 4
    tool_names = [t["name"] for t in all_tools]
    assert "soar_get_case" in tool_names
    assert "soar_close_case" in tool_names
    assert "siem_search_events" in tool_names
    assert "gti_lookup_ioc" in tool_names

    # Search by keyword in name
    case_tools = registry.search_tools(query="case")
    assert len(case_tools) == 2
    assert all(t["server"] == "soar" for t in case_tools)

    # Search by keyword in description
    reputation_tools = registry.search_tools(query="reputation")
    assert len(reputation_tools) == 1
    assert reputation_tools[0]["name"] == "gti_lookup_ioc"

    # Search by server filter
    siem_tools = registry.search_tools(server="siem")
    assert len(siem_tools) == 1
    assert siem_tools[0]["name"] == "siem_search_events"

    # Search with combined query and server
    soar_close = registry.search_tools(query="close", server="soar")
    assert len(soar_close) == 1
    assert soar_close[0]["name"] == "soar_close_case"

    # Search with unmatched query
    empty = registry.search_tools(query="nonexistent_keyword")
    assert empty == []


def test_registry_get_tool_schema():
    """Verify tool schema retrieval and formatting."""
    registry = MCPToolRegistry()
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Chronicle UDM filter expression"},
            "limit": {"type": "integer", "description": "Max events to return", "default": 50},
        },
        "required": ["query"],
    }
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Search Chronicle SIEM events.",
            input_schema=schema,
        )
    )

    retrieved = registry.get_tool_schema("siem_search_events")
    assert retrieved is not None
    assert retrieved["name"] == "siem_search_events"
    assert retrieved["server"] == "siem"
    assert retrieved["description"] == "Search Chronicle SIEM events."
    assert retrieved["input_schema"] == schema

    # Normalized lookup for schema
    retrieved_kebab = registry.get_tool_schema("siem-search-events")
    assert retrieved_kebab is not None
    assert retrieved_kebab["name"] == "siem_search_events"

    # Missing tool returns None
    assert registry.get_tool_schema("missing_tool") is None


def test_registry_get_compact_catalog():
    """Verify compact markdown catalog generation."""
    registry = MCPToolRegistry()
    registry.register_tool(
        MCPToolMetadata(
            name="soar_get_case",
            server="soar",
            description="Retrieve case from SOAR.",
            input_schema={},
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Query Chronicle UDM security events.",
            input_schema={},
        )
    )

    full_catalog = registry.get_compact_catalog()
    assert "- **siem_search_events** (siem): Query Chronicle UDM security events." in full_catalog
    assert "- **soar_get_case** (soar): Retrieve case from SOAR." in full_catalog

    # Filtered catalog by server
    soar_catalog = registry.get_compact_catalog(server="soar")
    assert "soar_get_case" in soar_catalog
    assert "siem_search_events" not in soar_catalog

    # Empty registry catalog
    empty_registry = MCPToolRegistry()
    assert empty_registry.get_compact_catalog() == ""


def test_registry_execute_tool_sync():
    """Verify synchronous tool execution and parameter validation."""
    registry = MCPToolRegistry()

    def mock_executor(case_id: str, priority: str = "medium") -> dict[str, Any]:
        return {"status": "success", "case_id": case_id, "priority": priority}

    schema = {
        "type": "object",
        "properties": {
            "case_id": {"type": "string"},
            "priority": {"type": "string", "default": "medium"},
        },
        "required": ["case_id"],
    }
    registry.register_tool(
        MCPToolMetadata(
            name="soar_update_case",
            server="soar",
            description="Update case priority.",
            input_schema=schema,
            executor=mock_executor,
        )
    )

    # Valid execution
    res = registry.execute_tool("soar_update_case", {"case_id": "CASE-101", "priority": "high"})
    assert res == {"status": "success", "case_id": "CASE-101", "priority": "high"}

    # Execution with default argument
    res_default = registry.execute_tool("soar-update-case", {"case_id": "CASE-102"})
    assert res_default == {"status": "success", "case_id": "CASE-102", "priority": "medium"}

    # Missing required argument raises ValueError
    with pytest.raises(ValueError, match="Missing required argument 'case_id'"):
        registry.execute_tool("soar_update_case", {})

    # Unknown tool raises ValueError
    with pytest.raises(ValueError, match="Tool 'nonexistent' not found in registry"):
        registry.execute_tool("nonexistent", {})


def test_registry_execute_tool_async():
    """Verify asynchronous tool execution."""
    registry = MCPToolRegistry()

    async def async_executor(query: str) -> list[str]:
        await asyncio.sleep(0.01)
        return [f"event_match_for_{query}"]

    registry.register_tool(
        MCPToolMetadata(
            name="siem_query",
            server="siem",
            description="Async SIEM query.",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
            executor=async_executor,
        )
    )

    # Execute async tool using asyncio.run
    async def runner():
        res = registry.execute_tool("siem_query", {"query": "principal.ip = '10.0.0.1'"})
        if asyncio.iscoroutine(res):
            res = await res
        return res

    result = asyncio.run(runner())
    assert result == ["event_match_for_principal.ip = '10.0.0.1'"]


def test_registry_execute_tool_without_executor():
    """Verify error when executing tool without executor."""
    registry = MCPToolRegistry()
    registry.register_tool(
        MCPToolMetadata(
            name="unimplemented_tool",
            server="custom",
            description="Tool without executor.",
            input_schema={},
            executor=None,
        )
    )

    with pytest.raises(RuntimeError, match="No executor registered for tool 'unimplemented_tool'"):
        registry.execute_tool("unimplemented_tool", {})


def test_registry_register_mcp_toolset_reflection():
    """Verify auto-registration from toolset objects."""
    class MockTool:
        def __init__(self, name: str, description: str, schema: dict[str, Any]):
            self.name = name
            self.description = description
            self._schema = schema

        def _get_declaration(self):
            class Decl:
                def __init__(self, name, desc, schema):
                    self.name = name
                    self.description = desc
                    self.parameters_json_schema = schema
            return Decl(self.name, self.description, self._schema)

        def __call__(self, **kwargs):
            return {"called": self.name, "args": kwargs}

    class MockToolset:
        def __init__(self, tools):
            self._tools = tools

        def get_tools(self, readonly_context=None):
            return self._tools

    tool1 = MockTool("secops_get_alert", "Get alert by ID", {"type": "object", "properties": {"id": {"type": "string"}}})
    tool2 = MockTool("secops_list_alerts", "List active alerts", {"type": "object"})
    toolset = MockToolset([tool1, tool2])

    registry = MCPToolRegistry()
    count = registry.register_mcp_toolset(toolset, server_name="siem")

    assert count == 2
    assert registry.get_tool("secops_get_alert") is not None
    assert registry.get_tool("secops-get-alert") is not None
    assert registry.get_tool("secops_list_alerts") is not None
    assert registry.get_tool("secops_get_alert").server == "siem"

    # Test execution of reflected tool
    res = registry.execute_tool("secops_get_alert", {"id": "ALERT-1"})
    assert res == {"called": "secops_get_alert", "args": {"id": "ALERT-1"}}
