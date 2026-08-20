import asyncio
import json
import pytest
from unittest.mock import patch

from manager.tools.mcp_registry import MCPToolMetadata, MCPToolRegistry
from manager.tools.tools import (
    global_mcp_registry,
    search_mcp_tools,
    get_mcp_tool_schema,
    execute_mcp_tool,
    init_shared_mcp_tools,
    get_agent_tools,
)


@pytest.fixture
def mock_registry():
    """Provides a fresh test MCPToolRegistry populated with mock security tools."""
    registry = MCPToolRegistry()

    def mock_soar_close(case_id: str, root_cause: str = "Resolved") -> dict:
        return {"status": "closed", "case_id": case_id, "root_cause": root_cause}

    async def mock_siem_search(query: str, limit: int = 10) -> list:
        await asyncio.sleep(0.01)
        return [{"id": "E1", "query": query, "limit": limit}]

    def mock_gti_lookup(ioc: str) -> dict:
        if ioc == "malicious.com":
            return {"verdict": "malicious", "score": 95}
        return {"verdict": "clean", "score": 0}

    registry.register_tool(
        MCPToolMetadata(
            name="soar_close_case",
            server="soar",
            description="Closes a security incident case in SecOps SOAR.",
            input_schema={
                "type": "object",
                "properties": {
                    "case_id": {"type": "string", "description": "The unique case ID."},
                    "root_cause": {"type": "string", "description": "Reason for closure.", "default": "Resolved"},
                },
                "required": ["case_id"],
            },
            executor=mock_soar_close,
        )
    )

    registry.register_tool(
        MCPToolMetadata(
            name="siem_search_events",
            server="siem",
            description="Executes a UDM filter query against Chronicle SIEM events.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "UDM filter string."},
                    "limit": {"type": "integer", "description": "Max results.", "default": 10},
                },
                "required": ["query"],
            },
            executor=mock_siem_search,
        )
    )

    registry.register_tool(
        MCPToolMetadata(
            name="gti_lookup_ioc",
            server="gti",
            description="Queries VirusTotal / GTI threat intelligence for IOC reputation.",
            input_schema={
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "Domain, IP, or hash."},
                },
                "required": ["ioc"],
            },
            executor=mock_gti_lookup,
        )
    )

    return registry


def test_global_mcp_registry_instance():
    """Verify global_mcp_registry exists and is an MCPToolRegistry."""
    assert global_mcp_registry is not None
    assert isinstance(global_mcp_registry, MCPToolRegistry)


def test_search_mcp_tools(mock_registry):
    """Verify progressive tool discovery by query, server, or list all."""
    with patch("manager.tools.tools.global_mcp_registry", mock_registry):
        # Search all tools
        all_tools = search_mcp_tools()
        assert "soar_close_case" in all_tools
        assert "siem_search_events" in all_tools
        assert "gti_lookup_ioc" in all_tools
        assert "### Discovered MCP Security Tools" in all_tools

        # Filter by server
        soar_tools = search_mcp_tools(server="soar")
        assert "soar_close_case" in soar_tools
        assert "siem_search_events" not in soar_tools

        # Filter by keyword query
        gti_tools = search_mcp_tools(query="reputation")
        assert "gti_lookup_ioc" in gti_tools
        assert "soar_close_case" not in gti_tools

        # Filter with no matches
        empty_res = search_mcp_tools(query="nonexistent_service")
        assert "No MCP tools found" in empty_res

    assert search_mcp_tools.__doc__ is not None
    assert "search" in search_mcp_tools.__doc__.lower() or "discover" in search_mcp_tools.__doc__.lower()


def test_get_mcp_tool_schema(mock_registry):
    """Verify schema retrieval for specific tools with dual-key normalization."""
    with patch("manager.tools.tools.global_mcp_registry", mock_registry):
        # Direct snake_case
        schema_str = get_mcp_tool_schema("soar_close_case")
        parsed = json.loads(schema_str)
        assert parsed["name"] == "soar_close_case"
        assert parsed["server"] == "soar"
        assert "case_id" in parsed["input_schema"]["properties"]
        assert "case_id" in parsed["input_schema"]["required"]

        # Dual-key kebab-case
        schema_kebab = get_mcp_tool_schema("soar-close-case")
        parsed_kebab = json.loads(schema_kebab)
        assert parsed_kebab["name"] == "soar_close_case"

        # Missing tool
        missing = get_mcp_tool_schema("nonexistent_tool")
        assert "Error: MCP tool 'nonexistent_tool' not found" in missing

    assert get_mcp_tool_schema.__doc__ is not None


def test_execute_mcp_tool_sync(mock_registry):
    """Verify dynamic execution of synchronous MCP tool."""
    with patch("manager.tools.tools.global_mcp_registry", mock_registry):
        # Valid execution with dict
        res_str = execute_mcp_tool("soar_close_case", {"case_id": "CASE-999", "root_cause": "False Positive"})
        res = json.loads(res_str)
        assert res["status"] == "closed"
        assert res["case_id"] == "CASE-999"
        assert res["root_cause"] == "False Positive"

        # Valid execution with JSON string arguments
        json_args = json.dumps({"case_id": "CASE-888"})
        res_str2 = execute_mcp_tool("soar-close-case", json_args)
        res2 = json.loads(res_str2)
        assert res2["status"] == "closed"
        assert res2["case_id"] == "CASE-888"
        assert res2["root_cause"] == "Resolved"

        # Missing required parameter error
        err_res = execute_mcp_tool("soar_close_case", {})
        assert "Error executing tool" in err_res
        assert "Missing required argument 'case_id'" in err_res

        # Non-existent tool error
        err_missing = execute_mcp_tool("unknown_tool", {})
        assert "Error executing tool 'unknown_tool'" in err_missing

        # Invalid JSON string argument
        err_json = execute_mcp_tool("soar_close_case", "{invalid_json")
        assert "Error parsing arguments JSON" in err_json


def test_execute_mcp_tool_async(mock_registry):
    """Verify dynamic execution of asynchronous MCP tool."""
    with patch("manager.tools.tools.global_mcp_registry", mock_registry):
        res_str = execute_mcp_tool("siem_search_events", {"query": "metadata.event_type = 'USER_LOGIN'", "limit": 5})
        res = json.loads(res_str)
        assert isinstance(res, list)
        assert len(res) == 1
        assert res[0]["id"] == "E1"
        assert res[0]["limit"] == 5


def test_init_shared_mcp_tools():
    """Verify init_shared_mcp_tools registers toolsets into global_mcp_registry."""
    toolsets = init_shared_mcp_tools()
    assert len(toolsets) == 3
    assert global_mcp_registry is not None


def test_get_agent_tools_includes_mcp_meta_tools():
    """Verify get_agent_tools returns search, schema, and execute MCP meta-tools."""
    tools = get_agent_tools()
    tool_names = [getattr(t, "__name__", str(t)) for t in tools]

    assert any("search_mcp_tools" in name for name in tool_names), "search_mcp_tools missing from get_agent_tools"
    assert any("get_mcp_tool_schema" in name for name in tool_names), "get_mcp_tool_schema missing from get_agent_tools"
    assert any("execute_mcp_tool" in name for name in tool_names), "execute_mcp_tool missing from get_agent_tools"
