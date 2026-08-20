# Design Specification: Progressive MCP Tool Discovery & Dispatcher

**Date:** 2026-08-20  
**Branch:** `progressive_discovery_mcp_v0001`  
**Status:** Approved  
**Author:** Antigravity (Google DeepMind) & Dan Dye  

---

## 1. Executive Summary

This specification defines the **Progressive MCP Tool Discovery & Dispatcher Framework** for the Google ADK Multi-Agent Cybersecurity Operations platform. 

While the previous iteration (`skills_v0001`) solved procedural knowledge bloat via **Skills Progressive Disclosure** (`SkillRegistry` and `load_skill`), raw Model Context Protocol (MCP) security tools (`siem-mcp`, `soar-mcp`, `gti-mcp`) are still registered statically across agent definitions. As additional security integrations and MCP servers are connected, injecting dozens of full JSON schemas upfront leads to prompt context bloat, increased latency, and tool-selection degradation.

This design introduces a two-tier **MCP Progressive Discovery** architecture:
1. **`MCPToolRegistry`**: Discovers, indexes, normalizes, and manages tool schemas across all connected MCP security servers (Chronicle SIEM, SecOps SOAR, Google Threat Intelligence / VirusTotal).
2. **Progressive MCP Meta-Tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`)**: Enables LLM agents to maintain ultra-lean tool definitions (~2 meta-tools) while retaining the full capability to discover parameters and dynamically dispatch calls to any connected MCP tool at runtime.

---

## 2. Architectural Overview

```
                                  ┌──────────────────────────────────────────────────┐
                                  │                LLM Agent Context                 │
                                  │                                                  │
                                  │  • System Prompt: Lean Skills & Tools Catalog   │
                                  │  • Active Tools:                                 │
                                  │      - load_skill(skill_name)                    │
                                  │      - search_mcp_tools(query, server)           │
                                  │      - get_mcp_tool_schema(tool_name)            │
                                  │      - execute_mcp_tool(tool_name, arguments)    │
                                  └────────────────────────┬─────────────────────────┘
                                                           │
                        ┌──────────────────────────────────┴──────────────────────────────────┐
                        │                                                                     │
                        ▼ (Discovery / Schema Lookup)                                         ▼ (Execution)
        ┌────────────────────────────────┐                                    ┌─────────────────────────────────┐
        │        MCPToolRegistry         │                                    │      MCP Execution Engine       │
        │  • Discovers & indexes tools   │                                    │  • Validates parameters         │
        │    from all connected servers  │                                    │  • Resolves target MCP client   │
        │  • Generates concise catalogs  │                                    │  • Routes call via async client │
        │  • Serves full JSON schemas    │                                    │  • Returns structured outcome   │
        └───────────────┬────────────────┘                                    └────────────────┬────────────────┘
                        │                                                                      │
                        └───────────────────────────────┬──────────────────────────────────────┘
                                                        │
                                                        ▼
                        ┌─────────────────────────────────────────────────────────────┐
                        │                 Connected MCP Security Servers              │
                        │                                                             │
                        │   ┌────────────────┐   ┌───────────────┐   ┌────────────┐   │
                        │   │   Chronicle    │   │  SecOps SOAR  │   │ VirusTotal │   │
                        │   │   SIEM MCP     │   │     MCP       │   │  GTI MCP   │   │
                        │   └────────────────┘   └───────────────┘   └────────────┘   │
                        └─────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Component Architecture

### 3.1 Data Structures & MCPToolRegistry (`multi-agent/manager/tools/mcp_registry.py`)

#### `MCPToolMetadata`
Dataclass capturing indexed MCP tool attributes:
- `name: str` - Standard tool identifier (e.g. `soar_get_case_full_details` or `siem_search_security_events`).
- `server: str` - Server namespace (`siem`, `soar`, `gti`, `custom`).
- `description: str` - Concise one-sentence summary for routing (< 200 chars).
- `input_schema: dict[str, Any]` - Full JSON Schema defining required/optional properties and types.
- `executor: Callable | None` - Optional direct async/sync execution callable.

#### `MCPToolRegistry`
Core registry providing:
- `register_tool(metadata: MCPToolMetadata) -> None`: Indexes tool under normalized dual keys (kebab-case and snake_case).
- `register_mcp_toolset(toolset: McpToolset | Any, server_name: str) -> int`: Auto-extracts tool definitions from Google ADK `McpToolset` instances.
- `search_tools(query: str = "", server: str = "") -> list[dict[str, str]]`: Keyword search across tool names, server tags, and descriptions.
- `get_tool_schema(tool_name: str) -> dict[str, Any] | None`: Returns formatted parameter documentation and JSON Schema.
- `get_compact_catalog(server: str = "") -> str`: Generates a compact Markdown table/list for persona prompt injection.
- `execute_tool(tool_name: str, arguments: dict[str, Any]) -> Any`: Validates inputs and routes execution to the registered tool executor.

---

### 3.2 Progressive Discovery Meta-Tools (`multi-agent/manager/tools/tools.py`)

The agent is equipped with three standard meta-tools:

1. **`search_mcp_tools(query: str = "", server: str = "") -> str`**
   - Discovers available MCP security tools by keyword or server without loading parameter schemas into context.

2. **`get_mcp_tool_schema(tool_name: str) -> str`**
   - Retrieves full parameter definitions, required fields, data types, and descriptions for a specific tool on demand.

3. **`execute_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> str`**
   - Executes the selected MCP tool dynamically with the supplied arguments.
   - Includes execution error boundaries, JSON serialization handling, and latency instrumentation.

---

## 4. Integration with Multi-Agent System & DAC Agent

1. **Manager & Sub-Agents (`multi-agent/manager/sub_agents/*`)**:
   - Sub-agents are configured with `get_agent_tools()` which includes:
     - `load_skill`, `list_available_skills` (Procedural Knowledge)
     - `search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool` (Progressive Tool Discovery)
     - ADK Graph Workflow tools (`run_case_report_workflow`, `run_malware_irp_workflow`, etc.)
2. **Detection-as-Code Agent (`dac-agent/`)**:
   - Equipped with `MCPToolRegistry` to query Chronicle SIEM rule endpoints on demand.

---

## 5. Security & Safety

- **Path & Name Traversal Guard:** Tool execution is strictly mediated through indexed registry entries. Arbitrary function execution is impossible.
- **Argument Schema Validation:** Validates required parameters against the tool's JSON schema before dispatching.
- **Fail-Safe Fallbacks:** Clear, actionable error messages if an unknown tool or missing parameter is requested.

---

## 6. Verification & Evaluation Plan

1. **Unit Tests:**
   - `tests/test_mcp_registry.py`: Registry indexing, search, schema retrieval, dual-key normalization, and error handling.
   - `tests/test_mcp_tools.py`: Meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`) integration and mock dispatch.
2. **System & Agent Tests:**
   - Verify Manager and all 8 sub-agents initialize with lean MCP meta-tools.
3. **Full Benchmark Verification:**
   - Run 100% of benchmark suites (`core_workflows`, `all_36_workflows`, `expanded_cases_alerts`).
