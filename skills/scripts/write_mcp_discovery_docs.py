"""
Helper script to populate the design spec and implementation plan for progressive_discovery_mcp_v0001.
"""

from pathlib import Path

target_root = Path(__file__).resolve().parent.parent.parent.parent / "progressive_discovery_mcp_v0001"
spec_dir = target_root / "docs" / "superpowers" / "specs"
plan_dir = target_root / "docs" / "superpowers" / "plans"

spec_dir.mkdir(parents=True, exist_ok=True)
plan_dir.mkdir(parents=True, exist_ok=True)

spec_file = spec_dir / "2026-08-20-progressive-discovery-mcp-design.md"
plan_file = plan_dir / "2026-08-20-progressive-discovery-mcp.md"

spec_text = """# Design Specification: Progressive MCP Tool Discovery & Dispatcher

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
"""

plan_text = """# Progressive MCP Tool Discovery & Dispatcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement client-side progressive discovery and on-demand schema expansion for connected MCP Security tools (SIEM, SOAR, GTI).

**Architecture:** Build a centralized `MCPToolRegistry` that indexes tools from connected MCP servers at startup and provides lightweight meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`) to agents.

**Tech Stack:** Python 3.11+, Google ADK (`McpToolset`), Pydantic, pytest.

**Spec:** `docs/superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md`

## Global Constraints
- Must maintain 100% backward compatibility for all existing ADK Graph Workflows and Skills.
- Every MCP tool must be normalized (supporting both snake_case and kebab-case).
- All 52 unit/eval tests and benchmark datasets must pass.
- No hardcoded API secrets or credentials.

---

### Task 1: Centralized MCP Tool Registry (`MCPToolRegistry`)

**Files:**
- Create: `multi-agent/manager/tools/mcp_registry.py`
- Test: `tests/test_mcp_registry.py`

**Interfaces:**
- Produces: `MCPToolMetadata`, `MCPToolRegistry`, `register_mcp_toolset`, `search_tools`, `get_tool_schema`, `execute_tool`.

- [ ] **Step 1: Write failing test for MCPToolRegistry**
  - Create `tests/test_mcp_registry.py` covering tool registration, dual-key normalization, keyword search, schema retrieval, and error handling.
- [ ] **Step 2: Run pytest to verify failure**
  - Run `./venv/bin/pytest tests/test_mcp_registry.py -v`
- [ ] **Step 3: Implement `MCPToolRegistry` in `multi-agent/manager/tools/mcp_registry.py`**
  - Define `MCPToolMetadata` dataclass.
  - Implement indexing, dual-key normalization, search filtering, schema formatting, and safe execution routing.
- [ ] **Step 4: Run pytest to verify pass**
  - Run `./venv/bin/pytest tests/test_mcp_registry.py -v`
- [ ] **Step 5: Commit**
  - `git add multi-agent/manager/tools/mcp_registry.py tests/test_mcp_registry.py && git commit -m "feat(mcp): implement centralized MCPToolRegistry engine"`

---

### Task 2: Progressive MCP Meta-Tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`)

**Files:**
- Modify: `multi-agent/manager/tools/tools.py`
- Test: `tests/test_mcp_tools.py`

**Interfaces:**
- Consumes: `MCPToolRegistry` from `mcp_registry.py`
- Produces: `search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`, updated `get_agent_tools()`.

- [ ] **Step 1: Write failing test for progressive MCP tools**
  - Create `tests/test_mcp_tools.py` testing discovery, schema lookup, parameter validation, and execution forwarding.
- [ ] **Step 2: Run pytest to verify failure**
  - Run `./venv/bin/pytest tests/test_mcp_tools.py -v`
- [ ] **Step 3: Implement meta-tools in `multi-agent/manager/tools/tools.py`**
  - Add `global_mcp_registry`.
  - Implement `search_mcp_tools(query, server)`.
  - Implement `get_mcp_tool_schema(tool_name)`.
  - Implement `execute_mcp_tool(tool_name, arguments)`.
  - Update `get_agent_tools()` to wrap and expose these tools.
- [ ] **Step 4: Run pytest to verify pass**
  - Run `./venv/bin/pytest tests/test_mcp_tools.py -v`
- [ ] **Step 5: Commit**
  - `git add multi-agent/manager/tools/tools.py tests/test_mcp_tools.py && git commit -m "feat(tools): add progressive MCP discovery meta-tools"`

---

### Task 3: Multi-Agent & DAC Agent Integration

**Files:**
- Modify: `multi-agent/manager/agent.py`
- Modify: `multi-agent/manager/sub_agents/*/agent.py`
- Modify: `dac-agent/tools/tools.py` & `dac-agent/agent.py`
- Test: `tests/test_agents_initialization.py`, `tests/test_dac_agent_initialization.py`

- [ ] **Step 1: Update agent tests to verify MCP meta-tools presence**
  - Add assertions in `tests/test_agents_initialization.py` and `tests/test_dac_agent_initialization.py`.
- [ ] **Step 2: Run pytest to verify failure**
  - Run `./venv/bin/pytest tests/test_agents_initialization.py tests/test_dac_agent_initialization.py -v`
- [ ] **Step 3: Integrate MCPToolRegistry across Manager, Sub-Agents, and DAC Agent**
  - Update agent prompt descriptions to mention MCP tool discovery capabilities.
- [ ] **Step 4: Run pytest to verify pass**
  - Run `./venv/bin/pytest tests/test_agents_initialization.py tests/test_dac_agent_initialization.py -v`
- [ ] **Step 5: Commit**
  - `git add multi-agent/ dac-agent/ tests/ && git commit -m "feat(agents): integrate progressive MCP tool discovery across all agents"`

---

### Task 4: Full Benchmark & End-to-End Verification

**Files:**
- Create: `multi-agent/reports/progressive_mcp_discovery_benchmark.md`
- Test: Full pytest suite & dataset runners

- [ ] **Step 1: Run complete test suite**
  - Run `./venv/bin/pytest tests/ evals/tests/ -v`
- [ ] **Step 2: Run all 3 benchmark evaluation datasets**
  - `./venv/bin/python -m evals.runner --dataset core_workflows`
  - `./venv/bin/python -m evals.runner --dataset all_36_workflows`
  - `./venv/bin/python -m evals.runner --dataset expanded_cases_alerts`
- [ ] **Step 3: Run cross-experiment benchmarks and generate comparative report**
  - `./venv/bin/python evals/run_cross_experiment_benchmarks.py`
- [ ] **Step 4: Commit**
  - `git add multi-agent/reports/ && git commit -m "docs(benchmarks): verify progressive MCP discovery with complete test suite"`
"""

spec_file.write_text(spec_text)
plan_file.write_text(plan_text)
print("[+] Successfully generated Design Spec and Implementation Plan in target worktree.")
