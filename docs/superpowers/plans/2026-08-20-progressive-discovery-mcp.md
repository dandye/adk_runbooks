# Progressive MCP Tool Discovery & Dispatcher Implementation Plan

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
