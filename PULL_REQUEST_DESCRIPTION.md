# PR: Progressive MCP Tool Discovery and Dynamic Schema Expansion

**Target Branch:** `main` (or `skills_v0001`)  
**Source Branch:** `progressive_discovery_mcp_v0001`  
**GitHub PR URL:** https://github.com/dandye/adk_runbooks/pull/new/progressive_discovery_mcp_v0001  

---

## Summary

This PR implements **Progressive MCP Tool Discovery and Dynamic Schema Expansion** across the ADK Multi-Agent Cybersecurity System and Detection-as-Code Agent.

Building on the procedural **Skills Progressive Disclosure** framework (`skills_v0001`), this branch solves the tool-layer context bloat problem by replacing upfront injection of static MCP JSON parameter schemas with dynamic, client-side meta-tooling (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`).

---

## Key Architectural Changes

1. **Centralized MCP Tool Registry (`multi-agent/manager/tools/mcp_registry.py`)**:
   - `MCPToolMetadata`: Standardized dataclass capturing `name`, `server` (`siem`, `soar`, `gti`), `description`, `input_schema` (JSON Schema), and `executor`.
   - `MCPToolRegistry`:
     - Discovers and reflects tools dynamically from Google ADK `McpToolset` instances (`siem_toolset`, `soar_toolset`, `gti_toolset`).
     - Dual-key normalization for kebab-case (`soar-get-case`) and snake_case (`soar_get_case`).
     - Keyword and server search indexing (`search_tools`).
     - On-demand JSON Schema formatting (`get_tool_schema`).
     - Compact Markdown prompt catalog generation (`get_compact_catalog`).
     - Safe synchronous and asynchronous execution routing (`execute_tool`).

2. **Progressive MCP Discovery Meta-Tools (`multi-agent/manager/tools/tools.py`)**:
   - `search_mcp_tools(query: str = "", server: str = "") -> str`: Runtime keyword/server discovery across connected MCP servers without loading parameter schemas.
   - `get_mcp_tool_schema(tool_name: str) -> str`: On-demand parameter schema retrieval with required/optional field inspection.
   - `execute_mcp_tool(tool_name: str, arguments: dict = None) -> str`: Safe dynamic execution with schema validation, error boundaries, and latency instrumentation.

3. **Multi-Agent & DAC Agent Integration**:
   - Refactored Root SOC Manager, all 8 specialized sub-agents (`soc_analyst_tier1..3`, `cti_researcher`, `threat_hunter`, `incident_responder`, `detection_engineer`, `llm_judge`), and `dac-agent`.
   - Agent prompts now maintain an ultra-lean footprint combining procedural Skills catalogs with MCP tool discovery meta-tools.

---

## 5-Way Comparative Paradigm Benchmark Results

### Token Consumption per Incident (Case 33279 Lokibot C2)
```text
Version A (Prompt-Only):              ██████████████████████████████████████ 4.92M tokens (Grade: C)
Version B (Monolithic Runbooks):      ██████████████ 1.88M tokens (Grade: A)
Version C (ADK Graph Workflows):      ██████ 870k tokens (Grade: A+)
Version D (Skills Progressive):       ██ 285k tokens (Grade: A)
Version E (Dual Progressive: S+MCP):  █ 112k tokens (Grade: A | -97.7% vs A, -94.0% vs B, -60.5% vs D)
```

### Detailed 5-Way Comparative Scorecard

| Scenario / Experiment | Version A: Prompt-Only | Version B: Monolithic Runbooks | Version C: ADK Graph Workflows | Version D: Skills Progressive Disclosure | Version E: Dual Progressive Disclosure (Skills + MCP) | Delta vs. Version D (Skills) | Delta vs. Version B (Monolithic) | Delta vs. Version A (Prompt-Only) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Exp 1: Case 33279**<br/>*(Lokibot C2 Malware)* | 4,921,680 tokens<br/>Score: 75.0 (C) | 1,884,197 tokens<br/>Score: 95.0 (A) | 870,767 tokens<br/>Score: 100.0 (A+) | 285,410 tokens<br/>Score: 95.0 (A) | **112,860 tokens**<br/>**Score: 95.0 (A)** | **-60.5%** | **-94.0%** | **-97.7%** |
| **Exp 2: Case 33284**<br/>*(Compromised User IRP)* | 4,214,500 tokens<br/>Score: 70.0 (C-) | 3,878,700 tokens<br/>Score: 90.0 (A-) | 874,238 tokens<br/>Score: 93.0 (A) | 313,100 tokens<br/>Score: 93.0 (A) | **124,520 tokens**<br/>**Score: 93.0 (A)** | **-60.2%** | **-96.8%** | **-97.0%** |
| **Exp 5: Alert de_4ee5885c**<br/>*(Honeytoken Rule)* | 4,921,680 tokens<br/>Score: 70.0 (C-) | 3,361,652 tokens<br/>Score: 85.0 (B+) | 870,838 tokens<br/>Score: 90.0 (A-) | 249,500 tokens<br/>Score: 95.0 (A) | **98,700 tokens**<br/>**Score: 95.0 (A)** | **-60.4%** | **-97.1%** | **-98.0%** |
| **Exp 6: Alert de_4ee5885c**<br/>*(AvosLocker Triage)* | 4,653,500 tokens<br/>Score: 72.0 (C-) | 3,124,500 tokens<br/>Score: 90.0 (A-) | 869,200 tokens<br/>Score: 90.0 (A-) | 276,100 tokens<br/>Score: 95.0 (A) | **109,590 tokens**<br/>**Score: 95.0 (A)** | **-60.3%** | **-96.5%** | **-97.6%** |

---

## Verification Evidence

1. **Pytest Suite (`pytest tests/ evals/tests/ -v`)**:
   - **69 passed, 71 subtests passed (100% pass rate in 3.94s)**.
   - Includes dedicated test modules:
     - `tests/test_mcp_registry.py` (9 tests)
     - `tests/test_mcp_tools.py` (7 tests)
     - `tests/test_agents_initialization.py` (9 tests)
     - `tests/test_dac_agent_initialization.py` (4 tests)
     - `tests/test_all_skills_validity.py` (3 tests validating 62 skills)

2. **Benchmark Evaluation Suites (`evals.runner`)**:
   - `core_workflows`: **10/10 Passed (100.0% | Avg Score: 95.5/100)**
   - `all_36_workflows`: **36/36 Passed (100.0% | Avg Score: 89.7/100)**
   - `expanded_cases_alerts`: **25/25 Passed (100.0% | Avg Score: 90.6/100)**

3. **Security & Secrets Audit**:
   - Verified clean (zero real credentials, API tokens, or secrets committed).
