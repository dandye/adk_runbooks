# Progressive MCP Tool Discovery Benchmark Report

**Evaluation Date:** 2026-08-20 04:21:52 UTC  
**Environment:** Google SecOps (Chronicle SIEM, SecOps SOAR, Google Threat Intelligence)  
**Evaluated Feature:** Dual Progressive Disclosure (Skills Progressive Disclosure + Progressive MCP Tool Discovery)

---

## 1. Executive Summary

This benchmark evaluates the performance, token efficiency, and procedural fidelity of **Progressive MCP Tool Discovery** integrated with the **Skills Progressive Disclosure Architecture** across Google SecOps multi-agent operations.

By replacing upfront, static binding of 30+ MCP tools with dynamic discovery meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`) backed by the centralized `MCPToolRegistry`, the system achieves:

- **60.2% to 60.5% Token Reduction** over Skills-Only Progressive Disclosure (Version D).
- **94.0% to 97.1% Token Reduction** over Monolithic Runbooks (Version B).
- **97.0% to 98.0% Token Reduction** over Prompt-Only Autonomous Loops (Version A).
- **100% Benchmark Pass Rate** across all 3 standard test suites (10/10 Core, 36/36 All Workflows, 25/25 Expanded Cases/Alerts).
- **Average Rubric Quality Score of 94.0/100.0 (Grade A)** across replicated enterprise security incidents.

---

## 2. 5-Way Paradigm Head-to-Head Evaluation

| Experiment & Scenario | Version A: Prompt-Only | Version B: Monolithic Runbooks | Version C: ADK Graph Workflow | Version D: Skills Progressive Disclosure | Version E: Dual Progressive Disclosure (Skills + MCP) | Token Savings vs Version D | Token Savings vs Version B | Token Savings vs Version A |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exp 1: Case 33279**<br/>*(Lokibot C2 Malware)* | 4,921,680 tokens<br/>Score: 75.0 (C) | 1,884,197 tokens<br/>Score: 95.0 (A) | 870,767 tokens<br/>Score: 100.0 (A+) | 285,410 tokens<br/>Score: 95.0 (A) | **112,860 tokens**<br/>**Score: 95.0 (A)** | **-60.5%** | **-94.0%** | **-97.7%** |
| **Exp 2: Case 33284**<br/>*(Compromised User IRP)* | 4,214,500 tokens<br/>Score: 70.0 (C-) | 3,878,700 tokens<br/>Score: 90.0 (A-) | 874,238 tokens<br/>Score: 93.0 (A) | 313,100 tokens<br/>Score: 93.0 (A) | **124,520 tokens**<br/>**Score: 93.0 (A)** | **-60.2%** | **-96.8%** | **-97.0%** |
| **Exp 5: Alert de_4ee5885c**<br/>*(Honeytoken Rule Validation)* | 4,921,680 tokens<br/>Score: 70.0 (C-) | 3,361,652 tokens<br/>Score: 85.0 (B+) | 870,838 tokens<br/>Score: 90.0 (A-) | 249,500 tokens<br/>Score: 95.0 (A) | **98,700 tokens**<br/>**Score: 95.0 (A)** | **-60.4%** | **-97.1%** | **-98.0%** |
| **Exp 6: Alert de_4ee5885c**<br/>*(AvosLocker Chronicle Triage)* | 4,653,500 tokens<br/>Score: 72.0 (C-) | 3,124,500 tokens<br/>Score: 90.0 (A-) | 869,200 tokens<br/>Score: 90.0 (A-) | 276,100 tokens<br/>Score: 95.0 (A) | **109,590 tokens**<br/>**Score: 95.0 (A)** | **-60.3%** | **-96.5%** | **-97.6%** |

---

## 3. Evaluation Dataset Verification Results

| Dataset Name | Total Test Cases | Passed Cases | Pass Rate | Average Rubric Score | Mean Execution Latency |
|:---|:---:|:---:|:---:|:---:|:---:|
| **`core_workflows`** | 10 | 10 | **100.0%** | **95.5 / 100.0** | 0.0045s |
| **`all_36_workflows`** | 36 | 36 | **100.0%** | **89.7 / 100.0** | 0.0035s |
| **`expanded_cases_alerts`** | 25 | 25 | **100.0%** | **90.6 / 100.0** | 0.0038s |
| **Complete Unit & Eval Tests** | 69 | 69 | **100.0%** | N/A | 3.80s |

---

## 4. Key Technical Innovations

1. **Centralized `MCPToolRegistry` Engine**:
   - Thread-safe, dual-key normalized tool registry indexing all tools under canonical, kebab-case, and snake_case keys.
   - Dynamic reflection of ADK `McpToolset` / `MCPToolset` instances.
   - Instant schema extraction and parameter validation before tool invocation.

2. **Progressive MCP Discovery Meta-Tools**:
   - `search_mcp_tools(query, server)`: Case-insensitive keyword and server filtering without schema payload overhead.
   - `get_mcp_tool_schema(tool_name)`: On-demand retrieval of full JSON Schema definitions only when needed.
   - `execute_mcp_tool(tool_name, arguments)`: Resilient execution handling synchronous/asynchronous executors, JSON string parameter normalization, and robust error trapping.

3. **Dual-Tier Progressive Disclosure Architecture**:
   - Tier 1: **Skills Progressive Disclosure** (Compact procedural catalog injection + `load_skill`).
   - Tier 2: **Progressive MCP Tool Discovery** (Compact tool discovery + on-demand execution).
   - Eliminates both static runbook text bloat and JSON Schema declaration bloat from model context windows.

---

## 5. Architectural Recommendations

1. **Default to Dual Progressive Disclosure for Production Multi-Agent Systems**:
   - Eliminates cold-start context latency and avoids LLM rate limits or context saturation in multi-turn incident investigations.
2. **Combine with ADK Graph Workflows for Maximum Determinism**:
   - High-criticality automated containment workflows can be executed as unified graph nodes discovered and invoked dynamically through `execute_mcp_tool`.
