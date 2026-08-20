# Benchmark Report: Experiment 6 (Balanced 3-Way Paradigm Evaluation)

**Case Evaluated:** Chronicle Alert `de_4ee5885c-dbce-16c1-96fa-12da21a652d0` (`avoslocker_encryptor_hash_ransom_note_T1486`)  
**Evaluation Date:** 2026-08-17  
**Environment:** Google SecOps (Chronicle SIEM, SecOps SOAR, Google Threat Intelligence)

---

## 1. Executive Summary

Experiment 6 evaluates three distinct execution paradigms across identical security alert telemetry with full analytical depth and physical artifact generation on disk:
1. **Version A (Prompt-Only Balanced)**: Open-ended alert investigation without procedural or graph steering.
2. **Version B (Runbook-Guided Balanced)**: Step-by-step SOP procedural execution using individual MCP tools.
3. **Version C (ADK Graph Workflow)**: Compiled deterministic DAG executed via `run_alert_report_workflow` with full forensic analysis and automatic report writing to disk.

### Key Benchmark Findings
* **76.2% Token Volume Reduction** (Graph vs. Prompt-Only: 872,928 tokens vs. 3,674,957 tokens).
* **59.6% Token Volume Reduction** (Graph vs. Runbook-Guided: 872,928 tokens vs. 2,162,187 tokens).
* **68.9% Wall Clock Speedup** (Graph executed in **31.10 seconds** vs. **99.93 seconds** for Prompt-Only and **73.44 seconds** for Runbook-Guided).
* **All 3 paradigms produced complete, forensic-grade markdown reports saved to disk in `multi-agent/reports/`**.

---

## 2. Head-to-Head 3-Way Metrics Table

| Metric / Dimension | Version A: Prompt-Only (`627afcb0...`) | Version B: Runbook-Guided (`6681974c...`) | Version C: Graph Workflow (`c7a41894...`) | Graph vs. Prompt Delta | Graph vs. Runbook Delta |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Wall Clock Execution Time** | 1m 39.9s (99.9s) | 1m 13.4s (73.4s) | **31.10s** | **-68.9%** (3.2x faster) | **-57.6%** (2.4x faster) |
| **Total Events (Session Turns)** | 22 | 14 | **6** | **-72.7%** | **-57.1%** |
| **Model LLM Invocations** | 10 | 6 | **3** | **-70.0%** | **-50.0%** |
| **Tool Calls Handled by LLM** | 10 | 6 | **2** | **-80.0%** | **-66.7%** |
| **Prompt Tokens (Up / Ingested)** | 3,670,210 | 2,158,081 | **870,890** | **-76.3%** | **-59.6%** |
| **Output Tokens (Down / Generated)**| 2,065 | 1,921 | **1,082** | **-47.6%** | **-43.7%** |
| **Total Tokens Consumed** | 3,674,957 | 2,162,187 | **872,928** | **-76.2%** | **-59.6%** |
| **Report Saved to Disk** | Yes (`reports/`) | Yes (`reports/`) | **Yes (`reports/`)** | Verified | Verified |
| **Analysis Depth / Completeness** | High (Multi-turn) | High (Multi-turn) | **High (Deterministic DAG)** | Standardized | Standardized |

---

## 3. Behavioral Analysis of Execution Modes

### Version A: Prompt-Only (3.67M Tokens | 1m 40s)
* Without step-by-step guidance, the agent searched SIEM for unrelated workstations (`CYM-WKS-24`, `CYM-FS01`) and multiple external IPs before synthesizing the alert findings.
* Took 10 tool calls and 22 turns.

### Version B: Runbook-Guided (2.16M Tokens | 1m 13s)
* Procedural SOP structure prevented broad wandering. The agent queried alert details, ran targeted SIEM network searches, checked GTI IP reputation for `45.147.230.131`, and wrote the report.
* Reduced token usage by 41.2% and wall clock time by 26.5% vs. prompt-only.

### Version C: ADK Graph Workflow (873k Tokens | 31.1s)
* Single tool call `run_alert_report_workflow` executed the complete analytical pipeline in Python (alert metadata, rule logic, GTI threat reputation, true positive confidence scoring) and wrote `Alert_Report_de_4ee5885c...md` to disk.
* Delivered the lowest latency (31s), lowest token footprint (873k tokens), and 100% deterministic forensic structure.
