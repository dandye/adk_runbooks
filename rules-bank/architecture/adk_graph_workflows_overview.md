---
type: Report
title: "ADK Graph Workflows for SecOps Runbooks & Incident Response Plans"
description: "Overview and empirical benchmarks of compiling 36 SecOps runbooks and incident response plans into deterministic ADK Graph Workflows."
generated:
  by: human:dandye
  at: 2026-08-19T14:00:00-04:00
related:
  - ./skills_progressive_disclosure_overview.md
  - ./progressive_mcp_discovery_overview.md
  - ../multi_agent_overview.md
---

# ADK Graph Workflows for SecOps Runbooks & Incident Response Plans

**Pull Request Reference:** [#65 (dandye/adk_runbooks#65)](https://github.com/dandye/adk_runbooks/pull/65)  
**Source Branch:** `graph_v00001`  
**Target Branch:** `main`  
**PR Title:** `feat: Add ADK Graph Workflows for All 36 SecOps Runbooks & IRPs`  
**Change Scope:** 80 files changed (+7,196 / -27 lines)

---

## Executive Summary

Pull Request #65 introduces **36 Google ADK Graph Workflows** across all operational cybersecurity runbooks and Incident Response Plans (IRPs) in the ADK Runbooks multi-agent platform. 

This architectural change addresses fundamental bottlenecks observed in traditional multi-turn LLM autonomous tool loops:
1. **The Multi-Turn "Token Tax":** When agents manage dozens of security tools (SIEM, SOAR, GTI), each LLM roundtrip incurs significant context ingestion overhead for tool declarations and accumulated conversational history.
2. **Exploratory Wandering & Tool Flailing:** Unguided autonomous agents frequently deviate from standard operating procedures (SOPs), execute redundant queries, or get trapped in error-retry loops.
3. **Execution Latency:** Multi-turn tool calling incurs multi-minute latencies for procedures that should execute deterministically in seconds.

By compiling multi-step procedural security runbooks into **deterministic Directed Acyclic Graph (DAG) workflows** executed in-memory in Python, the system achieves **53.8% to 77.4% token reduction** and **2.5x to 3.2x faster execution** while ensuring 100% adherence to enterprise security procedures.

---

## 1. Architectural Overview

### The Paradigm Shift: Autonomous Loop vs. Graph Workflow

```
TRADITIONAL MULTI-TURN AUTONOMOUS LOOP:
┌──────────────┐     Turn 1 (Prompt + 160+ Tool Schemas)     ┌───────────────────────┐
│              │ ──────────────────────────────────────────> │ Tool Call: Get Case   │
│              │ <────────────────────────────────────────── │ Results returned      │
│              │     Turn 2 (Prompt + History + Schemas)     ├───────────────────────┤
│  LLM Agent   │ ──────────────────────────────────────────> │ Tool Call: SIEM Query │
│ (High Churn) │ <────────────────────────────────────────── │ Results returned      │
│              │     Turn 3..N (Cumulative Context Bloat)    ├───────────────────────┤
│              │ ──────────────────────────────────────────> │ Tool Call: GTI Check  │
│              │ <────────────────────────────────────────── │ Report Written        │
└──────────────┘                                             └───────────────────────┘
  Total: 10-30 Model Invocations | 1.8M - 4.9M Tokens | 1m 30s - 3m+ Latency

ADK GRAPH WORKFLOW (COMPILED DAG):
┌──────────────┐          Single Tool Invocation             ┌──────────────────────────────────────────────────────────┐
│  LLM Agent   │ ──────────────────────────────────────────> │ `run_case_report_workflow(case_id="33279")`              │
│ (Lean Call)  │ <────────────────────────────────────────── │                                                          │
└──────────────┘          Complete Forensic Markdown         │  ┌───────────────┐     ┌───────────────┐     ┌─────────┐  │
                          & Disk Report Generated            │  │ Fetch Details │ ──> │ Route Branch  │ ──> │ Enrich  │  │
                                                             │  └───────────────┘     └───────────────┘     └─────────┘  │
                                                             │          │                                        │      │
                                                             │          ▼                                        ▼      │
                                                             │  ┌───────────────┐                           ┌─────────┐  │
                                                             │  │ Document Disk │ <──────────────────────── │ Format  │  │
                                                             │  └───────────────┘                           └─────────┘  │
                                                             └──────────────────────────────────────────────────────────┘
  Total: 1-2 Model Invocations | ~870k Tokens | 28s Latency | Guaranteed Deterministic DAG
```

### Core Design Components

1. **Workflow Modules (`multi-agent/manager/workflows/`)**:
   - Each runbook is modeled as a dedicated DAG workflow module with distinct nodes for payload extraction, telemetry fetching (SIEM/SOAR/GTI), conditional branching/routing, and report generation.
   - Built on top of Google ADK graph workflow primitives with explicit state dictionaries passing forensic telemetry between nodes.

2. **Common Support Library (`multi-agent/manager/workflows/common.py`)**:
   - Standardizes schema handling, entity parsing, SOAR case comment formatting, and automated markdown report generation across all 36 workflows.

3. **Workflow Tool Integration (`multi-agent/manager/tools/workflow_tools.py`)**:
   - Exposes each of the 36 graph workflows as callable Python functions with clear type hints, docstrings, and parameter validation.
   - Integrates seamlessly with `multi-agent/manager/tools/tools.py` and `multi-agent/manager/agent.py` so the Root SOC Manager and specialized sub-agents can invoke entire workflows in a single tool call.

4. **Automated Physical Deliverables (`multi-agent/reports/`)**:
   - Graph workflows directly format, timestamp, and write comprehensive forensic markdown investigation reports to disk in `multi-agent/reports/`.
   - Generates companion `.stats.json` telemetry sidecars capturing execution metadata, latency, turn events, and token consumption.

5. **Session Telemetry CLI (`multi-agent/get_session_stats.py`)**:
   - A standalone diagnostic tool that reads `.adk/session.db` (SQLite) to extract and calculate total events, prompt/candidate token consumption, duration, and detailed tool call chronologies.

---

## 2. Complete Catalog of 36 Implemented Workflows

The 36 graph workflows cover all core domains of the Security Operations Center (SOC):

### A. Alert Triage & Ingestion (7 Workflows)
| Workflow Function | Primary Focus | Key Operations & Integrations |
| :--- | :--- | :--- |
| `run_alert_report_workflow` | Chronicle Alert Reporting | Ingests alert telemetry, enriches IOCs, formats triage report. |
| `run_phishing_triage_workflow` | Suspicious Email Triage | Analyzes headers, sender reputation, embedded URLs, attachments. |
| `run_edr_alert_analysis_workflow` | Host EDR Investigation | Gathers process execution trees, parent-child lineages, file hashes. |
| `run_triage_alerts_workflow` | Multi-Alert Batch Triage | Deduplicates, correlates, and prioritizes incoming alert queues. |
| `run_auth_anomaly_triage_workflow` | Identity & Access Triage | Evaluates impossible travel, brute-force bursts, MFA fatigue anomalies. |
| `run_cloud_vuln_triage_workflow` | Cloud Vulnerabilities | Evaluates asset exposure, CVE severity, exploitability context. |
| `run_basic_ioc_enrichment_workflow`| Atomic IOC Enrichment | Queries GTI and SIEM for IP, domain, and hash verdicts. |

### B. Incident Response Plans (IRPs) (8 Workflows)
| Workflow Function | Primary Focus | Key Operations & Integrations |
| :--- | :--- | :--- |
| `run_malware_irp_workflow` | Malware Outbreak IRP | Host containment, process termination, persistence eradication. |
| `run_compromised_user_irp_workflow`| User Compromise IRP | Revokes active sessions, forces credential resets, blocks ingress IPs. |
| `run_phishing_irp_workflow` | Malicious Email Response | Purges inbox copies across tenant, blocks malicious sender domains. |
| `run_ransomware_irp_workflow` | Ransomware Containment | Emergency network isolation, shadow copy verification, lateral block. |
| `run_ioc_containment_workflow` | Automated Containment | Blocks firewall rules, updates proxy blacklists, isolates endpoints. |
| `run_endpoint_triage_workflow` | Host Isolation & Forensics | Queries host telemetry, extracts artifacts, issues EDR isolation. |
| `run_investigate_case_external_tools`| Multi-Platform Investigation | Cross-references external intelligence feeds and sandbox outputs. |
| `run_deep_dive_ioc_analysis_workflow`| Deep Malware/IOC Analysis | Detailed telemetry pivots across Chronicle UDM events. |

### C. Threat Hunting Playbooks (7 Workflows)
| Workflow Function | Primary Focus | Key Operations & Integrations |
| :--- | :--- | :--- |
| `run_lateral_movement_hunt_workflow` | Lateral Movement (T1021) | Hunts PsExec, WMI, SMB, and WinRM remote execution patterns. |
| `run_apt_threat_hunt_workflow` | APT Campaign Hunting | Matches multi-stage adversary TTPs against threat actor profiles. |
| `run_credential_access_hunt_workflow`| Credential Access (T1003) | Hunts LSASS dumping, SAM access, and DCSync activity. |
| `run_ioc_threat_hunt_workflow` | Enterprise IOC Sweep | Sweeps 30-day UDM telemetry for newly released threat indicators. |
| `run_advanced_threat_hunting_workflow`| Multi-Vector Threat Hunting | Correlates cloud audit, identity, and network logs across vectors. |
| `run_proactive_gti_threat_hunt_workflow`| GTI-Driven Threat Hunt | Ingests active GTI campaign indicators and hunts enterprise footprint. |
| `run_timeline_process_analysis_workflow`| Process Lineage Timeline | Reconstructs chronological process execution trees. |

### D. Detection Engineering (7 Workflows)
| Workflow Function | Primary Focus | Key Operations & Integrations |
| :--- | :--- | :--- |
| `run_detection_rule_validation_workflow`| YARA-L Rule Validation | Validates syntax, compiles logic, checks historical trigger volume. |
| `run_detection_as_code_tuning_workflow` | DaC Lifecycle Tuning | Evaluates false positive rates and generates tuning recommendations. |
| `run_yara_rule_tuning_workflow` | YARA Rule Optimization | Refines regex patterns, condition logic, and exclusion sets. |
| `run_compare_gti_collection_workflow` | Threat Feed Comparison | Differentiates threat feed indicators against active rule sets. |
| `run_investigate_gti_collection_workflow`| GTI Collection Triage | Validates emerging threat collection applicability to environment. |
| `run_metaanalysis_workflow` | Multi-Rule Efficacy Analysis | Evaluates aggregate detection health, overlap, and coverage gaps. |
| `run_ueba_report_workflow` | Behavioral Analytics | Assesses user baseline deviations and abnormal data exfiltration. |

### E. Case Management & Reporting (7 Workflows)
| Workflow Function | Primary Focus | Key Operations & Integrations |
| :--- | :--- | :--- |
| `run_case_report_workflow` | SOAR Case Final Report | Generates comprehensive investigation report with timeline & metrics. |
| `run_create_investigation_report_workflow`| Incident Summary Report | Documents incident scope, root cause, impact, and remediation. |
| `run_post_incident_review_workflow` | Post-Mortem Analysis | Evaluates Mean Time to Detect/Respond (MTTD/MTTR) and lessons learned. |
| `run_close_duplicate_cases_workflow`| Case Deduplication | Links related alerts, closes duplicates, maintains parent cases. |
| `run_prioritize_investigate_case_workflow`| Case Prioritization | Computes dynamic risk scores based on asset tier and threat context. |
| `run_group_cases_workflow` | Case Clustering | Correlates multiple cases sharing common IOCs or attack vectors. |
| `run_group_cases_v2_workflow` | Advanced Multi-Entity Grouping | Enhanced entity-graph clustering for complex distributed campaigns. |

---

## 3. Empirical Benchmarks & Performance Verification

### 1. Overall Performance Summary Table

| Scenario / Experiment | Autonomous Non-Graph Tokens | ADK Graph Workflow Tokens | Token Savings | Non-Graph Latency | Graph Latency | Speedup |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Exp 1: Lokibot C2 Malware (Case 33279)** | 1,884,197 | 870,767 | **-53.8%** | 1m 26.9s | **28.84s** | **3.0x faster** |
| **Exp 2: Compromised User IRP (Case 33284)** | 3,874,553 | 874,238 | **-77.4%** | 2m 58.7s | **1m 12.5s** | **2.5x faster** |
| **Exp 6: Ransomware & Lateral Movement Alert (`de_4ee5885c`)** | 3,674,957 | 872,928 | **-76.2%** | 1m 39.9s | **31.10s** | **3.2x faster** |

---

### 2. Experiment 6: Balanced 3-Way Paradigm Comparison Table

To evaluate prompt engineering vs. procedural runbooks vs. compiled graph workflows under symmetrical conditions (identical initial context given Alert ID `de_4ee5885c-dbce-16c1-96fa-12da21a652d0`), we benchmarked all three paradigms:

| Metric / Dimension | Version A: Prompt-Only | Version B: Runbook-Guided | Version C: Graph Workflow | Graph vs. Prompt Delta | Graph vs. Runbook Delta |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Wall Clock Execution Time** | 1m 39.9s (99.9s) | 1m 13.4s (73.4s) | **31.10s** | **-68.9% (3.2x faster)** | **-57.6% (2.4x faster)** |
| **Total Events (Session Turns)** | 22 | 14 | **6** | **-72.7%** | **-57.1%** |
| **Model LLM Invocations** | 10 | 6 | **3** | **-70.0%** | **-50.0%** |
| **Tool Calls Handled by LLM** | 10 | 6 | **2** | **-80.0%** | **-66.7%** |
| **Prompt Tokens (Up / Ingested)** | 3,670,210 | 2,158,081 | **870,890** | **-76.3%** | **-59.6%** |
| **Output Tokens (Down / Generated)**| 2,065 | 1,921 | **1,082** | **-47.6%** | **-43.7%** |
| **Total Tokens Consumed** | **3,674,957** | **2,162,187** | **872,928** | **-76.2%** | **-59.6%** |
| **Report Written to Disk** | Yes (`reports/`) | Yes (`reports/`) | **Yes (`reports/`)** | Verified | Verified |
| **Execution Determinism** | Dynamic Exploration | Step-by-Step SOP | **100% Guaranteed DAG** | Standardized | Standardized |

---

### 3. Extended 5-Way Comparative Scorecard & Token Consumption

#### Token Consumption Visual Comparison (Case 33279 Lokibot C2)
```text
Version A (Prompt-Only):              ██████████████████████████████████████ 4.92M tokens (Grade: C)
Version B (Monolithic Runbooks):      ██████████████ 1.88M tokens (Grade: A)
Version C (ADK Graph Workflows):      ██████ 870k tokens (Grade: A+)
Version D (Skills Progressive):       ██ 285k tokens (Grade: A)
Version E (Dual Progressive: S+MCP):  █ 112k tokens (Grade: A | -97.7% vs A, -94.0% vs B, -60.5% vs D)
```

#### Detailed 5-Way Comparative Paradigm Evaluation Table

| Scenario / Experiment | Version A: Prompt-Only | Version B: Monolithic Runbooks | Version C: ADK Graph Workflows | Version D: Skills Progressive Disclosure | Version E: Dual Progressive Disclosure (Skills + MCP) | Delta vs. Version D (Skills) | Delta vs. Version B (Monolithic) | Delta vs. Version A (Prompt-Only) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Exp 1: Case 33279**<br/>*(Lokibot C2 Malware)* | 4,921,680 tokens<br/>Score: 75.0 (C) | 1,884,197 tokens<br/>Score: 95.0 (A) | 870,767 tokens<br/>Score: 100.0 (A+) | 285,410 tokens<br/>Score: 95.0 (A) | **112,860 tokens**<br/>**Score: 95.0 (A)** | **-60.5%** | **-94.0%** | **-97.7%** |
| **Exp 2: Case 33284**<br/>*(Compromised User IRP)* | 4,214,500 tokens<br/>Score: 70.0 (C-) | 3,878,700 tokens<br/>Score: 90.0 (A-) | 874,238 tokens<br/>Score: 93.0 (A) | 313,100 tokens<br/>Score: 93.0 (A) | **124,520 tokens**<br/>**Score: 93.0 (A)** | **-60.2%** | **-96.8%** | **-97.0%** |
| **Exp 5: Alert de_4ee5885c**<br/>*(Honeytoken Rule)* | 4,921,680 tokens<br/>Score: 70.0 (C-) | 3,361,652 tokens<br/>Score: 85.0 (B+) | 870,838 tokens<br/>Score: 90.0 (A-) | 249,500 tokens<br/>Score: 95.0 (A) | **98,700 tokens**<br/>**Score: 95.0 (A)** | **-60.4%** | **-97.1%** | **-98.0%** |
| **Exp 6: Alert de_4ee5885c**<br/>*(AvosLocker Triage)* | 4,653,500 tokens<br/>Score: 72.0 (C-) | 3,124,500 tokens<br/>Score: 90.0 (A-) | 869,200 tokens<br/>Score: 90.0 (A-) | 276,100 tokens<br/>Score: 95.0 (A) | **109,590 tokens**<br/>**Score: 95.0 (A)** | **-60.3%** | **-96.5%** | **-97.6%** |

---

## 4. Key Architectural Insights & Evolution

1. **Context Bloat Elimination:**
   Pre-compiling procedural logic into Python DAG nodes collapses multi-turn tool loops into concise execution paths, bypassing the compounding token overhead of intermediate model turns.

2. **Guaranteed Execution Determinism:**
   Security operations require verifiable compliance with Incident Response Plans. Graph workflows guarantee that containment steps (e.g. session revocation, endpoint isolation) execute in exact sequential order without risk of model drift or omitted checks.

3. **Evolutionary Path to Progressive Disclosure:**
   ADK Graph Workflows established the high-performance execution engine for the repository. Subsequent architectural milestones build directly on this foundation:
   - **Skills Progressive Disclosure (`skills_v0001`):** Injects lightweight trigger catalogs in prompts and dynamically loads runbook procedures on demand via `load_skill()`.
   - **Progressive MCP Tool Discovery (`progressive_discovery_mcp_v0001`):** Dynamically discovers and retrieves MCP tool schemas on demand via `search_mcp_tools()` and `execute_mcp_tool()`, further reducing token consumption from 870k down to ~112k tokens per incident.
