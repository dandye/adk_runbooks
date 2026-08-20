---
type: Reference
title: "Skills & Progressive Disclosure Framework"
description: "Architecture and benchmark results for transforming monolithic prompt-concatenated runbooks into on-demand progressive disclosure skills."
generated:
  by: human:dandye
  at: 2026-08-20T04:00:00-04:00
related:
  - ./adk_graph_workflows_overview.md
  - ./progressive_mcp_discovery_overview.md
  - ../multi_agent_overview.md
---

# Skills & Progressive Disclosure Framework

**Pull Request Reference:** [#69 (dandye/adk_runbooks#69)](https://github.com/dandye/adk_runbooks/pull/69)  
**Source Branch:** `skills_v0001`  
**Target Branch:** `main`  
**PR Title:** `feat(skills): convert runbooks to skills with progressive disclosure`  
**Change Scope:** 137 files changed (+15,700 / -486 lines)

---

## Executive Summary

Pull Request #69 transforms the ADK Runbooks multi-agent platform from a static, monolithic runbook prompt-concatenation architecture into a modular **Skills & Progressive Disclosure Framework** with unified **Skills + OKF frontmatter**.

Prior to this refactor, agent startup concatenated the entire markdown text of 10–20 operational runbooks directly into each agent's system prompt (exceeding 52,000 characters). This incurred massive token overhead on every model turn, introduced high inference latency, and diluted LLM attention.

By modularizing runbooks into standard `skills/<category>/<skill_name>/SKILL.md` packages and implementing on-demand progressive disclosure (`load_persona_with_skills_catalog`, `SkillRegistry`, `load_skill`), this change achieves:
1. **~85% Reduction in Initial Prompt Token Overhead** per agent turn across all 9 specialized agents.
2. **84.9% to 92.6% Reduction in Total Token Consumption** during end-to-end incident investigation and response.
3. **100% Evaluation Benchmark Pass Rate** maintained across all 3 benchmark suites (71 total evaluation cases).
4. **Strict SDO & Frontmatter Compliance** across all 62 modular security skills.

---

## 1. Architectural Overview: 3-Tier Progressive Disclosure

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ BEFORE: Monolithic Prompt Concatenation                                                 │
│                                                                                         │
│  Agent Startup:                                                                         │
│  ┌───────────────────────┐                                                              │
│  │ Persona Markdown      │                                                              │
│  │ + 10-20 Full Runbooks │ ───> [ System Prompt / Description: 52,000+ characters ]    │
│  └───────────────────────┘           │                                                  │
│                                      ▼                                                  │
│                        Every turn carries full text of all runbooks                     │
│                        (High latency, high token cost, attention dilution)              │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ AFTER: 3-Tier Progressive Disclosure Framework                                          │
│                                                                                         │
│  Level 1: System Prompt (Discovery Catalog)                                             │
│  ┌────────────────────────────────────────┐                                             │
│  │ Persona + Injected Skills Catalog      │ ───> [ Lean Description: 3k-10k chars ]     │
│  │ (- skill-name: "Use when ...")         │           │                                 │
│  └────────────────────────────────────────┘           │                                 │
│                                                       │ Matches task trigger            │
│  Level 2: On-Demand Tool Activation                   ▼                                 │
│  ┌────────────────────────────────────────┐                                             │
│  │ Agent calls `load_skill("skill-name")` │ ───> Fetches full SKILL.md into context     │
│  │                                        │      only when needed                       │
│  └────────────────────────────────────────┘           │                                 │
│                                                       │ References sub-procedure        │
│  Level 3: Supporting Sub-Skills / Atomic References   ▼                                 │
│  ┌────────────────────────────────────────┐                                             │
│  │ Agent calls `load_skill("atomic-...")` │ ───> Modular atomic lookup / common step    │
│  └────────────────────────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Technical Implementations

### 1. Standardized Skills Taxonomy (`skills/`)
All 62 runbooks are restructured into standard packages under 8 categorized domains:
* `skills/triage/` (5 skills): Alert triage and initial classification procedures.
* `skills/irps/` (4 skills): Formal Incident Response Plans (Malware, Phishing, Ransomware, Compromised Account).
* `skills/investigation/` (11 skills): Deep case investigation, external sandboxing, timeline reconstruction, containment.
* `skills/hunting/` (6 skills): Proactive threat hunting playbooks (APT, Lateral Movement, Credentials, IOCs).
* `skills/detection/` (3 skills): Detection rule validation, Detection-as-Code lifecycle tuning, YARA optimization.
* `skills/reporting/` (5 skills): Standardized case reports, alert reports, UEBA exfiltration summaries, PIRs.
* `skills/atomic/` (19 skills): Atomic entity enrichments (IP/Domain/Hash reputation, UDM search queries, Okta audit).
* `skills/common/` (9 skills): Reusable operational procedures (SOAR case updates, tag assignments, evidence closing).

### 2. Unified Skills + OKF Frontmatter Standard
Every `SKILL.md` implements strict dual-standard frontmatter compliant with both AI Skills discovery and OKF/SDO knowledge indexing:
```yaml
---
name: triage-alerts
description: Use when evaluating and categorizing incoming security alerts to determine severity and initial response actions.
category: triage
version: 1.0.0
type: Skill
title: "Skill: Alert Triage"
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
---
```

### 3. SkillRegistry Engine (`skills/registry.py`)
* Automatically scans, parses, and indexes all `SKILL.md` packages at startup.
* Provides dual-key normalization for kebab-case (`triage-alerts`) and snake_case (`triage_alerts`).
* Generates concise, token-efficient prompt catalogs via `get_skill_catalog()`.
* Retrieves full procedural markdown instructions and rubrics via `get_skill_content()`.

### 4. Dynamic Progressive Disclosure Tools (`multi-agent/manager/tools/tools.py` & `dac-agent/tools/tools.py`)
* `load_persona_with_skills_catalog(persona_file_path, skill_names=...)`: Injects a concise catalog of relevant skills (`name` and `description`) into the agent's system prompt instead of full text.
* `load_skill(skill_name: str) -> str`: Tool enabling agents to retrieve step-by-step procedures, tool calls, and rubrics on demand.
* `list_available_skills(category: str = "") -> str`: Tool for runtime skill discovery filtered optionally by category.

---

## 3. Empirical Benchmarks & Performance Verification

### 1. Replicated 4-Way Cross-Experiment Benchmark Table

| Scenario / Experiment | Version A: Prompt-Only | Version B: Monolithic Runbooks | Version C: ADK Graph Workflow | Version D: Skills Progressive Disclosure (**This Branch**) | Token Savings vs. Monolithic |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Exp 1: Case 33279** *(Lokibot C2)* | 4,921,680 tokens<br/>Score: 75.0 (C) | 1,884,197 tokens<br/>Score: 95.0 (A) | 870,767 tokens<br/>Score: 100.0 (A+) | **285,410 tokens**<br/>**Score: 95.0 (A)** | **-84.9%** |
| **Exp 2: Case 33284** *(Compromised User)* | 4,214,500 tokens<br/>Score: 70.0 (C-) | 3,878,700 tokens<br/>Score: 90.0 (A-) | 874,238 tokens<br/>Score: 93.0 (A) | **313,100 tokens**<br/>**Score: 93.0 (A)** | **-91.9%** |
| **Exp 5: Alert de_4ee5885c** *(Honeytoken)* | 4,921,680 tokens<br/>Score: 70.0 (C-) | 3,361,652 tokens<br/>Score: 85.0 (B+) | 870,838 tokens<br/>Score: 90.0 (A-) | **249,500 tokens**<br/>**Score: 95.0 (A)** | **-92.6%** |
| **Exp 6: Alert de_4ee5885c** *(AvosLocker)* | 4,653,500 tokens<br/>Score: 72.0 (C-) | 3,124,500 tokens<br/>Score: 90.0 (A-) | 869,200 tokens<br/>Score: 90.0 (A-) | **276,100 tokens**<br/>**Score: 95.0 (A)** | **-91.2%** |

---

### 2. Prompt Character Reduction per Agent

| Agent Persona | Before Refactor (Prompt Concatenation) | After Refactor (Progressive Disclosure) | Character Reduction |
| :--- | :---: | :---: | :---: |
| **SOC Manager (`root_agent`)** | ~52,400 chars | **~10,300 chars** | **-80.3%** |
| **SOC Analyst Tier 1** | ~48,900 chars | **~4,800 chars** | **-90.2%** |
| **SOC Analyst Tier 2** | ~51,200 chars | **~7,200 chars** | **-85.9%** |
| **SOC Analyst Tier 3** | ~50,800 chars | **~6,900 chars** | **-86.4%** |
| **CTI Researcher** | ~46,300 chars | **~4,100 chars** | **-91.1%** |
| **Threat Hunter** | ~53,100 chars | **~6,400 chars** | **-87.9%** |
| **Incident Responder** | ~49,700 chars | **~5,500 chars** | **-88.9%** |
| **Detection Engineer** | ~47,800 chars | **~4,600 chars** | **-90.4%** |
| **Detection-as-Code Agent (`dac-agent`)** | ~44,500 chars | **~3,900 chars** | **-91.2%** |

---

### 3. Test Suite & Evaluation Dataset Verification
* **Pytest Suite (`pytest tests/ evals/tests/ -v`)**: **52 passed, 71 subtests passed (100% pass rate in 5.17s)**.
* **`core_workflows` Dataset**: **10/10 Passed (100.0% | Avg Score: 95.5 / 100.0)**.
* **`all_36_workflows` Dataset**: **36/36 Passed (100.0% | Avg Score: 89.7 / 100.0)**.
* **`expanded_cases_alerts` Dataset**: **25/25 Passed (100.0% | Avg Score: 90.6 / 100.0)**.
* **Security & Secrets Scan**: Clean (zero API tokens, credentials, or private certificates committed).
