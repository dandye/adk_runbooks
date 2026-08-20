---
type: Reference
title: Multi-Agent Systems in ADK
description: "Comprehensive architecture guide for the ADK Runbooks multi-agent security operations platform, covering dual progressive disclosure, compiled graph workflows, and model distribution."
generated:
  by: human:dandye
  at: 2026-08-20T18:00:00-04:00
related:
  - ./architecture/adk_graph_workflows_overview.md
  - ./architecture/skills_progressive_disclosure_overview.md
  - ./architecture/progressive_mcp_discovery_overview.md
  - ./personas/personas.md
---

# Multi-Agent Systems in ADK

This document provides a comprehensive architectural overview of the **ADK Runbooks Multi-Agent System**, an enterprise-grade cybersecurity operations platform built on the Google Agent Development Kit (ADK 2.x). 

Specialized security agents collaborate through intelligent delegation, procedural skills, progressive MCP discovery, and pre-compiled graph workflows to triage alerts, execute incident response plans (IRPs), hunt advanced threats, and engineer detection rules.

---

## 1. Architectural Paradigms

The platform combines three core design patterns to eliminate context bloat, prevent model drift, and maximize token efficiency:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ ADK RUNBOOKS MULTI-AGENT ARCHITECTURE                                                   │
│                                                                                         │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 1. DUAL PROGRESSIVE DISCLOSURE (PROMPT & TOOL LEANNESS)                           │  │
│  │    • Tier 1: Skills Catalog (`SkillRegistry`) - Injects compact "Use when..."     │  │
│  │      triggers; full procedural runbooks loaded on demand via `load_skill()`.      │  │
│  │    • Tier 2: MCP Tool Registry (`MCPToolRegistry`) - Replaces 30+ static tool     │  │
│  │      schemas with 3 meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`,       │  │
│  │      `execute_mcp_tool`).                                                         │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                             │
│                                           ▼                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 2. COMPILED ADK GRAPH WORKFLOWS (DETERMINISTIC DAG EXECUTION)                     │  │
│  │    • 36 Pre-compiled Directed Acyclic Graph (DAG) workflows executed in-memory.   │  │
│  │    • Collapses 10–30 multi-turn LLM loops into 1–2 turns, reducing token          │  │
│  │      consumption by up to 97.7% while guaranteeing 100% SOP compliance.          │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
│                                           │                                             │
│                                           ▼                                             │
│  ┌───────────────────────────────────────────────────────────────────────────────────┐  │
│  │ 3. HIERARCHICAL MODEL DISTRIBUTION & SPECIALIZED PERSONAS                         │  │
│  │    • gemini-3.7-flash: Root SOC Manager, CTI Researcher, Detection Engineer,     │  │
│  │      Threat Hunter, LLM Judge, Detection-as-Code Agent.                           │  │
│  │    • gemini-2.5-flash: Tier 2/3 SOC Analysts, Incident Responder.                 │  │
│  │    • gemini-2.5-flash-lite: Tier 1 SOC Analyst (high-throughput initial triage). │  │
│  └───────────────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Project & Directory Structure

```text
project_root/
├── multi-agent/                       # Multi-agent system root
│   ├── manager/                       # Root SOC Manager agent package
│   │   ├── __init__.py                # Package initialization & root_agent export
│   │   ├── agent.py                   # Root SOC Manager configuration & sub-agent wiring
│   │   ├── tools/                     # Core tool integrations
│   │   │   ├── tools.py               # Progressive discovery meta-tools & skill helpers
│   │   │   ├── mcp_registry.py        # Centralized MCP tool registry & schema manager
│   │   │   └── workflow_tools.py      # 36 ADK Graph Workflow tool functions
│   │   ├── workflows/                 # Compiled ADK Graph Workflow modules
│   │   │   ├── common.py              # Shared schemas, payload parsing, SOAR formatting
│   │   │   ├── alert_report_workflow.py
│   │   │   ├── malware_irp_workflow.py
│   │   │   └── ... (36 dedicated workflow modules)
│   │   └── sub_agents/                # Specialized sub-agent packages
│   │       ├── cti_researcher/        # Cyber Threat Intelligence Specialist
│   │       ├── detection_engineer/    # Detection Rule & DaC Specialist
│   │       ├── incident_responder/    # IR & Containment Specialist
│   │       ├── llm_judge/             # Rubric & Artifact Evaluation Judge
│   │       ├── soc_analyst_tier1/     # First-line alert triage & IOC lookup
│   │       ├── soc_analyst_tier2/     # Escalation, correlation, deep analysis
│   │       ├── soc_analyst_tier3/     # Advanced forensic analysis & hunting
│   │       └── threat_hunter/         # Hypothesis-driven proactive hunter
│   ├── reports/                       # Generated forensic investigation reports & .stats.json
│   └── requirements.txt               # Multi-agent Python dependencies
├── skills/                            # Standardized Agent Skills taxonomy (62 packages)
│   ├── triage/                        # Alert triage & initial categorization
│   ├── irps/                          # Incident Response Plans (Malware, Phishing, Ransomware, User)
│   ├── investigation/                 # Deep dive analysis, timeline extraction, containment
│   ├── hunting/                       # Proactive threat hunting playbooks (APT, Credentials, WMI)
│   ├── detection/                     # Detection rule validation & DaC workflows
│   ├── reporting/                     # Case reports, alert reports, executive summaries
│   ├── atomic/                        # 19 atomic entity lookups (IP, Domain, Hash, URL, User)
│   ├── common/                        # Shared SOAR documentation & artifact procedures
│   └── registry.py                    # Centralized SkillRegistry discovery & loader engine
├── evals/                             # Declarative evaluation harness & benchmark test suites
│   ├── datasets/                      # Golden evaluation datasets (71 total test cases)
│   ├── rubrics/                       # 100-point rubric scoring models
│   └── tests/                         # Full Pytest test suite
└── rules-bank/                        # Knowledge catalog, personas, & Sphinx documentation
```

---

## 3. Specialized Security Personas & Model Distribution

The multi-agent system models real-world SOC operational roles. Each agent is configured with an optimized Gemini model balancing reasoning depth, context capacity, and execution latency:

| Persona / Agent | Model | Primary Mission | Key Skills & Capabilities |
| :--- | :--- | :--- | :--- |
| **Root SOC Manager** | `gemini-3.7-flash` | Executive oversight, cross-agent coordination, IRP orchestration. | `run_case_report_workflow`, `load_skill`, `search_mcp_tools`, delegation. |
| **Tier 1 SOC Analyst** | `gemini-2.5-flash-lite` | High-throughput first-line alert monitoring, duplicate closure. | `triage-alerts`, `basic-ioc-enrichment`, `close-duplicate-cases`. |
| **Tier 2 SOC Analyst** | `gemini-2.5-flash` | Escalated alert investigation, correlation, cloud triage. | `deep-dive-ioc-analysis`, `case-event-timeline-analysis`, `cloud-vulnerability-triage`. |
| **Tier 3 SOC Analyst** | `gemini-2.5-flash` | Complex incident triage, digital forensics, advanced hunts. | `apt-threat-hunt`, `lateral-movement-hunt`, `detection-rule-validation`. |
| **CTI Researcher** | `gemini-3.7-flash` | Threat actor profiling, GTI campaign mapping, IOC intelligence. | `proactive-hunt-gti-campaign`, `investigate-gti-collection`, GTI MCP tools. |
| **Threat Hunter** | `gemini-3.7-flash` | Hypothesis-driven proactive anomaly searches across UDM logs. | `guided-ttp-hunt-credential-access`, `ioc-threat-hunt`, UDM query sweeps. |
| **Incident Responder** | `gemini-2.5-flash` | End-to-end incident containment, host isolation, recovery. | `ransomware-response`, `compromised-user-account-response`, `ioc-containment`. |
| **Detection Engineer** | `gemini-3.7-flash` | YARA-L rule lifecycle, DaC pipeline validation, FP tuning. | `detection-as-code-workflows`, `detection-rule-validation-tuning`, DaC tests. |
| **LLM Judge** | `gemini-3.7-flash` | Objective rubric scoring (0–100 pts) and artifact auditing. | 100-point rubric engines, execution trace fact-checking. |

---

## 4. Progressive Disclosure & Dynamic Tooling

### Procedural Skills (`skills/`)
Instead of dumping full runbook markdown into system prompts, agents receive a lean catalog:
* **System Prompt Injection:** `load_persona_with_skills_catalog(persona_path, skill_ids)` generates a compact markdown list (`- skill-name: "Use when..."`).
* **On-Demand Loading:** Agents invoke `load_skill(skill_name="ransomware-response")` to pull full step-by-step procedures, tool arguments, and completion criteria into working context only when needed.

### Progressive MCP Tool Discovery
Instead of binding dozens of static JSON schemas upfront:
* **`search_mcp_tools(query, server)`**: Discovers security tools dynamically by keyword or server namespace (`siem`, `soar`, `gti`).
* **`get_mcp_tool_schema(tool_name)`**: Retrieves structured parameter definitions and JSON schema on demand.
* **`execute_mcp_tool(tool_name, arguments)`**: Validates arguments against schema and executes calls with latency and error tracking.

---

## 5. Getting Started & Execution

### Prerequisites
* Python 3.11+
* Google Cloud Project with Vertex AI API enabled and `GOOGLE_API_KEY` configured.

### Installation
```bash
# Clone repository with submodules
git clone --recurse-submodules https://github.com/dandye/adk_runbooks.git
cd adk_runbooks/multi-agent

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate

# Install compiled dependencies
pip install -r requirements.txt
```

### Environment Configuration
1. **ADK Agent Credentials:**
   * Copy `./multi-agent/manager/.env.example` to `./multi-agent/manager/.env`
   * Set your `GOOGLE_API_KEY` (and `GOOGLE_GENAI_USE_VERTEXAI=true` if using Vertex AI).
2. **MCP Security Tools Credentials:**
   * Copy `./external/mcp-security/.env.example` to `./external/mcp-security/.env`
   * Configure API credentials for Chronicle SIEM, SecOps SOAR, and VirusTotal/GTI.

### Running the System
```bash
# Run the interactive CLI agent from the multi-agent directory
adk run manager

# Or launch the local web UI
adk web manager
```

---

## 6. Evaluation & Benchmarking

The platform includes a native Pytest evaluation harness in `evals/`:
```bash
# Run all unit and harness tests
pytest tests/ evals/tests/ -v

# Run full regression suite across all 36 graph workflows
pytest evals/tests/test_all_36_workflows.py -v

# Execute CLI benchmark runner
python -m evals.runner --dataset core_workflows --report
```

---

## 7. Additional Resources

* {doc}`ADK Graph Workflows Architecture & Benchmarks <architecture/adk_graph_workflows_overview>`
* {doc}`Skills Progressive Disclosure Framework <architecture/skills_progressive_disclosure_overview>`
* {doc}`Progressive MCP Discovery & Schema Expansion <architecture/progressive_mcp_discovery_overview>`
* {doc}`Security Personas Catalog <personas/personas>`
