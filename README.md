# ADK Runbooks

A comprehensive multi-agent cybersecurity operations system built on Google's Agent Development Kit (ADK). This project provides specialized AI agents that collaborate to handle complex security operations tasks—including incident response, threat hunting, detection engineering, alert triage, and investigation—powered by a **Progressive Disclosure Skills Architecture**.

## Documentation

The full documentation for this project, including detailed runbooks and agent information, is available at:
[https://dandye.github.io/adk_runbooks](https://dandye.github.io/adk_runbooks)

## Overview

ADK Runbooks implements a manager-orchestrated multi-agent system where specialized security agents work together to execute security operations. Instead of inlining entire runbook corpora into system prompts, the system employs **Progressive Disclosure**: agents receive concise skill catalogs in their context and dynamically load full procedural playbooks, execution guidelines, and rubrics on-demand using specialized skill tools.

### Key Features

- **Multi-Agent Architecture**: A root Manager agent coordinates specialized sub-agents with domain expertise and shared toolsets.
- **Progressive Disclosure Skills Framework**: 62+ battle-tested security skills organized into standard taxonomy packages (`SKILL.md`) indexed by `SkillRegistry`. Agents dynamically fetch step-by-step instructions via `load_skill()`.
- **Detection-as-Code (DAC)**: Dedicated `dac-agent` for rule lifecycle management, validation, and automated tuning.
- **Model Context Protocol (MCP) Integration**: Seamless integration with security tools including Chronicle SIEM, Chronicle SOAR, and VirusTotal / Google Threat Intelligence (GTI).
- **Rigorous Evaluation & Benchmarking**: 4-rubric graph workflow evaluation framework covering 36+ end-to-end security operations workflows with automated scoring and markdown report generation.

---

## Skills & Progressive Disclosure Architecture

Operational playbooks, incident response plans (IRPs), and atomic procedures are structured as self-contained skills under `skills/`.

### Skill Taxonomy Categories

| Category | Description | Examples |
|---|---|---|
| **`skills/triage/`** | Alert triage and initial investigation | `triage-alerts`, `suspicious-login-triage`, `malware-triage`, `cloud-vulnerability-triage` |
| **`skills/irps/`** | Incident Response Plans for specific incident classes | `malware-incident-response`, `phishing-response`, `ransomware-response`, `compromised-user-account-response` |
| **`skills/investigation/`** | Case investigation, grouping, timelines, and IOC analysis | `deep-dive-ioc-analysis`, `prioritize-and-investigate-case`, `case-event-timeline-analysis`, `ioc-containment` |
| **`skills/hunting/`** | Proactive threat hunting playbooks | `advanced-threat-hunting`, `apt-threat-hunt`, `ioc-threat-hunt`, `lateral-movement-hunt-psexec-wmi` |
| **`skills/detection/`** | Detection-as-Code workflows and rule validation | `detection-rule-validation-tuning`, `detection-as-code-workflows`, `detection-as-code-rule-tuning` |
| **`skills/reporting/`** | Standardized reporting guidelines and templates | `report-writing-guidelines`, `create-investigation-report`, `alert-report`, `case-report`, `detection-report` |
| **`skills/atomic/`** | Atomic IOC lookups and enrichment steps | `lookup-ip-chronicle`, `lookup-domain-gti`, `search-chronicle-udm-hash`, `lookup-user-chronicle` |
| **`skills/common/`** | Reusable operational procedures | `document-in-soar`, `close-soar-artifact`, `find-relevant-soar-case`, `enrich-ioc`, `generate-report-file` |

### How Progressive Disclosure Works

```
┌────────────────────────────────────────────────────────┐
│ Agent System Prompt                                    │
│ - Persona / Role Definition                            │
│ - Available Skills Catalog (Names & Brief Descriptions)│
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼ (Agent identifies needed procedure)
┌────────────────────────────────────────────────────────┐
│ Dynamic Tool Call: load_skill("<skill-name>")          │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼ (SkillRegistry returns full markdown)
┌────────────────────────────────────────────────────────┐
│ Execution Context                                      │
│ - Step-by-step instructions & decision trees           │
│ - Prerequisites, tool call sequences, and rubrics      │
│ - Markdown operational report writing in reports/      │
└────────────────────────────────────────────────────────┘
```

---

## Security Agents

| Agent | Module | Role & Core Responsibilities |
|---|---|---|
| **Manager Agent** | `multi-agent/manager/agent.py` | Orchestrator; triages incoming requests, delegates to specialists, tracks IRP lifecycle. |
| **SOC Analyst Tier 1** | `multi-agent/manager/sub_agents/soc_analyst_tier1/` | Initial alert triage, basic investigation, IOC enrichment, duplicate case handling. |
| **SOC Analyst Tier 2** | `multi-agent/manager/sub_agents/soc_analyst_tier2/` | Deep-dive case investigation, event timeline analysis, GTI campaign correlation. |
| **SOC Analyst Tier 3** | `multi-agent/manager/sub_agents/soc_analyst_tier3/` | Advanced forensics, complex incident escalation, detection rule tuning. |
| **Threat Hunter** | `multi-agent/manager/sub_agents/threat_hunter/` | Proactive hypothesis-driven hunting, APT campaigns, TTP credential access & lateral movement hunts. |
| **CTI Researcher** | `multi-agent/manager/sub_agents/cti_researcher/` | Cyber threat intelligence research, GTI collections, actor profiling. |
| **Incident Responder** | `multi-agent/manager/sub_agents/incident_responder/` | Containment, eradication, recovery, endpoint isolation, and full IRP execution. |
| **Detection Engineer** | `multi-agent/manager/sub_agents/detection_engineer/` | Rule authoring, YARA-L validation, Detection-as-Code workflows, false positive tuning. |
| **LLM Judge** | `multi-agent/manager/sub_agents/llm_judge/` | Procedural compliance assessment and rubric-based report evaluation. |
| **DAC Agent** | `dac-agent/agent.py` | Standalone Detection-as-Code agent for rule management and CI/CD validation. |

---

## Project Structure

```
adk_runbooks/
├── multi-agent/              # Multi-agent system implementation
│   ├── manager/              # Manager agent and sub-agents
│   │   ├── sub_agents/       # Specialized security sub-agents
│   │   └── tools/            # MCP tool configurations & skill loading tools
│   └── reports/              # Generated markdown operational reports
├── dac-agent/                # Standalone Detection-as-Code agent
├── skills/                   # Standardized security skills repository (SKILL.md)
│   ├── atomic/               # Atomic IOC lookups and enrichment skills
│   ├── common/               # Reusable SOAR and reporting procedures
│   ├── detection/            # Detection engineering and rule tuning
│   ├── hunting/              # Threat hunting playbooks
│   ├── investigation/        # Case investigation and timeline analysis
│   ├── irps/                 # Incident Response Plans (IRPs)
│   ├── reporting/            # Standardized report writing guidelines
│   ├── triage/               # Alert and vulnerability triage procedures
│   └── registry.py           # Central SkillRegistry and parser engine
├── rules-bank/               # Agent personas and behavioral definitions
│   └── personas/             # System prompts and role definitions
├── evals/                    # Evaluation and benchmark framework
│   ├── datasets/             # Workflow benchmark datasets (core, all 36, expanded)
│   ├── rubrics/              # 4-rubric evaluation implementations
│   ├── runner.py             # CLI benchmark evaluation runner
│   └── registry.py           # Workflow definitions and graph executor
└── tests/                    # Unit and integration test suites
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Google API key (for Gemini models)
- Virtual environment tool (`venv`)

### Basic Setup

```bash
# Clone the repository with submodules
git clone --recurse-submodules https://github.com/dandye/adk_runbooks.git
cd adk_runbooks

# If already cloned without submodules:
git submodule update --init --recursive

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r multi-agent/requirements.txt

# Configure environment
cp multi-agent/manager/.env.example multi-agent/manager/.env
# Edit multi-agent/manager/.env and add your GOOGLE_API_KEY
```

### Running the Multi-Agent System

```bash
# Run CLI interface
cd multi-agent
adk run manager

# Run Web UI
adk web
```

---

## Testing & Benchmarking

### Running Test Suites

```bash
# Run all unit and integration tests
./venv/bin/pytest tests/ evals/tests/ -v
```

### Running Workflow Evaluations

The evaluation harness tests multi-agent and graph workflows against 4 procedural compliance rubrics (Triage/IRP, Threat Hunting, Detection Engineering, Reporting):

```bash
# Run core benchmark workflows (10 test cases)
./venv/bin/python -m evals.runner --dataset core_workflows

# Run all 36 operational workflows
./venv/bin/python -m evals.runner --dataset all_36_workflows

# Run expanded cases and alerts dataset (25 test cases)
./venv/bin/python -m evals.runner --dataset expanded_cases_alerts
```

---

## Contributing

Contributions are welcome! Please see our contributing guidelines for more information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on [Google's Agent Development Kit (ADK)](https://github.com/google/adk)
- Leverages [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for security tool integration
- Security procedures based on industry best practices and frameworks