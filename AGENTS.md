# Project Overview: ADK Multi-Agent Security System

This project implements a multi-agent cybersecurity system using the Agent Development Kit (ADK). It is designed to demonstrate how specialized agents can collaborate to handle complex security operations tasks, such as incident response, threat hunting, and detection engineering.

## Core Architecture

The system follows a hierarchical **Manager-Subagent** architecture:

*   **Manager Agent (`multi-agent/manager`)**: The root agent that acts as the primary interface for the user. It orchestrates the workflow by delegating tasks to specialized sub-agents based on the user's request and the active Incident Response Plan (IRP).
*   **Sub-Agents (`multi-agent/manager/sub_agents/`)**: Specialized agents with distinct personas and domains of expertise. They operate somewhat independently but report back to the manager.

## Agents & Personas

The system comprises the following agents, each defined by a persona in `rules-bank/personas/`:

1.  **Manager**:
    *   **Role**: Orchestrator and Team Lead.
    *   **Responsibilities**: Delegating tasks, overseeing IRP execution, ensuring collaboration, and writing final reports.
    *   **Tools**: `get_current_time`, `write_report`.

2.  **CTI Researcher** (`cti_researcher`):
    *   **Role**: Cyber Threat Intelligence Analyst.
    *   **Responsibilities**: Investigating threat actors, analyzing malware campaigns, researching TTPs (Tactics, Techniques, and Procedures), and providing context on external threats.

3.  **Detection Engineer** (`detection_engineer`):
    *   **Role**: Security Engineering Specialist.
    *   **Responsibilities**: Creating, testing, and tuning detection rules (e.g., YARA, SIGMA), and analyzing detection gaps.

4.  **Incident Responder** (`incident_responder`):
    *   **Role**: Incident Response Specialist.
    *   **Responsibilities**: Executing containment, eradication, and recovery strategies during active security incidents.

5.  **SOC Analyst Tier 1** (`soc_analyst_tier1`):
    *   **Role**: Triage Specialist.
    *   **Responsibilities**: Initial alert validation, basic IoC enrichment, and filtering false positives.

6.  **SOC Analyst Tier 2** (`soc_analyst_tier2`):
    *   **Role**: Incident Investigator.
    *   **Responsibilities**: Deep-dive analysis of escalated alerts, correlation of events, and handling standard incident cases.

7.  **SOC Analyst Tier 3** (`soc_analyst_tier3`):
    *   **Role**: Advanced Investigator & Hunter.
    *   **Responsibilities**: Handling complex or critical incidents, forensic analysis, and high-level threat analysis.

8.  **Threat Hunter** (`threat_hunter`):
    *   **Role**: Proactive Hunter.
    *   **Responsibilities**: Searching for undetected threats, hypothesis-driven hunting, and analyzing broad datasets for anomalies.

9.  **LLM Judge** (`llm_judge`):
    *   **Role**: Quality Assurance & Evaluator.
    *   **Responsibilities**: Evaluating runbook executions against defined rubrics, verifying artifacts, and providing scoring/feedback.

### Additional Personas (Without dedicated sub-agents)

*   **Chief Information Security Officer (CISO)**: Strategic oversight, risk management, and executive communication.
*   **Compliance Manager**: Ensuring adherence to regulatory standards (GDPR, PCI-DSS, etc.) and internal policies.
*   **Red Team Member**: Adversarial simulation, penetration testing, and testing Blue Team defenses.
*   **Security Engineer**: Infrastructure security, tool maintenance, and system hardening.


## Tooling & Capabilities

The system capabilities are significantly extended through the **Google MCP Security** submodule (`external/mcp-security`), which provides real-world security operations integration.

### MCP Security Tools
These tools are initialized by the Manager and shared with relevant sub-agents:

1.  **Google Security Operations (Chronicle)** (`secops_mcp`):
    *   Used by: `soc_analyst`, `threat_hunter`
    *   Capabilities: Threat detection, UDM searches, investigation, and hunting.
2.  **Google Security Operations SOAR** (`secops_soar_mcp`):
    *   Used by: `incident_responder`, `manager`
    *   Capabilities: Case management, playbook execution, and orchestration.
3.  **Google Threat Intelligence (GTI)** (`gti_mcp`):
    *   Used by: `cti_researcher`, `soc_analyst`
    *   Capabilities: Threat actor profiling, VirusTotal enrichment, and IOC reputation.
4.  **Security Command Center (SCC)** (`scc_mcp`):
    *   Used by: `security_engineer`, `compliance_manager`
    *   Capabilities: Cloud security posture management, risk analysis, and finding remediation.

## Key Directories

*   **`multi-agent/`**: Contains the source code for the agents.
    *   `manager/`: The root agent implementation.
    *   `manager/sub_agents/`: Implementations of all specialized sub-agents.
*   **`rules-bank/`**: collaborative knowledge base.
    *   `personas/`: Markdown files defining the personality, tone, and specific instructions for each agent.
    *   `run_books/`: Operational procedures (SOPs, IRPs) that agents follow to execute tasks consistently.
    *   `multi_agent_overview.md`: Documentation on the multi-agent patterns used.

## Configuration & Operation

*   **Environment**: Requires Python virtual environment and a `.env` file with `GOOGLE_API_KEY`.
*   **Execution**: Run `adk web` from the `multi-agent` directory.
*   **Interaction**: Users interact via a web UI, chatting primarily with the `manager` agent, which then routes queries.

## Design Philosophy

Information is strictly separated from Code.
*   **Code** (`multi-agent/`) is for the "body" of the agent (tools, connectivity, strict logic).
*   **Rules Bank** (`rules-bank/`) is for the "mind" of the agent (personas, knowledge, procedures).

This separation allows for easier updates to agent behaviors (via prompt engineering in Markdown) without modifying the underlying Python code.
