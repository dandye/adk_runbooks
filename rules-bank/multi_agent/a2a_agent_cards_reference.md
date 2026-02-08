# A2A Agent Cards Reference

This document serves as a reference for the Agent-to-Agent (A2A) Cards used in the ADK multi-agent system. These cards, implemented as YAML configuration files, define the capabilities, expertise, and tool access for each specialized agent in the system, enabling the SOC Manager agent to intelligently delegate tasks.

## Purpose

The A2A Agent Cards are the foundation of the [Configuration-Based Delegation System](./configuration_based_delegation.md). They allow the SOC Manager to "know" its team members' capabilities without hardcoding this logic into the manager's persona or prompt. This makes the system more modular, maintainable, and easier to expand.

## Location

The configuration files are located in:
`multi-agent/manager/config/agents/`

## Configuration Structure

Each agent card is a YAML file (e.g., `soc_analyst_tier1.yaml`) containing the following sections:

### 1. Identity & Description
Defines who the agent is and its high-level role.

```yaml
agent_name: soc_analyst_tier1        # Unique identifier (snake_case)
display_name: "SOC Analyst Tier 1"   # Human-readable name
description: "Initial alert triage and basic IOC enrichment specialist"
```

### 2. Expertise Areas
A list of specific skills or domains the agent specializes in. The manager uses these keywords to match tasks to agents.

```yaml
expertise_areas:
  - alert_triage
  - basic_ioc_enrichment
  - phishing_email_analysis
```

### 3. MCP Servers (Tools)
Lists the Model Context Protocol (MCP) servers the agent has access to. This defines the agent's "toolbox."

```yaml
mcp_servers:
  - name: secops-mcp
    description: "SIEM operations"
  - name: gti-mcp
    description: "Threat Intelligence"
```

### 4. Delegation Triggers
Keywords or phrases that, when present in a user request or manager's intent, strongly suggest this agent should handle the task.

```yaml
delegation_triggers:
  - "triage"
  - "alert"
  - "suspicious login"
```

### 5. Capabilities
Operational constraints and relationships, such as escalation paths and alert severity handling.

```yaml
capabilities:
  can_escalate_to:
    - soc_analyst_tier2
    - incident_responder
  handles_alert_severity:
    - low
    - medium
```

## Configured Agents

The following agents are currently configured in the system:

*   **SOC Manager (`manager.yaml`):** Orchestrates operations, delegates tasks, and writes reports.
*   **SOC Analyst Tier 1 (`soc_analyst_tier1.yaml`):** Handles initial triage, basic enrichment, and low/medium severity alerts.
*   **SOC Analyst Tier 2 (`soc_analyst_tier2.yaml`):** Performs deep investigations, manages SOAR cases, and handles medium/high severity alerts.
*   **SOC Analyst Tier 3 (`soc_analyst_tier3.yaml`):** Manages critical incidents, complex malware analysis, and high-severity escalations.
*   **CTI Researcher (`cti_researcher.yaml`):** Conducts threat intelligence research, actor profiling, and campaign analysis.
*   **Threat Hunter (`threat_hunter.yaml`):** Executes proactive, hypothesis-driven threat hunts.
*   **Incident Responder (`incident_responder.yaml`):** Focuses on containment, eradication, and recovery phases of incident response.
*   **Detection Engineer (`detection_engineer.yaml`):** Develops and tunes detection rules and manages detection-as-code workflows.
*   **LLM Judge (`llm_judge.yaml`):** Evaluates runbook executions and agent performance against defined rubrics.

## How to Add or Modify Agent Cards

### Modifying an Existing Agent
1.  Navigate to `multi-agent/manager/config/agents/`.
2.  Open the relevant YAML file.
3.  Update fields (e.g., add a new `delegation_trigger` or `expertise_area`).
4.  Save the file. The changes will take effect the next time the manager loads its configuration.

### Adding a New Agent
1.  Create a new YAML file in `multi-agent/manager/config/agents/` (e.g., `forensics_specialist.yaml`).
2.  Fill in the required fields following the structure above.
3.  Ensure the `agent_name` is unique.
4.  (Optional) Update `tool_agent_mapping.yaml` if specific tool-based routing rules are needed (see [Configuration-Based Delegation](./configuration_based_delegation.md)).

## Best Practices

*   **Specificity:** Make `delegation_triggers` specific enough to avoid ambiguity but broad enough to capture relevant variations.
*   **Overlap:** Avoid significant overlap in `delegation_triggers` between agents unless intended for fallback or collaborative scenarios.
*   **Consistency:** Keep `agent_name` consistent with the Python module names in `multi-agent/manager/sub_agents/` if manual instantiation is used alongside configuration loading.
