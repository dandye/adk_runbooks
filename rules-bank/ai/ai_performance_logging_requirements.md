# AI Performance Logging Requirements

This document specifies the key data points that AI agents must log for significant actions and decisions. Consistent and comprehensive logging is crucial for calculating PICERL-related metrics, troubleshooting AI behavior, and facilitating continuous improvement.

## Purpose

-   To ensure all necessary data is captured for measuring AI agent performance against the PICERL framework.
-   To provide a clear audit trail of AI agent actions and the data influencing them.
-   To support debugging, analysis of AI decision-making, and identification of areas for improvement.
-   To enable the calculation of metrics such as Mean Time to Triage (MTTT), AI Decision Accuracy, auto-close reversal rates, containment accuracy, etc.

## General Logging Principles for AI Agents

1.  **Structured Logging:** Logs should be in a structured format (e.g., JSON) for easier parsing and analysis.
2.  **Timestamp Everything:** All significant events and decisions logged by the AI must have an accurate timestamp (UTC, RFC3339/ISO8601 format).
3.  **Unique Identifiers:** Associate logs with relevant IDs (e.g., Alert ID, Case ID, AI Agent ID, AI Transaction/Decision ID).
4.  **Contextual References:** Log references to specific `rules-bank` documents, protocols, or criteria that influenced a decision.
5.  **Clarity and Conciseness:** Log messages should be clear and to the point, but contain all necessary information.

## Key Data Points to Log per AI Action/Decision Type

The following sections detail specific data points to be logged. These should ideally be sent to a centralized logging system or stored as structured data within SOAR case notes/artifacts.

---

### 1. Alert Ingestion & Initial Processing by AI

-   **Event:** AI agent ingests a new alert.
-   **Log Data:**
    -   `event_type`: "AI_Alert_Ingestion"
    -   `timestamp`: Timestamp of ingestion by AI.
    -   `alert_id`: Unique identifier of the alert from the source system (e.g., SIEM alert ID).
    -   `soar_case_id` (if applicable): Case ID if the alert is already part of a SOAR case.
    -   `alert_source_system`: (e.g., "Chronicle SIEM", "EDR Product X")
    -   `alert_name`: Name/title of the alert.
    -   `alert_severity_original`: Severity as reported by the source system.
    -   `ai_agent_id`: Identifier of the AI agent processing the alert.

---

### 2. AI Triage Decision (e.g., Close, Escalate, Investigate Further)

-   **Event:** AI agent makes a triage decision on an alert.
-   **Log Data:**
    -   `event_type`: "AI_Triage_Decision"
    -   `timestamp`: Timestamp of the AI's decision.
    -   `alert_id`: Original alert ID.
    -   `soar_case_id` (if applicable).
    -   `ai_agent_id`.
    -   `ai_decision`: (e.g., "AutoClose_Benign", "AutoClose_FalsePositive", "Escalate_Tier2", "Escalate_Human_Review", "Initiate_Automated_Investigation")
    -   `ai_confidence_score`: AI's confidence in this decision (e.g., 0.0 - 1.0).
    -   `ai_triage_rationale_summary`: Brief text summary of why the decision was made (as per `ai_explainability_standards.md`).
    -   `key_evidence_triggers`: (List of key IOCs, rule IDs, or data points that led to the decision).
    -   `rules_bank_references`: (List of `rules-bank` documents/protocols consulted, e.g., "`common_benign_alerts.md`", "`indicator_handling_protocols.md`").
    -   `processing_time_ms`: Time taken by AI from ingestion to this decision.

---

### 3. AI-Initiated Automated Action (e.g., Host Isolation, IP Block)

-   **Event:** AI agent initiates an automated response action.
-   **Log Data:**
    -   `event_type`: "AI_Automated_Action_Initiated"
    -   `timestamp`: Timestamp of action initiation.
    -   `alert_id` / `soar_case_id`.
    -   `ai_agent_id`.
    -   `action_type`: (e.g., "Host_Isolation_EDR", "IP_Block_Firewall", "User_Account_Disable_AD").
    -   `target_entity_identifier`: (e.g., Hostname, IP address, Username).
    -   `target_entity_type`: (e.g., "Hostname", "IPAddress", "User").
    -   `action_parameters`: (Any specific parameters passed to the tool performing the action).
    -   `tool_used_mcp_server`: (e.g., "secops-soar").
    -   `tool_used_mcp_tool_name`: (e.g., "siemplify_isolate_host" - hypothetical).
    -   `ai_action_rationale_summary`: (as per `ai_explainability_standards.md`).
    -   `rules_bank_criteria_reference`: (Specific criteria from `automated_response_playbook_criteria.md` that were met).

---

### 4. Outcome of AI-Initiated Automated Action

-   **Event:** Result of an AI-initiated automated action is received.
-   **Log Data:**
    -   `event_type`: "AI_Automated_Action_Outcome"
    -   `timestamp`: Timestamp of receiving the action outcome.
    -   `ai_transaction_id` (correlates to the "AI_Automated_Action_Initiated" event).
    -   `alert_id` / `soar_case_id`.
    -   `ai_agent_id`.
    -   `action_type` (same as in initiation event).
    -   `action_outcome`: "Success" / "Failure" / "Partial_Success".
    -   `action_result_details`: (API response or summary from the tool that executed the action).
    -   `action_failure_reason` (if `action_outcome` is "Failure").
    -   `validation_procedure_attempted_by_ai` (if applicable, from `automated_response_playbook_criteria.md`).
    -   `validation_procedure_outcome`: "Success" / "Failure" / "Not_Attempted".

---

### 5. Human Review/Override of AI Decision/Action

-   **Event:** A human analyst reviews and potentially overrides an AI decision or action.
-   **Log Data:** (This data is typically captured via the process in `ai_decision_review_guidelines.md` but should be logged centrally if possible).
    -   `event_type`: "Human_Review_AI_Decision"
    -   `timestamp`: Timestamp of the human review.
    -   `reviewed_item_id` (Alert ID, AI Decision ID, etc.).
    -   `ai_agent_id` (of the agent whose decision is being reviewed).
    -   `analyst_id`.
    -   `ai_decision_correct`: Yes / No.
    -   `human_corrected_outcome` (if overridden).
    -   `reason_for_override` (if overridden).
    -   `missing_context_identified_by_human` (if any).

---

### 6. AI-Generated Report/Summary

-   **Event:** AI agent generates a report or summary (e.g., incident summary, investigation findings).
-   **Log Data:**
    -   `event_type`: "AI_Report_Generated"
    -   `timestamp`: Timestamp of report generation.
    -   `alert_id` / `soar_case_id`.
    -   `ai_agent_id`.
    -   `report_type`: (e.g., "Incident_Summary", "IOC_Enrichment_Report").
    -   `report_content_reference`: (Link to or embedded content of the report).
    -   `key_findings_in_report`: (List of key conclusions or findings).

## Log Storage & Accessibility

-   Logs generated by AI agents should be stored in a centralized logging platform (e.g., Chronicle, dedicated application logs, or within SOAR case artifacts if structured).
-   Logs must be accessible for analysis, metric calculation, and auditing purposes.
-   Consider retention policies for these AI operational logs.

By implementing these logging requirements, the organization can gain valuable insights into AI agent performance, identify areas for improvement, and build a robust dataset for measuring ROI and effectiveness across the PICERL lifecycle.
