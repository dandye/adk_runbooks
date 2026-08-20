---
name: alert-report
description: Use when summarizing alert triage decisions, key indicators, and immediate
  actions taken.
category: reporting
version: 1.0.0
type: Skill
title: 'Skill: Alert Investigation Summary Report Runbook'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
---

# Alert Investigation Summary Report Runbook

## Objective

Generate a standardized report summarizing the key findings from the investigation of a specific security alert or a group of related alerts within a SOAR case. This report is intended for documentation, handover, or escalation purposes.

## Scope

This runbook covers gathering essential details about the alert(s), associated events, involved entities, basic enrichment, and producing a structured summary report in Markdown format. It does not typically involve deep-dive analysis or containment actions, which would be covered by other runbooks.

## Inputs

*   `${CASE_ID}`: The relevant SOAR case ID containing the alert(s).
*   `${ALERT_GROUP_IDENTIFIERS}`: A list of relevant alert group identifiers within the case. Alternatively, provide specific `${ALERT_IDS}`.
*   *(Optional) `${ALERT_IDS}`: Comma-separated list of specific alert IDs to focus on if `${ALERT_GROUP_IDENTIFIERS}` is not used.*
*   *(Optional) `${REPORT_FILENAME_SUFFIX}`: A suffix to append to the report filename (e.g., "initial_triage").*

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `get_entities_by_alert_group_identifiers`, `post_case_comment`
*   `secops-mcp`: `lookup_entity`, `search_security_events` (optional, for broader context)
*   `Google Threat Intelligence MCP server`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
*   `write_report`

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}` (or `${ALERT_IDS}`), and optionally `${REPORT_FILENAME_SUFFIX}`. Get case details using `soar-mcp_get_case_full_details`.
2.  **Identify Target Alerts & Entities:**
    *   If using `${ALERT_GROUP_IDENTIFIERS}`, use `soar-mcp_get_entities_by_alert_group_identifiers` to list involved entities. Use `soar-mcp_list_alerts_by_case` and filter based on the group identifiers (if possible, otherwise use all alerts in the group).
    *   If using `${ALERT_IDS}`, retrieve details for those specific alerts (potentially from the `get_case_full_details` output or by iterating `list_alerts_by_case` if needed). Identify entities directly from these alerts.
    *   Compile a list of unique key entities (Users, Hosts, IPs, Hashes, Domains, URLs) involved in the target alert(s). Let this be `KEY_ENTITIES`.
3.  **Gather Alert Events:**
    *   Retrieve underlying UDM events for key alerts. Use `soar-mcp_list_events_by_alert` for detailed events, or summarize event details available within the `soar-mcp_get_case_full_details` output if sufficient for a summary perspective.
    *   Extract key event details (timestamps, event types, process info, network info, file info).
4.  **Enrich Key Entities:**
    *   Initialize an empty structure for enrichment findings.
    *   For each entity in `KEY_ENTITIES`:
        *   Use `secops-mcp_lookup_entity` to get SIEM context (first/last seen, related alerts).
        *   Use the appropriate `gti-mcp_get_..._report` tool based on entity type (IP, Domain, Hash, URL) to get threat intelligence reputation/context.
    *   Store enrichment summaries.
5.  **(Optional) Search Related SIEM Activity:**
    *   *(Guidance: Consider performing this step if initial enrichment reveals highly critical IOCs or if the alert context is unclear).*
        *   Perform limited `secops-mcp_search_security_events` queries around the alert timeframe for the most critical entities identified (e.g., the primary host or user) to find immediate related context beyond the specific alert events.
6.  **Synthesize & Format Report:**
    *   Create a Markdown report structure including (referencing `rules-bank/reporting_templates.md` and `rules-bank/run_books/guidelines/runbook_guidelines.md`):
        *   **Metadata:** Runbook Used, Timestamp, Case ID(s).
        *   **Case Summary:** Case ID, Name, Priority, Status (from `get_case_full_details`).
        *   **Alert(s) Summary:** List target Alert IDs, Names, Timestamps, Severities.
        *   **Key Entities Involved:** List entities from `KEY_ENTITIES` with a brief description.
        *   **Enrichment Summary:** Provide concise summaries of SIEM and GTI findings for each key entity.
        *   **Event Summary:** Briefly describe the key events triggering the alert(s). Include timestamps and event types.
        *   **(Optional) Related SIEM Activity:** Summarize findings from Step 5.
        *   **Initial Assessment/Conclusion:** A brief statement on the nature of the alert based on the gathered data (e.g., "Likely malicious activity involving...", "Appears to be benign based on...", "Requires further investigation by Tier 2...").
        *   **Workflow Diagram:** Include a Mermaid sequence diagram illustrating the steps taken during this runbook execution.
7.  **Write Report File:**
    *   Generate a timestamp string (`${timestamp}`, e.g., `yyyymmdd_hhmm`).
    *   Construct `REPORT_NAME_VAR` (e.g., `alert_report_${CASE_ID}_${REPORT_FILENAME_SUFFIX}_${timestamp}.md`). Ensure `${REPORT_FILENAME_SUFFIX}` is handled (e.g., if empty, don't include extra underscores).
    *   Let the formatted Markdown content be `REPORT_CONTENTS_VAR`.
    *   Use `write_report` with `report_name=${REPORT_NAME_VAR}` and `report_contents=${REPORT_CONTENTS_VAR}`.
8.  **(Optional) Update SOAR Case:**
    *   Use `soar-mcp_post_case_comment` to add a comment to `${CASE_ID}` stating that the report has been generated and providing the filename, or pasting a concise summary directly.
9.  **Completion:** Conclude the runbook execution.

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_alert_report_payload_node["1. extract_alert_report_payload_node<br/><i>(Extract Alert Payload)</i>"]
    extract_alert_report_payload_node --> fetch_alert_details_node["2. fetch_alert_details_node<br/><i>(Fetch Alert & Entity Details)</i>"]
    fetch_alert_details_node --> alert_report_type_router{"3. alert_report_type_router<br/><i>(Event.actions.route)</i>"}

    alert_report_type_router -- "HIGH_SEVERITY_ALERT_REPORT" --> handle_high_severity_report_branch["4a. handle_high_severity_report_branch<br/><i>(Generate High Severity Report)</i>"]
    alert_report_type_router -- "STANDARD_ALERT_REPORT" --> handle_standard_report_branch["4b. handle_standard_report_branch<br/><i>(Generate Standard Alert Report)</i>"]

    handle_high_severity_report_branch --> document_alert_report_node["5. document_alert_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_standard_report_branch --> document_alert_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as Google Threat Intelligence MCP server

    Analyst/User->>AutomatedAgent: Generate Alert Report\nInput: CASE_ID, ALERT_GROUP_IDS/ALERT_IDS, FILENAME_SUFFIX (opt)

    %% Step 1: Context
    AutomatedAgent->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>AutomatedAgent: Case Details

    %% Step 2: Identify Alerts & Entities
    alt Use Alert Group IDs
        AutomatedAgent->>SOAR: get_entities_by_alert_group_identifiers(case_id=CASE_ID, alert_group_identifiers=ALERT_GROUP_IDS)
        SOAR-->>AutomatedAgent: Entities List (KEY_ENTITIES)
        AutomatedAgent->>SOAR: list_alerts_by_case(case_id=CASE_ID) %% Filter alerts based on group if possible
        SOAR-->>AutomatedAgent: Target Alert List (A1, A2...)
    else Use Alert IDs
        Note over AutomatedAgent: Extract Target Alerts (A1, A2...) from Case Details or list_alerts_by_case
        Note over AutomatedAgent: Extract KEY_ENTITIES from Target Alerts
    end

    %% Step 3: Gather Alert Events
    loop For each Target Alert Ai
        AutomatedAgent->>SOAR: list_events_by_alert(case_id=CASE_ID, alert_id=Ai)
        SOAR-->>AutomatedAgent: Events for Alert Ai
        Note over AutomatedAgent: Store key event details
    end

    %% Step 4: Enrich Key Entities
    loop For each Entity Ei in KEY_ENTITIES
        AutomatedAgent->>SIEM: lookup_entity(entity_value=Ei)
        SIEM-->>AutomatedAgent: SIEM Summary for Ei
        alt Entity Type is IP/Domain/Hash/URL
            AutomatedAgent->>GTI: get_..._report(ioc=Ei)
            GTI-->>AutomatedAgent: GTI Report Summary for Ei
        end
        Note over AutomatedAgent: Store enrichment findings
    end

    %% Step 5: Optional SIEM Search
    opt Search Related Activity
        loop For critical Entity Ec in KEY_ENTITIES
            AutomatedAgent->>SIEM: search_security_events(text="Activity related to Ec near alert time")
            SIEM-->>AutomatedAgent: Related SIEM Events
            Note over AutomatedAgent: Store summary of related activity
        end
    end

    %% Step 6 & 7: Synthesize & Write Report
    Note over AutomatedAgent: Format report content (ReportMarkdown) (Case Summary, Alert Summary, Entities, Enrichment, Events, Assessment)
    Note over AutomatedAgent: Construct REPORT_NAME_VAR (e.g., alert_report_${CASE_ID}_${REPORT_FILENAME_SUFFIX}_${timestamp}.md)
    AutomatedAgent->>AutomatedAgent: write_report(report_name=REPORT_NAME_VAR, report_contents=ReportMarkdown)
    Note over AutomatedAgent: Report file created

    %% Step 8: Optional SOAR Update
    opt Update SOAR Case
        AutomatedAgent->>SOAR: post_case_comment(case_id=CASE_ID, comment="Alert report generated: alert_report_....md. Summary: [...]")
        SOAR-->>AutomatedAgent: Comment Confirmation
    end

    %% Step 9: Completion
    AutomatedAgent->>Analyst/User: attempt_completion(result="Alert investigation summary report generated for Case CASE_ID.")

## Rubrics

The following rubric is used to evaluate the execution of this **Reporting** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Data Collection** | 25 | Gathered all necessary data points and metrics for the report. |
| **Report Generation** | 30 | Generated the report in the correct format with accurate content. |
| **Quality & Clarity** | 15 | Ensure the report is readable, well-structured, and error-free. |
| **Delivery** | 15 | Delivered or saved the report to the correct location/recipient. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Data Collection (25 Points)
- **25 pts**: Successfully retrieved all required data (alerts, stats, summaries) from sources.

#### 2. Report Generation (30 Points)
- **15 pts**: Formatted the data correctly into the target template (Markdown, PDF, etc.).
- **15 pts**: Included all required sections (Executive Summary, Details, etc.).

#### 3. Quality & Clarity (15 Points)
- **15 pts**: The generated text is coherent, accurate, and professional.

#### 4. Delivery (15 Points)
- **15 pts**: Successfully saved the file or sent the notification/email as required.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
