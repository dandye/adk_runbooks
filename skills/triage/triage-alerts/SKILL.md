---
name: triage-alerts
description: Use when evaluating and categorizing incoming security alerts to determine
  severity and initial response actions.
category: triage
version: 1.0.0
type: Skill
title: 'Skill: Alert Triage'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
---

# Runbook: Alert Triage

## Objective

To provide a standardized process for the initial assessment and triage of incoming security alerts. This runbook guides the analyst in determining if an alert represents a potential threat requiring further investigation or if it can be closed as a false positive or duplicate. The process involves gathering initial context, checking for duplicates, performing basic enrichment, an alert-specific SIEM search, and making an initial assessment to decide on escalation or closure.

## Scope

This runbook covers:
*   Initial review of an alert or case.
*   Gathering context using SOAR and SIEM tools.
*   Checking for duplicate or similar existing SOAR cases.
*   Finding other SOAR cases related by key entities.
*   Performing an initial, targeted SIEM search based on the alert type for immediate context.
*   Basic enrichment of key entities using SIEM and GTI tools.
*   Decision-making for escalation or closure based on predefined criteria and gathered information.

This runbook explicitly **excludes**:
*   Deep-dive investigation of alerts or entities.
*   Containment or eradication actions.
*   Advanced threat hunting.

## Inputs

*   `${ALERT_ID}` or `${CASE_ID}`: The identifier for the alert or case to be triaged.
*   *(Optional) `${ALERT_DETAILS}`: Initial details provided by the alerting system (e.g., alert name, severity, specific indicators).
*   *(Derived) `${KEY_ENTITIES}`: Key entities (IPs, domains, hashes, users) extracted from the alert/case during initial context gathering. These are used for enrichment and finding related cases.*
*   *(Derived) `${ALERT_TYPE}`: The type of alert (e.g., "Suspicious Login", "Malware Detection", "Network Alert"), used to guide the alert-specific SIEM search.*

## Outputs

*   `${ASSESSMENT}`: The outcome of the triage (e.g., "False Positive", "Benign True Positive", "True Positive/Suspicious").
*   `${ACTION_TAKEN}`: The action performed based on the assessment (e.g., "Closed", "Escalated", "Priority Changed").
*   `${SIMILAR_CASE_IDS}`: List of case IDs identified as potentially similar or duplicate by `skills/common/check-duplicate-cases/SKILL.md`.
*   `${ENTITY_RELATED_CASES}`: List of case IDs related to key entities involved in the current alert/case, found by `skills/common/find-relevant-soar-case/SKILL.md`.
*   `${INITIAL_SIEM_CONTEXT}`: Summary of findings from the alert-specific SIEM search performed in Step 6.
*   `${ENRICHMENT_RESULTS}`: A structured collection of enrichment data for key entities, gathered by `skills/common/enrich-ioc/SKILL.md`.
*   `${DOCUMENTATION_STATUS}`: Status of the attempt to document findings in the SOAR case via `skills/common/document-in-soar/SKILL.md`.
*   `${CLOSURE_STATUS}`: Status of the attempt to close the SOAR artifact (case or alert) via `skills/common/close-soar-artifact/SKILL.md`, if applicable.

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`, `change_case_priority`, `siemplify_get_similar_cases`, `siemplify_close_case`, `siemplify_close_alert`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`
*   `gti-mcp`: `get_file_report`, `get_domain_report`, `get_ip_address_report`, `get_url_report`
*   **Common Steps:** `skills/common/check-duplicate-cases/SKILL.md`, `skills/common/enrich-ioc/SKILL.md`, `skills/common/find-relevant-soar-case/SKILL.md`, `skills/common/document-in-soar/SKILL.md`, `skills/common/close-soar-artifact/SKILL.md`

## Workflow Steps & Diagram

1.  **Receive Alert/Case:** Obtain the `${ALERT_ID}` or `${CASE_ID}`.
2.  **Gather Initial Context:** Use `soar-mcp_get_case_full_details` or `list_alerts_by_case` / `list_events_by_alert` to understand the alert type, severity, involved entities (`KEY_ENTITIES`), and triggering events.
3.  **Check for Duplicates:** Execute `skills/common/check-duplicate-cases/SKILL.md` with `${CASE_ID}`. Obtain `${SIMILAR_CASE_IDS}`.
4.  **Handle Duplicates:** If `${SIMILAR_CASE_IDS}` is not empty and duplication is confirmed by analyst:
    *   Execute `skills/common/document-in-soar/SKILL.md` with `${CASE_ID}` and comment "Closing as duplicate of [Similar Case ID]".
    *   Execute `skills/common/close-soar-artifact/SKILL.md` with:
        *   `${ARTIFACT_ID}` = `${CASE_ID}` (or `${ALERT_ID}`)
        *   `${ARTIFACT_TYPE}` = "Case" (or "Alert")
        *   `${CLOSURE_REASON}` = `"NOT_MALICIOUS"`
        *   `${ROOT_CAUSE}` = `"Similar case is already under investigation"`
        *   `${CLOSURE_COMMENT}` = "Closing as duplicate of [Similar Case ID]"
    *   End runbook execution.
5.  **Find Entity-Related Cases:**
    *   Execute `skills/common/find-relevant-soar-case/SKILL.md` with `SEARCH_TERMS=KEY_ENTITIES` (list of entities from Step 2) and `CASE_STATUS_FILTER="Opened"`.
    *   Obtain `${ENTITY_RELATED_CASES}` (list of potentially relevant open case summaries/IDs).
6.  **(New) Alert-Specific SIEM Search:**
    *   Based on the alert type identified in Step 2, perform an initial targeted search using `secops-mcp_search_security_events` to gather immediate context. Examples:
        *   **Suspicious Login:** Search for related login events (success/failure) for the user/source IP/hostname around the alert time (e.g., last hour).
        *   **Malware Detection:** Search for process execution, file modification, or network events related to the file hash/endpoint around the alert time.
        *   **Network Alert:** Search for related network flows or DNS lookups involving the source/destination IPs/domains.
    *   Store a summary of findings in `${INITIAL_SIEM_CONTEXT}`. This helps provide more specific context before broader enrichment.
7.  **Basic Enrichment:** Initialize `ENRICHMENT_RESULTS` structure. For each entity `Ei` in `KEY_ENTITIES`:
    *   Execute `skills/common/enrich-ioc/SKILL.md` with `IOC_VALUE=Ei` and appropriate `IOC_TYPE`.
    *   Store results (`GTI_FINDINGS`, `SIEM_ENTITY_SUMMARY`, `SIEM_IOC_MATCH_STATUS`) in `ENRICHMENT_RESULTS[Ei]`.
8.  **Initial Assessment:** Based on alert type, `ENRICHMENT_RESULTS`, `${ENTITY_RELATED_CASES}`, `${INITIAL_SIEM_CONTEXT}`, and potential known benign patterns (referencing `.agentrules/common_benign_alerts.md` if available), make an initial assessment:
    *   False Positive (FP)
    *   Benign True Positive (BTP - expected/authorized activity)
    *   Requires Further Investigation (True Positive - TP or Suspicious)
9.  **Action Based on Assessment:**
    *   **If FP/BTP:**
        *   Execute `skills/common/document-in-soar/SKILL.md` with `${CASE_ID}` and comment explaining FP/BTP reason.
        *   **Guidance for Closure:**
            *   Choose an appropriate `${CLOSURE_REASON}` (likely `NOT_MALICIOUS`).
            *   Choose a valid `${ROOT_CAUSE}` from the SOAR platform's predefined list (e.g., `"Legit action"`, `"Normal behavior"`, `"Other"`). Use `soar-mcp_get_case_settings_root_causes` to list valid options if unsure.
        *   Execute `skills/common/close-soar-artifact/SKILL.md` with `${ARTIFACT_ID}` = `${CASE_ID}` (or `${ALERT_ID}`), `${ARTIFACT_TYPE}` = "Case" (or "Alert"), the chosen `${CLOSURE_REASON}`/`${ROOT_CAUSE}`, and `${CLOSURE_COMMENT}` = "Closed as FP/BTP during triage.".
    *   **If TP/Suspicious:**
        *   *(Optional)* Use `soar-mcp_change_case_priority` if needed.
        *   Execute `skills/common/document-in-soar/SKILL.md` with `${CASE_ID}` and comment summarizing initial findings and assessment.
### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_alerts_payload_node["1. extract_alerts_payload_node<br/><i>(Extract Alert Payload)</i>"]
    extract_alerts_payload_node --> enrich_and_assess_alerts_node["2. enrich_and_assess_alerts_node<br/><i>(Enrich Entities & Assess Severity)</i>"]
    enrich_and_assess_alerts_node --> alerts_disposition_router{"3. alerts_disposition_router<br/><i>(Event.actions.route)</i>"}

    alerts_disposition_router -- "ESCALATE_INCIDENT" --> handle_escalate_incident_branch["4a. handle_escalate_incident_branch<br/><i>(Escalate High Risk Incident)</i>"]
    alerts_disposition_router -- "CLOSE_FALSE_POSITIVE" --> handle_close_fp_alerts_branch["4b. handle_close_fp_alerts_branch<br/><i>(Close False Positive Alert)</i>"]

    handle_escalate_incident_branch --> document_alerts_triage_report_node["5. document_alerts_triage_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_close_fp_alerts_branch --> document_alerts_triage_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant CheckDuplicates as skills/common/check-duplicate-cases/SKILL.md
    participant FindCase as skills/common/find-relevant-soar-case/SKILL.md
    participant EnrichIOC as skills/common/enrich-ioc/SKILL.md
    participant DocumentInSOAR as skills/common/document-in-soar/SKILL.md
    participant CloseArtifact as skills/common/close-soar-artifact/SKILL.md

    Analyst->>AutomatedAgent: Start Alert Triage\nInput: ALERT_ID/CASE_ID

    %% Step 2: Gather Initial Context
    AutomatedAgent->>SOAR: get_case_full_details / list_alerts_by_case / list_events_by_alert
    SOAR-->>AutomatedAgent: Context (KEY_ENTITIES: E1, E2...)

    %% Step 3: Check for Duplicates
    AutomatedAgent->>CheckDuplicates: Execute(Input: CASE_ID)
    CheckDuplicates-->>AutomatedAgent: Results: SIMILAR_CASE_IDS

    %% Step 4: Handle Duplicates
    alt SIMILAR_CASE_IDS not empty & Confirmed Duplicate
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, Comment="Closing as duplicate...")
        DocumentInSOAR-->>AutomatedAgent: Status
        AutomatedAgent->>CloseArtifact: Execute(Input: ARTIFACT_ID=CASE_ID/ALERT_ID, TYPE=..., REASON="Duplicate"...)
        CloseArtifact-->>AutomatedAgent: Status
        AutomatedAgent->>Analyst: End Triage (Duplicate)
    end

    %% Step 5: Find Entity-Related Cases
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=KEY_ENTITIES, CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: ENTITY_RELATED_CASES

    %% Step 6: Alert-Specific SIEM Search
    Note over AutomatedAgent: Construct alert-specific SIEM query based on alert type
    AutomatedAgent->>SIEM: search_security_events(text=AlertSpecificQuery, hours_back=1)
    SIEM-->>AutomatedAgent: Initial SIEM Context Results (INITIAL_SIEM_CONTEXT)

    %% Step 7: Basic Enrichment
    loop For each Key Entity Ei
        AutomatedAgent->>EnrichIOC: Execute(Input: IOC_VALUE=Ei, IOC_TYPE=...)
        EnrichIOC-->>AutomatedAgent: Results: Enrichment Data for Ei
    end

    %% Step 8: Initial Assessment
    Note over AutomatedAgent: Assess: FP / BTP / TP / Suspicious based on Context, Enrichment, Related Cases & Initial SIEM Context

    %% Step 9: Action Based on Assessment
    alt FP / BTP
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, Comment="Closing as FP/BTP...")
        DocumentInSOAR-->>AutomatedAgent: Status
        AutomatedAgent->>CloseArtifact: Execute(Input: ARTIFACT_ID=CASE_ID/ALERT_ID, TYPE=..., REASON="FP/BTP"...)
        CloseArtifact-->>AutomatedAgent: Status
        AutomatedAgent->>Analyst: End Triage (FP/BTP)
    else TP / Suspicious
        opt Change Priority
             AutomatedAgent->>SOAR: change_case_priority(...)
             SOAR-->>AutomatedAgent: Status
        end
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, Comment="Initial Findings...")
        DocumentInSOAR-->>AutomatedAgent: Status
        Note over AutomatedAgent: Escalate / Assign / Trigger Next Runbook
        AutomatedAgent->>Analyst: End Triage (Escalated)
    end
```

## Completion Criteria

The alert or case has been successfully triaged:
*   Initial context has been gathered and understood.
*   A check for duplicate or similar cases has been performed.
*   Relevant existing cases related to key entities have been identified.
*   An alert-specific SIEM search has been conducted for immediate context.
*   Key entities have undergone basic enrichment.
*   An initial assessment (FP, BTP, TP/Suspicious) has been made.
*   Appropriate action (closure or escalation/assignment) has been taken based on the assessment.
*   All steps, findings, and actions have been documented in the SOAR case.

## Rubrics

The following rubric is used to evaluate the execution of this **Triage/Response** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Context & Enrichment** | 25 | Correctly extracted entities and enriched them with relevant context (GTI, SIEM). |
| **Analysis & Decision** | 25 | Analyzed the enriched data to make a sound decision (FP/TP, Escalate/Close). |
| **Action Execution** | 20 | Performed the required response actions (e.g., isolation, containment) correctly. |
| **Documentation** | 15 | Clearly documented findings and actions in the case/ticket. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Context & Enrichment (25 Points)
- **10 pts**: Accurately extracted key entities (IPs, users, hashes) from the input.
- **15 pts**: Performed necessary enrichment (e.g., `enrich_ioc`) to gather reputation and history.

#### 2. Analysis & Decision (25 Points)
- **15 pts**: Interpreted the context correctly to determine the nature of the alert.
- **10 pts**: Reached a logical conclusion or next step (e.g., "Escalate to Tier 2" or "Isolate Host").

#### 3. Action Execution (20 Points)
- **10 pts**: Called the correct tools to perform response actions (if applicable) or investigative steps.
- **10 pts**: Verified the success of actions or handled errors appropriately.

#### 4. Documentation (15 Points)
- **15 pts**: Posted a comprehensive comment or update to the SOAR case summarizing the triage.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
