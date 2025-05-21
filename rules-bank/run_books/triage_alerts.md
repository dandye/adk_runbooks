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
*   `${SIMILAR_CASE_IDS}`: List of case IDs identified as potentially similar or duplicate by `common_steps/check_duplicate_cases.md`.
*   `${ENTITY_RELATED_CASES}`: List of case IDs related to key entities involved in the current alert/case, found by `common_steps/find_relevant_soar_case.md`.
*   `${INITIAL_SIEM_CONTEXT}`: Summary of findings from the alert-specific SIEM search performed in Step 6.
*   `${ENRICHMENT_RESULTS}`: A structured collection of enrichment data for key entities, gathered by `common_steps/enrich_ioc.md`.
*   `${DOCUMENTATION_STATUS}`: Status of the attempt to document findings in the SOAR case via `common_steps/document_in_soar.md`.
*   `${CLOSURE_STATUS}`: Status of the attempt to close the SOAR artifact (case or alert) via `common_steps/close_soar_artifact.md`, if applicable.

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`, `change_case_priority`, `siemplify_get_similar_cases`, `siemplify_close_case`, `siemplify_close_alert`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`
*   `gti-mcp`: `get_file_report`, `get_domain_report`, `get_ip_address_report`, `get_url_report`
*   **Common Steps:** `common_steps/check_duplicate_cases.md`, `common_steps/enrich_ioc.md`, `common_steps/find_relevant_soar_case.md`, `common_steps/document_in_soar.md`, `common_steps/close_soar_artifact.md`

## Workflow Steps & Diagram

1.  **Receive Alert/Case:** Obtain the `${ALERT_ID}` or `${CASE_ID}`.
2.  **Gather Initial Context:** Use `secops-soar.get_case_full_details` or `list_alerts_by_case` / `list_events_by_alert` to understand the alert type, severity, involved entities (`KEY_ENTITIES`), and triggering events.
3.  **Check for Duplicates:** Execute `common_steps/check_duplicate_cases.md` with `${CASE_ID}`. Obtain `${SIMILAR_CASE_IDS}`.
4.  **Handle Duplicates:** If `${SIMILAR_CASE_IDS}` is not empty and duplication is confirmed by analyst:
    *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and comment "Closing as duplicate of [Similar Case ID]".
    *   Execute `common_steps/close_soar_artifact.md` with:
        *   `${ARTIFACT_ID}` = `${CASE_ID}` (or `${ALERT_ID}`)
        *   `${ARTIFACT_TYPE}` = "Case" (or "Alert")
        *   `${CLOSURE_REASON}` = `"NOT_MALICIOUS"`
        *   `${ROOT_CAUSE}` = `"Similar case is already under investigation"`
        *   `${CLOSURE_COMMENT}` = "Closing as duplicate of [Similar Case ID]"
    *   End runbook execution.
5.  **Find Entity-Related Cases:**
    *   Execute `common_steps/find_relevant_soar_case.md` with `SEARCH_TERMS=KEY_ENTITIES` (list of entities from Step 2) and `CASE_STATUS_FILTER="Opened"`.
    *   Obtain `${ENTITY_RELATED_CASES}` (list of potentially relevant open case summaries/IDs).
6.  **(New) Alert-Specific SIEM Search:**
    *   Based on the alert type identified in Step 2, perform an initial targeted search using `secops-mcp.search_security_events` to gather immediate context. Examples:
        *   **Suspicious Login:** Search for related login events (success/failure) for the user/source IP/hostname around the alert time (e.g., last hour).
        *   **Malware Detection:** Search for process execution, file modification, or network events related to the file hash/endpoint around the alert time.
        *   **Network Alert:** Search for related network flows or DNS lookups involving the source/destination IPs/domains.
    *   Store a summary of findings in `${INITIAL_SIEM_CONTEXT}`. This helps provide more specific context before broader enrichment.
7.  **Basic Enrichment:** Initialize `ENRICHMENT_RESULTS` structure. For each entity `Ei` in `KEY_ENTITIES`:
    *   Execute `common_steps/enrich_ioc.md` with `IOC_VALUE=Ei` and appropriate `IOC_TYPE`.
    *   Store results (`GTI_FINDINGS`, `SIEM_ENTITY_SUMMARY`, `SIEM_IOC_MATCH_STATUS`) in `ENRICHMENT_RESULTS[Ei]`.
8.  **Initial Assessment:** Based on alert type, `ENRICHMENT_RESULTS`, `${ENTITY_RELATED_CASES}`, `${INITIAL_SIEM_CONTEXT}`, and potential known benign patterns (referencing `.agentrules/common_benign_alerts.md` if available), make an initial assessment:
    *   False Positive (FP)
    *   Benign True Positive (BTP - expected/authorized activity)
    *   Requires Further Investigation (True Positive - TP or Suspicious)
9.  **Action Based on Assessment:**
    *   **If FP/BTP:**
        *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and comment explaining FP/BTP reason.
        *   **Guidance for Closure:**
            *   Choose an appropriate `${CLOSURE_REASON}` (likely `NOT_MALICIOUS`).
            *   Choose a valid `${ROOT_CAUSE}` from the SOAR platform's predefined list (e.g., `"Legit action"`, `"Normal behavior"`, `"Other"`). Use `secops-soar.get_case_settings_root_causes` to list valid options if unsure.
        *   Execute `common_steps/close_soar_artifact.md` with `${ARTIFACT_ID}` = `${CASE_ID}` (or `${ALERT_ID}`), `${ARTIFACT_TYPE}` = "Case" (or "Alert"), the chosen `${CLOSURE_REASON}`/`${ROOT_CAUSE}`, and `${CLOSURE_COMMENT}` = "Closed as FP/BTP during triage.".
    *   **If TP/Suspicious:**
        *   *(Optional)* Use `secops-soar.change_case_priority` if needed.
        *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and comment summarizing initial findings and assessment.
        *   Escalate/assign to the appropriate next tier or trigger a relevant investigation runbook (e.g., `deep_dive_ioc_analysis.md`, `suspicious_login_triage.md`).

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant CheckDuplicates as common_steps/check_duplicate_cases.md
    participant FindCase as common_steps/find_relevant_soar_case.md
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant CloseArtifact as common_steps/close_soar_artifact.md

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
