# Runbook: UEBA Report Analysis

## Objective

To analyze a User and Entity Behavior Analytics (UEBA) alert or an associated SOAR case, investigate the reported anomalous activity, gather contextual information from SIEM and identity providers, and determine if the behavior represents a genuine security threat, a benign deviation, or an explainable anomaly. The outcome is a documented assessment and a recommendation for next steps.

## Scope

This runbook covers:
*   Retrieving details of the UEBA alert and any associated SOAR case.
*   Gathering SIEM context for the involved user and entity (e.g., host, resource).
*   Optionally, checking user status and recent activity via an Identity Provider (IDP) tool.
*   Searching for detailed SIEM logs corresponding to the specific anomalous activity described.
*   Comparing the observed activity against known baseline behavior (if available) or historical patterns.
*   Enriching any specific Indicators of Compromise (IOCs) that emerge from the anomalous activity using GTI tools.
*   Synthesizing all findings to assess the nature of the anomaly.
*   Documenting the analysis and recommending next steps (e.g., closure, monitoring, escalation).

This runbook explicitly **excludes**:
*   Deep forensic analysis of endpoints (unless findings strongly indicate a compromise and lead to triggering a different runbook).
*   Containment or eradication actions (recommendations may lead to these via other runbooks).
*   Configuration or tuning of UEBA system parameters.

## Inputs

*   `${UEBA_ALERT_ID}` or `${CASE_ID}`: Identifier for the UEBA alert or an associated SOAR case. This is mandatory.
*   `${USER_ID}`: The primary user ID (e.g., username, email) associated with the anomalous behavior. This is mandatory.
*   `${ENTITY_ID}`: Any primary entity identifier (e.g., hostname, resource name, IP address) associated with the behavior. This is mandatory.
*   `${ANOMALY_DESCRIPTION}`: A clear description of the anomalous behavior as reported by the UEBA system or alert. This is mandatory.
*   *(Optional) `${BASELINE_INFO}`: Pre-existing information about the user's or entity's normal baseline behavior relevant to the anomaly type.*
*   *(Optional) `${ALERT_TIMESTAMP}`: The timestamp of the UEBA alert, used to focus SIEM searches.*
*   *(Derived) `${USER_SIEM_CONTEXT}`: Summary of user activity from `secops-mcp.lookup_entity`.*
*   *(Derived) `${ENTITY_SIEM_CONTEXT}`: Summary of entity activity from `secops-mcp.lookup_entity`.*
*   *(Derived) `${IDP_USER_CONTEXT}`: (Optional) User details from an IDP tool like `okta-mcp.lookup_okta_user`.*
*   *(Derived) `${DETAILED_ACTIVITY_LOGS}`: Specific SIEM event logs related to the anomaly from `secops-mcp.search_security_events`.*
*   *(Derived) `${IOC_ENRICHMENT_RESULTS}`: Enrichment data for any IOCs identified during the analysis.*

## Outputs

*   `${ASSESSMENT}`: The analyst's conclusion about the nature of the UEBA alert (e.g., "Benign Anomaly - Explained", "Suspicious - Requires Monitoring", "Potential Threat - Escalate").
*   `${RECOMMENDATION}`: Suggested next steps based on the assessment (e.g., "Close case", "Monitor user activity for X days", "Trigger Compromised User Account runbook").
*   `${DOCUMENTATION_STATUS}`: Status of documenting the analysis and recommendation in the SOAR case.

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`
*   `secops-mcp`: `lookup_entity` (for user and entity), `search_security_events` (for detailed activity logs)
*   `gti-mcp`: Relevant enrichment tools (e.g., `get_ip_address_report`, `get_domain_report`, `get_file_report`) if IOCs are involved.
*   *(Potentially Identity Provider tools like `okta-mcp.lookup_okta_user` if available and relevant)*

## Workflow Steps & Diagram

1.  **Receive Alert/Case:** Obtain the UEBA alert details, associated user/entity, `${CASE_ID}` etc.
2.  **Gather Context:** Use `get_case_full_details` (if applicable). Use `lookup_entity` for `${USER_ID}` and `${ENTITY_ID}` to get SIEM context. *(Optional: Check IDP for user status/recent activity)*.
3.  **Analyze Specific Activity:** Use `search_security_events` to retrieve detailed logs corresponding to the timeframe and activity described in `${ANOMALY_DESCRIPTION}`.
4.  **Compare to Baseline:** Compare the observed activity against known baseline behavior (`${BASELINE_INFO}`) or historical patterns observed in SIEM logs. Identify deviations.
5.  **Enrich Associated Indicators:** If the anomalous activity involves specific IOCs (IPs, domains, files), enrich them using `lookup_entity` and GTI tools.
6.  **Synthesize Findings:** Combine UEBA anomaly details, SIEM logs, baseline comparison, and enrichment data. Determine if the activity is explainable, benign, or suspicious/malicious.
7.  **Document & Recommend:** Document findings and assessment in the SOAR case using `post_case_comment`. Recommend next steps: [Close as Benign/Explained | Monitor User/Entity | Escalate for Incident Response (Trigger relevant runbook like Compromised User Account Response)].

```{mermaid}
sequenceDiagram
    participant User/Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant IDP as Identity Provider (Optional)

    User/Analyst->>AutomatedAgent: Analyze UEBA Alert/Case (ID, User, Entity, Anomaly Desc.)
    AutomatedAgent->>SOAR: get_case_full_details (Optional, if CASE_ID provided)
    SOAR-->>AutomatedAgent: Case Context
    AutomatedAgent->>SIEM: lookup_entity(entity_value=USER_ID)
    SIEM-->>AutomatedAgent: User SIEM Context
    AutomatedAgent->>SIEM: lookup_entity(entity_value=ENTITY_ID)
    SIEM-->>AutomatedAgent: Entity SIEM Context
    opt IDP Check
        AutomatedAgent->>IDP: lookup_user(user=USER_ID)
        IDP-->>AutomatedAgent: User IDP Context
    end
    AutomatedAgent->>SIEM: search_security_events(text="Detailed logs for anomaly timeframe/activity")
    SIEM-->>AutomatedAgent: Specific Activity Logs
    Note over AutomatedAgent: Compare activity to baseline/history
    opt IOCs Involved (I1, I2...)
        loop For each IOC Ii
            AutomatedAgent->>SIEM: lookup_entity(entity_value=Ii)
            SIEM-->>AutomatedAgent: SIEM Context for Ii
            AutomatedAgent->>GTI: get...report(ioc=Ii)
            GTI-->>AutomatedAgent: GTI Context for Ii
        end
    end
    Note over AutomatedAgent: Synthesize findings, assess activity
    AutomatedAgent->>SOAR: post_case_comment(case_id=..., comment="UEBA Analysis Summary... Assessment: [...]. Recommendation: [Close/Monitor/Escalate]")
    SOAR-->>AutomatedAgent: Comment Confirmation
    AutomatedAgent->>User/Analyst: attempt_completion(result="UEBA analysis complete. Findings documented.")
```

## Completion Criteria

*   The UEBA alert/case details (`${UEBA_ALERT_ID}` or `${CASE_ID}`), including the `${ANOMALY_DESCRIPTION}`, `${USER_ID}`, and `${ENTITY_ID}`, have been reviewed.
*   Contextual information for the user and entity has been gathered from SIEM (`${USER_SIEM_CONTEXT}`, `${ENTITY_SIEM_CONTEXT}`) and optionally from an IDP (`${IDP_USER_CONTEXT}`).
*   Detailed SIEM logs (`${DETAILED_ACTIVITY_LOGS}`) corresponding to the anomalous activity have been retrieved and analyzed.
*   The observed activity has been compared against any available baseline information or historical patterns.
*   Any emergent IOCs have been enriched (`${IOC_ENRICHMENT_RESULTS}`).
*   All findings have been synthesized into an overall assessment (`${ASSESSMENT}`) of the UEBA alert (e.g., benign, suspicious, potential threat).
*   A clear recommendation (`${RECOMMENDATION}`) for next steps has been formulated.
*   The analysis, assessment, and recommendation have been documented in the SOAR case, and the `${DOCUMENTATION_STATUS}` is available.
