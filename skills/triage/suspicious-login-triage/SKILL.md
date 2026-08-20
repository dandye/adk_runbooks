---
name: suspicious-login-triage
description: Use when triaging anomalous or suspicious user authentication events, impossible travel, and credential anomalies.
category: triage
version: 1.0.0
---

# Suspicious Login Alert Triage Runbook

## Objective

Guide the initial triage of common suspicious login alerts (e.g., Impossible Travel, Login from Untrusted Location, Multiple Failed Logins) for Tier 1 SOC Analysts.

## Scope

This runbook covers the initial investigation steps to gather context about a suspicious login event, focusing on user history and source IP reputation, to help determine if escalation is needed.

## Inputs

*   `${CASE_ID}`: The relevant SOAR case ID containing the alert(s).
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   *(Optional) `${ALERT_ID}`: Specific Alert ID if targeting a single alert.*
*   *(Optional) `${USER_ID}`: The user ID associated with the suspicious login (if known upfront).*
*   *(Optional) `${SOURCE_IP}`: The source IP address (if known upfront).*
*   *(Optional) `${ALERT_DETAILS}`: Specific details from the alert (e.g., alert name, timestamp).*

## Tools

*   `secops-soar`: `get_case_full_details`, `list_events_by_alert`, `post_case_comment`
*   `secops-mcp`: `lookup_entity`, `search_security_events`
*   `gti-mcp`: `get_ip_address_report`
*   *(Optional: Identity Provider tools like `okta-mcp.lookup_okta_user`)*
*   You may ask follow up question
*   **Common Steps:** {doc}`common_steps/enrich_ioc </run_books/common_steps/enrich_ioc>`, {doc}`common_steps/find_relevant_soar_case </run_books/common_steps/find_relevant_soar_case>`, {doc}`common_steps/document_in_soar </run_books/common_steps/document_in_soar>`, {doc}`common_steps/generate_report_file </run_books/common_steps/generate_report_file>`

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}` (or `${ALERT_ID}`), and other optional inputs. Get full case details using `soar-mcp_get_case_full_details`.
2.  **Extract Key Entities:**
    *   Use `soar-mcp_list_events_by_alert` for the primary alert(s) in the case.
    *   Parse events to reliably extract the primary `${USER_ID}`, `${SOURCE_IP}`, and relevant `${HOSTNAME}`(s). Handle cases where these might be missing.
3.  **User Context (SIEM):**
    *   Use `secops-mcp_lookup_entity` with `entity_value=${USER_ID}`.
    *   Record summary of user's recent activity, first/last seen, related alerts (`USER_SIEM_SUMMARY`).
4.  **Source IP Enrichment:**
    *   Execute `common_steps/enrich_ioc.md` with `IOC_VALUE=${SOURCE_IP}` and `IOC_TYPE="IP Address"`.
    *   Obtain `${GTI_FINDINGS}`, `${SIEM_ENTITY_SUMMARY}` (for IP), `${SIEM_IOC_MATCH_STATUS}`. Let's call these `IP_GTI_FINDINGS`, `IP_SIEM_SUMMARY`, `IP_SIEM_MATCH`.
5.  **Hostname Context (SIEM):**
    *   If `${HOSTNAME}` was extracted:
        *   Use `secops-mcp_lookup_entity` with `entity_value=${HOSTNAME}`.
        *   Record summary (`HOSTNAME_SIEM_SUMMARY`).
6.  **Recent Login Activity (SIEM):**
    *   Use `secops-mcp_search_security_events` with a refined UDM query focusing on the last 24-72 hours:
        ```udm
        metadata.event_type IN ("USER_LOGIN", "AUTH_ATTEMPT") AND (
          principal.user.userid = "${USER_ID}" OR
          target.user.userid = "${USER_ID}" OR
          src.user.userid = "${USER_ID}"
        )
        ```
    *   Look for patterns: logins from other unusual IPs, successful logins after failures, frequency of logins from `${SOURCE_IP}` vs. others (`LOGIN_ACTIVITY_SUMMARY`).
7.  **Check Related SOAR Cases:**
    *   Execute `common_steps/find_relevant_soar_case.md` with `SEARCH_TERMS=["${USER_ID}", "${SOURCE_IP}", "${HOSTNAME}"]` (include hostname if available) and `CASE_STATUS_FILTER="Opened"`.
    *   Obtain `${RELATED_SOAR_CASES}` (list of potentially relevant open case summaries/IDs).
    *   *Note: `list_cases` filtering by entity is limited; review results carefully.*
8.  **(Optional) Identity Provider Check:**
    *   *(If `okta-mcp` or similar tool is available, use `okta-mcp.lookup_okta_user` with `${USER_ID}` to check account status, recent legitimate logins, MFA methods, etc. (`IDP_SUMMARY`))*
9.  **Synthesize & Document:**
    *   Combine findings: User context (`USER_SIEM_SUMMARY`), Source IP context (`IP_GTI_FINDINGS`, `IP_SIEM_SUMMARY`, `IP_SIEM_MATCH`), Hostname context (`HOSTNAME_SIEM_SUMMARY`), Login patterns (`LOGIN_ACTIVITY_SUMMARY`), Related cases (`${RELATED_SOAR_CASES}`), IDP check (`IDP_SUMMARY`).
    *   Prepare comment text: `COMMENT_TEXT = "Suspicious Login Triage for ${USER_ID} from ${SOURCE_IP} (Host: ${HOSTNAME}): User SIEM Summary: ${USER_SIEM_SUMMARY}. Source IP GTI: ${IP_GTI_FINDINGS}. Source IP SIEM: ${IP_SIEM_SUMMARY}. Source IP IOC Match: ${IP_SIEM_MATCH}. Hostname SIEM: ${HOSTNAME_SIEM_SUMMARY}. Recent Login Pattern: ${LOGIN_ACTIVITY_SUMMARY}. Related Open Cases: ${RELATED_SOAR_CASES}. Optional IDP Check: ${IDP_SUMMARY}. Recommendation: [Close as FP/Known Activity | Escalate to Tier 2 for further investigation | Consider Account Lockdown if high confidence of compromise]"`

    ```{warning}
    If account lockdown is considered as part of the recommendation, ensure proper authorization and communication protocols are followed before locking a user account to avoid disrupting legitimate business operations.
    ```

    *   Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `${COMMENT_TEXT}`. Obtain `${COMMENT_POST_STATUS}`.
10. **(Optional) Generate Report:**
    *   You may ask follow up question to ask the user: "Generate a markdown report file for this triage?". Obtain `${REPORT_CHOICE}`.
    *   **If `${REPORT_CHOICE}` is "Yes":**
        *   Prepare `REPORT_CONTENT` summarizing findings (similar to `${COMMENT_TEXT}` but formatted for a report, including the Mermaid diagram below).
        *   Execute `common_steps/generate_report_file.md` with `REPORT_CONTENT`, `REPORT_TYPE="suspicious_login_triage"`, `REPORT_NAME_SUFFIX=${CASE_ID}`. Obtain `${REPORT_GENERATION_STATUS}`.
    *   **Else:** Set `${REPORT_GENERATION_STATUS}` = "Skipped".
11. **Completion:** Conclude the runbook execution. Tier 1 analyst acts on the recommendation in the comment. Report generation status provided if applicable.

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_entities_node["1. extract_entities_node<br/><i>(Extract User ID, Source IP, Hostname)</i>"]
    extract_entities_node --> enrich_user_node["2. enrich_user_node<br/><i>(SIEM User Context)</i>"]
    enrich_user_node --> enrich_ip_node["3. enrich_ip_node<br/><i>(GTI & SIEM IP Threat Intel)</i>"]
    enrich_ip_node --> analyze_logins_node["4. analyze_logins_node<br/><i>(72h UDM Pattern Analysis)</i>"]
    analyze_logins_node --> triage_risk_router{"5. triage_risk_router<br/><i>(Event.actions.route)</i>"}

    triage_risk_router -- "LOW_RISK_BENIGN" --> handle_low_risk_branch["6a. handle_low_risk_branch<br/><i>(Draft FP Closure Note)</i>"]
    triage_risk_router -- "HIGH_RISK_SUSPICIOUS" --> handle_high_risk_branch["6b. handle_high_risk_branch<br/><i>(Draft Escalation & Lockdown)</i>"]

    handle_low_risk_branch --> document_and_report_node["7. document_and_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_high_risk_branch --> document_and_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant FindCase as common_steps/find_relevant_soar_case.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant GenerateReport as common_steps/generate_report_file.md
    participant IDP as Identity Provider (Optional)

    Analyst->>AutomatedAgent: Start Suspicious Login Triage\nInput: CASE_ID, ALERT_GROUP_IDS/ALERT_ID

    %% Step 1: Context
    AutomatedAgent->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>AutomatedAgent: Case Details

    %% Step 2: Extract Key Entities
    AutomatedAgent->>SOAR: list_events_by_alert(case_id=CASE_ID, alert_id=...)
    SOAR-->>AutomatedAgent: Events
    Note over AutomatedAgent: Extract USER_ID, SOURCE_IP, HOSTNAME

    %% Step 3: User Context
    AutomatedAgent->>SIEM: lookup_entity(entity_value=USER_ID)
    SIEM-->>AutomatedAgent: User SIEM Summary (USER_SIEM_SUMMARY)

    %% Step 4: Source IP Enrichment
    AutomatedAgent->>EnrichIOC: Execute(Input: IOC_VALUE=SOURCE_IP, IOC_TYPE="IP Address")
    EnrichIOC-->>AutomatedAgent: Results: IP_GTI_FINDINGS, IP_SIEM_SUMMARY, IP_SIEM_MATCH

    %% Step 5: Hostname Context
    opt HOSTNAME extracted
        AutomatedAgent->>SIEM: lookup_entity(entity_value=HOSTNAME)
        SIEM-->>AutomatedAgent: Hostname SIEM Summary (HOSTNAME_SIEM_SUMMARY)
    end

    %% Step 6: Recent Login Activity
    Note over AutomatedAgent: Use refined UDM query
    AutomatedAgent->>SIEM: search_security_events(text="Refined Login Query for USER_ID", hours_back=72)
    SIEM-->>AutomatedAgent: Recent Login Events (LOGIN_ACTIVITY_SUMMARY)

    %% Step 7: Check Related SOAR Cases
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=[USER_ID, SOURCE_IP, HOSTNAME], CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: RELATED_SOAR_CASES

    %% Step 8: Optional IDP Check
    opt IDP Tool Available (e.g., okta-mcp)
        AutomatedAgent->>IDP: lookup_okta_user(user=USER_ID)
        IDP-->>AutomatedAgent: User Account Details from IDP (IDP_SUMMARY)
    end

    %% Step 9: Synthesize & Document
    Note over AutomatedAgent: Synthesize findings (incl. related cases, hostname) and prepare COMMENT_TEXT with Recommendation
    AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
    DocumentInSOAR-->>AutomatedAgent: Results: COMMENT_POST_STATUS

    %% Step 10: Optional Report Generation
    AutomatedAgent->>AskReport: Confirm: "Generate markdown report? (Yes/No)"
    AskReport-->>AutomatedAgent: User Response (REPORT_CHOICE)
    alt REPORT_CHOICE is "Yes"
        Note over AutomatedAgent: Prepare REPORT_CONTENT (incl. Mermaid diagram)
        AutomatedAgent->>GenerateReport: Execute(Input: REPORT_CONTENT, REPORT_TYPE="suspicious_login_triage", REPORT_NAME_SUFFIX=CASE_ID)
        GenerateReport-->>AutomatedAgent: Results: REPORT_GENERATION_STATUS
    else REPORT_CHOICE is "No"
        Note over AutomatedAgent: REPORT_GENERATION_STATUS = "Skipped"
    end

    %% Step 11: Completion
    AutomatedAgent->>Analyst: attempt_completion(result="Suspicious Login Triage complete for USER_ID from SOURCE_IP. Findings documented in case CASE_ID. Report Status: REPORT_GENERATION_STATUS.")
```

## Rubrics

The following rubric is used to evaluate the execution of the **Suspicious Login Alert Triage** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Entity Extraction** | 20 | Correctly identified the User ID, Source IP, and Hostname from the alert data. |
| **Context Gathering** | 25 | Retrieved comprehensive context: User history, IP reputation, and recent login patterns. |
| **Analysis Depth** | 20 | Performed meaningful analysis of the data (e.g., identifying impossible travel or unusual times). |
| **Documentation** | 15 | Synthesized findings into a clear, actionable comment in the SOAR case. |
| **Tool Usage** | 5 | Used the correct tools and sub-runbooks (e.g., `enrich_ioc`, `find_relevant_soar_case`). |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Entity Extraction (20 Points)
- **10 pts**: Accurately extracted the primary User ID and Source IP.
- **10 pts**: Correctly identified the Hostname if present in the alert data.

#### 2. Context Gathering (25 Points)
- **10 pts**: Retrieved user summary and recent activity from SIEM (`lookup_entity`).
- **10 pts**: Enriched the Source IP using the `enrich_ioc` common step (GTI + SIEM).
- **5 pts**: Searched for recent login activity using a correct UDM query (`search_security_events`).

#### 3. Analysis Depth (20 Points)
- **10 pts**: Checked for related open SOAR cases (`find_relevant_soar_case`).
- **10 pts**: Identified key patterns (e.g., failed vs. successful logins, geographical anomalies) in the retrieved data.

#### 4. Documentation (15 Points)
- **10 pts**: Posted a comment to the SOAR case (`document_in_soar`) that summarizes all key findings.
- **5 pts**: Provided a clear recommendation (e.g., "Close as FP", "Escalate") based on the evidence.

#### 5. Tool Usage (5 Points)
- **5 pts**: Correctly called all specified tools and sub-runbooks with appropriate arguments, without hallucinating non-existent tools or skipping required steps.

#### 6. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken during execution.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost of the execution.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
