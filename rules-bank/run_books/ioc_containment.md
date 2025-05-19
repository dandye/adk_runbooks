# IOC Containment Runbook

## Objective

Quickly execute containment actions for identified malicious Indicators of Compromise (IOCs) such as IP addresses, domains, or file hashes, leveraging available SIEM, SOAR, GTI, and potentially EDR/Firewall tools.

## Scope

This runbook focuses on the immediate containment actions based on confirmed malicious IOCs. It assumes the IOCs have been identified through prior investigation (e.g., alert triage, threat hunting, GTI research).

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash").
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report` (Optional: for final reputation check)
*   `secops-soar`: `google_chronicle_add_values_to_reference_list` (Example: for adding to SIEM blocklist)
*   `secops-soar`: `post_case_comment` (For documentation)
*   *(Potentially other SOAR actions for specific integrations like Firewalls, Proxies, EDR)*
*   `secops-mcp`: `search_security_events` (To find related activity/endpoints for file hashes)
*   You may ask follow up question (To confirm actions)

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, `${CASE_ID}`, and `${ALERT_GROUP_IDENTIFIERS}`.
2.  **(Optional) Final Reputation Check:** Use the appropriate `gti-mcp` tool (`get_ip_address_report`, `get_domain_report`, `get_file_report`) for `${IOC_VALUE}` to confirm malicious reputation before blocking.
3.  **Confirm Containment Action:** Execute `common_steps/confirm_action.md` with `QUESTION_TEXT="Proceed with containment for ${IOC_VALUE} (${IOC_TYPE})?"` and `RESPONSE_OPTIONS=["Yes", "No"]`. Obtain `${USER_RESPONSE}`.
4.  **Execute Containment (If Confirmed):**
    *   If `${USER_RESPONSE}` is "Yes":
        *   **If `${IOC_TYPE}` is IP Address or Domain:**
            *   Add `${IOC_VALUE}` to the appropriate blocklist reference list in Chronicle SIEM using `secops-soar.google_chronicle_add_values_to_reference_list`. (Requires knowing the correct `reference_list_name`, e.g., "IP_Blocklist", "Domain_Blocklist"). Let the action status be `CONTAINMENT_ACTION_STATUS`.
            *   *(Optional: Execute actions via specific Firewall/Proxy SOAR integrations if available)*.
        *   **If `${IOC_TYPE}` is File Hash:**
            *   Search SIEM (`secops-mcp.search_security_events`) for events involving the file hash (`target.file.md5 = "${IOC_VALUE}"` or similar) to identify affected endpoints.
            *   *(Optional: Execute EDR actions like file quarantine/deletion on identified endpoints via specific EDR SOAR integrations if available)*. Let the action status be `CONTAINMENT_ACTION_STATUS`.
        *   **Document Action:** Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `COMMENT_TEXT="Containment action attempted for IOC: ${IOC_VALUE} (Type: ${IOC_TYPE}). Action: [Blocked/EDR Action Attempted]. Status: ${CONTAINMENT_ACTION_STATUS}"`. Obtain `${COMMENT_POST_STATUS}`.
    *   If `${USER_RESPONSE}` is "No":
        *   **Document Action:** Execute `common_steps/document_in_soar.md` with `${CASE_ID}` and `COMMENT_TEXT="Containment action aborted by analyst for IOC: ${IOC_VALUE} (Type: ${IOC_TYPE})."`. Obtain `${COMMENT_POST_STATUS}`.
5.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant GTI as gti-mcp
    participant ConfirmAction as common_steps/confirm_action.md
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant DocumentInSOAR as common_steps/document_in_soar.md
    %% EDR/Firewall conceptual participants
    participant EDR as EDR (Conceptual)
    participant Firewall as Firewall (Conceptual)

    Analyst->>AutomatedAgent: Start IOC Containment Runbook\nInput: IOC_VALUE, IOC_TYPE, CASE_ID, ALERT_GROUP_IDS

    %% Step 2: Optional Reputation Check
    opt Reputation Check
        alt IOC_TYPE is IP Address
            AutomatedAgent->>GTI: get_ip_address_report(ip_address=IOC_VALUE)
            GTI-->>AutomatedAgent: IP Report (Confirm Malicious)
        else IOC_TYPE is Domain
            AutomatedAgent->>GTI: get_domain_report(domain=IOC_VALUE)
            GTI-->>AutomatedAgent: Domain Report (Confirm Malicious)
        else IOC_TYPE is File Hash
            AutomatedAgent->>GTI: get_file_report(hash=IOC_VALUE)
            GTI-->>AutomatedAgent: File Report (Confirm Malicious)
        end
    end

    %% Step 3: Confirm Action
    AutomatedAgent->>ConfirmAction: Execute(Input: QUESTION_TEXT="Proceed...?", RESPONSE_OPTIONS=["Yes", "No"])
    ConfirmAction-->>AutomatedAgent: Results: USER_RESPONSE

    %% Step 4: Execute Containment (If Confirmed)
    alt USER_RESPONSE is "Yes"
        Note over AutomatedAgent: Containment_Action_Status = "Attempted"
        alt IOC_TYPE is IP Address or Domain
            Note over AutomatedAgent: Determine Reference List Name (e.g., "IP_Blocklist")
            AutomatedAgent->>SOAR: google_chronicle_add_values_to_reference_list(case_id=CASE_ID, ..., values=IOC_VALUE)
            SOAR-->>AutomatedAgent: Blocklist Add Result -> Update Containment_Action_Status
            opt Firewall/Proxy Integration Available
                 AutomatedAgent->>Firewall: (Conceptual) Block IOC_VALUE
                 Firewall-->>AutomatedAgent: Block Result -> Update Containment_Action_Status
            end
        else IOC_TYPE is File Hash
            AutomatedAgent->>SIEM: search_security_events(text="Events with hash IOC_VALUE")
            SIEM-->>AutomatedAgent: Events (Identify Endpoints E1, E2...)
            opt EDR Integration Available
                loop For each Endpoint Ei
                    AutomatedAgent->>EDR: (Conceptual) Quarantine/Delete Hash IOC_VALUE on Ei
                    EDR-->>AutomatedAgent: EDR Action Result -> Update Containment_Action_Status
                end
            else
                Note over AutomatedAgent: Containment_Action_Status = "Manual EDR Action Needed"
            end
        end

        %% Document Action (Yes case)
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT="Containment action attempted...")
        DocumentInSOAR-->>AutomatedAgent: Results: COMMENT_POST_STATUS
        AutomatedAgent->>Analyst: attempt_completion(result="IOC Containment runbook complete for IOC_VALUE. Action attempted.")

    else USER_RESPONSE is "No"
         %% Document Action (No case)
         AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT="Containment action aborted...")
         DocumentInSOAR-->>AutomatedAgent: Results: COMMENT_POST_STATUS
         AutomatedAgent->>Analyst: attempt_completion(result="IOC Containment runbook aborted for IOC_VALUE.")
    end
