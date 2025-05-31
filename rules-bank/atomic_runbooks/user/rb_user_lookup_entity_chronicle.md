# Atomic Runbook: Lookup User Entity Activity in Chronicle

**ID:** `RB-ATOM-USER-001`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a summary of a user's activity from Chronicle SIEM using the `lookup_entity` tool. This provides a quick overview of their logins, systems accessed, related alerts, and first/last seen times.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#user-indicator` (Assuming a future section for Users)
**Trigger:** When a username (e.g., from an alert, phishing report, or HR termination list) requires an initial check for activity within Chronicle.

---

## Inputs Required

-   `username`: string - The username to look up (e.g., `jdoe`, `admin@example.com`).
    -   *Source Example:* Alert field `principal.user.userid`, email sender/recipient.
-   `hours_back` (optional): integer - How many hours of historical data to consider. Defaults to 72 (3 days).

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `lookup_entity`
2.  **Parameter Mapping:**
    -   Map `username` (Input) to MCP Tool parameter `entity_value`.
    -   Map `hours_back` (Input or default) to MCP Tool parameter `hours_back`.
3.  **Execute Tool:** Call `lookup_entity`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`. Usernames might need to be in a specific format (e.g., UPN) depending on how they are logged and parsed into UDM.
4.  **Data Transformation/Extraction:**
    -   Output is textual. AI may parse for specific details (e.g., number of distinct hosts logged into, alert counts).

---

## Outputs Expected

-   `chronicle_entity_summary`: string - Textual summary from `lookup_entity`.
-   `related_alerts_count` (optional, if parsable): integer.
-   `accessed_hosts_count` (optional, if parsable): integer - Number of unique hosts associated with the user in the summary.
-   `login_locations_summary` (optional, if parsable): string/list - Summary of source IPs or geolocations for logins.
-   `output_status`: string - ["Success", "NoInfoFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log `chronicle_entity_summary`.
    -   IF `related_alerts_count` > 0 OR summary indicates logins from unusual locations OR access to an unusually high number of hosts THEN
        -   Flag User as "Suspicious Activity Observed - Needs Deeper Dive".
        -   Proceed to `rb_user_search_login_activity_chronicle.md` and `rb_user_search_process_activity_chronicle.md`.
    -   ELSE
        -   Flag User as "Low/Normal Activity Observed via Lookup".
        -   May still proceed to detailed searches if external context (e.g., user reported as compromised) warrants it.
-   IF `output_status` is "NoInfoFound":
    -   Log "No activity found for user {username} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to lookup user {username} in Chronicle."

---

## AI Agent Execution Notes

-   Be mindful of username formats (e.g., `samaccountname` vs. `userprincipalname` vs. short name). The `data_normalization_map.md` might be relevant if the input username needs translation to the format typically found in UDM `principal.user.userid`.
-   AI parsing `chronicle_entity_summary` should look for "Logon Events:", "Distinct Hosts:", "Related Alerts:".

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future User section)
-   `rules-bank/ai_performance_logging_requirements.md`
-   `rules-bank/data_normalization_map.md`
