# Atomic Runbook: Search User Login Activity in Chronicle

**ID:** `RB-ATOM-USER-002`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for user login events (successful and failed) associated with a specific username in Chronicle SIEM using `search_security_events`.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#user-indicator`, `rb_user_lookup_entity_chronicle.md`
**Trigger:** When detailed login activity for a user is required, often after an initial entity lookup or if suspicious account behavior is suspected.

---

## Inputs Required

-   `username`: string - The username to search for (e.g., `jdoe`, `admin@example.com`).
-   `hours_back` (optional): integer - How many hours of historical data. Defaults to 72 (3 days).
-   `max_events` (optional): integer - Max event records. Defaults to 100.
-   `login_outcome_filter` (optional): string - Filter by login outcome ["Successful", "Failed", "Any"]. Defaults to "Any".

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter):**
    -   Base query: "Login events for user '{username}'"
    -   Outcome filter:
        -   If `login_outcome_filter` is "Successful": Append "where outcome is 'SUCCESSFUL_LOGIN' or 'ALLOW'" (UDM `security_result.action` can be `ALLOW` for successful logins).
        -   If `login_outcome_filter` is "Failed": Append "where outcome is 'FAILED_LOGIN' or 'BLOCK'" (UDM `security_result.action` can be `BLOCK` for failed logins).
    -   Append time window: "... in the last {hours_back} hours"
    -   *Example:* "Login events for user 'jdoe' where outcome is 'FAILED_LOGIN' in the last 24 hours"
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back`, `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* UDM event types for logins can be `USER_LOGIN` or sometimes `USER_UNCATEGORIZED` with specific outcome details. The natural language query should handle this.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events`. Extract `metadata.event_timestamp`, `principal.user.userid`, `principal.hostname` (source of login), `target.hostname` (target system), `src.ip`, `security_result.action`, `security_result.description`.

---

## Outputs Expected

-   `login_events`: list - List of UDM login event records.
-   `translated_udm_query`: string.
-   `total_events_matched`: integer.
-   `source_ips_logins`: list - Unique `src.ip` from login events.
-   `target_systems_logins`: list - Unique `target.hostname` from login events.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings (e.g., number of successful/failed logins, unique source IPs, target systems).
    -   Analyze for patterns: Logins from unusual geolocations/IPs (correlate source IPs with GTI), impossible travel, brute-force attempts (many fails then a success), logins to unexpected systems.
    -   If suspicious patterns found, escalate or proceed to other runbooks (e.g., IP investigation for source IPs, process activity search for the user on target systems).
-   IF `output_status` is "NoEventsFound":
    -   Log "No {login_outcome_filter} login events found for user {username} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search login events for user {username} in Chronicle."

---

## AI Agent Execution Notes

-   The term for `security_result.action` (e.g. `ALLOW`, `BLOCK`) can vary by log source, so natural language queries are generally better here than trying to construct a precise UDM filter for outcome unless the exact UDM values are known for the target log sources.
-   Correlate `source_ips_logins` with `rb_ip_get_gti_report.md` if suspicious.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `login_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future User section)
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
