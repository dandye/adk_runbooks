# Atomic Runbook: Search User Process Activity in Chronicle

**ID:** `RB-ATOM-USER-003`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for process launch events associated with a specific username in Chronicle SIEM using `search_security_events`. This helps identify what applications and commands a user has executed.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#user-indicator`, `rb_user_lookup_entity_chronicle.md`
**Trigger:** When detailed process activity for a user is required, often after an initial entity lookup or if suspicious account behavior (e.g., unusual logins) is noted.

---

## Inputs Required

-   `username`: string - The username whose process activity is to be searched (e.g., `jdoe`, `admin@example.com`).
-   `hours_back` (optional): integer - How many hours of historical data. Defaults to 24.
-   `max_events` (optional): integer - Max event records. Defaults to 100.
-   `target_hostname` (optional): string - Filter process activity to a specific host.
-   `process_name_filter` (optional): string - Filter for specific process names (e.g., "powershell.exe", "cmd.exe").

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter):**
    -   Base query: "Process launch events for user '{username}'"
    -   Hostname filter (if `target_hostname` provided): " on host '{target_hostname}'"
    -   Process name filter (if `process_name_filter` provided): " involving process '{process_name_filter}'"
    -   Append time window: "... in the last {hours_back} hours"
    -   *Example:* "Process launch events for user 'jdoe' on host 'workstation123' involving process 'powershell.exe' in the last 24 hours"
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back`, `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* Ensure username format matches UDM `principal.user.userid`.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events`. Extract `metadata.event_timestamp`, `principal.user.userid`, `principal.hostname`, `principal.process.file.full_path`, `principal.process.command_line`, `principal.process.parent_process.file.full_path`.

---

## Outputs Expected

-   `process_events`: list - List of UDM process launch event records.
-   `translated_udm_query`: string.
-   `total_events_matched`: integer.
-   `executed_commands`: list - Unique `principal.process.command_line` from events.
-   `involved_hosts`: list - Unique `principal.hostname` where processes were launched.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings (e.g., list of commands, hosts involved).
    -   Analyze `executed_commands` for suspicious activity (e.g., use of hacking tools, unusual scripts, reconnaissance commands).
    -   Correlate with `analytical_query_patterns.md` for known malicious command patterns.
    -   If suspicious commands or processes are found, escalate or proceed to deeper investigation of affected hosts or related IOCs (file hashes from processes, network connections).
-   IF `output_status` is "NoEventsFound":
    -   Log "No process launch events found for user {username} matching criteria in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search process events for user {username} in Chronicle."

---

## AI Agent Execution Notes

-   If `process_name_filter` is used, ensure it's specific enough or use wildcards appropriately if the tool's natural language processing supports it well for process names.
-   This runbook is powerful when combined with login activity; e.g., investigate processes launched after a suspicious login.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `process_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future User section)
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
