# Atomic Runbook: Search File Hash Process Events in Chronicle

**ID:** `RB-ATOM-HASH-004`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for process launch or other file-related events associated with a specific file hash in Chronicle SIEM using `search_security_events`. This is used for in-depth analysis of where and how a file was executed or observed.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#3-atomic-indicator-file-hash`, `rb_hash_lookup_entity_chronicle.md`
**Trigger:** When detailed process execution or file observation logs for a specific hash are needed, typically after an initial entity lookup indicates internal sightings.

---

## Inputs Required

-   `file_hash`: string - The file hash (MD5, SHA1, or SHA256) to search for.
-   `hash_type_udm_field`: string - The specific UDM field for the hash type (e.g., `principal.process.file.sha256`, `target.file.md5`, `about.file.sha1`).
    -   *Source Example:* Determined by context (e.g., if looking for executions, `principal.process.file.sha256` is common).
-   `hours_back` (optional): integer - How many hours of historical data. Defaults to 72 (3 days).
-   `max_events` (optional): integer - Max event records. Defaults to 100.
-   `additional_query_terms` (optional): string - e.g., "AND metadata.event_type = 'PROCESS_LAUNCH'".

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter):**
    -   Base query: "Events where {hash_type_udm_field} = '{file_hash}'"
    -   Append time: "... in the last {hours_back} hours"
    -   Append additional terms: " {additional_query_terms}"
    -   *Example:* "Events where principal.process.file.sha256 = '{some_sha256_hash}' AND metadata.event_type = 'PROCESS_LAUNCH' in the last 72 hours"
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back`, `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events`. Extract `principal.hostname`, `principal.user.userid`, `principal.process.command_line`, `principal.process.parent_process.file.full_path`, `metadata.event_timestamp`.

---

## Outputs Expected

-   `process_events`: list - List of UDM event records.
-   `translated_udm_query`: string.
-   `total_events_matched`: integer.
-   `affected_hosts`: list - Unique `principal.hostname` from events.
-   `executed_commands`: list (optional) - Unique `principal.process.command_line` if event_type is PROCESS_LAUNCH.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings (e.g., list of affected hosts, unique command lines).
    -   Analyze command lines for suspicious parameters or further IOCs.
    -   For each host in `affected_hosts`, consider initiating host-specific investigation runbooks.
    -   If widespread execution of a malicious hash is found, escalate immediately.
-   IF `output_status` is "NoEventsFound":
    -   Log "No specific process/file events found for hash {file_hash} with field {hash_type_udm_field} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search process events for hash {file_hash} in Chronicle."

---

## AI Agent Execution Notes

-   Choosing the correct `hash_type_udm_field` is critical. Common ones include:
    -   `principal.process.file.sha256` (for executed processes)
    -   `target.file.sha256` (for files written, read, or modified)
    -   `about.file.sha256` (for files scanned by AV/security tools)
    -   (and their `md5`, `sha1` equivalents)
-   If `additional_query_terms` is not specified, the search might be very broad. Consider defaulting to `metadata.event_type = "PROCESS_LAUNCH"` if looking for executions.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `process_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
