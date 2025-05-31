# Atomic Runbook: Lookup File Hash Entity Activity in Chronicle

**ID:** `RB-ATOM-HASH-003`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a summary of a file hash's activity from Chronicle SIEM using the `lookup_entity` tool. This provides a quick overview of internal sightings (e.g., process executions, file observations), related alerts, and first/last seen times.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#3-atomic-indicator-file-hash`
**Trigger:** When a file hash requires an initial check for internal activity within Chronicle, often after external reputation checks.

---

## Inputs Required

-   `file_hash`: string - The file hash (MD5, SHA1, SHA256) to look up.
    -   *Source Example:* Alert data, output from `rb_hash_get_gti_report.md`.
-   `hours_back` (optional): integer - How many hours of historical data to consider. Defaults to 72 (3 days).

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `lookup_entity`
2.  **Parameter Mapping:**
    -   Map `file_hash` (Input) to MCP Tool parameter `entity_value`.
    -   Map `hours_back` (Input or default) to MCP Tool parameter `hours_back`.
3.  **Execute Tool:** Call `lookup_entity`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
4.  **Data Transformation/Extraction:**
    -   Output is textual. AI may parse for specific details (e.g., number of hosts, related alerts).

---

## Outputs Expected

-   `chronicle_entity_summary`: string - Textual summary from `lookup_entity`.
-   `related_alerts_count` (optional, if parsable): integer.
-   `hosts_observed_count` (optional, if parsable): integer - Number of unique hosts where hash was seen.
-   `output_status`: string - ["Success", "NoInfoFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log `chronicle_entity_summary`.
    -   IF `related_alerts_count` > 0 OR `hosts_observed_count` > 0 (or summary indicates sightings) THEN
        -   Flag Hash for "Further Internal Investigation - Activity Observed".
        -   Proceed to `rb_hash_search_process_events_chronicle.md` for detailed execution logs.
    -   ELSE
        -   Flag Hash as "No Internal Activity Observed via Lookup".
-   IF `output_status` is "NoInfoFound":
    -   Log "No activity found for file hash {file_hash} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to lookup file hash {file_hash} in Chronicle."

---

## AI Agent Execution Notes

-   Default `hours_back` is 72. Adjust as needed.
-   AI parsing `chronicle_entity_summary` should look for "Observed on hosts:", "Related Alerts:", "File Executions:".

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/ai_performance_logging_requirements.md`
