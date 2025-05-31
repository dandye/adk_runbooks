# Atomic Runbook: Lookup IP Entity Activity in Chronicle

**ID:** `RB-ATOM-IP-003`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a summary of an IP address's activity from Chronicle SIEM using the `lookup_entity` tool. This provides a quick overview of internal interactions, related alerts, and first/last seen times within a defined window.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#1-atomic-indicator-ip-address`
**Trigger:** When an IP address requires an initial check for internal activity within Chronicle, often after external reputation checks.

---

## Inputs Required

-   `ip_address`: string - The IP address to look up.
    -   *Source Example:* Alert field, output from other enrichment runbooks like `rb_ip_get_gti_report.md`.
-   `hours_back` (optional): integer - How many hours of historical data to consider for the summary. Defaults to 24 if not provided.
    -   *Source Example:* Analyst preference, default value, or dynamically set based on alert age.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `lookup_entity`
2.  **Parameter Mapping:**
    -   Map `ip_address` (Input) to MCP Tool parameter `entity_value`.
    -   Map `hours_back` (Input, if provided, else use default) to MCP Tool parameter `hours_back`.
3.  **Execute Tool:** Call the `lookup_entity` tool.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for guidance on `lookup_entity`.
4.  **Data Transformation/Extraction:**
    -   The output is a textual summary. The AI agent may need to parse this text to extract specific details if required for subsequent automated decisions (e.g., number of related alerts, presence of critical assets in related entities).

---

## Outputs Expected

-   `chronicle_entity_summary`: string - The textual summary provided by the `lookup_entity` tool.
-   `related_alerts_count` (optional, if parsable by AI): integer - Number of alerts associated with the entity in the summary.
-   `first_seen_in_window` (optional, if parsable by AI): string/timestamp - First seen timestamp from the summary.
-   `last_seen_in_window` (optional, if parsable by AI): string/timestamp - Last seen timestamp from the summary.
-   `output_status`: string - ["Success", "NoInfoFound", "Failure"]
    -   "NoInfoFound" indicates the tool ran successfully but found no information for the entity in the time window.
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log `chronicle_entity_summary` to the case.
    -   IF `related_alerts_count` > 0 (or summary indicates significant activity/alerts) THEN
        -   Flag IP for "Further Internal Investigation - High Activity".
        -   Proceed to more detailed log analysis using `rb_ip_search_network_traffic_chronicle.md` or specific TTP hunting runbooks.
    -   ELSE (low activity, no critical alerts mentioned in summary)
        -   Flag IP as "Low Internal Activity Observed".
        -   May still proceed to `rb_ip_search_network_traffic_chronicle.md` for due diligence if external reputation was medium/high.
-   IF `output_status` is "NoInfoFound":
    -   Log "No activity found for IP {ip_address} in Chronicle for the last {hours_back} hours."
    -   Decision on next steps depends heavily on external reputation findings. If external reputation is high risk, absence of internal logs might be suspicious in itself (e.g., new C2) or indicate logging gaps.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate to human analyst: "Failed to lookup IP {ip_address} in Chronicle."

---

## AI Agent Execution Notes

-   The default `hours_back` is 24. For older incidents or broader context, this may need to be explicitly set to a larger value (e.g., 168 for 7 days).
-   AI agents performing NLP on `chronicle_entity_summary` should look for keywords like "alerts:", "Related Entities:", "First seen:", "Last seen:".

---

## Metrics Collection Points

-   Log execution time for this runbook.
-   Log `output_status`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/ai_performance_logging_requirements.md`
