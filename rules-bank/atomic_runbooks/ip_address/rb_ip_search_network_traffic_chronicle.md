# Atomic Runbook: Search IP Network Traffic in Chronicle

**ID:** `RB-ATOM-IP-004`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for network traffic events associated with a specific IP address in Chronicle SIEM using the `search_security_events` tool. This is typically used when a broader summary from `lookup_entity` is insufficient or indicates suspicious activity requiring deeper analysis.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#1-atomic-indicator-ip-address`, `rb_ip_lookup_entity_chronicle.md`
**Trigger:** When detailed network logs for an IP address are needed for investigation, often following an initial entity lookup or based on external threat intelligence.

---

## Inputs Required

-   `ip_address`: string - The IP address to search for.
    -   *Source Example:* Alert field, output from other enrichment runbooks.
-   `hours_back` (optional): integer - How many hours of historical data to search. Defaults to 24 if not provided.
    -   *Source Example:* Analyst preference, default, or dynamically set.
-   `max_events` (optional): integer - Maximum number of event records to return. Defaults to 100.
    -   *Source Example:* Default, or increased if a high volume of traffic is expected and needs review.
-   `additional_query_terms` (optional): string - Any additional UDM filter conditions to append to the query (e.g., "AND network.application_protocol = 'DNS'").
    -   *Source Example:* Analyst input, or derived from context (e.g., investigating specific protocol activity).

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter of the tool):**
    -   Base query: "Network traffic where principal.ip is '{ip_address}' or target.ip is '{ip_address}'"
    -   Append time window: "... in the last {hours_back} hours"
    -   Append additional terms: " {additional_query_terms}" (if provided).
    -   *Example `text` value:* "Network traffic where principal.ip is '192.168.1.100' or target.ip is '192.168.1.100' in the last 48 hours AND target.port = 445"
3.  **Parameter Mapping:**
    -   Map the constructed query string to MCP Tool parameter `text`.
    -   Map `hours_back` (Input or default) to MCP Tool parameter `hours_back`.
    -   Map `max_events` (Input or default) to MCP Tool parameter `max_events`.
4.  **Execute Tool:** Call the `search_security_events` tool.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for guidance on `search_security_events`.
5.  **Data Transformation/Extraction:**
    -   The primary output is `events.events` (a list of UDM event records).
    -   AI agents may need to iterate through these events to extract key fields for summary or further processing.

---

## Outputs Expected

-   `udm_events`: list - A list of UDM event records matching the search criteria.
-   `translated_udm_query`: string - The UDM query that was actually executed by Chronicle.
-   `total_events_matched`: integer - The total number of events matching the query (may exceed `max_events` returned).
-   `output_status`: string - ["Success", "NoEventsFound", "Failure"]
    -   "NoEventsFound" indicates the tool ran successfully but found no matching events.
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings from `udm_events` (e.g., unique destination IPs/ports, protocols, data volumes, associated hostnames).
    -   Analyze events for suspicious patterns (e.g., beaconing, large data transfers to unusual destinations, connections to known malicious infrastructure IPs from `rb_ip_get_gti_report.md`).
    -   Based on analysis, proceed to:
        -   Other atomic runbooks for related indicators (e.g., `rb_domain_get_gti_report.md` if new domains are found).
        -   Containment runbooks if malicious activity is confirmed (e.g., `rules-bank/automated_response_playbook_criteria.md` for blocking).
        -   Escalation to human analyst if complex or ambiguous.
-   IF `output_status` is "NoEventsFound":
    -   Log "No network traffic found for IP {ip_address} matching criteria in Chronicle for the last {hours_back} hours."
    -   Consider if this lack of activity is itself suspicious depending on the IP's role and external reputation.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`. Review `translated_udm_query` for potential syntax issues if available.
    -   Escalate to human analyst: "Failed to search network traffic for IP {ip_address} in Chronicle."

---

## AI Agent Execution Notes

-   Be cautious with very broad queries (e.g., long `hours_back` without specific `additional_query_terms`) as they can return excessive data or hit performance limits.
-   If `total_events_matched` is significantly higher than `max_events` returned, the AI should note that only a subset of data was analyzed and consider if refined queries are needed to cover the remaining events.
-   The AI should correlate findings with `network_map.md` to understand if traffic is internal/external or crossing trust boundaries.

---

## Metrics Collection Points

-   Log execution time for this runbook.
-   Log `output_status`, number of `udm_events` returned, and `total_events_matched`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
