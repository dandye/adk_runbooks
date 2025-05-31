# Atomic Runbook: Search URL Activity in Chronicle

**ID:** `RB-ATOM-URL-003`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for network traffic or other events associated with a specific URL in Chronicle SIEM using the `search_security_events` tool.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#url-indicator` (Assuming a future section for URLs), `rb_url_get_gti_report.md`
**Trigger:** When internal activity related to a URL needs to be investigated, often after external reputation checks.

---

## Inputs Required

-   `url`: string - The full URL to search for.
    -   *Source Example:* Alert field, output from other enrichment runbooks.
-   `hours_back` (optional): integer - How many hours of historical data. Defaults to 24.
-   `max_events` (optional): integer - Max event records. Defaults to 100.
-   `search_strategy` (optional): string - ["ExactURL", "DomainAndPath", "DomainOnly", "ResolvedIPs"]. Default: "ExactURL".
    -   "ExactURL": Searches for the exact URL string.
    -   "DomainAndPath": Searches for the domain and path components.
    -   "DomainOnly": Extracts domain and searches for traffic to that domain.
    -   "ResolvedIPs": If IPs resolved from the URL's domain are known, search traffic to those IPs.
-   `resolved_ips_for_url_domain` (optional): list - List of IPs if `search_strategy` is "ResolvedIPs".

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter):**
    -   Based on `search_strategy`:
        -   **ExactURL:** "Events where target.url = '{url}' OR about.url = '{url}'"
        -   **DomainAndPath:** (Extract domain and path from `url`) "Events where target.url CONTAINS '{domain_from_url}{path_from_url}'"
        -   **DomainOnly:** (Extract domain from `url`) "Events where target.hostname = '{domain_from_url}' OR target.url CONTAINS '{domain_from_url}/'"
        -   **ResolvedIPs:** (Requires `resolved_ips_for_url_domain`) "Network traffic where target.ip IN ({ip_list_string}) OR principal.ip IN ({ip_list_string})"
    -   Append time window: "... in the last {hours_back} hours"
    -   *AI Agent Note:* If `search_strategy` is not "ExactURL", the AI needs to parse the input `url` to extract domain/path.
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back`, `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events`. Extract `principal.ip`, `principal.hostname`, `target.ip`, `target.port`, `metadata.event_type`.

---

## Outputs Expected

-   `url_related_events`: list - List of UDM event records.
-   `translated_udm_query`: string.
-   `total_events_matched`: integer.
-   `source_hosts_accessing_url`: list - Unique `principal.hostname` or `principal.ip`.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure", "InputError_MissingResolvedIPs"]
-   `output_message`: string (if Failure or InputError).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings (e.g., hosts accessing the URL, event types).
    -   Analyze events for suspicious patterns (e.g., downloads, POST requests to suspicious URLs).
    -   If malicious activity confirmed, consider containment or escalation.
-   IF `output_status` is "NoEventsFound":
    -   Log "No Chronicle events found related to URL {url} with strategy {search_strategy} for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure" or "InputError_MissingResolvedIPs"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search Chronicle for URL {url}."

---

## AI Agent Execution Notes

-   URL parsing (for domain/path extraction) needs to be robust.
-   If `search_strategy` is "ResolvedIPs" but `resolved_ips_for_url_domain` is not provided, the runbook should ideally default to another strategy or return an error.
-   Consider the possibility of URL variations (HTTP vs HTTPS, www vs non-www) if "ExactURL" is too restrictive. The CONTAINS operator in other strategies can help.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `url_related_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future URL section)
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
