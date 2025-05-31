# Atomic Runbook: Search Domain-Related Network Traffic in Chronicle

**ID:** `RB-ATOM-DOMAIN-005`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for network traffic events potentially related to a specific domain/FQDN. This often involves searching for connections to/from IP addresses previously resolved from the domain.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#2-atomic-indicator-domain-name--fqdn`, `rb_domain_search_dns_chronicle.md`
**Trigger:** When network connection details related to a domain are needed, typically after identifying IPs resolved from the domain or if direct domain logging is sparse.

---

## Inputs Required

-   `domain_name`: string - The domain name or FQDN under investigation.
    -   *Source Example:* Alert field, output from other enrichment runbooks.
-   `resolved_ips` (optional): list - A list of IP addresses known to be associated with the `domain_name` (e.g., from `rb_domain_get_gti_report.md` or `rb_domain_search_dns_chronicle.md`).
    -   *Source Example:* Output from `rb_domain_search_dns_chronicle.md`.
-   `hours_back` (optional): integer - How many hours of historical data to search. Defaults to 24.
-   `max_events` (optional): integer - Maximum event records to return. Defaults to 100.
-   `additional_query_terms` (optional): string - Additional UDM filter conditions.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter of the tool):**
    -   **Strategy 1 (Direct Domain in URL/Hostname):**
        -   Query: "Network traffic where target.hostname CONTAINS '{domain_name}' OR target.url CONTAINS '{domain_name}'"
    -   **Strategy 2 (Using Resolved IPs - if `resolved_ips` list is provided and not empty):**
        -   Construct an IP list string: `"{ip1}", "{ip2}", ...`
        -   Query: "Network traffic where target.ip IN ({ip_list_string}) OR principal.ip IN ({ip_list_string})"
    -   *AI Agent Note:* Prioritize Strategy 2 if `resolved_ips` are available, as it's often more direct for network traffic. If not, use Strategy 1. Combine if necessary.
    -   Append time window: "... in the last {hours_back} hours"
    -   Append additional terms: " {additional_query_terms}" (if provided).
    -   *Example `text` (Strategy 2):* "Network traffic where target.ip IN ('1.2.3.4', '5.6.7.8') OR principal.ip IN ('1.2.3.4', '5.6.7.8') in the last 24 hours"
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back` to `hours_back`.
    -   Map `max_events` to `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events`. Extract connection details: `principal.ip`, `target.ip`, `target.port`, `network.application_protocol`, `network.direction`.

---

## Outputs Expected

-   `network_traffic_events`: list - List of UDM network event records.
-   `translated_udm_query`: string.
-   `total_events_matched`: integer.
-   `contacted_ips_ports`: list - Unique list of (target.ip, target.port) tuples from events.
-   `source_ips_contacting`: list - Unique list of `principal.ip` from events.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure", "PartialSuccess_NoResolvedIPs"]
    -   "PartialSuccess_NoResolvedIPs" if `resolved_ips` was empty and only Strategy 1 could be attempted.
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings.
    -   Analyze events for suspicious patterns (e.g., specific ports, protocols, data volumes to/from IPs associated with the domain).
    -   If new suspicious IPs are identified in `contacted_ips_ports` or `source_ips_contacting` that were not in the initial `resolved_ips` list, consider initiating IP-specific atomic runbooks for them.
    -   Escalate if high-risk activity confirmed.
-   IF `output_status` is "NoEventsFound" or "PartialSuccess_NoResolvedIPs":
    -   Log result. This might indicate the domain is not actively being connected to/from, or only Strategy 1 was possible and yielded no results.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search network traffic for domain {domain_name} in Chronicle."

---

## AI Agent Execution Notes

-   If the `resolved_ips` list is very long, the AI might need to batch queries or summarize, as UDM query length can be a constraint.
-   Correlate findings with `network_map.md` and `asset_inventory_guidelines.md`.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `network_traffic_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
