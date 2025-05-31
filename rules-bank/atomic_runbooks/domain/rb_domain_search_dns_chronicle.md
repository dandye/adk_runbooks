# Atomic Runbook: Search Domain DNS Queries in Chronicle

**ID:** `RB-ATOM-DOMAIN-004`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To perform a detailed search for DNS query events associated with a specific domain/FQDN in Chronicle SIEM using the `search_security_events` tool. This helps identify which internal hosts resolved or attempted to resolve the domain.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#2-atomic-indicator-domain-name--fqdn`, `rb_domain_lookup_entity_chronicle.md`
**Trigger:** When detailed DNS resolution logs for a domain are needed, often after an initial entity lookup or if suspicious domain activity is suspected.

---

## Inputs Required

-   `domain_name`: string - The domain name or FQDN to search for in DNS queries.
    -   *Source Example:* Alert field, output from other enrichment runbooks.
-   `hours_back` (optional): integer - How many hours of historical data to search. Defaults to 72 (3 days).
-   `max_events` (optional): integer - Maximum event records to return. Defaults to 100.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `search_security_events`
2.  **Query Construction (for `text` parameter of the tool):**
    -   Base query: "DNS lookups for '{domain_name}'"
    -   Append time window: "... in the last {hours_back} hours"
    -   *Example `text` value:* "DNS lookups for 'malicious-example.com' in the last 48 hours"
3.  **Parameter Mapping:**
    -   Map constructed query to `text`.
    -   Map `hours_back` to `hours_back`.
    -   Map `max_events` to `max_events`.
4.  **Execute Tool:** Call `search_security_events`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
5.  **Data Transformation/Extraction:**
    -   Focus on `events.events` list. Extract `principal.hostname`, `principal.ip` (client resolving), `network.dns.question.name`, and `network.dns.answers.rdata` (resolved IPs).

---

## Outputs Expected

-   `dns_query_events`: list - List of UDM DNS event records.
-   `translated_udm_query`: string - The actual UDM query executed.
-   `total_events_matched`: integer.
-   `clients_resolving_domain`: list - Unique list of `principal.hostname` or `principal.ip` that queried the domain.
-   `resolved_ips_from_dns`: list - Unique list of IPs found in `network.dns.answers.rdata`.
-   `output_status`: string - ["Success", "NoEventsFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log key findings (e.g., number of clients, list of resolved IPs).
    -   For each unique IP in `resolved_ips_from_dns`, consider initiating IP-specific atomic runbooks (e.g., `RB-ATOM-IP-001`, `RB-ATOM-IP-003`).
    -   For each client in `clients_resolving_domain`, assess criticality using `asset_inventory_guidelines.md`.
    -   If many clients resolved a known malicious domain, escalate.
    -   Proceed to `rb_domain_search_network_traffic_chronicle.md` to look for actual connections to resolved IPs.
-   IF `output_status` is "NoEventsFound":
    -   Log "No DNS queries found for domain {domain_name} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to search DNS queries for domain {domain_name} in Chronicle."

---

## AI Agent Execution Notes

-   If `total_events_matched` is high, AI should summarize findings (e.g., top 5 client IPs, count of unique resolved IPs) rather than listing all events.
-   Correlate `resolved_ips_from_dns` with GTI reputation data if available.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, number of `dns_query_events` returned.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/analytical_query_patterns.md`
-   `rules-bank/ai_performance_logging_requirements.md`
