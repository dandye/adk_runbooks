# Atomic Runbook: Lookup Domain Entity Activity in Chronicle

**ID:** `RB-ATOM-DOMAIN-003`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a summary of a domain/FQDN's activity from Chronicle SIEM using the `lookup_entity` tool. This provides a quick overview of internal interactions (e.g., DNS queries, connections to resolved IPs), related alerts, and first/last seen times.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#2-atomic-indicator-domain-name--fqdn`
**Trigger:** When a domain/FQDN requires an initial check for internal activity within Chronicle, often after external reputation checks.

---

## Inputs Required

-   `domain_name`: string - The domain name or FQDN to look up.
    -   *Source Example:* Alert field, output from `rb_domain_get_gti_report.md`.
-   `hours_back` (optional): integer - How many hours of historical data to consider. Defaults to 24.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `lookup_entity`
2.  **Parameter Mapping:**
    -   Map `domain_name` (Input) to MCP Tool parameter `entity_value`.
    -   Map `hours_back` (Input or default) to MCP Tool parameter `hours_back`.
3.  **Execute Tool:** Call `lookup_entity`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
4.  **Data Transformation/Extraction:**
    -   Output is textual. AI may parse for specific details (related alerts, IPs).

---

## Outputs Expected

-   `chronicle_entity_summary`: string - Textual summary from `lookup_entity`.
-   `related_alerts_count` (optional, if parsable): integer.
-   `resolved_ips_in_summary` (optional, if parsable): list - IPs mentioned in the summary.
-   `output_status`: string - ["Success", "NoInfoFound", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   Log `chronicle_entity_summary`.
    -   IF `related_alerts_count` > 0 OR summary indicates significant DNS queries/connections THEN
        -   Flag Domain for "Further Internal Investigation - High Activity".
        -   Proceed to `rb_domain_search_dns_chronicle.md` and/or `rb_domain_search_network_traffic_chronicle.md`.
        -   For each IP in `resolved_ips_in_summary`, consider initiating IP-specific atomic runbooks (e.g., `RB-ATOM-IP-003`, `RB-ATOM-IP-004`).
    -   ELSE
        -   Flag Domain as "Low Internal Activity Observed".
-   IF `output_status` is "NoInfoFound":
    -   Log "No activity found for domain {domain_name} in Chronicle for the last {hours_back} hours."
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to lookup domain {domain_name} in Chronicle."

---

## AI Agent Execution Notes

-   Default `hours_back` is 24. Adjust for broader context.
-   AI parsing `chronicle_entity_summary` should look for "DNS Queries:", "Resolutions:", "Related Alerts:", "Related Entities:".

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
