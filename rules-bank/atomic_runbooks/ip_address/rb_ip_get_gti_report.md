# Atomic Runbook: Get IP Address Reputation from GTI

**ID:** `RB-ATOM-IP-001`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a comprehensive IP address analysis report from Google Threat Intelligence (GTI) to assess its reputation.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#1-atomic-indicator-ip-address`
**Trigger:** When an IP address requires an external reputation check as part of an investigation or triage process.

---

## Inputs Required

-   `ip_address`: string - The IP address to query.
    -   *Source Example:* Alert field `source.ip`, `destination.ip`, `principal.ip`, `target.ip`; Output from another runbook.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `Google Threat Intelligence MCP`
    -   **Primary_Tool_Name:** `get_ip_address_report`
2.  **Parameter Mapping:**
    -   Map `ip_address` (Input) to MCP Tool parameter `ip_address`.
3.  **Execute Tool:** Call the `get_ip_address_report` tool with the mapped `ip_address`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for specific guidance on GTI tools.
4.  **Data Transformation/Extraction:**
    -   The primary output is a JSON object. Key fields for initial assessment are typically found under `data.attributes.last_analysis_stats` (especially `malicious`), `data.attributes.categories`, `data.attributes.as_owner`, and `data.attributes.country`.

---

## Outputs Expected

-   `gti_ip_report`: JSON - The full JSON report from the GTI `get_ip_address_report` tool.
-   `malicious_score`: integer - The number of engines reporting the IP as malicious (extracted from `gti_ip_report.data.attributes.last_analysis_stats.malicious`).
-   `harmless_score`: integer - The number of engines reporting the IP as harmless (extracted from `gti_ip_report.data.attributes.last_analysis_stats.harmless`).
-   `suspicious_score`: integer - The number of engines reporting the IP as suspicious (extracted from `gti_ip_report.data.attributes.last_analysis_stats.suspicious`).
-   `categories`: list - List of categories assigned to the IP by GTI (e.g., "malware", "phishing").
-   `as_owner`: string - The AS owner of the IP.
-   `country`: string - The country associated with the IP.
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure) - Details of the issue (e.g., "API error", "Invalid IP format").

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `malicious_score` > 5 OR "malware" IN `categories` OR "phishing" IN `categories` THEN
        -   Flag IP as "High_Risk_GTI".
        -   Consider proceeding to containment-related runbooks or escalate immediately.
    -   ELSE IF `malicious_score` > 0 OR `suspicious_score` > 0 THEN
        -   Flag IP as "Medium_Risk_GTI_Needs_Correlation".
        -   Proceed to further internal investigation runbooks (e.g., `rb_ip_lookup_entity_chronicle.md`).
    -   ELSE (low malicious/suspicious score)
        -   Flag IP as "Low_Risk_GTI".
        -   Proceed to further internal investigation runbooks.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Consider executing `rb_ip_get_secops_threat_intel.md` as an alternative.
    -   IF alternative also fails, escalate to human analyst: "Failed to retrieve external reputation for IP {ip_address}."

---

## AI Agent Execution Notes

-   Ensure the input `ip_address` is a valid IPv4 or IPv6 address.
-   If the GTI tool returns an error related to API quotas, log this and consider a retry strategy with backoff, or escalate if retries fail.
-   The AI should parse the `gti_ip_report` to extract the specific output parameters listed above.

---

## Metrics Collection Points

-   Log execution time for this runbook.
-   Log `output_status`, `malicious_score`, `harmless_score`, `suspicious_score`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/ai_performance_logging_requirements.md`
-   "Blueprint for AI Agents in Cybersecurity" (for general AI agent interaction principles)
-   "Measuring ROI of AI agents in security operations" (for context on metric importance)
