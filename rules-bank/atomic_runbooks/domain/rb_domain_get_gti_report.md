# Atomic Runbook: Get Domain Reputation from GTI

**ID:** `RB-ATOM-DOMAIN-001`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a comprehensive domain analysis report from Google Threat Intelligence (GTI) to assess its reputation, resolution history, and categorization.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#2-atomic-indicator-domain-name--fqdn`
**Trigger:** When a domain name or FQDN requires an external reputation check as part of an investigation or triage process.

---

## Inputs Required

-   `domain_name`: string - The domain name or FQDN to query.
    -   *Source Example:* Alert field `target.hostname`, `network.dns.question.name`; IOC lists; Output from another runbook.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `Google Threat Intelligence MCP`
    -   **Primary_Tool_Name:** `get_domain_report`
2.  **Parameter Mapping:**
    -   Map `domain_name` (Input) to MCP Tool parameter `domain`.
3.  **Execute Tool:** Call the `get_domain_report` tool with the mapped `domain_name`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for specific guidance on GTI tools.
4.  **Data Transformation/Extraction:**
    -   The primary output is a JSON object. Key fields for initial assessment include `data.attributes.last_analysis_stats` (especially `malicious`), `data.attributes.categories`, `data.attributes.whois`, and `data.attributes.resolutions`.

---

## Outputs Expected

-   `gti_domain_report`: JSON - The full JSON report from the GTI `get_domain_report` tool.
-   `malicious_score`: integer - The number of engines reporting the domain as malicious (extracted from `gti_domain_report.data.attributes.last_analysis_stats.malicious`).
-   `harmless_score`: integer - The number of engines reporting the domain as harmless.
-   `suspicious_score`: integer - The number of engines reporting the domain as suspicious.
-   `categories`: list - List of categories assigned to the domain by GTI (e.g., "malware", "phishing", "benign").
-   `resolutions`: list - List of IP addresses the domain has resolved to historically.
-   `whois_registrar`: string (optional) - Registrar from WHOIS data.
-   `whois_creation_date`: string/timestamp (optional) - Creation date from WHOIS.
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure) - Details of the issue (e.g., "API error", "Invalid domain format").

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `malicious_score` > 5 OR "malware" IN `categories` OR "phishing" IN `categories` THEN
        -   Flag Domain as "High_Risk_GTI".
        -   For each IP in `resolutions`, consider initiating `RB-ATOM-IP-001` (Get IP Reputation From GTI).
        -   Consider proceeding to containment-related runbooks or escalate immediately.
    -   ELSE IF `malicious_score` > 0 OR `suspicious_score` > 0 THEN
        -   Flag Domain as "Medium_Risk_GTI_Needs_Correlation".
        -   Proceed to `rb_domain_lookup_entity_chronicle.md` and for each IP in `resolutions`, consider `RB-ATOM-IP-001`.
    -   ELSE (low malicious/suspicious score)
        -   Flag Domain as "Low_Risk_GTI".
        -   Proceed to `rb_domain_lookup_entity_chronicle.md`.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Consider executing `rb_domain_get_secops_threat_intel.md` as an alternative.
    -   IF alternative also fails, escalate to human analyst: "Failed to retrieve external reputation for domain {domain_name}."

---

## AI Agent Execution Notes

-   Ensure the input `domain_name` is a valid domain/FQDN.
-   The AI should parse the `gti_domain_report` to extract the specific output parameters.
-   Pay attention to recently registered domains (`whois_creation_date`) combined with malicious indicators, as this can be a sign of a new threat campaign.

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
