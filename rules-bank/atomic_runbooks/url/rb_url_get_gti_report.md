# Atomic Runbook: Get URL Reputation from GTI

**ID:** `RB-ATOM-URL-001`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a comprehensive URL analysis report from Google Threat Intelligence (GTI) to assess its reputation, categorization, and any associated threats.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#url-indicator` (Assuming a future section for URLs)
**Trigger:** When a URL requires an external reputation check as part of an investigation (e.g., from a phishing email, web proxy logs, or EDR alert).

---

## Inputs Required

-   `url`: string - The full URL to query (e.g., `http://example.com/path/to/file.html`).
    -   *Source Example:* Alert field `target.url`, email body, web proxy logs.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `Google Threat Intelligence MCP`
    -   **Primary_Tool_Name:** `get_url_report`
2.  **Parameter Mapping:**
    -   Map `url` (Input) to MCP Tool parameter `url`.
3.  **Execute Tool:** Call the `get_url_report` tool with the mapped `url`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for specific guidance on GTI tools. Ensure URL is properly encoded if necessary, though the tool should handle standard cases.
4.  **Data Transformation/Extraction:**
    -   The primary output is a JSON object. Key fields for assessment include `data.attributes.last_analysis_stats` (especially `malicious`), `data.attributes.categories`, `data.attributes.final_url` (after redirections), and `data.attributes.redirection_chain`.

---

## Outputs Expected

-   `gti_url_report`: JSON - The full JSON report from the GTI `get_url_report` tool.
-   `malicious_score`: integer - Engines reporting the URL as malicious (from `gti_url_report.data.attributes.last_analysis_stats.malicious`).
-   `suspicious_score`: integer - Engines reporting as suspicious.
-   `harmless_score`: integer - Engines reporting as harmless.
-   `categories`: list - List of categories assigned to the URL by GTI (e.g., "phishing", "malware", "benign").
-   `final_url`: string (optional) - The final URL after any redirections.
-   `redirection_chain`: list (optional) - List of URLs in a redirection chain.
-   `output_status`: string - ["Success", "Failure", "NotFound"]
    -   "NotFound" if GTI has no information on the URL.
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `malicious_score` > 5 OR "phishing" IN `categories` OR "malware" IN `categories` THEN
        -   Flag URL as "High_Risk_GTI".
        -   Extract domain from `url` (or `final_url`) and consider initiating `RB-ATOM-DOMAIN-001` (Get Domain Reputation From GTI).
        -   Consider proceeding to containment (e.g., block URL/domain) or escalate immediately.
    -   ELSE IF `malicious_score` > 0 OR `suspicious_score` > 0 THEN
        -   Flag URL as "Medium_Risk_GTI_Needs_Correlation".
        -   Extract domain and proceed to `rb_url_search_chronicle.md` and domain-specific runbooks.
    -   ELSE (low malicious/suspicious score)
        -   Flag URL as "Low_Risk_GTI".
        -   Proceed to `rb_url_search_chronicle.md` for internal context.
-   IF `output_status` is "NotFound":
    -   Log "URL {url} not found in GTI."
    -   Flag URL as "Unknown_Reputation_GTI".
    -   Extract domain and proceed with domain reputation checks (`RB-ATOM-DOMAIN-001`) and internal searches (`rb_url_search_chronicle.md`).
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Consider executing `rb_url_get_secops_threat_intel.md` as an alternative.
    -   IF alternative also fails, escalate: "Failed to retrieve external reputation for URL {url}."

---

## AI Agent Execution Notes

-   The AI should parse the `gti_url_report` to extract specific output parameters.
-   If a `final_url` is present and different from the input `url`, the AI should note this and potentially perform checks on the `final_url` as well.
-   The domain of the URL should be extracted for separate domain reputation checks.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, `malicious_score`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future URL section)
-   `rules-bank/ai_performance_logging_requirements.md`
