# Atomic Runbook: Get URL Threat Intel via SecOps MCP

**ID:** `RB-ATOM-URL-002`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve general threat intelligence about a URL using the Chronicle `secops-mcp` `get_threat_intel` tool. This is often used for broader context or as an alternative if specialized URL analysis tools are inconclusive.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#url-indicator`, `rb_url_get_gti_report.md` (as potential next step)
**Trigger:** When a URL requires external threat intelligence, possibly after a GTI check, or if narrative context is desired.

---

## Inputs Required

-   `url`: string - The URL to query.
    -   *Source Example:* Alert data, output from other tools.
-   `gti_confidence` (optional): string - Confidence from a preceding GTI check (e.g., "Unknown_Reputation_GTI").

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `get_threat_intel`
2.  **Parameter Mapping:**
    -   Construct query: `query`: "Provide threat intelligence summary for URL {url}"
3.  **Execute Tool:** Call `get_threat_intel` with the `query`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
4.  **Data Transformation/Extraction:**
    -   Output is textual. AI may parse for keywords.

---

## Outputs Expected

-   `secops_ti_summary`: string - Textual threat intelligence summary.
-   `identified_keywords`: list (optional) - Keywords extracted by AI (e.g., "phishing link", "malware download", "benign redirect").
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `secops_ti_summary` contains "known malicious URL", "phishing page", "drive-by download" THEN
        -   Flag URL as "High_Risk_SecOpsTI".
        -   Consider proceeding to containment or escalation.
    -   ELSE IF `secops_ti_summary` contains "suspicious redirect", "adware-related", "potential risk" OR (`gti_confidence` was "Unknown_Reputation_GTI" AND summary is not explicitly benign) THEN
        -   Flag URL as "Medium_Risk_SecOpsTI_Needs_Correlation".
        -   Proceed to `rb_url_search_chronicle.md`.
    -   ELSE
        -   Flag URL as "Low_Risk_SecOpsTI" (or "Info_Only_SecOpsTI").
        -   Proceed to `rb_url_search_chronicle.md`.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to retrieve SecOps threat intelligence for URL {url}."

---

## AI Agent Execution Notes

-   AI should perform NLP on `secops_ti_summary` for `identified_keywords`.
-   Context from `gti_confidence` should inform interpretation.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md` (future URL section)
-   `rules-bank/ai_performance_logging_requirements.md`
