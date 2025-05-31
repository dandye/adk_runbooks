# Atomic Runbook: Get IP Address Threat Intel via SecOps MCP

**ID:** `RB-ATOM-IP-002`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve general threat intelligence about an IP address using the Chronicle `secops-mcp` `get_threat_intel` tool, often as a secondary check or when more narrative context is needed.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#1-atomic-indicator-ip-address`, `rb_ip_get_gti_report.md` (as potential next step)
**Trigger:** When an IP address requires external reputation/threat intelligence, potentially after an initial check with a more specialized tool like GTI, or if broader textual context is desired.

---

## Inputs Required

-   `ip_address`: string - The IP address to query.
    -   *Source Example:* Alert field, output from `rb_ip_get_gti_report.md` if further context is needed.
-   `gti_confidence` (optional): string - Confidence level from a preceding GTI check (e.g., "Low_Risk_GTI", "Medium_Risk_GTI_Needs_Correlation"). Used for context.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `get_threat_intel`
2.  **Parameter Mapping:**
    -   Map `ip_address` (Input) to the query for the MCP Tool. Construct a query string.
        -   `query`: "Provide threat intelligence summary for IP address {ip_address}"
3.  **Execute Tool:** Call the `get_threat_intel` tool with the constructed `query`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for specific guidance on `get_threat_intel`.
4.  **Data Transformation/Extraction:**
    -   The output is a textual summary. The AI agent will need to parse this text for keywords indicating risk or specific threat types if further automated decision-making is required based on this output.

---

## Outputs Expected

-   `secops_ti_summary`: string - The textual threat intelligence summary provided by the `get_threat_intel` tool.
-   `identified_keywords`: list (optional) - List of keywords extracted by AI from the summary (e.g., "malware", "C2", "benign", "scanning activity").
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `secops_ti_summary` contains keywords like "known malicious", "C2 server", "high confidence threat" THEN
        -   Flag IP as "High_Risk_SecOpsTI".
        -   Consider proceeding to containment-related runbooks or escalate immediately.
    -   ELSE IF `secops_ti_summary` contains keywords like "potentially unwanted", "suspicious activity", "mixed reputation" OR (`gti_confidence` was "Medium_Risk_GTI_Needs_Correlation" AND summary is not explicitly benign) THEN
        -   Flag IP as "Medium_Risk_SecOpsTI_Needs_Correlation".
        -   Proceed to further internal investigation runbooks (e.g., `rb_ip_lookup_entity_chronicle.md`).
    -   ELSE (summary suggests benign or no specific threat information)
        -   Flag IP as "Low_Risk_SecOpsTI" (or "Info_Only_SecOpsTI").
        -   Proceed to further internal investigation runbooks.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate to human analyst: "Failed to retrieve SecOps threat intelligence for IP {ip_address}."

---

## AI Agent Execution Notes

-   The AI agent should be prepared to perform basic Natural Language Processing (NLP) on the `secops_ti_summary` to extract `identified_keywords` if this output is to be used for further automated branching.
-   If this runbook is triggered due to a failure or inconclusive result from `rb_ip_get_gti_report.md`, that context should be logged.

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
-   "Blueprint for AI Agents in Cybersecurity"
-   "Measuring ROI of AI agents in security operations"
