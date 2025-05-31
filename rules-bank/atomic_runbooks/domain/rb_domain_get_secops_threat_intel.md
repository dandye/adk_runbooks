# Atomic Runbook: Get Domain Threat Intel via SecOps MCP

**ID:** `RB-ATOM-DOMAIN-002`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve general threat intelligence about a domain/FQDN using the Chronicle `secops-mcp` `get_threat_intel` tool. This is often used for broader context or as an alternative if specialized tools are inconclusive.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#2-atomic-indicator-domain-name--fqdn`, `rb_domain_get_gti_report.md` (as potential next step)
**Trigger:** When a domain/FQDN requires external threat intelligence, potentially after an initial GTI check, or if narrative context is desired.

---

## Inputs Required

-   `domain_name`: string - The domain name or FQDN to query.
    -   *Source Example:* Alert field, output from other enrichment runbooks.
-   `gti_confidence` (optional): string - Confidence level from a preceding GTI check (e.g., "Low_Risk_GTI"). Used for context.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `get_threat_intel`
2.  **Parameter Mapping:**
    -   Construct a query string for the MCP Tool.
        -   `query`: "Provide threat intelligence summary for domain {domain_name}"
3.  **Execute Tool:** Call the `get_threat_intel` tool with the constructed `query`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for guidance on `get_threat_intel`.
4.  **Data Transformation/Extraction:**
    -   Output is a textual summary. AI may need to parse for keywords indicating risk.

---

## Outputs Expected

-   `secops_ti_summary`: string - The textual threat intelligence summary.
-   `identified_keywords`: list (optional) - Keywords extracted by AI (e.g., "malware distribution", "phishing site", "benign").
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `secops_ti_summary` contains keywords like "known malicious", "phishing campaign", "malware C2" THEN
        -   Flag Domain as "High_Risk_SecOpsTI".
        -   Consider proceeding to containment or escalation.
    -   ELSE IF `secops_ti_summary` contains keywords like "suspicious", "mixed reputation" OR (`gti_confidence` was "Medium_Risk_GTI_Needs_Correlation" AND summary is not explicitly benign) THEN
        -   Flag Domain as "Medium_Risk_SecOpsTI_Needs_Correlation".
        -   Proceed to `rb_domain_lookup_entity_chronicle.md`.
    -   ELSE
        -   Flag Domain as "Low_Risk_SecOpsTI" (or "Info_Only_SecOpsTI").
        -   Proceed to `rb_domain_lookup_entity_chronicle.md`.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate to human analyst: "Failed to retrieve SecOps threat intelligence for domain {domain_name}."

---

## AI Agent Execution Notes

-   AI should perform NLP on `secops_ti_summary` to extract `identified_keywords` for automated decision branching.
-   Context from previous checks (like `gti_confidence`) should inform interpretation of this tool's output.

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
