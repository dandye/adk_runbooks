# Atomic Runbook: Get File Hash Threat Intel via SecOps MCP

**ID:** `RB-ATOM-HASH-002`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve general threat intelligence about a file hash using the Chronicle `secops-mcp` `get_threat_intel` tool. This serves as a supplementary check for narrative context or an alternative if specialized tools yield no results.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#3-atomic-indicator-file-hash`, `rb_hash_get_gti_report.md` (as potential next step)
**Trigger:** When a file hash requires external threat intelligence, possibly after a GTI check, or if broader textual context is needed.

---

## Inputs Required

-   `file_hash`: string - The file hash (MD5, SHA1, or SHA256) to query.
    -   *Source Example:* Alert data, output from other tools.
-   `gti_confidence` (optional): string - Confidence from a preceding GTI check (e.g., "Unknown_Reputation_GTI").

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `secops-mcp`
    -   **Primary_Tool_Name:** `get_threat_intel`
2.  **Parameter Mapping:**
    -   Construct query: `query`: "Provide threat intelligence summary for file hash {file_hash}"
3.  **Execute Tool:** Call `get_threat_intel` with the `query`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md`.
4.  **Data Transformation/Extraction:**
    -   Output is textual. AI may parse for keywords.

---

## Outputs Expected

-   `secops_ti_summary`: string - Textual threat intelligence summary.
-   `identified_keywords`: list (optional) - Keywords extracted by AI (e.g., "malware", "dropper", "benign utility").
-   `output_status`: string - ["Success", "Failure"]
-   `output_message`: string (if Failure).

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `secops_ti_summary` contains "known malicious", "malware family", "trojan" THEN
        -   Flag Hash as "High_Risk_SecOpsTI".
        -   Proceed to `rb_hash_lookup_entity_chronicle.md`.
    -   ELSE IF `secops_ti_summary` contains "suspicious", "hacktool", "PUA" OR (`gti_confidence` was "Unknown_Reputation_GTI" AND summary is not explicitly benign) THEN
        -   Flag Hash as "Medium_Risk_SecOpsTI_Needs_Correlation".
        -   Proceed to `rb_hash_lookup_entity_chronicle.md`.
    -   ELSE
        -   Flag Hash as "Low_Risk_SecOpsTI" (or "Info_Only_SecOpsTI").
        -   Proceed to `rb_hash_lookup_entity_chronicle.md`.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Escalate: "Failed to retrieve SecOps threat intelligence for file hash {file_hash}."

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
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/ai_performance_logging_requirements.md`
