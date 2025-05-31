# Atomic Runbook: Get File Hash Reputation from GTI

**ID:** `RB-ATOM-HASH-001`
**Version:** 1.0
**Last_Updated:** 2025-05-30
**Purpose:** To retrieve a comprehensive file analysis report from Google Threat Intelligence (GTI) for a given file hash (MD5, SHA1, or SHA256) to assess its reputation and known characteristics.
**Parent_Runbook(s)/Protocol(s):** `rules-bank/indicator_handling_protocols.md#3-atomic-indicator-file-hash`
**Trigger:** When a file hash requires an external reputation check as part of an investigation, malware analysis, or alert triage.

---

## Inputs Required

-   `file_hash`: string - The file hash (MD5, SHA1, or SHA256) to query.
    -   *Source Example:* Alert field `target.file.sha256`, EDR detection data, output from malware analysis sandbox.
-   `hash_type` (optional): string - Specify "MD5", "SHA1", or "SHA256" if known. GTI can often auto-detect.
    -   *Source Example:* Derived from context or tool output.

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `Google Threat Intelligence MCP`
    -   **Primary_Tool_Name:** `get_file_report`
2.  **Parameter Mapping:**
    -   Map `file_hash` (Input) to MCP Tool parameter `hash`.
3.  **Execute Tool:** Call the `get_file_report` tool with the mapped `hash`.
    -   *AI Agent Note:* Refer to `rules-bank/mcp_tool_best_practices.md` for specific guidance on GTI tools.
4.  **Data Transformation/Extraction:**
    -   The primary output is a JSON object. Key fields for assessment include `data.attributes.last_analysis_stats` (especially `malicious`), `data.attributes.popular_threat_classification`, `data.attributes.tags`, `data.attributes.meaningful_name`.

---

## Outputs Expected

-   `gti_file_report`: JSON - The full JSON report from the GTI `get_file_report` tool.
-   `malicious_score`: integer - Engines reporting as malicious (from `gti_file_report.data.attributes.last_analysis_stats.malicious`).
-   `suspicious_score`: integer - Engines reporting as suspicious.
-   `harmless_score`: integer - Engines reporting as harmless.
-   `threat_classification`: string (optional) - From `gti_file_report.data.attributes.popular_threat_classification.suggested_threat_label`.
-   `tags`: list - From `gti_file_report.data.attributes.tags`.
-   `meaningful_name`: string (optional) - From `gti_file_report.data.attributes.meaningful_name`.
-   `output_status`: string - ["Success", "Failure", "NotFound"]
    -   "NotFound" if GTI has no information on the hash.
-   `output_message`: string (if Failure) - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success":
    -   IF `malicious_score` > 5 OR `threat_classification` indicates a significant threat (e.g., "ransomware", "trojan") THEN
        -   Flag File Hash as "High_Risk_GTI".
        -   Proceed to `rb_hash_lookup_entity_chronicle.md` to check for internal sightings.
        -   Consider immediate escalation or containment playbook initiation.
    -   ELSE IF `malicious_score` > 0 OR `suspicious_score` > 0 OR `threat_classification` is "PUA" (Potentially Unwanted Application) THEN
        -   Flag File Hash as "Medium_Risk_GTI_Needs_Correlation".
        -   Proceed to `rb_hash_lookup_entity_chronicle.md`.
    -   ELSE (low malicious/suspicious score, no concerning classification)
        -   Flag File Hash as "Low_Risk_GTI".
        -   Proceed to `rb_hash_lookup_entity_chronicle.md` for due diligence.
-   IF `output_status` is "NotFound":
    -   Log "File hash {file_hash} not found in GTI."
    -   Flag File Hash as "Unknown_Reputation_GTI".
    -   Proceed to `rb_hash_lookup_entity_chronicle.md` and consider dynamic analysis if seen internally.
-   ELSE (`output_status` is "Failure"):
    -   Log error: `output_message`.
    -   Consider executing `rb_hash_get_secops_threat_intel.md` as an alternative.
    -   IF alternative also fails, escalate: "Failed to retrieve external reputation for file hash {file_hash}."

---

## AI Agent Execution Notes

-   The AI should parse the `gti_file_report` to extract the specific output parameters.
-   If `hash_type` is not provided, GTI usually auto-detects. If errors occur, prompting for hash type might be a fallback.

---

## Metrics Collection Points

-   Log execution time.
-   Log `output_status`, `malicious_score`.
-   (Reference `rules-bank/ai_performance_logging_requirements.md`)

---

## References

-   `rules-bank/mcp_tool_best_practices.md`
-   `rules-bank/indicator_handling_protocols.md`
-   `rules-bank/ai_performance_logging_requirements.md`
