# Atomic Runbook: [Clear, Verb-Oriented Title - e.g., Get_IP_Reputation_From_GTI]

**ID:** `RB-ATOM-[UniqueSequentialID]` (e.g., RB-ATOM-001)
**Version:** 1.0
**Last_Updated:** YYYY-MM-DD
**Purpose:** [Brief description of the single task this runbook accomplishes.]
**Parent_Runbook(s)/Protocol(s):** [Links to broader runbooks or protocols this atomic step is part of, e.g., `indicator_handling_protocols.md#ip-address`, `enrich_ioc.md`]
**Trigger:** [When should this atomic runbook be executed? e.g., "When an IP address needs external reputation check."]

---

## Inputs Required

-   `input_parameter_1_name`: [Data Type] - [Description, e.g., `ip_address`: string - The IP address to query.]
    -   *Source Example:* [e.g., From Alert Field `source.ip`, From previous runbook `RB-ATOM-XXX` output `target_ip`]
-   `input_parameter_2_name` (optional): [Data Type] - [Description]

---

## Execution Steps

1.  **Tool Selection:**
    -   **Primary_Tool_MCP_Server:** `[e.g., Google Threat Intelligence MCP]`
    -   **Primary_Tool_Name:** `[e.g., get_ip_address_report]`
    -   **Alternative_Tool_MCP_Server (if applicable):**
    -   **Alternative_Tool_Name (if applicable):**
2.  **Parameter Mapping:**
    -   Map `input_parameter_1_name` to MCP Tool parameter `[tool_param_name]`.
3.  **Execute Tool:** Call the selected MCP tool with mapped parameters.
    -   *AI Agent Note:* Refer to `mcp_tool_best_practices.md` for specific guidance on this tool.
    -   *AI Agent Note:* Check `tool_rate_limits.md` before execution if applicable.
4.  **(Optional) Data Transformation/Extraction:**
    -   [If necessary, describe how to extract specific fields from the tool's raw output.]
    -   [Reference `data_normalization_map.md` if applicable.]

---

## Outputs Expected

-   `output_parameter_1_name`: [Data Type] - [Description, e.g., `gti_ip_report_summary`: JSON - Summary of GTI findings.]
    -   *Key_Fields_Within_Output (example for JSON):* `last_analysis_stats.malicious`, `categories`, `as_owner`
-   `output_status`: [string] - ["Success", "Failure", "Partial_Success_Needs_Review"]
-   `output_message` (if Failure/Partial): [string] - Details of the issue.

---

## Decision Logic / Next Steps (If Applicable)

-   IF `output_status` is "Success" AND `output_parameter_1_name.last_analysis_stats.malicious` > 5 THEN
    -   Proceed to `[Next_Atomic_Runbook_ID_For_Malicious]` OR Flag as "High_Risk_IP".
-   ELSE IF `output_status` is "Success" THEN
    -   Proceed to `[Next_Atomic_Runbook_ID_For_Benign_Or_Unknown]` OR Flag as "Low_Risk_IP".
-   ELSE (`output_status` is "Failure")
    -   Log error from `output_message`.
    -   Attempt `Alternative_Tool_Name` if defined.
    -   ELSE Escalate to human analyst as per `[Escalation_Procedure_ID_or_Document]`.

---

## AI Agent Execution Notes

-   [Specific notes for AI on how to interpret inputs/outputs, handle common errors for this specific task, or when to deviate/escalate.]

---

## Metrics Collection Points

-   Log execution time for this atomic runbook.
-   Log `output_status` and any error messages.
-   (Reference `ai_performance_logging_requirements.md`)

---

## References

-   [Link to relevant sections in `mcp_tool_best_practices.md`, `data_normalization_map.md`, etc.]
-   [Link to source articles if a specific technique is from them, e.g., "Blueprint for AI Agents in Cybersecurity" if discussing general AI agent interaction.]
