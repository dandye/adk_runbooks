# Runbook: Report Writing Guidelines & Template

## Objective

To provide general guidelines and a basic template structure for writing consistent and informative security reports generated from runbook executions or ad-hoc investigations.

## Scope

These guidelines apply to various report types (e.g., investigation summaries, threat hunt reports, triage reports) generated within this security environment. Specific content requirements may vary based on the report type (refer to `rules-bank/reporting_templates.md`).

## Inputs

*   `${FINDINGS}`: The synthesized data, analysis, and conclusions from the investigation/hunt.
*   `${RUNBOOK_NAME}`: The name of the runbook used (if applicable).
*   `${CASE_ID}`: Relevant SOAR Case ID(s).
*   `${MERMAID_DIAGRAM}`: The Mermaid sequence diagram illustrating the workflow performed.

## Tools

*   `write_report`: To save the final report.
*   *(Tools used to gather `${FINDINGS}`)*

## Workflow Steps & Diagram (Conceptual - For Writing the Report)

1.  **Gather Information:** Collect all necessary findings, analysis, context, runbook name, case ID, and the generated Mermaid diagram.
2.  **Structure Report:** Organize the information logically. Start with metadata, followed by a summary/executive summary, detailed findings, analysis, conclusions, and recommendations. Refer to `rules-bank/reporting_templates.md` for specific section requirements based on report type.
3.  **Incorporate Metadata:** Ensure the report includes:
    *   `**Runbook Used:** ${RUNBOOK_NAME}` (If applicable)
    *   **Timestamp:** Generation time (e.g., YYYY-MM-DD HH:MM Timezone)
    *   **Case ID(s):** `${CASE_ID}`
    *   **Workflow Diagram:** Embed the `${MERMAID_DIAGRAM}`.
4.  **Write Content:** Clearly articulate findings, analysis, and conclusions. Use consistent terminology. Include links back to relevant tools/platforms where appropriate (e.g., links to SOAR cases, GTI reports).
5.  **Review & Refine:** Proofread the report for clarity, accuracy, and completeness. Let the final content be `${FinalReportContent}`.
6.  **Save Report:** Use `write_report` with `report_name="<report_type>_<report_name_suffix>_${CASE_ID}_${timestamp}.md"` and `report_contents=${FinalReportContent}`. (Ensure variables like `${CASE_ID}` and `${timestamp}` are resolved before the call).

Reports should include which agents called which MCP tools

**Agent Workflow Diagram:**

```{mermaid}
sequenceDiagram
    participant User
    participant Manager
    participant Tier2 as soc_analyst_tier2
    participant SOAR

    User->>Manager: research soar case 2396 and then write a report on what you find
    Manager->>Tier2: research soar case 2396 and then write a report on what you find
    Tier2->>SOAR: get_case_full_details(case_id="2396")
    SOAR-->>Tier2: Case Details
    Tier2->>Manager: Report on SOAR Case 2396 with Recommendations
    Manager->>User: Report on SOAR Case 2396 with Recommendations
    User->>Manager: update the report to include a mermaid sequence diagram for which agents called which mcp tools
    ...
```

## Completion Criteria

Report is written, reviewed, and saved in the standard format and location.
