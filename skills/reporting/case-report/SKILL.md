---
name: case-report
description: Use when drafting detailed case closure reports, root cause analysis,
  and impact summaries.
category: reporting
version: 1.0.0
type: Skill
title: 'Skill: Generate Case Investigation Report'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
---

# Runbook: Generate Case Investigation Report

## Objective

To consolidate findings from a completed or ongoing investigation for a specific SOAR case into a comprehensive Markdown report. This report is suitable for stakeholder communication, post-incident reviews, or general documentation of investigation activities.

## Scope

This runbook covers:
*   Gathering existing data for a specified SOAR case, including alerts, comments, and event summaries.
*   Synthesizing findings from the investigation.
*   Structuring the report according to a standard template, including an executive summary, timeline, entity analysis, root cause (if known), actions taken, and recommendations.
*   Generating a Mermaid sequence diagram summarizing the investigation workflow.
*   Formatting and writing the final Markdown report to a file.
*   Optionally, updating the SOAR case with a comment indicating the report's generation and location.

This runbook explicitly **excludes**:
*   Performing new investigation steps (it reports on existing or recently concluded investigations).
*   Deep forensic analysis or malware reverse engineering (these would be inputs if performed).
*   Executing containment or remediation actions.

## Inputs

*   `${CASE_ID}`: The SOAR case ID for which the report is being generated.
*   *(Optional) `${REPORT_FILENAME_SUFFIX}`: A suffix for the report filename (defaults to `${CASE_ID}` if not provided).
*   *(Optional) `${ADDITIONAL_CONTEXT}`: Any specific points, findings, or pre-synthesized summaries the analyst wants to ensure are included in the report.
*   *(Derived) `${INVESTIGATION_WORKFLOW_SUMMARY}`: A summary of the tools and steps taken during the investigation, used to generate the Mermaid diagram.*

## Outputs

*   `${REPORT_FILE_PATH}`: The full path to the generated Markdown report file.
*   `${REPORT_CONTENT}`: The full Markdown content of the generated report.
*   `${SOAR_UPDATE_STATUS}`: (Optional) Status of the attempt to post a comment to the SOAR case.

## Tools

*   `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment` (Potentially others depending on what needs summarizing from the case)
*   `secops-mcp`: `lookup_entity`, `search_security_events` (If summarizing previous searches performed during the investigation)
*   `gti-mcp`: Various `get_*_report` tools (If summarizing previous enrichment performed during the investigation)
*   `write_to_file` (Replaces the conceptual `write_report` tool)

## Workflow Steps & Diagram

1.  **Gather Case Data:** Retrieve all relevant data for `${CASE_ID}` using `get_case_full_details` (includes basic case info, alerts, comments). Potentially re-run `list_events_by_alert` for key alerts if needed.
2.  **Synthesize Findings:** Review case comments, alert details, event summaries, and previous enrichment data associated with the case.
3.  **Structure Report:** Organize the information according to a standard template (referencing `rules-bank/reporting_templates.md`). Key sections might include: Executive Summary, Timeline of Key Events, Involved Entities & Enrichment, Analysis/Root Cause (if determined), Actions Taken, Recommendations/Lessons Learned.
4.  **Generate Mermaid Diagram:** Create a Mermaid sequence diagram summarizing the *investigation workflow* that was performed for this case (which tools were used in what order).
5.  **Format Report:** Compile the synthesized information and the Mermaid diagram into a final Markdown report.
6.  **Write Report File:** Save the report using `write_to_file` with a standardized name (e.g., `./reports/case_report_${CASE_ID}_${timestamp}.md`).
7.  **(Optional) Update Case:** Add a comment to the SOAR case indicating the report has been generated and its location using `post_case_comment`.

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_case_report_payload_node["1. extract_case_report_payload_node<br/><i>(Extract Case Payload)</i>"]
    extract_case_report_payload_node --> fetch_full_case_details_node["2. fetch_full_case_details_node<br/><i>(Fetch Full Case Details & Priority)</i>"]
    fetch_full_case_details_node --> case_report_type_router{"3. case_report_type_router<br/><i>(Event.actions.route)</i>"}

    case_report_type_router -- "EXECUTIVE_CASE_REPORT" --> handle_executive_case_report_branch["4a. handle_executive_case_report_branch<br/><i>(Generate Executive Case Report)</i>"]
    case_report_type_router -- "STANDARD_CASE_REPORT" --> handle_standard_case_report_branch["4b. handle_standard_case_report_branch<br/><i>(Generate Standard Case Report)</i>"]

    handle_executive_case_report_branch --> document_case_report_node["5. document_case_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_standard_case_report_branch --> document_case_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp %% Example servers used during investigation
    participant GTI as gti-mcp  %% Example servers used during investigation

    Analyst/User->>AutomatedAgent: Generate Case Report\nInput: CASE_ID, ...

    %% Step 1: Gather Case Data
    AutomatedAgent->>SOAR: get_case_full_details(case_id=CASE_ID)
    SOAR-->>AutomatedAgent: Case Details, Alerts, Comments
    %% Potentially re-run list_events_by_alert if needed

    %% Step 2: Synthesize Findings
    Note over AutomatedAgent: Review all gathered data (comments, events, enrichment from investigation)

    %% Step 3 & 4: Structure Report & Generate Diagram
    Note over AutomatedAgent: Organize report sections (Exec Summary, Timeline, Entities, Analysis, Actions...)
    Note over AutomatedAgent: Create Mermaid diagram summarizing investigation steps

    %% Step 5 & 6: Format & Write Report
    Note over AutomatedAgent: Compile final Markdown content (ReportMarkdown)
    AutomatedAgent->>AutomatedAgent: write_to_file(path="./reports/case_report_${CASE_ID}_${timestamp}.md", content=ReportMarkdown)
    Note over AutomatedAgent: Report file created

    %% Step 7: Optional SOAR Update
    opt Update SOAR Case
        AutomatedAgent->>SOAR: post_case_comment(case_id=CASE_ID, comment="Case report generated: case_report_....md")
        SOAR-->>AutomatedAgent: Comment Confirmation
    end

    AutomatedAgent->>Analyst/User: attempt_completion(result="Case investigation report generated for Case CASE_ID.")

```

## Completion Criteria

*   Relevant data for the specified SOAR case (`${CASE_ID}`) has been gathered and synthesized.
*   The investigation workflow has been summarized in a Mermaid diagram.
*   A comprehensive Markdown report, structured according to standard templates, has been formatted.
*   The final report has been successfully written to a file (`${REPORT_FILE_PATH}`).
*   (Optional) The SOAR case has been updated with a comment indicating the report's generation and location, and the `${SOAR_UPDATE_STATUS}` is available.

## Rubrics

The following rubric is used to evaluate the execution of this **Reporting** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Data Collection** | 25 | Gathered all necessary data points and metrics for the report. |
| **Report Generation** | 30 | Generated the report in the correct format with accurate content. |
| **Quality & Clarity** | 15 | Ensure the report is readable, well-structured, and error-free. |
| **Delivery** | 15 | Delivered or saved the report to the correct location/recipient. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Data Collection (25 Points)
- **25 pts**: Successfully retrieved all required data (alerts, stats, summaries) from sources.

#### 2. Report Generation (30 Points)
- **15 pts**: Formatted the data correctly into the target template (Markdown, PDF, etc.).
- **15 pts**: Included all required sections (Executive Summary, Details, etc.).

#### 3. Quality & Clarity (15 Points)
- **15 pts**: The generated text is coherent, accurate, and professional.

#### 4. Delivery (15 Points)
- **15 pts**: Successfully saved the file or sent the notification/email as required.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
