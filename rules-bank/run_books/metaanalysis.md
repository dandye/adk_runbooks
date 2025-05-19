# Runbook: Meta-Analysis (Placeholder)

## Objective

*(Define the goal, e.g., To analyze trends, patterns, or correlations across multiple incidents, alerts, or hunts over a defined period to identify broader security issues, detection gaps, or recurring threats.)*

## Scope

*(Define what is included/excluded, e.g., Focuses on analyzing aggregated data from SIEM, SOAR, and potentially other sources. Excludes deep investigation of individual events unless relevant to the identified pattern.)*

## Inputs

*   `${ANALYSIS_TIMEFRAME_DAYS}`: Lookback period for the analysis (e.g., 90, 180).
*   `${ANALYSIS_FOCUS}`: The specific area of focus (e.g., "Recurring False Positives for Rule X", "Common Malware Families Observed", "Lateral Movement Patterns", "Effectiveness of Phishing Response").
*   *(Optional) `${DATA_SOURCES}`: Specific SIEM queries, SOAR case filters, or other data sources to use.*

## Tools

*   `secops-soar`: `list_cases`, `get_case_full_details` (for analyzing case data)
*   `secops-mcp`: `search_security_events`, `get_security_alerts` (for analyzing event/alert data)
*   `bigquery`: `execute-query` (if analyzing data lake information)
*   `write_report` (for report generation)
*   *(Potentially other tools for data aggregation or visualization if available)*

## Workflow Steps & Diagram

1.  **Define Scope & Objective:** Clearly define the `${ANALYSIS_FOCUS}` and `${ANALYSIS_TIMEFRAME_DAYS}`. Identify necessary `${DATA_SOURCES}`.
2.  **Data Collection:** Gather relevant data using specified tools (e.g., export case details, run broad SIEM/BigQuery queries).
3.  **Data Aggregation & Analysis:** Aggregate the collected data. Analyze for trends, patterns, outliers, and correlations related to the `${ANALYSIS_FOCUS}`.
4.  **Synthesize Findings:** Summarize the key findings and insights derived from the analysis.
5.  **Develop Recommendations:** Based on the findings, formulate actionable recommendations (e.g., tune specific detection rules, update runbooks, implement new security controls, focus threat hunting efforts).
6.  **Generate Report:** Create a comprehensive report detailing the analysis objective, methodology, data sources, findings, and recommendations using `write_report` (e.g., `report_name="meta_analysis_${ANALYSIS_FOCUS_Sanitized}_${timestamp}.md"`, `report_contents=ReportMarkdown`). Include visualizations (e.g., Mermaid diagrams summarizing data flow or findings) if applicable.

```{mermaid}
sequenceDiagram
    participant Analyst/Researcher
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant BigQuery as bigquery (Optional)

    Analyst/Researcher->>AutomatedAgent: Start Meta-Analysis\nInput: ANALYSIS_FOCUS, TIMEFRAME_DAYS, DATA_SOURCES (opt)

    %% Step 1: Define Scope
    Note over AutomatedAgent: Define analysis objective and scope

    %% Step 2: Data Collection
    opt Collect SOAR Data
        AutomatedAgent->>SOAR: list_cases(filter=..., time_range=...)
        SOAR-->>AutomatedAgent: Case List
        loop For relevant Case Ci
            AutomatedAgent->>SOAR: get_case_full_details(case_id=Ci)
            SOAR-->>AutomatedAgent: Case Details for Ci
        end
    end
    opt Collect SIEM Data
        AutomatedAgent->>SIEM: search_security_events(text=..., hours_back=...)
        SIEM-->>AutomatedAgent: SIEM Event Data
        AutomatedAgent->>SIEM: get_security_alerts(query=..., hours_back=...)
        SIEM-->>AutomatedAgent: SIEM Alert Data
    end
    opt Collect Data Lake Data
        AutomatedAgent->>BigQuery: execute-query(query=...)
        BigQuery-->>AutomatedAgent: Data Lake Results
    end

    %% Step 3: Data Aggregation & Analysis
    Note over AutomatedAgent: Aggregate and analyze collected data for trends/patterns

    %% Step 4 & 5: Synthesize Findings & Recommendations
    Note over AutomatedAgent: Summarize key findings and formulate recommendations

    %% Step 6: Generate Report
    Note over AutomatedAgent: Compile report content (ReportMarkdown) (Objective, Method, Findings, Recommendations)
    AutomatedAgent->>AutomatedAgent: write_report(report_name="meta_analysis_${ANALYSIS_FOCUS_Sanitized}_${timestamp}.md", report_contents=ReportMarkdown)
    Note over AutomatedAgent: Report file created

    AutomatedAgent->>Analyst/Researcher: attempt_completion(result="Meta-analysis complete. Report generated.")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Data collected and analyzed, findings documented, recommendations formulated, report generated.)*
