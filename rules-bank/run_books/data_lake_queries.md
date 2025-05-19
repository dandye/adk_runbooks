# Runbook: Data Lake Queries (Placeholder)

## Objective

*(Define the goal, e.g., To query the security data lake for specific historical data, large-scale analysis, or information not readily available via standard SIEM searches.)*

## Scope

*(Define what is included/excluded, e.g., Focuses on constructing and executing BigQuery queries against specific datasets. Excludes real-time alerting.)*

## Inputs

*   `${QUERY_OBJECTIVE}`: Description of the data needed or the question to answer.
*   `${TARGET_DATASETS}`: Comma-separated list of BigQuery tables/datasets to query (e.g., `my_project.my_dataset.my_table`).
*   `${TIME_RANGE_START}`: Start timestamp for the query (e.g., ISO 8601 format).
*   `${TIME_RANGE_END}`: End timestamp for the query (e.g., ISO 8601 format).
*   *(Optional) `${SPECIFIC_FIELDS}`: Comma-separated list of specific fields to retrieve.*
*   *(Optional) `${FILTER_CONDITIONS}`: Specific WHERE clause conditions.*

## Tools

*   `bigquery`: `execute-query`, `describe-table`, `list-tables`
*   `write_report` (Optional, for saving results as a report file)
*   `secops-soar`: `post_case_comment` (Optional, for documenting query/results)

## Workflow Steps & Diagram

1.  **Define Query:** Based on `${QUERY_OBJECTIVE}`, `${TARGET_DATASETS}`, time range, and filters, construct the BigQuery SQL query. Use `describe-table` or `list-tables` if needed to confirm schema/table names.
2.  **Execute Query:** Run the query using `bigquery.execute-query`.
3.  **Analyze Results:** Review the query results.
4.  **Format/Save Results (Optional):** If needed, format the results (e.g., as Markdown, CSV, or JSON, let this be `${FormattedResults}`) and save them using `write_report` with `report_name="query_results_${QUERY_OBJECTIVE_Sanitized}_${timestamp}.md"` and `report_contents=${FormattedResults}`.
5.  **Document (Optional):** Document the query executed and a summary of the results in a relevant SOAR case using `post_case_comment`.

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant BigQuery as bigquery
    participant SOAR as secops-soar (Optional)

    Analyst/User->>AutomatedAgent: Start Data Lake Query\nInput: QUERY_OBJECTIVE, TARGET_DATASETS, TIME_RANGE...

    %% Step 1: Define Query
    opt Need Schema/Table Info
        AutomatedAgent->>BigQuery: list-tables() / describe-table(table_name=...)
        BigQuery-->>AutomatedAgent: Table/Schema Info
    end
    Note over AutomatedAgent: Construct BigQuery SQL Query

    %% Step 2: Execute Query
    AutomatedAgent->>BigQuery: execute-query(query=SQL_QUERY)
    BigQuery-->>AutomatedAgent: Query Results

    %% Step 3: Analyze Results
    Note over AutomatedAgent: Analyze query results

    %% Step 4: Format/Save Results (Optional)
    opt Save Results
        Note over AutomatedAgent: Format results (e.g., CSV, JSON) (FormattedResults)
        AutomatedAgent->>AutomatedAgent: write_report(report_name="query_results_${QUERY_OBJECTIVE_Sanitized}_${timestamp}.md", report_contents=FormattedResults)
        Note over AutomatedAgent: Results saved as a report file
    end

    %% Step 5: Document (Optional)
    opt Document in SOAR
        AutomatedAgent->>SOAR: post_case_comment(case_id=..., comment="Data Lake Query Executed: [...], Summary: [...]")
        SOAR-->>AutomatedAgent: Comment Confirmation
    end

    AutomatedAgent->>Analyst/User: attempt_completion(result="Data lake query executed. Results analyzed/saved/documented as requested.")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Query successfully executed, results returned and analyzed/saved/documented as required.)*
