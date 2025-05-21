# Runbook: Data Lake Queries

## Objective

To query security data lakes (e.g., BigQuery) for specific historical data, large-scale analysis, or information not readily available through standard SIEM searches. This runbook facilitates constructing and executing SQL queries against defined datasets and optionally saving or documenting the results.

## Scope

This runbook covers:
*   Defining a BigQuery SQL query based on a specified objective, target datasets, time range, and filter conditions.
*   Optionally using `describe-table` or `list-tables` to understand schema or table names before query construction.
*   Executing the constructed SQL query using the `bigquery.execute-query` tool.
*   Analyzing the results of the query.
*   Optionally formatting and saving the query results to a file.
*   Optionally documenting the query and a summary of its results in a SOAR case.

This runbook explicitly **excludes**:
*   Real-time alerting based on data lake queries.
*   Complex data engineering or ETL processes for data lakes.
*   Automated actions based on query results (though results might inform manual actions).

## Inputs

*   `${QUERY_OBJECTIVE}`: A description of the data needed or the question the query aims to answer. This is mandatory.
*   `${TARGET_DATASETS}`: A comma-separated list of BigQuery tables or datasets to query (e.g., `my_project.my_dataset.my_table1,my_project.my_dataset.my_table2`). This is mandatory.
*   `${TIME_RANGE_START}`: The start timestamp for the query's time range (e.g., ISO 8601 format like "YYYY-MM-DDTHH:MM:SSZ"). This is mandatory.
*   `${TIME_RANGE_END}`: The end timestamp for the query's time range (e.g., ISO 8601 format). This is mandatory.
*   *(Optional) `${SPECIFIC_FIELDS}`: A comma-separated list of specific fields to retrieve (e.g., "field1,field2,field3"). If not provided, `SELECT *` might be assumed or all relevant fields based on the objective.*
*   *(Optional) `${FILTER_CONDITIONS}`: Specific SQL WHERE clause conditions (e.g., `field1 = 'value' AND field2 > 100`).*
*   *(Optional) `${SOAR_CASE_ID}`: If results need to be documented in a specific SOAR case.*
*   *(Derived) `${SQL_QUERY}`: The fully constructed BigQuery SQL query.*
*   *(Derived) `${QUERY_RESULTS}`: The raw results returned by `bigquery.execute-query`.*
*   *(Derived) `${FORMATTED_RESULTS}`: (Optional) Query results formatted for saving to a file (e.g., CSV, JSON, Markdown).*

## Outputs

*   `${QUERY_EXECUTION_STATUS}`: Status of the BigQuery query execution (e.g., Success, Failure, Error message).
*   `${ANALYSIS_SUMMARY}`: A brief summary of the analysis performed on the query results.
*   *(Optional) `${SAVED_FILE_PATH}`: If results are saved, the path to the file.*
*   *(Optional) `${SOAR_COMMENT_STATUS}`: If documented in SOAR, the status of the comment posting.*

## Tools

*   `bigquery`: `execute-query`, `describe-table`, `list-tables`
*   `write_to_file` (Optional, for saving results to a file, replaces `write_report`)
*   `secops-soar`: `post_case_comment` (Optional, for documenting query/results in a SOAR case)

## Workflow Steps & Diagram

1.  **Define Query:** Based on `${QUERY_OBJECTIVE}`, `${TARGET_DATASETS}`, time range (`${TIME_RANGE_START}`, `${TIME_RANGE_END}`), `${SPECIFIC_FIELDS}`, and `${FILTER_CONDITIONS}`, construct the BigQuery SQL query (`${SQL_QUERY}`). Use `bigquery.describe-table` or `bigquery.list-tables` if needed to confirm schema/table names.
2.  **Execute Query:** Run the `${SQL_QUERY}` using `bigquery.execute-query`. Store results in `${QUERY_RESULTS}` and status in `${QUERY_EXECUTION_STATUS}`.
3.  **Analyze Results:** Review the `${QUERY_RESULTS}`. Summarize findings in `${ANALYSIS_SUMMARY}`.
4.  **Format/Save Results (Optional):** If needed, format the `${QUERY_RESULTS}` (e.g., as Markdown, CSV, or JSON, let this be `${FORMATTED_RESULTS}`) and save them using `write_to_file` with `path="./reports/query_results_${QUERY_OBJECTIVE_Sanitized}_${timestamp}.md"` (or other appropriate extension) and `content=${FORMATTED_RESULTS}`. Store path in `${SAVED_FILE_PATH}`.
5.  **Document (Optional):** If `${SOAR_CASE_ID}` is provided, document the `${SQL_QUERY}` executed and the `${ANALYSIS_SUMMARY}` in the relevant SOAR case using `secops-soar.post_case_comment`. Store status in `${SOAR_COMMENT_STATUS}`.

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
    Note over AutomatedAgent: Construct BigQuery SQL Query (SQL_QUERY)

    %% Step 2: Execute Query
    AutomatedAgent->>BigQuery: execute-query(query=SQL_QUERY)
    BigQuery-->>AutomatedAgent: Query Results (QUERY_RESULTS), Status (QUERY_EXECUTION_STATUS)

    %% Step 3: Analyze Results
    Note over AutomatedAgent: Analyze query results. Store summary in ANALYSIS_SUMMARY.

    %% Step 4: Format/Save Results (Optional)
    opt Save Results
        Note over AutomatedAgent: Format results (e.g., CSV, JSON) (FORMATTED_RESULTS)
        AutomatedAgent->>AutomatedAgent: write_to_file(path="./reports/query_results...", content=FORMATTED_RESULTS)
        Note over AutomatedAgent: Results saved to file (SAVED_FILE_PATH)
    end

    %% Step 5: Document (Optional)
    opt Document in SOAR and SOAR_CASE_ID provided
        AutomatedAgent->>SOAR: post_case_comment(case_id=SOAR_CASE_ID, comment="Data Lake Query Executed: SQL_QUERY, Summary: ANALYSIS_SUMMARY")
        SOAR-->>AutomatedAgent: Comment Confirmation (SOAR_COMMENT_STATUS)
    end

    AutomatedAgent->>Analyst/User: attempt_completion(result="Data lake query executed. Status: QUERY_EXECUTION_STATUS. Analysis: ANALYSIS_SUMMARY. File: SAVED_FILE_PATH. SOAR Update: SOAR_COMMENT_STATUS.")

```

## Completion Criteria

*   The BigQuery SQL query (`${SQL_QUERY}`) has been successfully constructed based on the provided inputs.
*   The query has been executed using `bigquery.execute-query`, and the `${QUERY_EXECUTION_STATUS}` is available.
*   The `${QUERY_RESULTS}` have been returned and an `${ANALYSIS_SUMMARY}` has been formulated.
*   (Optional) If requested, the results have been formatted and saved to a file, and `${SAVED_FILE_PATH}` is available.
*   (Optional) If requested and `${SOAR_CASE_ID}` was provided, the query and summary have been documented in the SOAR case, and `${SOAR_COMMENT_STATUS}` is available.
