---
type: "Playbook"
title: "Data Lake Queries Runbook (Simplified)"
description: "Simplified plain-English runbook to query large-scale historical security data in BigQuery."
resource: "adk_runbooks/rules-bank/run_books/data_lake_queries_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "data lake"
    - "BigQuery"
    - "SQL"
    - "historical data"
    - "SOAR case"
  technical_verbs:
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for database/lake SQL queries"
---

# Data Lake Queries Runbook

## Objective
Execute SQL queries across security data lakes (for example, BigQuery) for historical analysis.

## Inputs
*   `SQL_QUERY`: The SQL query to execute.
*   `PROJECT_ID`: Cloud project ID.

## Core Steps

1. Validate SQL Query Syntax:
   * Review SQL query syntax, table partitions, and date filters to optimize query performance.

2. Run Query in Data Lake:
   * Execute the query against target security tables in BigQuery or the Data Lake.

3. Export and Analyze Results:
   * Format result rows and analyze patterns, counts, and anomalies.

4. Document Output:
   * Save query results to a report file or attach findings to the SOAR case.
