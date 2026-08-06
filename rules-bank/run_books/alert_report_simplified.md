---
type: "Playbook"
title: "Alert Investigation Summary Report Runbook (Simplified)"
description: "Simplified plain-English runbook to generate standardized investigation summary reports for alerts."
resource: "adk_runbooks/rules-bank/run_books/alert_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "alert report"
    - "security alert"
    - "SOAR case"
    - "SIEM"
    - "verdict"
  technical_verbs:
    - "triage"
---

# Alert Investigation Summary Report Runbook

## Objective
Generate a concise, standardized Markdown summary report for a triaged security alert.

## Inputs
*   `ALERT_ID`: Security alert ID.
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Collect Alert Findings:
   * Gather trigger telemetry, enriched entity context, and analyst notes from `ALERT_ID`.

2. Format Summary Sections:
   * Structure report with Executive Summary, Technical Details, Evidence, and Verdict.

3. Save Report File:
   * Write and save the report Markdown file.

4. Attach to SOAR:
   * Post report link or content into the SOAR case comments.
