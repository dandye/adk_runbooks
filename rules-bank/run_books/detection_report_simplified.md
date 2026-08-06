---
type: "Playbook"
title: "Detection Report Generation Runbook (Simplified)"
description: "Simplified plain-English runbook to summarize detection rule coverage, logic, and effectiveness."
resource: "adk_runbooks/rules-bank/run_books/detection_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "detection report"
    - "detection rule"
    - "YARA-L"
    - "coverage"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Detection Report Generation Runbook

## Objective
Generate a standardized report summarizing detection rule logic, alert volume, and coverage metrics.

## Inputs
*   `RULE_ID`: Detection rule ID.
*   `REPORT_TIMEFRAME_DAYS`: Reporting period in days.

## Core Steps

1. Retrieve Rule Definition & Metrics:
   * Get YARA-L rule text, enabled status, severity, and alert counts over the reporting period.

2. Evaluate True vs False Positive Ratios:
   * Compile triage outcomes from associated SOAR cases.

3. Document MITRE ATT&CK Mapping:
   * List tactics and techniques covered by the rule.

4. Generate Report File:
   * Write and save the Detection Report Markdown file.
