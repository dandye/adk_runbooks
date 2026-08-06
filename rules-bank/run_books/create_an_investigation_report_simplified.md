---
type: "Playbook"
title: "Create Investigation Report Runbook (Simplified)"
description: "Simplified plain-English runbook to generate cross-tool investigation reports."
resource: "adk_runbooks/rules-bank/run_books/create_an_investigation_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "investigation report"
    - "SOAR case"
    - "SIEM"
    - "GTI"
    - "SCC"
  technical_verbs:
    - "triage"
---

# Create Investigation Report Runbook

## Objective
Consolidate multi-tool investigation findings (SIEM, SOAR, GTI, SCC) into a structured report.

## Inputs
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Collect Multi-Tool Findings:
   * Compile telemetry summaries from SIEM event searches, GTI reputation queries, and SCC findings.

2. Structure Investigation Report:
   * Organize report into Executive Summary, Threat Details, Affected Assets, and Recommended Actions.

3. Save Report File:
   * Write the Markdown report to the designated report storage path.

4. Notify Stakeholders:
   * Post report summary to the SOAR case and inform relevant response teams.
