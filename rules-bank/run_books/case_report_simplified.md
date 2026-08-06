---
type: "Playbook"
title: "Case Investigation Report Runbook (Simplified)"
description: "Simplified plain-English runbook to consolidate case findings into a formal Markdown report."
resource: "adk_runbooks/rules-bank/run_books/case_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "case report"
    - "SOAR case"
    - "timeline"
    - "root cause"
    - "containment"
  technical_verbs:
    - "triage"
---

# Case Investigation Report Runbook

## Objective
Consolidate all findings from an investigation into a formal Case Investigation Markdown report.

## Inputs
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Aggregate Case Data:
   * Gather all alerts, entity enrichments, investigation comments, and containment actions for `CASE_ID`.

2. Compile Timeline and Root Cause:
   * Document the chronological attack sequence, affected assets, and root cause.

3. Detail Containment and Remediation:
   * List all containment steps executed and verify threat eradication.

4. Generate and Save Report:
   * Save the Case Investigation Report Markdown file and attach to the case.
