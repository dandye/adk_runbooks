---
type: "Playbook"
title: "Close Duplicate or Similar Cases Runbook (Simplified)"
description: "Simplified plain-English runbook to identify and close duplicate SOAR cases."
resource: "adk_runbooks/rules-bank/run_books/close_duplicate_or_similar_cases_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "security alert"
    - "duplicate case"
    - "root cause"
  technical_verbs:
    - "triage"
    - "close"
---

# Close Duplicate or Similar Cases Runbook

## Objective
Identify duplicate or similar SOAR cases and close redundant cases with standardized justification.

## Inputs
*   `PRIMARY_CASE_ID`: Main active case.
*   `DUPLICATE_CASE_IDS`: List of duplicate case IDs to close.

## Core Steps

1. Verify Case Similarity:
   * Compare alert types, affected entities, and timestamps to confirm cases are duplicates.

2. Link Duplicate Cases:
   * Add cross-reference comments linking duplicate cases to `PRIMARY_CASE_ID`.

3. Close Duplicate Cases:
   * Close each duplicate case with closure reason 'Duplicate' and reference `PRIMARY_CASE_ID`.
