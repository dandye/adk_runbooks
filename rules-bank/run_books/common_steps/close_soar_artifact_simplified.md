---
type: "Playbook"
title: "Common Step: Close SOAR Case or Alert (Simplified)"
description: "Simplified plain-English procedure to close a SOAR case or alert with required justification."
resource: "adk_runbooks/rules-bank/run_books/common_steps/close_soar_artifact_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "security alert"
    - "root cause"
  technical_verbs:
    - "close"
    - "triage"
---

# Common Step: Close SOAR Case or Alert

## Objective
Close a specified SOAR case or alert with standardized closure reason, root cause, and summary comment.

## Inputs
*   `CASE_ID`: Case or alert ID to close.
*   `CLOSURE_REASON`: Closure category (for example, False Positive, Resolved).
*   `COMMENT`: Summary explanation.

## Core Steps

1. Validate Closure Prerequisites:
   * Verify that all investigation and containment tasks are complete.

2. Submit Closure Action:
   * Execute the SOAR close action with `CLOSURE_REASON` and `COMMENT`.
