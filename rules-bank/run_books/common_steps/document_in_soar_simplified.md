---
type: "Playbook"
title: "Common Step: Document Findings in SOAR Case (Simplified)"
description: "Simplified plain-English procedure to post structured comments to a SOAR case."
resource: "adk_runbooks/rules-bank/run_books/common_steps/document_in_soar_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "comment"
    - "evidence"
  technical_verbs:
    - "triage"
---

# Common Step: Document Findings in SOAR Case

## Objective
Add a standardized markdown comment to a SOAR case to record findings, evidence, or recommendations.

## Inputs
*   `CASE_ID`: Target SOAR case ID.
*   `CONTENT`: Text or markdown content to record.

## Core Steps

1. Format Comment Body:
   * Structure content with clear headings, bullet points, and actionable next steps.

2. Post Comment to Case:
   * Execute the SOAR comment action to add the note to `CASE_ID`.
