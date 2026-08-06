---
type: "Playbook"
title: "Post-Incident Review Runbook (Simplified)"
description: "Simplified plain-English runbook to conduct post-incident reviews (PIR) and capture lessons learned."
resource: "adk_runbooks/rules-bank/run_books/post_incident_review_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "post-incident review"
    - "incident"
    - "root cause"
    - "security control"
    - "SOAR case"
  technical_verbs:
    - "triage"
    - "tune"
---

# Post-Incident Review Runbook

## Objective
Conduct a structured post-incident review (PIR) to document root cause, timeline, and control improvements.

## Inputs
*   `INCIDENT_ID`: Incident or SOAR case ID.

## Core Steps

1. Reconstruct Incident Timeline:
   * Review complete timeline from initial access to final eradication.

2. Identify Root Cause & Gaps:
   * Determine root cause vulnerability and identify gaps in detection or response speed.

3. Define Corrective Action Items:
   * List required detection engineering updates, architecture changes, or security control patches.

4. Publish PIR Report:
   * Generate and publish the formal PIR Markdown report.
