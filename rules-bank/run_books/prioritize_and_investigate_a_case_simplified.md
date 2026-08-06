---
type: "Playbook"
title: "Prioritize and Investigate a Case Runbook (Simplified)"
description: "Simplified plain-English runbook to prioritize incoming SOAR cases and guide deep investigation."
resource: "adk_runbooks/rules-bank/run_books/prioritize_and_investigate_a_case_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "severity"
    - "SIEM"
    - "IOC"
    - "threat intelligence"
    - "endpoint"
  technical_verbs:
    - "triage"
    - "isolate"
    - "escalate"
    - "enrich"
---

# Prioritize and Investigate a Case Runbook

## Objective
Prioritize open SOAR cases based on asset criticality and guide the investigation workflow.

## Inputs
*   `CASE_ID`: SOAR case ID to prioritize and investigate.

## Core Steps

1. Determine Case Priority:
   * Evaluate alert severity, affected asset criticality, and threat intelligence scores to set case priority.

2. Collect Investigation Context:
   * Get all alerts, entities, and event timelines associated with `CASE_ID`.

3. Correlate Across SIEM and GTI:
   * Search SIEM telemetry for related adversary activity and enrich all extracted IOCs.

4. Formulate Verdict and Next Steps:
   * Document investigation conclusions and recommend containment or closure actions.
