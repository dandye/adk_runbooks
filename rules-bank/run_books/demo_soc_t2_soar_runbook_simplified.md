---
type: "Playbook"
title: "SOC Analyst Tier 2 Demo Runbook (Simplified)"
description: "Simplified plain-English runbook demonstrating Tier 2 investigation and manual containment actions."
resource: "adk_runbooks/rules-bank/run_books/demo_soc_t2_soar_runbook_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "endpoint"
    - "manual action"
    - "playbook"
    - "SIEM"
  technical_verbs:
    - "isolate"
    - "escalate"
    - "triage"
---

# SOC Analyst Tier 2 Demo Runbook

## Objective
Demonstrate Tier 2 escalation handling, deep context review, and manual playbook execution in SOAR.

## Inputs
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Review Tier 1 Findings:
   * Get case notes, enriched entities, and alert summaries from `CASE_ID`.

2. Perform Additional Telemetry Checks:
   * Search SIEM logs for extended context and lateral movement indicators.

3. Execute Manual Response Action:
   * Trigger confirmed manual SOAR actions (for example, isolate endpoint or reset credentials).

4. Conclude Investigation:
   * Document remediation outcome and update case status in SOAR.
