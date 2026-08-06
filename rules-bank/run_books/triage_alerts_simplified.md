---
type: "Playbook"
title: "Alert Triage Runbook (Simplified)"
description: "Simplified plain-English runbook for initial assessment and triage of incoming security alerts."
resource: "adk_runbooks/rules-bank/run_books/triage_alerts_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "security alert"
    - "SIEM"
    - "SOAR case"
    - "IOC"
    - "false positive"
    - "true positive"
  technical_verbs:
    - "triage"
    - "escalate"
    - "enrich"
---

# Alert Triage Runbook

## Objective
Perform initial assessment, deduplication, enrichment, and severity classification on incoming security alerts.

## Inputs
*   `ALERT_ID`: Identifier of the incoming alert.
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Get Alert Details:
   * Get alert metadata, rule name, severity, involved entities, and trigger telemetry from the SIEM/SOAR.

2. Check for Duplicate Alerts:
   * Search for duplicate or related alerts across active SOAR cases.

3. Enrich Involved Entities:
   * Enrich all extractable IP addresses, domains, hashes, and users with threat intelligence tools.

4. Classify and Route:
   * Determine verdict: False Positive (close alert) or True Positive (escalate for investigation).
   * Document findings and update alert status in the SOAR case.
