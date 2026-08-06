---
type: "Playbook"
title: "UEBA Report Analysis Runbook (Simplified)"
description: "Simplified plain-English runbook to investigate User and Entity Behavior Analytics alerts."
resource: "adk_runbooks/rules-bank/run_books/ueba_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "UEBA"
    - "anomaly"
    - "user account"
    - "behavioral baseline"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "triage"
    - "isolate"
---

# UEBA Report Analysis Runbook

## Objective
Analyze User and Entity Behavior Analytics (UEBA) anomaly alerts to distinguish benign outliers from threats.

## Inputs
*   `USER_ID`: User account identifier.
*   `ANOMALY_TYPE`: Description of the anomalous behavior.

## Core Steps

1. Inspect Behavioral Anomaly Metrics:
   * Get baseline behavior scores, deviation thresholds, and specific trigger events from the UEBA alert.

2. Check Business Context:
   * Verify if the user has approved exceptions, recent role changes, or authorized business travel.

3. Correlate with SIEM Telemetry:
   * Search SIEM logs for concurrent unauthorized resource access or data exfiltration.

4. Document Assessment:
   * Record verdict in SOAR and escalate if unauthorized insider activity is confirmed.
