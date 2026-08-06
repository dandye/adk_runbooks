---
type: "Playbook"
title: "Advanced Threat Hunting Runbook (Simplified)"
description: "Simplified plain-English runbook to conduct hypothesis-driven threat hunts across telemetry."
resource: "adk_runbooks/rules-bank/run_books/advanced_threat_hunting_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "threat hunt"
    - "hypothesis"
    - "TTP"
    - "MITRE ATT&CK"
    - "SIEM"
    - "data lake"
    - "SOAR case"
  technical_verbs:
    - "triage"
---

# Advanced Threat Hunting Runbook

## Objective
Conduct proactive, hypothesis-driven threat hunts across SIEM telemetry and data lakes.

## Inputs
*   `HUNT_HYPOTHESIS`: Plain-English description of the adversary behavior to hunt.
*   `TIMEFRAME_DAYS`: Lookback period in days.

## Core Steps

1. Define Hunt Scope & Hypothesis:
   * Formulate specific adversary behavior hypothesis based on threat intelligence or threat models.

2. Construct Behavioral Queries:
   * Write and execute UDM or SQL queries in SIEM and Data Lake across process, network, and auth events.

3. Analyze Anomalies & Outliers:
   * Filter benign baseline activity to identify statistically anomalous process executions or connections.

4. Synthesize Findings & Propose Detections:
   * Document hunt results and recommend new detection rules or tuning updates.
