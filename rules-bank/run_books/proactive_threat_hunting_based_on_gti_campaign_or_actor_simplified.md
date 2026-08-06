---
type: "Playbook"
title: "Proactive Threat Hunting Based on GTI Campaign Runbook (Simplified)"
description: "Simplified plain-English runbook to convert GTI campaign intelligence into proactive hunts."
resource: "adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campaign_or_actor_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "GTI"
    - "campaign"
    - "threat actor"
    - "TTP"
    - "IOC"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for campaign queries"
---

# Proactive Threat Hunting Based on GTI Campaign Runbook

## Objective
Convert GTI campaign or actor intelligence into targeted hunting queries across SIEM telemetry.

## Inputs
*   `COLLECTION_ID`: GTI Collection ID for the campaign or actor.

## Core Steps

1. Extract Campaign Profile from GTI:
   * Query GTI to extract all IOCs, target industries, and MITRE ATT&CK techniques from `COLLECTION_ID`.

2. Run Telemetry Scans:
   * Search SIEM event logs for matching IOCs and behavioral signatures.

3. Analyze Results:
   * Identify any internal hosts that communicated with campaign infrastructure.

4. Record Findings:
   * Document findings in SOAR and create detection rules for new techniques.
