---
type: "Playbook"
title: "APT Threat Hunt Runbook (Simplified)"
description: "Simplified plain-English runbook to proactively hunt for APT threat actor TTPs and IOCs."
resource: "adk_runbooks/rules-bank/run_books/apt_threat_hunt_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "threat actor"
    - "APT"
    - "TTP"
    - "IOC"
    - "MITRE ATT&CK"
    - "GTI"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for threat intelligence queries"
---

# APT Threat Hunt Runbook

## Objective
Proactively hunt for Tactics, Techniques, and Procedures (TTPs) and IOCs associated with an APT group.

## Inputs
*   `THREAT_ACTOR_NAME`: Name or GTI collection ID of the target threat actor.
*   `HUNT_TIMEFRAME_HOURS`: Search window in hours.

## Core Steps

1. Gather Threat Intelligence:
   * Query GTI to get known TTPs, MITRE ATT&CK mappings, and IOCs for `THREAT_ACTOR_NAME`.

2. Check SIEM Feeds for IOC Matches:
   * Search SIEM IOC match tables for actor-linked IP addresses, domains, and file hashes.

3. Execute TTP Behavioral Searches:
   * Run SIEM behavioral queries targeting the actor's primary MITRE ATT&CK techniques.

4. Document and Escalate Findings:
   * Document confirmed suspicious activity in a hunt case and trigger incident response if needed.
