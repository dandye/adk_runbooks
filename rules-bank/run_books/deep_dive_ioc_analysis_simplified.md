---
type: "Playbook"
title: "Deep Dive IOC Analysis Runbook (Simplified)"
description: "Simplified plain-English runbook for exhaustive analysis of high-priority IOCs."
resource: "adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "GTI"
    - "threat actor"
    - "sandbox"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "triage"
    - "isolate"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for intelligence queries"
---

# Deep Dive IOC Analysis Runbook

## Objective
Conduct exhaustive analysis on a high-risk IOC, including sandbox reports, resolutions, and actor links.

## Inputs
*   `IOC_VALUE`: The high-risk indicator value.
*   `IOC_TYPE`: Type of IOC.

## Core Steps

1. Multi-Engine Reputation & Graph Analysis:
   * Query GTI for sandbox execution reports, passive DNS history, SSL certificates, and actor linkages.

2. Full SIEM Telemetry Correlation:
   * Search all SIEM log types for historical connections, executions, or user interactions with `IOC_VALUE`.

3. Determine Blast Radius:
   * Identify all internal endpoints and users that interacted with `IOC_VALUE`.

4. Document Detailed Analysis:
   * Document technical findings, attribution, and recommended countermeasures in SOAR.
