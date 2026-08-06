---
type: "Playbook"
title: "Common Step: Correlate IOC with SIEM Alerts and SOAR Cases (Simplified)"
description: "Simplified plain-English procedure to correlate an IOC against active alerts and cases."
resource: "adk_runbooks/rules-bank/run_books/common_steps/correlate_ioc_with_alerts_cases_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "SIEM"
    - "SOAR case"
    - "security alert"
  technical_verbs:
    - "enrich"
    - "triage"
---

# Common Step: Correlate IOC with SIEM Alerts and SOAR Cases

## Objective
Check for existing SIEM alerts and open SOAR cases associated with a specific IOC.

## Inputs
*   `IOC_VALUE`: Indicator to correlate.

## Core Steps

1. Query SIEM Alert Matches:
   * Search SIEM alert indexes for detections triggered by `IOC_VALUE`.

2. Search Open SOAR Cases:
   * Search SOAR cases for tickets referencing `IOC_VALUE`.

3. Return Correlated Context:
   * Return consolidated list of related alert names and case IDs.
