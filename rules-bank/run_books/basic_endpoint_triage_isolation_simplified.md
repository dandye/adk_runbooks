---
type: "Playbook"
title: "Basic Endpoint Triage and Isolation Runbook (Simplified)"
description: "Simplified plain-English runbook to assess endpoint compromise and execute network isolation."
resource: "adk_runbooks/rules-bank/run_books/basic_endpoint_triage_isolation_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "endpoint"
    - "SIEM"
    - "SOAR case"
    - "EDR"
    - "vulnerability"
    - "process execution event"
  technical_verbs:
    - "isolate"
    - "triage"
    - "escalate"
---

# Basic Endpoint Triage and Isolation Runbook

## Objective
Assess a potentially compromised endpoint with SIEM telemetry and isolate the endpoint when confirmed.

## Inputs
*   `ENDPOINT_ID`: Hostname or IP address of the endpoint.
*   `CASE_ID`: SOAR case ID for documentation.

## Core Steps

1. Gather Endpoint Telemetry:
   * Get recent process execution, network connection, and authentication events for `ENDPOINT_ID` from the SIEM.
   * Check vulnerability status and active EDR alerts for the host.

2. Assess Compromise Likelihood:
   * Evaluate whether observed activity indicates active attacker access or malware execution.

3. Confirm and Isolate Endpoint:
   * Confirm isolation requirement with the analyst or playbook criteria.
   * Execute network isolation with EDR or network containment tools.

4. Document and Handover:
   * Document findings and isolation status in the SOAR case.
   * Escalate the case to Tier 2 or Incident Response if compromise is confirmed.
