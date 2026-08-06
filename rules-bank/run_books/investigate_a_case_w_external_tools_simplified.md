---
type: "Playbook"
title: "Investigate a Case with External Tools Runbook (Simplified)"
description: "Simplified plain-English runbook to investigate cases using integrated external security tools."
resource: "adk_runbooks/rules-bank/run_books/investigate_a_case_w_external_tools_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "GTI"
    - "SIEM"
    - "SCC"
    - "vulnerability"
    - "IOC"
  technical_verbs:
    - "enrich"
    - "escalate"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for tool queries"
---

# Investigate a Case with External Tools Runbook

## Objective
Investigate a SOAR case by combining telemetry from SIEM, GTI, and Cloud Security Command Center (SCC).

## Inputs
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Get Case Details:
   * Get full case details, alerts, and involved entities from the SOAR platform.

2. Query External Threat Intelligence (GTI):
   * Query GTI for all external IP addresses, domains, and file hashes in the case.

3. Query Cloud Security Findings (SCC):
   * Query SCC for vulnerability and misconfiguration findings on affected cloud resources.

4. Correlate and Document:
   * Synthesize multi-tool telemetry and document consolidated findings in the SOAR case.
