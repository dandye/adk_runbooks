---
type: "Playbook"
title: "Basic IOC Enrichment Runbook (Simplified)"
description: "Simplified plain-English runbook to enrich a single Indicator of Compromise using GTI and SIEM."
resource: "adk_runbooks/rules-bank/run_books/basic_ioc_enrichment_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "IP address"
    - "domain"
    - "file hash"
    - "URL"
    - "GTI"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "escalate"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for database lookups"
---

# Basic IOC Enrichment Runbook

## Objective
Enrich an Indicator of Compromise with GTI threat intelligence and check recent SIEM telemetry.

## Inputs
*   `IOC_VALUE`: The IP address, domain, file hash, or URL to analyze.
*   `IOC_TYPE`: The type of the IOC (IP, Domain, Hash, URL).
*   `CASE_ID`: Optional SOAR case ID for documentation.

## Core Steps

1. Query GTI Threat Intelligence:
   * Query `IOC_VALUE` with GTI threat intelligence tools to get reputation scores and threat categories.

2. Check SIEM Events & IOC Matches:
   * Search SIEM telemetry to find internal hosts communicating with or executing `IOC_VALUE`.
   * Check if `IOC_VALUE` matches active SIEM threat intelligence feeds.

3. Search Related SOAR Cases:
   * Search for open SOAR cases that contain `IOC_VALUE`.

4. Synthesize and Recommend Action:
   * Evaluate combined risk score and recommend next actions (close, monitor, or escalate).
