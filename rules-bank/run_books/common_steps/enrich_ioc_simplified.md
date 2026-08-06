---
type: "Playbook"
title: "Common Step: Enrich IOC (Simplified)"
description: "Simplified plain-English procedure to enrich an indicator with threat intelligence and SIEM lookup."
resource: "adk_runbooks/rules-bank/run_books/common_steps/enrich_ioc_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "GTI"
    - "SIEM"
    - "reputation"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for intelligence queries"
---

# Common Step: Enrich IOC

## Objective
Perform standardized enrichment for a single IOC with GTI threat intelligence and SIEM entity lookup.

## Inputs
*   `IOC_VALUE`: Indicator value.
*   `IOC_TYPE`: Indicator type (IP, Domain, Hash, URL).

## Core Steps

1. Query GTI Threat Intelligence:
   * Get reputation score, malware associations, and detection ratios from GTI.

2. Query SIEM Entity Lookup:
   * Lookup entity in SIEM to get internal hostname, first seen date, and asset owner.

3. Return Enriched Context:
   * Return consolidated enrichment summary object.
