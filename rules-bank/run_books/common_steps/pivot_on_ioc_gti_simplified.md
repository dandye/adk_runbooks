---
type: "Playbook"
title: "Common Step: Pivot on IOC Using GTI (Simplified)"
description: "Simplified plain-English procedure to pivot on IOC relationships in GTI."
resource: "adk_runbooks/rules-bank/run_books/common_steps/pivot_on_ioc_gti_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "GTI"
    - "relationship"
    - "domain"
    - "IP address"
    - "file hash"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for pivot queries"
---

# Common Step: Pivot on IOC Using GTI

## Objective
Explore relationships connected to a specific IOC in GTI (contacted domains, resolutions, communicating files).

## Inputs
*   `IOC_VALUE`: Indicator value.
*   `RELATIONSHIP_NAME`: Relationship type to query.

## Core Steps

1. Query GTI Relationship Endpoint:
   * Query GTI for related entities linked to `IOC_VALUE` by `RELATIONSHIP_NAME`.

2. Extract High-Risk Linked Entities:
   * Filter and return high-risk connected domains, IP addresses, or file hashes.
