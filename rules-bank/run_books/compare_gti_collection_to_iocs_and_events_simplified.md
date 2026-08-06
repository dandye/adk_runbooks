---
type: "Playbook"
title: "Compare GTI Collection to IOCs and Events Runbook (Simplified)"
description: "Simplified plain-English runbook to compare GTI collection artifacts with internal SIEM events."
resource: "adk_runbooks/rules-bank/run_books/compare_gti_collection_to_iocs_and_events_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "GTI"
    - "collection"
    - "IOC"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for collection comparison lookups"
---

# Compare GTI Collection to IOCs and Events Runbook

## Objective
Compare indicators from a GTI Collection with internal SIEM event logs to identify overlap.

## Inputs
*   `COLLECTION_ID`: GTI Collection ID.
*   `SEARCH_WINDOW_HOURS`: Search window in hours.

## Core Steps

1. Extract Collection IOCs:
   * Get all domains, IPs, URLs, and file hashes from GTI `COLLECTION_ID`.

2. Execute SIEM Cross-Correlation:
   * Search SIEM telemetry for internal matches against extracted collection IOCs.

3. Summarize Overlap:
   * List all internal entities that matched collection indicators with timestamps.

4. Document in SOAR:
   * Add findings to the SOAR case and recommend remediation.
