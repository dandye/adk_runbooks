---
type: "Playbook"
title: "Investigate GTI Collection ID Runbook (Simplified)"
description: "Simplified plain-English runbook to analyze a GTI threat actor or campaign collection."
resource: "adk_runbooks/rules-bank/run_books/investigate_a_gti_collection_id_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "GTI"
    - "threat actor"
    - "campaign"
    - "MITRE ATT&CK"
    - "TTP"
    - "IOC"
    - "SIEM"
  technical_verbs:
    - "enrich"
    - "triage"
  allowed_overrides:
    - word: "query"
      reason: "Approved verb for collection queries"
---

# Investigate GTI Collection ID Runbook

## Objective
Investigate a Google Threat Intelligence (GTI) Collection ID to profile threat actors and extract IOCs.

## Inputs
*   `COLLECTION_ID`: GTI Collection identifier for the actor, campaign, or report.

## Core Steps

1. Get Collection Overview:
   * Query GTI for `COLLECTION_ID` to get the summary, targeted industries, and threat actor aliases.

2. Extract MITRE ATT&CK TTPs:
   * Get the MITRE ATT&CK technique mapping for the collection.

3. Extract Associated IOCs:
   * Get all related file hashes, domains, and IP addresses linked to `COLLECTION_ID`.

4. Search SIEM Telemetry:
   * Search SIEM logs for any matching extracted IOCs or suspicious behavior patterns.
   * Document matched indicators and recommend threat hunting or blocking actions.
