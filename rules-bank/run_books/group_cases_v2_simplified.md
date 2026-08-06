---
type: "Playbook"
title: "Group Cases v2 Runbook (Simplified)"
description: "Simplified plain-English runbook for advanced multi-entity case clustering and prioritization."
resource: "adk_runbooks/rules-bank/run_books/group_cases_v2_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "clustering"
    - "priority"
    - "entity"
  technical_verbs:
    - "triage"
---

# Group Cases v2 Runbook

## Objective
Cluster recent SOAR cases with multi-entity correlation and assign priority to composite incidents.

## Inputs
*   `TIME_WINDOW_HOURS`: Case lookback window in hours (default: 24).

## Core Steps

1. Fetch Active Cases:
   * Query all open cases created within `TIME_WINDOW_HOURS`.

2. Calculate Entity Overlap Matrix:
   * Correlate shared users, endpoints, and external IP addresses across cases.

3. Form Logical Case Clusters:
   * Group related cases into composite incident records.

4. Re-calculate Incident Priority:
   * Elevate composite priority based on combined blast radius and document in SOAR.
