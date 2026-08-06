---
type: "Playbook"
title: "Group Cases Runbook (Simplified)"
description: "Simplified plain-English runbook to group related SOAR cases based on common entities and alerts."
resource: "adk_runbooks/rules-bank/run_books/group_cases_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "grouping"
    - "entity"
    - "security alert"
  technical_verbs:
    - "triage"
---

# Group Cases Runbook

## Objective
Analyze open SOAR cases and group related cases that share common entities, IOCs, or alert patterns.

## Inputs
*   `CASE_IDS`: List of active case IDs to evaluate.

## Core Steps

1. Extract Case Entities and Alerts:
   * Get all involved hosts, users, IP addresses, and alert types for each case.

2. Identify Common Overlap:
   * Cluster cases that share identical attacker infrastructure, compromised accounts, or alert chains.

3. Create or Update Group:
   * Link clustered cases together in SOAR under a primary master case.

4. Document Grouping Rationale:
   * Add comments to each case explaining the grouping basis.
