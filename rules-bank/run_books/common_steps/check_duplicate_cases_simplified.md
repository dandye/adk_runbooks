---
type: "Playbook"
title: "Common Step: Check Duplicate Cases (Simplified)"
description: "Simplified plain-English procedure to find existing duplicate SOAR cases."
resource: "adk_runbooks/rules-bank/run_books/common_steps/check_duplicate_cases_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "duplicate case"
    - "entity"
  technical_verbs:
    - "triage"
---

# Common Step: Check Duplicate Cases

## Objective
Find existing open SOAR cases that contain matching entities or alerts to prevent duplicate effort.

## Inputs
*   `SEARCH_ENTITIES`: List of IP addresses, hostnames, or usernames to check.

## Core Steps

1. Search Active Cases:
   * Query open SOAR cases that contain any entity in `SEARCH_ENTITIES`.

2. Return Match List:
   * Return list of matching case IDs and alert summaries.
