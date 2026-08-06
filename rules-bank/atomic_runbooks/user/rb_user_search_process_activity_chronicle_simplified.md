---
type: "Playbook"
title: "Atomic: User Process Activity Search (Simplified)"
description: "Search Chronicle SIEM for process execution events by a user."
resource: "adk_runbooks/rules-bank/atomic_runbooks/user/rb_user_search_process_activity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "user account"
    - "process execution event"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: User Process Activity Search

## Objective
Search Chronicle SIEM for process execution events by a user.

## Inputs
*   `USER_ID`: User account identifier.

## Core Steps

1. **Execute Action:**
   * Search SIEM process launch logs for processes executed by `USER_ID`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
