---
type: "Playbook"
title: "Atomic: User Login Activity Search (Simplified)"
description: "Search Chronicle SIEM for user login and authentication events."
resource: "adk_runbooks/rules-bank/atomic_runbooks/user/rb_user_search_login_activity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "user account"
    - "login event"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: User Login Activity Search

## Objective
Search Chronicle SIEM for user login and authentication events.

## Inputs
*   `USER_ID`: User account identifier.

## Core Steps

1. **Execute Action:**
   * Search SIEM authentication logs for login activity for `USER_ID`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
