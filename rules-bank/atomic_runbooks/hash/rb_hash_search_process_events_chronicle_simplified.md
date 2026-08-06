---
type: "Playbook"
title: "Atomic: Hash Process Event Search (Simplified)"
description: "Search Chronicle SIEM for process executions of a file hash."
resource: "adk_runbooks/rules-bank/atomic_runbooks/hash/rb_hash_search_process_events_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "file hash"
    - "process execution event"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: Hash Process Event Search

## Objective
Search Chronicle SIEM for process executions of a file hash.

## Inputs
*   `FILE_HASH`: File hash.

## Core Steps

1. **Execute Action:**
   * Search SIEM process launch events for binary matching `FILE_HASH`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
