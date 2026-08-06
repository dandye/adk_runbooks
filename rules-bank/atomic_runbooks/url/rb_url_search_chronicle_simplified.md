---
type: "Playbook"
title: "Atomic: URL Chronicle Search (Simplified)"
description: "Search Chronicle SIEM for HTTP and proxy events involving a URL."
resource: "adk_runbooks/rules-bank/atomic_runbooks/url/rb_url_search_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "URL"
    - "HTTP event"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: URL Chronicle Search

## Objective
Search Chronicle SIEM for HTTP and proxy events involving a URL.

## Inputs
*   `URL`: Target URL.

## Core Steps

1. **Execute Action:**
   * Search SIEM HTTP and web proxy logs for requests targeting `URL`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
