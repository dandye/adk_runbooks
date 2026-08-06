---
type: "Playbook"
title: "Atomic: URL GTI Report (Simplified)"
description: "Query GTI for URL reputation and categorization."
resource: "adk_runbooks/rules-bank/atomic_runbooks/url/rb_url_get_gti_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "URL"
    - "GTI"
    - "reputation"
  technical_verbs:
    - "enrich"
---

# Atomic: URL GTI Report

## Objective
Query GTI for URL reputation and categorization.

## Inputs
*   `URL`: Target URL.

## Core Steps

1. **Execute Action:**
   * Query GTI for `URL` reputation, categories, and redirection targets.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
