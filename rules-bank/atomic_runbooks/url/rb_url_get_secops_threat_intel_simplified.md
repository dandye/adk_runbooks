---
type: "Playbook"
title: "Atomic: URL Threat Intel Lookup (Simplified)"
description: "Check if URL matches SIEM threat intelligence feeds."
resource: "adk_runbooks/rules-bank/atomic_runbooks/url/rb_url_get_secops_threat_intel_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "URL"
    - "SIEM"
    - "threat intelligence"
  technical_verbs:
    - "enrich"
---

# Atomic: URL Threat Intel Lookup

## Objective
Check if URL matches SIEM threat intelligence feeds.

## Inputs
*   `URL`: Target URL.

## Core Steps

1. **Execute Action:**
   * Check if `URL` matches active SIEM threat intelligence feeds.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
