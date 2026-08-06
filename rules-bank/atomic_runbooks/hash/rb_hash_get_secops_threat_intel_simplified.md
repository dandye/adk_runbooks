---
type: "Playbook"
title: "Atomic: Hash Threat Intel Lookup (Simplified)"
description: "Check if file hash matches SIEM threat intelligence feeds."
resource: "adk_runbooks/rules-bank/atomic_runbooks/hash/rb_hash_get_secops_threat_intel_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "file hash"
    - "SIEM"
    - "threat intelligence"
  technical_verbs:
    - "enrich"
---

# Atomic: Hash Threat Intel Lookup

## Objective
Check if file hash matches SIEM threat intelligence feeds.

## Inputs
*   `FILE_HASH`: File hash.

## Core Steps

1. **Execute Action:**
   * Check if `FILE_HASH` matches active SIEM threat intelligence feeds.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
