---
type: "Playbook"
title: "Atomic: Hash GTI Report (Simplified)"
description: "Query GTI for file hash reputation and malware classification."
resource: "adk_runbooks/rules-bank/atomic_runbooks/hash/rb_hash_get_gti_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "file hash"
    - "GTI"
    - "malware"
  technical_verbs:
    - "enrich"
---

# Atomic: Hash GTI Report

## Objective
Query GTI for file hash reputation and malware classification.

## Inputs
*   `FILE_HASH`: MD5, SHA1, or SHA256 file hash.

## Core Steps

1. **Execute Action:**
   * Query GTI for `FILE_HASH` malware family, detection ratio, and threat tags.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
