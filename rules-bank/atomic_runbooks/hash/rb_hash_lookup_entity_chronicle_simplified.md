---
type: "Playbook"
title: "Atomic: Hash Entity Lookup (Simplified)"
description: "Lookup file hash entity summary in Chronicle SIEM."
resource: "adk_runbooks/rules-bank/atomic_runbooks/hash/rb_hash_lookup_entity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "file hash"
    - "SIEM"
    - "entity"
  technical_verbs:
    - "enrich"
---

# Atomic: Hash Entity Lookup

## Objective
Lookup file hash entity summary in Chronicle SIEM.

## Inputs
*   `FILE_HASH`: File hash.

## Core Steps

1. **Execute Action:**
   * Lookup `FILE_HASH` in Chronicle SIEM entity table.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
