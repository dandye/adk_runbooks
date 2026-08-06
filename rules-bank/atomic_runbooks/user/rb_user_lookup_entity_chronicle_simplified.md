---
type: "Playbook"
title: "Atomic: User Entity Lookup (Simplified)"
description: "Lookup user account summary and profile in Chronicle SIEM."
resource: "adk_runbooks/rules-bank/atomic_runbooks/user/rb_user_lookup_entity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "user account"
    - "SIEM"
    - "entity"
  technical_verbs:
    - "enrich"
---

# Atomic: User Entity Lookup

## Objective
Lookup user account summary and profile in Chronicle SIEM.

## Inputs
*   `USER_ID`: User account identifier.

## Core Steps

1. **Execute Action:**
   * Lookup `USER_ID` in Chronicle SIEM entity directory.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
