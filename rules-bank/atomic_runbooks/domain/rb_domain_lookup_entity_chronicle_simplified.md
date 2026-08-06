---
type: "Playbook"
title: "Atomic: Domain Entity Lookup (Simplified)"
description: "Lookup domain summary and activity profile in Chronicle SIEM."
resource: "adk_runbooks/rules-bank/atomic_runbooks/domain/rb_domain_lookup_entity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "domain"
    - "SIEM"
    - "entity"
  technical_verbs:
    - "enrich"
---

# Atomic: Domain Entity Lookup

## Objective
Lookup domain summary and activity profile in Chronicle SIEM.

## Inputs
*   `DOMAIN`: Domain name.

## Core Steps

1. **Execute Action:**
   * Lookup `DOMAIN` in Chronicle SIEM entity summary.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
