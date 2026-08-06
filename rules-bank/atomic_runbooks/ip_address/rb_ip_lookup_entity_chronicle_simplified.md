---
type: "Playbook"
title: "Atomic: IP Address Entity Lookup (Simplified)"
description: "Lookup IP address entity summary in Chronicle SIEM."
resource: "adk_runbooks/rules-bank/atomic_runbooks/ip_address/rb_ip_lookup_entity_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IP address"
    - "SIEM"
    - "entity"
  technical_verbs:
    - "enrich"
---

# Atomic: IP Address Entity Lookup

## Objective
Lookup IP address entity summary in Chronicle SIEM.

## Inputs
*   `IP_ADDRESS`: IP address.

## Core Steps

1. **Execute Action:**
   * Lookup `IP_ADDRESS` in Chronicle SIEM entity summary.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
