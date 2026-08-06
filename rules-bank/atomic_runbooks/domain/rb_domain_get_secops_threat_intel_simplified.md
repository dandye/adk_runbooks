---
type: "Playbook"
title: "Atomic: Domain Threat Intel Lookup (Simplified)"
description: "Lookup domain reputation in SIEM threat intelligence feeds."
resource: "adk_runbooks/rules-bank/atomic_runbooks/domain/rb_domain_get_secops_threat_intel_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "domain"
    - "SIEM"
    - "threat intelligence"
  technical_verbs:
    - "enrich"
---

# Atomic: Domain Threat Intel Lookup

## Objective
Lookup domain reputation in SIEM threat intelligence feeds.

## Inputs
*   `DOMAIN`: Domain name.

## Core Steps

1. **Execute Action:**
   * Check if `DOMAIN` matches active SIEM threat intelligence feeds.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
