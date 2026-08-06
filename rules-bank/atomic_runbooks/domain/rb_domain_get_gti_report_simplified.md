---
type: "Playbook"
title: "Atomic: Domain GTI Report (Simplified)"
description: "Query GTI to get reputation and category for a domain."
resource: "adk_runbooks/rules-bank/atomic_runbooks/domain/rb_domain_get_gti_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "domain"
    - "GTI"
    - "reputation"
  technical_verbs:
    - "enrich"
---

# Atomic: Domain GTI Report

## Objective
Query GTI to get reputation and category for a domain.

## Inputs
*   `DOMAIN`: Domain name.

## Core Steps

1. **Execute Action:**
   * Query GTI for `DOMAIN` reputation, maliciousness score, and category.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
