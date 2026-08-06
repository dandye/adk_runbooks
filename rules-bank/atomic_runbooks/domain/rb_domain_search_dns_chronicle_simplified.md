---
type: "Playbook"
title: "Atomic: Domain DNS Event Search (Simplified)"
description: "Search Chronicle SIEM for DNS resolution events for a domain."
resource: "adk_runbooks/rules-bank/atomic_runbooks/domain/rb_domain_search_dns_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "domain"
    - "DNS event"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: Domain DNS Event Search

## Objective
Search Chronicle SIEM for DNS resolution events for a domain.

## Inputs
*   `DOMAIN`: Domain name.

## Core Steps

1. **Execute Action:**
   * Search SIEM DNS query logs for requests resolving `DOMAIN`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
