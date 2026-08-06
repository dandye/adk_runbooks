---
type: "Playbook"
title: "Atomic: Domain Network Traffic Search (Simplified)"
description: "Search Chronicle SIEM for network connections to a domain."
resource: "adk_runbooks/rules-bank/atomic_runbooks/domain/rb_domain_search_network_traffic_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "domain"
    - "network connection"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: Domain Network Traffic Search

## Objective
Search Chronicle SIEM for network connections to a domain.

## Inputs
*   `DOMAIN`: Domain name.

## Core Steps

1. **Execute Action:**
   * Search SIEM network traffic logs for connections to `DOMAIN`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
