---
type: "Playbook"
title: "Atomic: IP Address Network Traffic Search (Simplified)"
description: "Search Chronicle SIEM for network traffic with an IP address."
resource: "adk_runbooks/rules-bank/atomic_runbooks/ip_address/rb_ip_search_network_traffic_chronicle_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IP address"
    - "network connection"
    - "SIEM"
  technical_verbs:
    - "triage"
---

# Atomic: IP Address Network Traffic Search

## Objective
Search Chronicle SIEM for network traffic with an IP address.

## Inputs
*   `IP_ADDRESS`: IP address.

## Core Steps

1. **Execute Action:**
   * Search SIEM network events for outbound or inbound traffic with `IP_ADDRESS`.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
