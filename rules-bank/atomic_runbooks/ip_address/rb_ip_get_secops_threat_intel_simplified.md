---
type: "Playbook"
title: "Atomic: IP Address Threat Intel Lookup (Simplified)"
description: "Check if IP address matches SIEM threat intelligence feeds."
resource: "adk_runbooks/rules-bank/atomic_runbooks/ip_address/rb_ip_get_secops_threat_intel_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IP address"
    - "SIEM"
    - "threat intelligence"
  technical_verbs:
    - "enrich"
---

# Atomic: IP Address Threat Intel Lookup

## Objective
Check if IP address matches SIEM threat intelligence feeds.

## Inputs
*   `IP_ADDRESS`: IP address.

## Core Steps

1. **Execute Action:**
   * Check if `IP_ADDRESS` matches active SIEM threat intelligence feeds.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
