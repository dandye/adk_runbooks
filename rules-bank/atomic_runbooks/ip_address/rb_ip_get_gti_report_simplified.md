---
type: "Playbook"
title: "Atomic: IP Address GTI Report (Simplified)"
description: "Query GTI for IP address reputation and threat classification."
resource: "adk_runbooks/rules-bank/atomic_runbooks/ip_address/rb_ip_get_gti_report_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IP address"
    - "GTI"
    - "reputation"
  technical_verbs:
    - "enrich"
---

# Atomic: IP Address GTI Report

## Objective
Query GTI for IP address reputation and threat classification.

## Inputs
*   `IP_ADDRESS`: IP address.

## Core Steps

1. **Execute Action:**
   * Query GTI for `IP_ADDRESS` reputation score, country, and ASN.
2. **Return Output:**
   * Return structured output data to the calling runbook or agent.
