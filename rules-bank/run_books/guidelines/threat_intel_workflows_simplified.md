---
type: "Playbook"
title: "Threat Intelligence Workflows Guide (Simplified)"
description: "Simplified plain-English guide for Cyber Threat Intelligence research and profiling."
resource: "adk_runbooks/rules-bank/run_books/guidelines/threat_intel_workflows_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "threat intelligence"
    - "CTI"
    - "threat actor"
    - "campaign"
    - "TTP"
    - "IOC"
  technical_verbs:
    - "enrich"
    - "triage"
---

# Threat Intelligence Workflows Guide

## Objective
Outline core workflows for Cyber Threat Intelligence (CTI) analysts to profile threats and support SOC operations.

## Inputs
*   `INTEL_SOURCE`: Threat intelligence feed, report, or collection.

## Core Steps

1. Ingest Threat Intelligence:
   * Extract actor profiles, MITRE ATT&CK techniques, and IOCs from threat reports.

2. Proactive IOC & TTP Hunting:
   * Pass intelligence to threat hunting runbooks to search for internal matches.

3. Detection Rule Feedback:
   * Collaborate with detection engineers to deploy detection rules for new techniques.
