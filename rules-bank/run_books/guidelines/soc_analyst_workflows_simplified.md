---
type: "Playbook"
title: "SOC Analyst Standard Workflow Guide (Simplified)"
description: "Simplified plain-English navigation guide for SOC analyst triage and escalation workflows."
resource: "adk_runbooks/rules-bank/run_books/guidelines/soc_analyst_workflows_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOC analyst"
    - "triage"
    - "escalation"
    - "SOAR case"
    - "incident response"
  technical_verbs:
    - "triage"
    - "escalate"
    - "isolate"
---

# SOC Analyst Standard Workflow Guide

## Objective
Guide SOC analysts through the standard lifecycle from alert ingestion to case resolution.

## Inputs
*   `ANALYST_TIER`: Tier 1 (Triage), Tier 2 (Investigation), or Tier 3 (Incident Response).

## Core Steps

1. Tier 1 Workflow (Triage):
   * Assess incoming alerts, enrich IOCs, close false positives, and escalate true positives.

2. Tier 2 Workflow (Investigation & Containment):
   * Conduct deep event correlation, identify root cause, and execute confirmed containment.

3. Tier 3 Workflow (Remediation & PIR):
   * Coordinate incident eradication, system recovery, and post-incident reviews.
