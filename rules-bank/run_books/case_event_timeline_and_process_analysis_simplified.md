---
type: "Playbook"
title: "Case Event Timeline and Process Analysis Runbook (Simplified)"
description: "Simplified plain-English runbook to construct event timelines and analyze process trees."
resource: "adk_runbooks/rules-bank/run_books/case_event_timeline_and_process_analysis_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "timeline"
    - "process tree"
    - "command line"
    - "SIEM"
    - "SOAR case"
    - "endpoint"
  technical_verbs:
    - "triage"
---

# Case Event Timeline and Process Analysis Runbook

## Objective
Construct a chronological event timeline and analyze process execution trees for an incident.

## Inputs
*   `CASE_ID`: SOAR case ID.
*   `TIME_FRAME_HOURS`: Lookback window in hours.

## Core Steps

1. Extract Case Timestamps and Entities:
   * Get first seen and last seen timestamps and all affected hosts/users from `CASE_ID`.

2. Build Chronological Event Timeline:
   * Query SIEM events across authentication, network, and process logs to build a chronological timeline.

3. Analyze Process Execution Trees:
   * Inspect parent-child process relationships, command-line arguments, and spawning binaries.

4. Document Findings:
   * Document the attack sequence, root cause process, and timeline in the SOAR case.
