---
type: "Playbook"
title: "Lateral Movement Hunt: PsExec and WMI Runbook (Simplified)"
description: "Simplified plain-English runbook to hunt for adversary lateral movement via PsExec and WMI."
resource: "adk_runbooks/rules-bank/run_books/lateral_movement_hunt_psexec_wmi_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "lateral movement"
    - "PsExec"
    - "WMI"
    - "command line"
    - "SMB"
    - "SIEM"
    - "endpoint"
  technical_verbs:
    - "triage"
    - "isolate"
---

# Lateral Movement Hunt: PsExec and WMI Runbook

## Objective
Hunt for adversary lateral movement using administrative tools including PsExec and WMI.

## Inputs
*   `TIME_WINDOW_DAYS`: Lookback period in days (default: 7).

## Core Steps

1. Search PsExec Service Installations:
   * Search SIEM Windows System event logs for service installation events matching `PSEXESVC` or named pipes.

2. Search Remote WMI Executions:
   * Search SIEM process creation events for `wmic.exe` or PowerShell executing remote process calls (`Win32_Process`).

3. Trace Source and Destination Hosts:
   * Correlate SMB network traffic with authentication logs to identify source and target systems.

4. Document Findings:
   * Document lateral movement paths in a SOAR case and isolate compromised source endpoints.
