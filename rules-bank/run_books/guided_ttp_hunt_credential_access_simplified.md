---
type: "Playbook"
title: "Guided TTP Hunt: Credential Access Runbook (Simplified)"
description: "Simplified plain-English runbook to hunt for MITRE ATT&CK Credential Access techniques."
resource: "adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "Credential Access"
    - "LSASS"
    - "SAM registry"
    - "NTDS.dit"
    - "MITRE ATT&CK"
    - "SIEM"
    - "endpoint"
  technical_verbs:
    - "triage"
    - "isolate"
---

# Guided TTP Hunt: Credential Access Runbook

## Objective
Hunt for signs of Credential Access techniques, including LSASS memory dumping and credential file access.

## Inputs
*   `TIME_WINDOW_DAYS`: Lookback window in days (default: 7).

## Core Steps

1. Search Process Access to LSASS:
   * Search SIEM process events for non-system processes accessing `lsass.exe` with memory read permissions.

2. Search Registry & Shadow Copy Access:
   * Search command-line events for access to SAM, SECURITY registry hives, or `vssadmin` shadow copy deletions.

3. Search Active Directory Dumping Tools:
   * Search process execution logs for known credential tools (for example, `mimikatz`, `secretsdump`, `procdump`).

4. Document and Escalate:
   * Document confirmed credential dumping attempts and isolate affected endpoints immediately.
