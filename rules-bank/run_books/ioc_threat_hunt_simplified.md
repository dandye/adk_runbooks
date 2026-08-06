---
type: "Playbook"
title: "IOC Threat Hunt Runbook (Simplified)"
description: "Simplified plain-English runbook to hunt for specific IOC lists across enterprise telemetry."
resource: "adk_runbooks/rules-bank/run_books/ioc_threat_hunt_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "IOC"
    - "IP address"
    - "domain"
    - "file hash"
    - "URL"
    - "SIEM"
    - "data lake"
    - "SOAR case"
  technical_verbs:
    - "enrich"
    - "isolate"
    - "triage"
---

# IOC Threat Hunt Runbook

## Objective
Hunt for a batch of Indicators of Compromise (IOCs) across SIEM events and historical data lakes.

## Inputs
*   `IOC_LIST`: List of IP addresses, domains, file hashes, or URLs to hunt.
*   `LOOKBACK_DAYS`: Search period in days.

## Core Steps

1. Ingest and Validate IOC List:
   * Validate IOC formats and enrich indicators with threat intelligence tools.

2. Search SIEM Telemetry:
   * Run bulk queries across network, process, DNS, and HTTP events matching `IOC_LIST`.

3. Search Historical Data Lake:
   * Query long-term historical security logs in the Data Lake for older matches.

4. Summarize Matches and Actions:
   * Document all matched hosts and users in the SOAR case and recommend containment.
