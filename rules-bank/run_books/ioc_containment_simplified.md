---
type: "Playbook"
title: "IOC Containment Runbook (Simplified)"
description: "Simplified plain-English runbook to block malicious IOCs across security controls."
resource: "adk_runbooks/rules-bank/run_books/ioc_containment_simplified.md"
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
    - "URL"
    - "file hash"
    - "security control"
    - "firewall"
    - "SOAR case"
  technical_verbs:
    - "contain"
    - "isolate"
    - "quarantine"
---

# IOC Containment Runbook

## Objective
Execute rapid containment actions across firewalls, proxies, and EDR controls for malicious IOCs.

## Inputs
*   `IOC_VALUE`: Malicious indicator value.
*   `IOC_TYPE`: Type of indicator.
*   `CASE_ID`: SOAR case ID.

## Core Steps

1. Validate Containment Request:
   * Verify that `IOC_VALUE` has confirmed malicious reputation in threat intelligence.

2. Select Containment Target Controls:
   * Select appropriate controls: block IP/domain on firewall/proxy, or block hash on EDR.

3. Execute Blocking Action:
   * Run the SOAR containment action to add `IOC_VALUE` to blocklists.

4. Verify and Document:
   * Verify policy enforcement and log containment confirmation in the SOAR case.
