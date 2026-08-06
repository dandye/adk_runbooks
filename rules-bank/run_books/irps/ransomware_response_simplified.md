---
type: "Playbook"
title: "Ransomware Incident Response Plan (Simplified)"
description: "Simplified plain-English incident response plan to investigate, contain, eradicate, and recover from a suspected ransomware incident."
resource: "adk_runbooks/rules-bank/run_books/irps/ransomware_response_simplified.md"
timestamp: "2026-08-05T21:48:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:48:00Z"
ste_vocabulary:
  technical_names:
    - "ransomware"
    - "lateral movement"
    - "initial access"
    - "persistence mechanism"
    - "decryptor"
    - "SOAR case"
    - "endpoint"
    - "security control"
  technical_verbs:
    - "isolate"
    - "re-image"
    - "patch"
    - "contain"
    - "eradicate"
---

# Ransomware Incident Response Plan

## Objective
Investigate, contain, eradicate, and recover from a suspected ransomware incident.

## Core Response Steps

1. **Identification:**
   * Get case details and check for duplicate incident reports.
   * Identify the ransomware strain and family with threat intelligence tools or file hash lookups.
   * Search SIEM events to find the initial access method, lateral movement, and affected endpoints.
   * Identify malicious network indicators and affected user accounts.

2. **Containment:**
   * Isolate affected endpoints immediately to stop lateral movement.
   * Block malicious network IP addresses and domains with SOAR tools.
   * Disable or restrict compromised user accounts from the initial access.

3. **Eradication:**
   * Find persistence mechanisms (scheduled tasks, registry keys, services) linked to the ransomware.
   * Clean or re-image infected hosts to remove all malicious files.

4. **Recovery:**
   * Restore affected systems from verified clean backups or official decryptors.
   * Install security patches before you connect hosts to the network.

5. **Documentation and Lessons Learned:**
   * Record all containment actions and evidence in the SOAR case.
   * Document post-incident findings and update security controls.
