---
type: "Playbook"
title: "Suspicious Login Alert Triage Runbook (Simplified)"
description: "Simplified plain-English runbook to triage anomalous login and authentication alerts."
resource: "adk_runbooks/rules-bank/run_books/suspicious_login_triage_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "user account"
    - "IP address"
    - "MFA"
    - "SIEM"
    - "SOAR case"
    - "impossible travel"
    - "anomaly"
  technical_verbs:
    - "triage"
    - "isolate"
    - "escalate"
    - "authenticate"
---

# Suspicious Login Alert Triage Runbook

## Objective
Triage suspicious login alerts to verify whether authentication was authorized or malicious.

## Inputs
*   `USER_ID`: Target user account.
*   `SOURCE_IP`: Source IP address of the login attempt.
*   `CASE_ID`: SOAR case ID for documentation.

## Core Steps

1. Analyze Authentication Context:
   * Get login time, source IP address, geolocation, user agent, and MFA result from the SIEM.

2. Check User Baseline & Travel History:
   * Compare source location with previous user authentication history to detect impossible travel.

3. Enrich Source IP Address:
   * Query GTI threat intelligence to check if `SOURCE_IP` is a VPN, proxy, Tor node, or malicious host.

4. Check Post-Authentication Activity:
   * Search SIEM events for anomalous actions immediately following login.

5. Determine Verdict and Document:
   * Classify alert as True Positive (compromised) or False Positive (benign).
   * Document the verdict in the SOAR case and trigger password reset if compromised.
