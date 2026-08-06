---
type: "Playbook"
title: "Compromised User Account Incident Response Plan (Simplified)"
description: "Simplified plain-English incident response plan to investigate, contain, and remediate compromised user accounts."
resource: "adk_runbooks/rules-bank/run_books/irps/compromised_user_account_response_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "user account"
    - "MFA"
    - "session token"
    - "audit log"
    - "SOAR case"
    - "endpoint"
  technical_verbs:
    - "revoke"
    - "isolate"
    - "authenticate"
    - "contain"
    - "eradicate"
---

# Compromised User Account Incident Response Plan

## Objective
Investigate, contain, and remediate incidents that involve a compromised user account.

## Inputs
*   `USER_ID`: Username or email address of the affected user.
*   `CASE_ID`: SOAR case ID for tracking and documentation.

## Core Steps

1. Identification & Analysis:
   * Get user activity logs and authentication events from the SIEM.
   * Identify suspicious logins (anomalous IP addresses, impossible travel, or MFA fatigue).
   * Search process executions and data access events initiated by the user account.

2. Containment:
   * Revoke active session tokens and reset the user password immediately.
   * Enforce MFA re-authentication for all user devices.
   * Isolate endpoints with active malicious sessions.

3. Eradication:
   * Remove unauthorized OAuth applications, inbox forwarding rules, and delegate permissions.
   * Terminate all active unauthorized remote sessions.

4. Recovery & Documentation:
   * Restore user access after you verify account integrity.
   * Record all containment actions and findings in the SOAR case.
