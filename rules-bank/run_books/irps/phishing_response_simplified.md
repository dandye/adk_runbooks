---
type: "Playbook"
title: "Phishing Incident Response Plan (Simplified)"
description: "Simplified plain-English incident response plan to investigate phishing emails, enrich indicators, contain threats, and remove malicious messages."
resource: "adk_runbooks/rules-bank/run_books/irps/phishing_response_simplified.md"
timestamp: "2026-08-05T21:48:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:48:00Z"
ste_vocabulary:
  technical_names:
    - "phishing"
    - "Credential Harvesting"
    - "Spear Phishing"
    - "BEC"
    - "Brand Impersonation"
    - "Malware Delivery"
    - "MFA"
    - "mailbox"
    - "SOAR case"
    - "header artifact"
    - "URL"
    - "IP address"
    - "domain"
    - "file hash"
    - "endpoint"
  technical_verbs:
    - "quarantine"
    - "isolate"
    - "enrich"
    - "authenticate"
---

# Phishing Incident Response Plan

## Objective
Investigate phishing emails, enrich indicators, contain threats, and remove malicious messages.

## Core Response Steps

1. **Identification and Analysis:**
   * Get reported email details and header data from the SOAR case.
   * Extract sender domains, IP addresses, attached file hashes, and URLs.
   * Enrich extracted indicators with threat intelligence tools.
   * Classify the phishing type (for example, Credential Harvesting, Spear Phishing, BEC, Brand Impersonation, or Malware Delivery).
   * Search SIEM logs for users who received similar emails, clicked links, or downloaded attachments.

2. **Containment:**
   * Block malicious URLs, domains, and IP addresses across network controls.
   * Reset passwords and require MFA authentication for exposed user accounts.
   * Isolate endpoints that show suspicious activity after a link click.

3. **Eradication:**
   * Delete or quarantine matching phishing messages in user mailboxes.
   * Remove any malware dropped from phishing links or attachments.

4. **Recovery and Documentation:**
   * Restore user account access after you verify system security.
   * Document key findings, affected users, and containment actions in the SOAR case.
