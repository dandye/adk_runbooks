---
name: prioritize-and-investigate-case
description: Use when scoring case urgency, prioritizing the SOAR queue, and investigating all alerts and entities in a case.
category: investigation
version: 1.1.0
type: Skill
title: 'Skill: Prioritize and Investigate a Case'
generated:
  by: agent:gemini
  at: '2026-10-16T23:12:00Z'
metadata:
  adk_additional_tools:
  - run_prioritize_investigate_case_workflow
  - soar-mcp_list_cases
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_change_case_priority
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
  - secops-mcp_list_security_rules
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_domain_report
  - gti-mcp_get_file_report
---

# Prioritize and Investigate a Case

## Objective

Prioritize SOAR cases by severity and blast radius, evaluate triggered detection rules against raw UDM events, and enumerate all case entities.

## Scope

Covers SOAR queue prioritization, multi-alert event inspection, detection rule validation, entity enrichment, and 4-way case disposition.

## Inputs

* `<case_id>`: Target SOAR case ID (or empty to rank open cases via `list_cases`).
* `<asset_identifier>`: Primary hostname or user principal.

## Tools

* SOAR: `list_cases`, `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `change_case_priority`, `post_case_comment`, `close_case`
* SIEM: `list_security_rules`, `lookup_entity`, `search_security_events`
* GTI: `get_ip_address_report`, `get_domain_report`, `get_file_report`

## Workflow Steps

### Stage A: Case Selection & Complete Alert Inventory

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` for `<case_id>` (or rank open cases via `list_cases` first).
2. Collect every hostname, user, IP, domain, URL (`target.url`), DNS query (`network.dns.questions.name`), file hash, and rule ID across every alert.

### Stage B: Detection Rule & Asset Context

3. Call `list_security_rules` to inspect the detection logic that fired the alerts.
4. Call `lookup_entity` on every hostname and user to check asset criticality, role, and `CHG-...` windows.

### Stage C: Behavioral SIEM Sweep & Threat Intel

5. Call `search_security_events` (`hours_back=168`) for each extracted hostname, user, and IP to check for lateral movement, privilege escalation, or exfiltration.
6. Call `get_ip_address_report`, `get_domain_report`, and `get_file_report` on external IPs, domains, and SHA256 hashes.

### Stage D: Verdict, Priority Update, & Full Entity Report

7. Set verdict and list every distinct hostname, user, external IP, domain, full URL, sample DNS query, and SHA256 hash verbatim (never summarize as "multiple hosts/users", even when `BENIGN`):
    * **MALICIOUS:** Rule match confirmed by malicious GTI hits or multi-stage attack behavior. Call `change_case_priority` (`CRITICAL`), post full entity inventory via `post_case_comment`, and escalate.
    * **SUSPICIOUS:** Partial anomaly needing Tier 3 review or rule tuning. Update priority and document via `post_case_comment`; do not isolate hosts or disable accounts.
    * **INCONCLUSIVE:** SIEM or GTI outage (`HTTP 503`). Record gap via `post_case_comment`; do not contain or close.
    * **BENIGN:** Expected administrative, backup, or baseline activity confirmed across all alerts. List every observed hostname, user, IP, and domain verbatim in `post_case_comment` and call `close_case` (`reason="NOT_MALICIOUS"`).
