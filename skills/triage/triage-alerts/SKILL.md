---
name: triage-alerts
description: Use when evaluating and categorizing incoming security alerts to determine severity, entity scope, and initial response actions.
category: triage
version: 1.1.0
type: Skill
title: 'Skill: Alert Triage'
generated:
  by: agent:gemini
  at: '2026-10-16T23:12:00Z'
metadata:
  adk_additional_tools:
  - run_triage_alerts_workflow
  - run_demo_soc_t2_workflow
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - secops-mcp_get_ioc_matches
  - gti-mcp_get_file_report
  - gti-mcp_get_domain_report
  - gti-mcp_get_ip_address_report
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_change_case_priority
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
---

# Alert Triage

## Objective

Assess SOAR cases and alerts, enrich all involved entities across SIEM and GTI, and decide whether to escalate or close as benign.

## Scope

Covers initial alert review, duplicate checks, full entity inventory across all alerts, SIEM sweeps, and 4-way triage disposition.

## Inputs

* `<case_id>`: SOAR case or alert identifier.
* `<asset_identifier>`: Primary hostname, IP, or user principal in the alert.

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `change_case_priority`, `post_case_comment`, `close_case`
* SIEM: `search_security_events`, `lookup_entity`, `get_ioc_matches`
* GTI: `get_file_report`, `get_domain_report`, `get_ip_address_report`

## Workflow Steps

### Stage A: Full Case & Alert Entity Inventory

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to extract every alert rule name, severity, hostname, user, IP, domain, URL (`target.url`), DNS query (`network.dns.questions.name`), and SHA256 hash across all alerts.
2. Call `lookup_entity` on `<asset_identifier>` to check asset role, criticality, and `CHG-...` windows.

### Stage B: Alert-Specific SIEM Sweep

3. Call `search_security_events` (`hours_back=168`) for all extracted hostnames, users, IPs, domains, and hashes across `USER_LOGIN`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, and `NETWORK_DNS` to check for corroborating activity.
4. Decode Base64 command-line flags (`-enc`, `-EncodedCommand`) before classifying dual-use tools (`powershell.exe`, `wmic.exe`, `rundll32.exe`).

### Stage C: Threat Intelligence Reputation Check

5. Call `get_ip_address_report`, `get_domain_report`, or `get_file_report` on every external IP, domain, and file hash found in Stage A and Stage B.

### Stage D: Disposition, Action, & Mandatory Entity Listing

6. Classify and list every distinct hostname, user, external IP, domain, full URL, sample DNS query, and SHA256 hash verbatim in the final summary (never summarize as "multiple hosts/users", even when `BENIGN`):
    * **MALICIOUS:** Corroborated compromise across SIEM events and GTI reputation. Call `change_case_priority` (`HIGH`/`CRITICAL`), document all entities via `post_case_comment`, and escalate for containment.
    * **SUSPICIOUS:** Unverified anomaly without second-source corroboration. Document via `post_case_comment` and escalate to Tier 2; do not isolate hosts or disable accounts.
    * **INCONCLUSIVE:** Telemetry or API outage (`HTTP 503`). Record gap via `post_case_comment`; execute zero destructive actions.
    * **BENIGN:** Verified IT/EDR/backup administration, `CHG-...` maintenance, or clean baseline noise with zero malicious GTI hits. Call `post_case_comment` listing every observed host, user, IP, and domain verbatim, then call `close_case` (`reason="NOT_MALICIOUS"`). Execute zero containment actions.
