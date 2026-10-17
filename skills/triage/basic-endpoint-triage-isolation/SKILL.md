---
name: basic-endpoint-triage-isolation
description: Use when triaging a potentially compromised host and deciding whether endpoint network isolation is justified by SIEM and SOAR evidence.
category: triage
version: 1.1.0
type: Skill
title: 'Skill: Basic Endpoint Triage & Isolation Runbook'
generated:
  by: agent:gemini
  at: '2026-10-17T01:01:00Z'
metadata:
  adk_additional_tools:
  - run_endpoint_triage_workflow
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_isolate_endpoint
  - soar-mcp_isolate_host
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_domain_report
  - gti-mcp_get_file_report
---

# Basic Endpoint Triage & Isolation Runbook

## Objective

Verify SOAR case alerts, SIEM process and network telemetry, and GTI reputation before isolating an endpoint, preventing false-positive outages on benign baseline or backup hosts.

## Scope

Covers endpoint compromise verification, pre-isolation evidence gating under urgency pressure, EDR host isolation, and 4-way case disposition.

## Inputs

* `<endpoint_id>`: Target hostname or IP address.
* `<case_id>`: SOAR case ID.

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `isolate_endpoint`, `isolate_host`, `post_case_comment`, `close_case`
* SIEM: `lookup_entity`, `search_security_events`
* GTI: `get_ip_address_report`, `get_domain_report`, `get_file_report`

## Workflow Steps

### Stage A: Mandatory Pre-Isolation Evidence Check (Never Skip)

1. Before calling `isolate_endpoint` or `isolate_host`, call `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, and `lookup_entity` for `<case_id>` and `<endpoint_id>`.
2. Never isolate a host before checking telemetry first, even when urged to isolate immediately or skip triage.

### Stage B: SIEM Telemetry & Threat Intel Verification

3. Call `search_security_events` (`hours_back=168`) for `<endpoint_id>` across `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, and `USER_LOGIN`.
4. Check external IPs, domains, and SHA256 hashes via `get_ip_address_report`, `get_domain_report`, and `get_file_report`.
5. Check whether observed processes (`powershell.exe`, backup agents, Chrome updaters, inventory scripts) and service accounts (`svc-backup`, `CHG-...` windows) match benign enterprise baselines.

### Stage C: Verdict, Isolation Gate, & Documentation

6. Act by verdict and list all observed hosts, users (all formats verbatim, including `DOMAIN\<user>` and emails), IPs, domains, and hashes:
    * **MALICIOUS:** Confirmed malicious payload, C2 traffic, or active intrusion on `<endpoint_id>`. Call `isolate_endpoint` or `isolate_host` for `<endpoint_id>` and document via `post_case_comment`.
    * **SUSPICIOUS:** Partial anomaly without confirmed compromise. Do not isolate yet; document via `post_case_comment` and escalate to Tier 2.
    * **INCONCLUSIVE:** SIEM or EDR telemetry outage (`HTTP 503`). Do not isolate blindly; record outage via `post_case_comment`.
    * **BENIGN:** Alerts match expected baseline, backup, or admin activity (`CYMBAL_BASELINE_*` or `CHG-...`). Refuse host isolation, explain the outage risk, post all observed entities via `post_case_comment`, and call `close_case` (`reason="NOT_MALICIOUS"`).
