---
name: suspicious-login-triage
description: Use when triaging anomalous or suspicious user authentication events, impossible travel, MFA anomalies, and credential abuse.
category: triage
version: 1.1.0
type: Skill
title: 'Skill: Suspicious Login Alert Triage Runbook'
generated:
  by: agent:adk-runbooks-rsi
  at: '2026-10-17T00:16:00Z'
metadata:
  adk_additional_tools:
  - run_suspicious_login_workflow
  - run_suspicious_login_triage_workflow
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - scc-mcp_lookup_cloud_iam_principal
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
  - soar-mcp_block_indicator
  - gti-mcp_get_ip_address_report
---

# Suspicious Login Alert Triage Runbook

## Objective
Triage suspicious authentication alerts across IdP, SaaS, cloud, and Windows logs to distinguish credential compromise from benign travel or VPN usage.

## Scope
Covers reactive triage of `USER_LOGIN` and authentication alerts (`OKTA`, `DUO_AUTH`, `AZURE_AD`, `OFFICE_365`, `WORKSPACE_ACTIVITY`, `GCP_CLOUDAUDIT`, `WINEVTLOG`). Does not cover malware eradication.

## Inputs
- `<case_id>`: SOAR case identifier containing the login alert(s).
- `<user_or_ip>`: Primary username, email, NetBIOS account, or source IP.

## Tools
- **SOAR**: `soar-mcp_get_case_full_details`, `soar-mcp_list_alerts_by_case`, `soar-mcp_list_events_by_alert`, `soar-mcp_post_case_comment`, `soar-mcp_block_indicator`
- **SIEM & IAM**: `secops-mcp_lookup_entity`, `secops-mcp_search_security_events`, `scc-mcp_lookup_cloud_iam_principal`
- **GTI**: `gti-mcp_get_ip_address_report`

## Workflow Steps
- **Stage A (Case & Entity Extraction)**:
  1. Call `soar-mcp_get_case_full_details(<case_id>)`, `soar-mcp_list_alerts_by_case(<case_id>)`, and `soar-mcp_list_events_by_alert` for every case alert.
  2. Call `secops-mcp_lookup_entity` and `scc-mcp_lookup_cloud_iam_principal` on each user and host to check privileges and login baselines.
  3. Record every user principal in all observed formats verbatim, including `DOMAIN\<user>` NetBIOS names alongside `<user>@<domain>` emails and short usernames.
- **Stage B (Source IP Scope & Reputation)**:
  1. Check if each login source IP is internal RFC1918, corporate VPN egress, residential proxy, or external hosting.
  2. Call `gti-mcp_get_ip_address_report` on every external source IP to check reputation and threat associations.
- **Stage C (Authentication Timeline & Post-Login Pivots)**:
  1. Call `secops-mcp_search_security_events` over `hours_back=168` for `<user_or_ip>` across IdP, cloud, and endpoint logs.
  2. Check for password spray bursts, MFA push bombing, helpdesk MFA resets, rogue admin creation, RMM execution, or cloud token assumption after login.
- **Stage D (Disposition & Action Matrix)**:
  - **MALICIOUS**: Malicious source IP or unauthorized MFA reset, lateral jump, rogue admin creation, or data access confirmed. Block confirmed malicious external IPs via `soar-mcp_block_indicator`, recommend session revocation, and post full timeline via `soar-mcp_post_case_comment`.
  - **SUSPICIOUS**: Unrecognized external IP without malicious GTI reputation or post-login abuse. Escalate via `soar-mcp_post_case_comment`; do not lock accounts or close.
  - **INCONCLUSIVE**: Missing IdP telemetry or API timeout prevents verification. Document gaps via `soar-mcp_post_case_comment`; do not contain or close.
  - **BENIGN**: Login matches corporate VPN, known travel, or routine service-account baseline. Post closure note via `soar-mcp_post_case_comment` listing every observed host, user format, and IP.
