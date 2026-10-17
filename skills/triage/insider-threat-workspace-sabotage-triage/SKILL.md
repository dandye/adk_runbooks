---
name: insider-threat-workspace-sabotage-triage
description: Use when triaging insider sabotage, backup deletion, source code theft, Google Workspace Drive/Gmail exfiltration, MFA push bombing, helpdesk social engineering, or illicit OAuth app consent.
category: triage
version: 1.0.0
type: Skill
title: "Skill: Insider Threat, Workspace Exfiltration & Identity Abuse Triage"
generated:
  by: agent:adk-runbooks-rsi
  at: "2026-10-17T00:15:00Z"
metadata:
  adk_additional_tools:
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - secops-mcp_list_security_rules
  - secops-mcp_validate_yaral2_rule
  - scc-mcp_lookup_cloud_iam_principal
  - scc-mcp_list_scc_findings
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
  - soar-mcp_block_indicator
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_domain_report
---

# Insider Threat, Workspace Exfiltration & Identity Abuse Triage

## Objective
Triage insider sabotage, source-code or Workspace exfiltration, MFA push bombing, helpdesk social engineering, and illicit OAuth consent across SIEM, IAM, GTI, and SOAR.

## Scope
Covers reactive triage of identity, SaaS, and cloud audit alerts (`WORKSPACE_ACTIVITY`, `GMAIL_LOGS`, `GITHUB`, `GCP_CLOUDAUDIT`, `AWS_CLOUDTRAIL`, `OKTA`, `DUO_AUTH`, `AZURE_AD`, `OFFICE_365`, `WINEVTLOG`).

## Inputs
- `<case_id>`: SOAR case identifier.
- `<principal_or_host>`: Initial user email, NetBIOS account, service account, or host.

## Tools
- **SOAR**: `soar-mcp_get_case_full_details`, `soar-mcp_list_alerts_by_case`, `soar-mcp_list_events_by_alert`, `soar-mcp_post_case_comment`, `soar-mcp_block_indicator`
- **SIEM & IAM**: `secops-mcp_search_security_events`, `secops-mcp_lookup_entity`, `secops-mcp_list_security_rules`, `secops-mcp_validate_yaral2_rule`, `scc-mcp_lookup_cloud_iam_principal`, `scc-mcp_list_scc_findings`
- **GTI**: `gti-mcp_get_ip_address_report`, `gti-mcp_get_domain_report`

## Workflow Steps
- **Stage A (Case, IAM & Entity Inventory)**:
  1. Call `soar-mcp_get_case_full_details(<case_id>)`, `soar-mcp_list_alerts_by_case(<case_id>)`, and `soar-mcp_list_events_by_alert` for every case alert.
  2. Call `scc-mcp_lookup_cloud_iam_principal` and `secops-mcp_lookup_entity` for `<principal_or_host>` to check role scope and rogue admin accounts.
  3. Record every user principal in all observed formats verbatim (`DOMAIN\<user>` NetBIOS names, `<user>@<domain>` emails, and short usernames).
- **Stage B (Caller IP & Network Scope)**:
  1. Classify caller IPs as corporate egress, VPN, residential proxy, or external hosting.
  2. Call `gti-mcp_get_ip_address_report` and `gti-mcp_get_domain_report` on external caller IPs, RMM domains, and storage endpoints.
- **Stage C (Destructive, Exfiltration & Identity Pivots)**:
  1. Call `secops-mcp_search_security_events` over `hours_back=168` for `<principal_or_host>` across cloud, SaaS, IdP, and Windows logs.
  2. Check for: (a) backup or snapshot deletion (`DeleteBackup`, `DeleteSnapshot`, `cloudsql.instances.delete`); (b) mass Google Drive download, external sharing, or GitHub cloning; (c) MFA push fatigue (`DUO_AUTH`) or helpdesk MFA reset; (d) rogue admin creation or illicit OAuth consent (`Mail.Read`, `Files.Read.All`).
  3. When rule checks are requested, call `secops-mcp_list_security_rules` and `secops-mcp_validate_yaral2_rule`.
- **Stage D (Disposition & Action Matrix)**:
  - **MALICIOUS**: Unauthorized backup deletion, mass exfiltration, MFA social engineering, rogue admin creation, or illicit OAuth consent confirmed. Block external attacker IPs/domains via `soar-mcp_block_indicator`, recommend credential revocation, and post timeline via `soar-mcp_post_case_comment`.
  - **SUSPICIOUS**: Anomalous bulk access without confirmed malice. Escalate via `soar-mcp_post_case_comment`; do not disable accounts or close.
  - **INCONCLUSIVE**: Telemetry gap or API error prevents attribution. Document gaps via `soar-mcp_post_case_comment`; do not contain or close.
  - **BENIGN**: Routine role-aligned workflow confirmed. Post summary via `soar-mcp_post_case_comment` listing every host, user format, and IP.
