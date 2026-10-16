---
name: cloud-honeytoken-deception-triage
description: Use when triaging cloud honeytoken triggers, canary service accounts, decoy secrets, or unauthorized Vertex AI and cloud resource access.
category: triage
version: 1.0.0
type: Skill
title: 'Skill: Cloud Honeytoken and Deception Triage'
generated:
  by: agent:gemini
  at: '2026-10-16T23:10:00Z'
metadata:
  adk_additional_tools:
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - secops-mcp_list_security_rules
  - secops-mcp_validate_yaral2_rule
  - scc-mcp_list_scc_findings
  - scc-mcp_lookup_cloud_iam_principal
  - gti-mcp_get_ip_address_report
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_block_ioc
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
---

# Cloud Honeytoken and Deception Triage

## Objective

Triage cloud deception alerts, canary service accounts, decoy secret reads, and unauthorized cloud or Vertex AI usage across Chronicle SIEM, SCC, and GTI.

## Scope

Covers canary IAM principals, decoy Secret Manager secrets, decoy GCS buckets, Terraform state access, and unauthorized Vertex AI invocation (LLMjacking).

## Inputs

* `<case_id>`: SOAR case identifier.
* `<principal_email>`: Cloud IAM user or service account (`principal.user.email_addresses`).
* `<src_ip>`: Source IP address (`principal.ip`).

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `block_ioc`, `post_case_comment`, `close_case`
* Cloud & SCC: `lookup_cloud_iam_principal`, `list_scc_findings`
* SIEM & GTI: `search_security_events`, `lookup_entity`, `get_ip_address_report`, `list_security_rules`, `validate_yaral2_rule`

## Workflow Steps

### Stage A: Case & Canary Identity Context

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to extract every `<principal_email>`, `<src_ip>`, target cloud resource, and user agent.
2. Call `lookup_cloud_iam_principal` on `<principal_email>` to check `is_canary`, `canary_purpose`, and IAM roles, and call `list_scc_findings` for active findings on the project or principal.

### Stage B: Cloud Audit & SIEM Pivot

3. Call `search_security_events` (`hours_back=168`) for `<principal_email>` and `<src_ip>` across `USER_RESOURCE_ACCESS`, `RESOURCE_READ`, `USER_LOGIN`, and `GENERIC_EVENT` to trace caller IP, `network.http.user_agent`, API methods (`AccessSecretVersion`, `storage.objects.get`, `Predict`), and lateral activity.

### Stage C: Threat Intelligence & Detection Rule Check

4. Call `get_ip_address_report` and `lookup_entity` on external `<src_ip>`.
5. Call `list_security_rules` to check existing YARA-L 2.0 coverage; validate any candidate YARA-L 2.0 rule with `validate_yaral2_rule`.

### Stage D: Verdict, Action, & Full Entity Inventory

6. Classify and act; list every distinct hostname, IAM principal, external IP, domain, and resource observed across the case:
    * **MALICIOUS:** Canary principal accessed (`is_canary=true`) or unauthorized external IP reading secrets, exfiltrating storage/models, or invoking Vertex AI. Disable compromised key/account, call `block_ioc` on verified malicious `<src_ip>`, and document via `post_case_comment`.
    * **SUSPICIOUS:** Anomalous cloud call from corporate IP without canary tag or confirmed exfiltration. Escalate via `post_case_comment` with validated YARA-L 2.0 rule; do not disable production service accounts.
    * **INCONCLUSIVE:** Cloud audit or tool outage (`HTTP 503`). Record gap via `post_case_comment`; do not disable accounts.
    * **BENIGN:** Verified deception test or approved `CHG-...` maintenance by security engineering staff. Call `close_case` (`reason="NOT_MALICIOUS"`) and document all observed entities via `post_case_comment`.
