---
name: ransomware-response
description: Use when responding to active ransomware deployment, shadow copy deletion, lateral movement, or host encryption threats.
category: irps
version: 1.1.0
type: Skill
title: 'Skill: Ransomware Incident Response Plan (IRP) / Runbook'
generated:
  by: agent:gemini
  at: '2026-10-16T23:38:00Z'
metadata:
  adk_additional_tools:
  - run_ransomware_irp_workflow
  - gti-mcp_get_file_report
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_domain_report
  - gti-mcp_search_threats
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_isolate_host
  - soar-mcp_block_ioc
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
---

# Ransomware Incident Response Plan (IRP) / Runbook

## Objective

Investigate, scope, and contain suspected ransomware intrusions across affected endpoints, compromised domain/service accounts, and external C2 infrastructure.

## Scope

Covers ransomware strain identification, initial access and lateral-movement scoping, shadow-copy/backup tampering checks, and host/IOC containment.

## Inputs

* `<case_id>`: SOAR case identifier.
* `<hostname>`: Initially alerted endpoint or server (`principal.hostname`).
* `<file_hash>`: Suspected ransomware binary or tool SHA256 hash.

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `isolate_host`, `block_ioc`, `post_case_comment`, `close_case`
* SIEM: `search_security_events`, `lookup_entity`
* GTI: `get_file_report`, `get_ip_address_report`, `get_domain_report`, `search_threats`

## Workflow Steps

### Stage A: Full Case, Host, & Account Inventory

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to collect every affected hostname, domain user (`Domain\user`), service account (`Domain\svc_*`), external IP, staging domain, and SHA256 hash.
2. Call `lookup_entity` on `<hostname>` and every involved account.

### Stage B: Lateral Movement, Precursor, & Encryption Sweep

3. Call `search_security_events` (`hours_back=168`) across `PROCESS_LAUNCH`, `USER_LOGIN`, `NETWORK_CONNECTION`, and `FILE_CREATION` for every host and account from Stage A.
4. Check for initial access (gateway exploit, RDP, phishing), credential dumping (`lsass`, `ntdsutil`, `Mimikatz`), RMM persistence (`AnyDesk`), lateral execution (`PsExec`, `WMI`, `SMB`), shadow copy deletion (`vssadmin delete shadows`), and `.lockbit`/ransom notes.

### Stage C: Strain & Indicator Verification

5. Call `get_file_report` on every `<file_hash>` to identify the ransomware family and check `cert_status` (never block signed OS LOLBins like `rundll32.exe`, `vssadmin.exe`, or `powershell.exe`).
6. Call `get_ip_address_report` and `get_domain_report` on external IPs and staging domains.

### Stage D: Containment, Disposition, & Complete Entity Listing

7. Classify and list every distinct hostname, domain user, service account, external IP, domain, and SHA256 hash verbatim:
    * **MALICIOUS:** Confirmed ransomware execution, shadow copy deletion, or precursor lateral movement. Call `isolate_host` on compromised hosts, call `block_ioc` on verified malicious hashes/IPs/domains, disable compromised accounts, and post full scope via `post_case_comment`.
    * **SUSPICIOUS:** Dual-use admin tool (`PsExec`, `vssadmin`) without malicious hash or C2 corroboration. Escalate via `post_case_comment`; do not isolate critical servers without verification.
    * **INCONCLUSIVE:** EDR/SIEM outage (`HTTP 503`). Record gap via `post_case_comment`.
    * **BENIGN:** Authorized backup/snapshot maintenance (`CHG-...`) or clean baseline administration. Call `close_case` (`reason="NOT_MALICIOUS"`) and list all observed hosts and accounts in `post_case_comment`.
