---
name: edge-appliance-webshell-hunt
description: Use when hunting or triaging edge appliance exploitation, webshells, session hijacking, or living-off-the-land post-exploitation.
category: hunting
version: 1.0.0
type: Skill
title: 'Skill: Edge Appliance and Webshell Hunt'
generated:
  by: agent:gemini
  at: '2026-10-16T23:38:00Z'
metadata:
  adk_additional_tools:
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - secops-mcp_list_security_rules
  - secops-mcp_validate_yaral2_rule
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_domain_report
  - gti-mcp_get_file_report
  - gti-mcp_get_url_report
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_isolate_host
  - soar-mcp_block_ioc
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
---

# Edge Appliance and Webshell Hunt

## Objective

Hunt and triage edge appliance exploits, webshells, stolen session tokens, and LOTL post-exploitation across gateways, web servers, and domain controllers.

## Scope

Covers gateway appliances (Citrix NetScaler, Barracuda, MoveIt, Confluence, ColdFusion, ManageEngine), webshell child processes, session hijacking, and AD lateral movement.

## Inputs

* `<case_id>`: SOAR case identifier.
* `<appliance_host>`: Edge gateway or web server (`principal.hostname`).
* `<src_ip>`: External client IP (`principal.ip`).

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `isolate_host`, `block_ioc`, `post_case_comment`, `close_case`
* SIEM: `search_security_events`, `lookup_entity`, `list_security_rules`, `validate_yaral2_rule`
* GTI: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`

## Workflow Steps

### Stage A: Case & Edge Asset Inventory

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to extract every appliance hostname, internal host, domain user, service account, external IP, domain, URL, and hash.
2. Call `lookup_entity` on `<appliance_host>` and `<src_ip>` to check asset role and `CHG-...` windows.

### Stage B: Webshell Child-Process & Session-Hijack Pivot

3. Call `search_security_events` (`hours_back=168`) across `PROCESS_LAUNCH`, `NETWORK_HTTP`, `USER_LOGIN`, and `FILE_CREATION` for `<appliance_host>` and `<src_ip>`.
4. Check for web workers (`httpd`, `w3wp.exe`, `tomcat`, `java`) spawning shells (`sh`, `bash`, `cmd.exe`, `powershell.exe`) or LOTL recon (`whoami`, `nltest`, `ntdsutil`, `vssadmin`), and check for hijacked session logons (`4624` without prior MFA).

### Stage C: Lateral Account & Threat Intel Enrichment

5. Trace every compromised domain user and service account (`Domain\user`, `Domain\svc_*`) across internal hosts (`CYM-DC01`, `CYM-FS01`, `CYM-JMP01`).
6. Call `get_ip_address_report`, `get_domain_report`, `get_url_report`, and `get_file_report` on external IPs, staging domains, URLs, and hashes (never block signed LOLBins).

### Stage D: Verdict, Action, & Verbatim Entity List

7. Classify and list every hostname, domain user, service account, external IP, domain, URL, and SHA256 hash verbatim:
    * **MALICIOUS:** Webshell execution, session hijack, or LOTL lateral movement confirmed. Call `isolate_host` on compromised hosts, call `block_ioc` on verified malicious IPs/domains/hashes, and document all entities via `post_case_comment`.
    * **SUSPICIOUS:** Uncorroborated probe without webshell execution or session reuse. Escalate via `post_case_comment` with validated YARA-L 2.0 rule (`validate_yaral2_rule`); do not isolate gateways.
    * **INCONCLUSIVE:** SIEM or GTI outage (`HTTP 503`). Record gap via `post_case_comment`.
    * **BENIGN:** Authorized patching, scan, or `CHG-...` maintenance. Call `close_case` (`reason="NOT_MALICIOUS"`) and list all observed entities in `post_case_comment`.
