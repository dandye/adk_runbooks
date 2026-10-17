---
name: dns-tunneling-network-beacon-hunt
description: Use when hunting or triaging DNS tunneling exfiltration, high-entropy DNS subdomains, HTTP/proxy C2 beaconing, or cloud VPC lateral movement.
category: hunting
version: 1.0.0
type: Skill
title: 'Skill: DNS Tunneling and Network Beacon Hunt'
generated:
  by: agent:gemini
  at: '2026-10-16T23:38:00Z'
metadata:
  adk_additional_tools:
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - secops-mcp_list_security_rules
  - secops-mcp_validate_yaral2_rule
  - gti-mcp_get_domain_report
  - gti-mcp_get_ip_address_report
  - gti-mcp_get_url_report
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_isolate_host
  - soar-mcp_block_ioc
  - soar-mcp_post_case_comment
  - soar-mcp_close_case
---

# DNS Tunneling and Network Beacon Hunt

## Objective

Hunt and triage covert DNS tunneling exfiltration, HTTP/proxy C2 beaconing, and cloud VPC lateral movement across DNS, firewall, and IDS telemetry.

## Scope

Covers high-entropy DNS TXT/A queries, DNS data smuggling, Squid/web proxy C2 beacons, and east-west VPC pivoting.

## Inputs

* `<case_id>`: SOAR case identifier.
* `<src_ip>`: Source host or VM IP (`principal.ip`).
* `<query_domain>`: Queried domain or full DNS question (`network.dns.questions.name`).

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `isolate_host`, `block_ioc`, `post_case_comment`, `close_case`
* SIEM: `search_security_events`, `lookup_entity`, `list_security_rules`, `validate_yaral2_rule`
* GTI: `get_domain_report`, `get_ip_address_report`, `get_url_report`

## Workflow Steps

### Stage A: Case & Alert Extraction

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to collect every source host/IP, user, destination IP, full URL, and exact DNS query (`network.dns.questions.name`).
2. Call `lookup_entity` on `<src_ip>` and involved hosts or users.

### Stage B: DNS Query & Network Flow Inspection

3. Call `search_security_events` (`hours_back=168`) for `<src_ip>` and `<query_domain>` across `NETWORK_DNS`, `NETWORK_CONNECTION`, and `NETWORK_HTTP`.
4. Inspect `network.dns.questions.name` for long hex/base32 subdomain labels (`>40` chars), TXT/A burst volume, Suricata IDS alerts, or periodic proxy `target.url` beacons.

### Stage C: Domain, URL, & IP Reputation

5. Call `get_domain_report` on the parent domain and full query names, `get_ip_address_report` on external resolver/C2 IPs, and `get_url_report` on proxy URLs.
6. Check `list_security_rules` and validate any candidate YARA-L 2.0 detection rule with `validate_yaral2_rule`.

### Stage D: Verdict, Action, & Verbatim DNS/URL Reporting

7. Classify and quote exact sample DNS query names (`network.dns.questions.name`) and full URLs (`target.url`) verbatim alongside every host, user, and IP:
    * **MALICIOUS:** High-entropy DNS tunneling burst or confirmed C2 beaconing corroborated by IDS/SIEM and GTI. Call `block_ioc` on malicious C2 domains/IPs, call `isolate_host` on compromised host/VM, and list exact sample DNS subdomain queries in `post_case_comment`.
    * **SUSPICIOUS:** Elevated DNS/HTTP volume without encoded labels or malicious GTI hit. Escalate via `post_case_comment` with validated YARA-L 2.0 rule; do not isolate host.
    * **INCONCLUSIVE:** DNS/proxy log gap or `HTTP 503`. Record gap via `post_case_comment`.
    * **BENIGN:** Legitimate CDN, Windows Update, cloud API, or security traffic (`CHG-...`). Call `close_case` (`reason="NOT_MALICIOUS"`) and list all observed users, IPs, and domains in `post_case_comment`.
