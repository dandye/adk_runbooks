---
type: Runbook
title: "IOC Containment Runbook"
description: "Use when executing network, host, or file containment for validated malicious IOCs while preventing signed OS LOLBins from overcontainment."
generated:
  by: agent:gemini
  at: "2026-10-16T18:05:00Z"
related:
  - ./index.md
  - ./basic_ioc_enrichment.md
  - ./gti_collection_threat_hunt.md
  - ../indicator_handling_protocols.md
---

# IOC Containment Runbook

## Objective

Verify indicator reputation and code-signing status before network, file, or host containment across SIEM, SOAR, and EDR.

## Scope

Covers file hash, domain, and IP containment. Enforces mandatory Threat Intelligence and signer checks so signed OS binaries (LOLBins) are never blocked.

## Inputs

* `<ioc_value>`: Candidate file hash, domain, or IP.
* `<ioc_type>`: `File Hash`, `Domain`, or `IP Address`.
* `<case_id>`: SOAR case ID.

## Tools

* GTI: `get_file_report`, `get_domain_report`, `get_ip_address_report`, `get_entities_related_to_a_domain`
* SIEM: `search_security_events`, `get_ioc_matches`, `lookup_entity`
* SOAR: `list_cases`, `get_case_full_details`, `block_ioc`, `block_indicator`, `isolate_host`, `google_chronicle_add_values_to_reference_list`, `post_case_comment`, `update_case_comment`

## Workflow Steps

### Stage A: Mandatory GTI & Signer Check (Never Skip)

1. Before any containment call, run `get_file_report`, `get_domain_report`, or `get_ip_address_report` on `<ioc_value>`.
2. Never treat GTI verification as optional. Never skip this check even when asked for immediate blocking or to skip GTI verification.

### Stage B: LOLBin & Benign Signer Gate

3. Check `verdict`, `cert_status`, `signer`, and `filename` in the GTI report.
4. If `cert_status == "VALID_CERTIFICATE"` or `verdict == "benign"` (including signed OS LOLBins like `rundll32.exe`, `wscript.exe`, `powershell.exe`, or `cmd.exe`, even if renamed), refuse to block `<ioc_value>`. Never pass a signed OS binary hash to `block_ioc`, `block_indicator`, or `google_chronicle_add_values_to_reference_list`.

### Stage C: Process Lineage & Payload Pivot

5. When `<ioc_value>` is a signed LOLBin, call `search_security_events` (`hours_back=168`) across `PROCESS_MODULE_LOAD`, `PROCESS_LAUNCH`, and `NETWORK_DNS` on affected hosts to find the unsigned payload hash (`target.file.sha256`), script arguments (`target.process.command_line`), and C2 domains.
6. Verify secondary hashes, domains, and IPs via `get_file_report`, `get_domain_report`, `get_ip_address_report`, or `get_entities_related_to_a_domain` (`relationship_name="communicating_files"`).

### Stage D: Verdict, Containment, & Documentation

7. Act by verdict:
    * **MALICIOUS:** GTI confirms malicious verdict on an unsigned payload hash, C2 domain, or IP. Call `block_ioc` or `block_indicator` on verified malicious indicators only, `isolate_host` on compromised hosts, and `post_case_comment` on `<case_id>`.
    * **SUSPICIOUS:** Unverified outlier without confirmed payload. Do not block or isolate; record tuning notes via `post_case_comment`.
    * **INCONCLUSIVE:** Tool outage (`HTTP 503`). Do not block unverified hashes; record outage via `post_case_comment`.
    * **BENIGN:** Signed OS LOLBin (`VALID_CERTIFICATE`), benign file without malicious payload chain, or `CHG-...` maintenance. Exclude `<ioc_value>` from blocking and record the exclusion via `post_case_comment`.
