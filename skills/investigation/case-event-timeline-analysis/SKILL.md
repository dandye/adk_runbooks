---
name: case-event-timeline-analysis
description: Use when reconstructing chronological event timelines and parent-child process execution trees for a SOAR case.
category: investigation
version: 1.1.0
type: Skill
title: 'Skill: Case Event Timeline & Process Analysis Workflow'
generated:
  by: agent:gemini
  at: '2026-10-16T23:12:00Z'
metadata:
  adk_additional_tools:
  - run_timeline_process_analysis_workflow
  - gti-mcp_get_file_report
  - gti-mcp_get_domain_report
  - gti-mcp_get_ip_address_report
  - secops-mcp_search_security_events
  - secops-mcp_lookup_entity
  - soar-mcp_get_case_full_details
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
---

# Case Event Timeline & Process Analysis Workflow

## Objective

Reconstruct a chronological UDM event timeline and parent-child process lineage for a SOAR case, distinguishing legitimate processes and signed LOLBins from malicious payloads.

## Scope

Covers multi-alert timeline reconstruction, iterative parent-process tracing (`PROCESS_LAUNCH`), hash and network reputation checks, and 4-way verdict mapping.

## Inputs

* `<case_id>`: SOAR case identifier.
* `<hostname>`: Primary endpoint hostname (`principal.hostname`).

## Tools

* SOAR: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`
* SIEM: `search_security_events`, `lookup_entity`
* GTI: `get_file_report`, `get_domain_report`, `get_ip_address_report`

## Workflow Steps

### Stage A: Case & Alert Event Extraction

1. Call `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert` on `<case_id>` to collect every alert timestamp, hostname, user principal, PID, parent PID, command line, file hash, IP, and domain.

### Stage B: Parent Process Tree & Timeline Reconstruction

2. Call `search_security_events` (`hours_back=168`) on `<hostname>` across `PROCESS_LAUNCH`, `PROCESS_MODULE_LOAD`, `USER_LOGIN`, `NETWORK_CONNECTION`, and `NETWORK_DNS` to trace parent PIDs backward to root services (`services.exe`, `explorer.exe`) and child processes forward.
3. Decode Base64 or obfuscated command-line flags (`-enc`, `-EncodedCommand`, reversed strings) and sort all events chronologically.

### Stage C: Hash, Signer, & Network Reputation

4. Call `get_file_report` on every process and module SHA256 hash to check `verdict` and `cert_status` (`VALID_CERTIFICATE` for signed OS LOLBins vs. unsigned malicious payloads).
5. Call `get_domain_report`, `get_ip_address_report`, and `lookup_entity` on external domains and IPs in the timeline.

### Stage D: Timeline Verdict & Full Entity Inventory

6. Classify the timeline and list every distinct hostname, user principal, external IP, domain, and SHA256 hash observed across all case alerts and SIEM events (even when `BENIGN`):
    * **MALICIOUS:** Process chain spawns unauthorized child shells, unsigned payloads, credential dumping, or external C2 traffic. Document chronological timeline via `post_case_comment` and escalate for containment (never block signed OS LOLBins).
    * **SUSPICIOUS:** Anomalous command line without confirmed payload or C2. Document timeline via `post_case_comment` for Tier 3 review; do not isolate host.
    * **INCONCLUSIVE:** Missing parent process logs or tool outage (`HTTP 503`). Note timeline boundary in `post_case_comment`.
    * **BENIGN:** Verified administrative scripts, scheduled backups, or EDR maintenance (`CHG-...`). Document full timeline and entity inventory via `post_case_comment`.
