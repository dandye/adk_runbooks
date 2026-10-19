---
name: compare-gti-collection
description: Use when correlating GTI collection indicators against local telemetry
  and event logs.
category: investigation
version: 1.0.0
type: Skill
title: 'Skill: Compare GTI Collection to IoCs, Events in SecOps'
generated:
  by: process:google-labs-jules
  at: '2026-08-20T02:00:00Z'
metadata:
  adk_additional_tools:
  - run_compare_gti_collection_workflow
  - gti-mcp_get_collection_report
  - secops-mcp_get_ioc_matches
  - secops-mcp_get_security_alerts
  - secops-mcp_search_security_events
  - soar-mcp_list_cases
  - soar-mcp_post_case_comment
---

# Compare GTI Collection to IoCs, Events in SecOps

## Objective
Correlate indicators of compromise and MITRE ATT&CK behavioral patterns from a Google Threat Intelligence (`GTI`) Collection (`<collection_id>`) against Chronicle SIEM telemetry and SOAR case history.

## Scope
Combines `run_compare_gti_collection_workflow` with multi-relationship GTI extraction (`files`, `domains`, `ip_addresses`, `urls`) and full UDM event inspection. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<collection_id>`: GTI Collection or Campaign identifier to compare against local telemetry.
- `<case_id>`: Optional SOAR case identifier for correlation and documentation.

## Tools
- `workflows`: `run_compare_gti_collection_workflow`
- `gti-mcp`: `get_collection_report`, `get_entities_related_to_a_collection`, `get_collection_mitre_tree`, `get_file_report`, `get_domain_report`, `get_ip_address_report`
- `secops-mcp`: `get_ioc_matches`, `search_security_events`, `get_security_alerts`
- `secops-soar`: `get_case_full_details`, `google_chronicle_list_events`, `list_cases`, `post_case_comment`
- `write_report`

## Workflow Steps
1. **Stage A (Collection Extraction & Multi-Horizon SIEM Sweep `72h` to `168h`)**: Execute `run_compare_gti_collection_workflow`, `get_collection_report`, `get_entities_related_to_a_collection` (`files`, `domains`, `ip_addresses`, `urls`), and `get_collection_mitre_tree` using `collection_id=<collection_id>`. Sweep `get_ioc_matches` and `search_security_events` at `hours_back=72`; if `72h` yields zero hits, widen `hours_back` to `168` (`7` days).
2. **Stage B (Event Retrieval, LOLBin Guard, & Case Correlation)**: When `search_security_events` reports `events_matched > 0`, retrieve full UDM event details via `google_chronicle_list_events` and `get_security_alerts`. Verify file hashes with `get_file_report` to separate malicious payloads from signed OS LOLBins (`rundll32.exe`, `wscript.exe`) — never block signed OS binaries. Correlate related SOAR cases via `get_case_full_details` and `list_cases`.
3. **Stage C (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If matched telemetry stems from authorized jump boxes, configuration management runners, or approved `CHG-...` maintenance windows with benign scripts, classify as `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed campaign IOC and behavioral overlap across >=2 sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, block verified malicious IOCs, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed active exploitation of a collection-associated vulnerability -> `BLOCK_IOC`, isolate host, and patch.
   - **`tune_detection`**: Benign administrative overlap generating recurring matches -> `PROPOSE_RULE_TUNING` with zero containment.
   - **`benign_or_inconclusive`**: Zero verified campaign overlap across `72h` and `168h` (`CLOSE_BENIGN`) -> document via `post_case_comment` and save the report with `write_report`.
