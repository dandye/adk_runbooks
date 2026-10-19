---
name: triage-alerts
description: Use when evaluating and categorizing incoming security alerts to determine
  severity and initial response actions.
category: triage
version: 1.0.0
type: Skill
title: 'Skill: Alert Triage'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_triage_alerts_workflow
  - run_demo_soc_t2_workflow
  - secops-mcp_search_security_events
  - soar-mcp_change_case_priority
  - soar-mcp_get_case_full_details
  - soar-mcp_get_case_settings_root_causes
---

# Alert Triage

## Objective
Evaluate and categorize incoming SIEM and SOAR security alerts by correlating asset context, duplicate/related cases, targeted UDM telemetry, and Threat Intelligence reputation to select an evidence-backed disposition.

## Scope
Follows Track A (Entity-First Reactive Triage). Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<case_id>`: SOAR case identifier to triage.
- `<alert_id>`: Specific alert identifier within the case.

## Tools
- `workflows`: `run_triage_alerts_workflow`, `run_demo_soc_t2_workflow`
- `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `siemplify_get_similar_cases`, `list_cases`, `change_case_priority`, `post_case_comment`, `siemplify_close_case`, `siemplify_close_alert`
- `secops-mcp`: `lookup_entity`, `search_security_events`, `get_ioc_matches`
- `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
- `write_report`

## Workflow Steps
1. **Stage A (Case Context & Duplicate Check)**: Execute `run_triage_alerts_workflow` and `get_case_full_details` (plus `list_alerts_by_case` and `list_events_by_alert`) to extract `principal.hostname`, `target.user.userid`, `principal.ip`, and `target.process.file.sha256`. Check for duplicate or entity-related open cases via `siemplify_get_similar_cases` and `list_cases`.
2. **Stage B (Targeted SIEM Telemetry & Command-Line Decoding)**: Query `search_security_events` around the alert window for login, process, or network activity. Always decode Base64 flags (`-enc`, `-EncodedCommand`) and inspect full `target.process.command_line` and `principal.process.command_line`. Distinguish RFC-1918 private IPs and RFC-5737 test ranges from external routable IPs.
3. **Stage C (Multi-Source Threat Intel Enrichment)**: Run `lookup_entity`, `get_ioc_matches`, and GTI reputation lookups (`get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`) on all extracted observables.
4. **Stage D (4-Way Disposition, Benign Admin Override, & Action)**:
   - **Benign Admin Override**: Verify whether the source host is an authorized jump box, CI/CD runner, or configuration management server operating within an approved `CHG-...` window with expected maintenance commands and zero external C2; if confirmed, select `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed malicious execution, credential compromise, or C2 corroborated across >=2 sources -> elevate priority (`change_case_priority`), `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed active exploitation of a vulnerable service -> `BLOCK_IOC`, isolate host, and apply emergency patch.
   - **`tune_detection`**: Confirmed benign administrative automation or recurring scanner noise -> `PROPOSE_RULE_TUNING` with zero destructive containment.
   - **`benign_or_inconclusive`**: Duplicate case or isolated anomaly with zero malicious GTI hits -> close via `siemplify_close_case` / `siemplify_close_alert` (`CLOSE_BENIGN`), document with `post_case_comment`, and save the report via `write_report`.
