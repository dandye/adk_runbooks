---
name: alert-report
description: Use when summarizing alert triage decisions, key indicators, and immediate
  actions taken.
category: reporting
version: 1.0.0
type: Skill
title: 'Skill: Alert Investigation Summary Report Runbook'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_alert_report_workflow
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - soar-mcp_get_case_full_details
  - soar-mcp_get_entities_by_alert_group_identifiers
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
---

# Alert Investigation Summary Report Runbook

## Objective
Generate a grounded Markdown investigation report summarizing alert metadata, UDM event evidence, entity enrichment, and disposition decisions for a SOAR case and its associated alerts.

## Scope
Prioritizes `run_alert_report_workflow` supplemented by SOAR/SIEM/GTI verification. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<case_id>`: SOAR case identifier containing the target alert(s).
- `<alert_id>`: Specific alert or alert group identifier(s).

## Tools
- `workflows`: `run_alert_report_workflow`
- `secops-soar`: `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `get_entities_by_alert_group_identifiers`, `post_case_comment`
- `secops-mcp`: `lookup_entity`, `search_security_events`
- `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
- `write_report`

## Workflow Steps
1. **Stage A (Workflow & Case Context)**: Execute `run_alert_report_workflow` with `<case_id>` and `<alert_id>`, and verify case/alert metadata via `get_case_full_details` and `list_alerts_by_case`. Extract all involved entities (`principal.hostname`, `target.user.userid`, `principal.ip`, `target.process.file.sha256`).
2. **Stage B (Event Inspection & Network Scope)**: Retrieve underlying UDM events via `list_events_by_alert` or `search_security_events`. Decode any Base64 command lines (`target.process.command_line`) and distinguish RFC-1918 private addresses from external routable IPs.
3. **Stage C (Multi-Source Enrichment)**: Enrich key entities with `lookup_entity` and GTI reputation tools (`get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`).
4. **Stage D (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If activity originates from an authorized jump box, CI/CD runner, or approved maintenance window (`CHG-...`) with expected scripts and no external C2, select `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed malicious execution, credential compromise, or C2 corroborated across >=2 sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed active exploitation of an exposed service -> `BLOCK_IOC`, isolate host, and apply emergency patch.
   - **`tune_detection`**: Confirmed benign administrative automation or scanner noise -> `PROPOSE_RULE_TUNING` with zero destructive containment.
   - **`benign_or_inconclusive`**: Isolated anomaly with zero malicious GTI hits and no corroborating telemetry -> `CLOSE_BENIGN` with zero containment.
   - Document in SOAR via `post_case_comment` and save the structured Markdown report using `write_report`.
