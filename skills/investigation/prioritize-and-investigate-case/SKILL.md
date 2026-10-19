---
name: prioritize-and-investigate-case
description: Use when scoring case urgency, prioritizing the queue, and running core
  investigations.
category: investigation
version: 1.0.0
type: Skill
title: 'Skill: Prioritize and Investigate a Case'
generated:
  by: process:google-labs-jules
  at: '2026-08-20T02:00:00Z'
metadata:
  adk_additional_tools:
  - run_prioritize_investigate_case_workflow
---

# Prioritize and Investigate a Case

## Objective
Score case urgency, validate underlying detection rule logic against firing UDM events, enrich all involved entities across SIEM and GTI, and execute an evidence-backed investigation and disposition.

## Scope
Integrates `run_prioritize_investigate_case_workflow` with fallback synthesis (`run_create_investigation_report_workflow`) when atomic SOAR endpoints return sparse details. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<case_id>`: Target SOAR case identifier (or queue of open cases) to prioritize and investigate.

## Tools
- `workflows`: `run_prioritize_investigate_case_workflow`, `run_create_investigation_report_workflow`, `run_suspicious_login_workflow`
- `secops-soar`: `list_cases`, `get_case_full_details`, `list_alerts_by_case`, `list_events_by_alert`, `post_case_comment`
- `secops-mcp`: `list_security_rules`, `list_rule_detections`, `lookup_entity`, `search_security_events`
- `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`
- `write_report`

## Workflow Steps
1. **Stage A (Priority Scoring & Case Extraction)**: Execute `run_prioritize_investigate_case_workflow` on `<case_id>`, and query `get_case_full_details`, `list_alerts_by_case`, and `list_events_by_alert`. If atomic SOAR calls return empty alerts/entities for `<case_id>`, invoke `run_create_investigation_report_workflow` and `search_security_events` to recover the case overview and involved entities (`principal.hostname`, `target.user.userid`, `principal.ip`, `target.process.file.sha256`).
2. **Stage B (Rule Logic & Behavioral Validation)**: Retrieve the triggering YARA-L 2.0 (`YL2`) rule via `list_security_rules` and `list_rule_detections`. Decode any Base64 command lines (`target.process.command_line`) and verify whether observed UDM events satisfy the rule's threat hypothesis.
3. **Stage C (Entity Enrichment & Cross-Case Correlation)**: Enrich every entity via `lookup_entity`, `search_security_events`, and GTI reputation lookups (`get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`), and check related open cases with `list_cases`.
4. **Stage D (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If activity originates from an authorized administrative jump box, CI/CD runner, or approved `CHG-...` maintenance window with expected commands and no external C2, select `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed malicious execution, credential compromise, or lateral movement corroborated across >=2 sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed active exploitation of an exposed service -> `BLOCK_IOC`, isolate host, and apply emergency patch.
   - **`tune_detection`**: Confirmed benign automation or false positive -> `PROPOSE_RULE_TUNING` with zero destructive containment.
   - **`benign_or_inconclusive`**: Uncorroborated anomaly with zero malicious GTI hits -> `CLOSE_BENIGN`, document via `post_case_comment`, and write the report with `write_report`.
