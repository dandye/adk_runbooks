---
name: group-cases-v2
description: Use when executing advanced multi-factor case grouping and relationship
  clustering.
category: investigation
version: 1.0.0
type: Skill
title: 'Skill: Group Cases v2'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_group_cases_v2_workflow
  - secops-mcp_lookup_entity
  - soar-mcp_get_case_full_details
  - soar-mcp_get_entities_by_alert_group_identifiers
  - soar-mcp_list_alerts_by_case
  - soar-mcp_list_cases
---

# Group Cases v2

## Objective
Cluster and prioritize related SOAR cases using multi-factor entity and alert similarity, reconcile v2 and v1 grouping outputs, enrich shared pivot entities, and produce a justified case consolidation report.

## Scope
Combines `run_group_cases_v2_workflow` and `run_group_cases_workflow` with SIEM/GTI entity enrichment. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<case_id>`: Seed SOAR case identifier(s) or recent case queue to cluster.
- `<similarity_threshold>`: Clustering threshold (default `0.8`; fallback `0.5` labeled as Low Confidence).

## Tools
- `workflows`: `run_group_cases_v2_workflow`, `run_group_cases_workflow`
- `secops-soar`: `list_cases`, `get_case_full_details`, `list_alerts_by_case`, `get_entities_by_alert_group_identifiers`, `post_case_comment`
- `secops-mcp`: `lookup_entity`, `search_security_events`
- `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`
- `write_report`

## Workflow Steps
1. **Stage A (Multi-Workflow Cluster Reconciliation)**: Execute `run_group_cases_v2_workflow` (default `similarity_threshold=0.8`) and reconcile with `run_group_cases_workflow` and `list_cases` to confirm whether seed `<case_id>` records and historical cluster members belong to the same consolidated incident cluster.
2. **Stage B (Entity Extraction & SIEM Fallback)**: Retrieve case details, alerts, and entities via `get_case_full_details`, `list_alerts_by_case`, and `get_entities_by_alert_group_identifiers`. If SOAR returns empty entities for a valid `<case_id>`, query `search_security_events` for `<case_id>` to extract shared `principal.hostname`, `target.user.userid`, `principal.ip`, and `target.process.file.sha256` from raw UDM telemetry.
3. **Stage C (Shared Entity Enrichment)**: Enrich shared pivot entities across high-priority clusters using `lookup_entity` and GTI reputation tools (`get_ip_address_report`, `get_domain_report`, `get_file_report`).
4. **Stage D (4-Way Disposition, Benign Admin Override, & Cluster Report)**:
   - **Benign Admin Override**: If a case cluster shares an authorized administrative jump box, scanner, or approved `CHG-...` maintenance window with benign command lines, classify the cluster as `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Multi-case cluster confirms coordinated intrusion, credential compromise, or lateral movement across >=2 sources -> consolidate cases, `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Cluster reflects active exploitation of a shared vulnerability across hosts -> `BLOCK_IOC`, isolate hosts, and patch.
   - **`tune_detection`**: Cluster stems from recurring benign automation or noisy rule logic -> consolidate and submit `PROPOSE_RULE_TUNING` with zero containment.
   - **`benign_or_inconclusive`**: Low-similarity (`< 0.8`) or uncorroborated cases with zero malicious GTI hits -> keep separate (`CLOSE_BENIGN`), document shared-entity justification via `post_case_comment`, and write the report with `write_report`.
