---
name: detection-rule-validation-tuning
description: Use when validating detection rule performance, reducing false positives,
  and tuning logic.
category: detection
version: 1.0.0
type: Skill
title: 'Skill: Detection Rule Validation & Tuning Runbook'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_detection_rule_validation_workflow
  - secops-mcp_get_security_alerts
  - secops-mcp_list_security_rules
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - soar-mcp_google_chronicle_get_rule_details
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
---

# Detection Rule Validation & Tuning Runbook

## Objective
Evaluate Chronicle SIEM YARA-L 2.0 (`YL2`) detection rule precision, sample true and false positive alerts, enrich involved entities, and propose grounded tuning exclusions without introducing detection blind spots.

## Scope
Covers historical alert volume, TP/FP ratio calculation, and `YL2` predicate refinement. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<rule_id>`: Detection rule identifier or name to validate.
- `<case_id>`: Optional SOAR review case identifier.

## Tools
- `workflows`: `run_detection_rule_validation_workflow`
- `secops-mcp`: `list_security_rules`, `get_security_alerts`, `search_security_events`, `lookup_entity`
- `secops-soar`: `google_chronicle_get_rule_details`, `list_events_by_alert`, `post_case_comment`
- `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`
- `write_report`

## Workflow Steps
1. **Stage A (Rule Logic & Baseline Metrics)**: Retrieve `YL2` logic via `list_security_rules` or `google_chronicle_get_rule_details` and execute `run_detection_rule_validation_workflow` to obtain baseline alert counts, TP/FP ratios, and quality score.
2. **Stage B (Alert Sampling & UDM Inspection)**: Query `get_security_alerts` and `list_events_by_alert` (or `search_security_events`) for `<rule_id>`. Inspect `principal.hostname`, `target.user.userid`, and full `target.process.command_line` (decoding any Base64 flags) across both FP and TP samples.
3. **Stage C (Entity & Threat Intel Enrichment)**: Run `lookup_entity` and GTI reputation lookups (`get_ip_address_report`, `get_domain_report`, `get_file_report`) on sampled external IPs, domains, and file SHA-256 hashes.
4. **Stage D (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: Confirm whether recurring triggers stem from authorized jump boxes, configuration management runners, or approved change windows (`CHG-...`). When verified, select `tune_detection` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Unhandled true-positive compromise corroborated across >=2 telemetry sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Active vulnerability exploitation confirmed in alert samples -> `BLOCK_IOC` and apply emergency patch.
   - **`tune_detection`**: High false-positive rate from verified benign administrative or scanner activity -> specify exact `YL2` `not (...)` predicate exclusions (`PROPOSE_RULE_TUNING`) with zero destructive containment.
   - **`benign_or_inconclusive`**: Rule performs within optimal precision thresholds or telemetry is inconclusive -> retain current logic (`CLOSE_BENIGN`), document via `post_case_comment`, and write the report with `write_report`.
