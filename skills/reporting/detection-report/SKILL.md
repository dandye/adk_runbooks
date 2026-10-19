---
name: detection-report
description: Use when documenting detection coverage assessments, test results, and
  tuning outcomes.
category: reporting
version: 1.0.0
type: Skill
title: 'Skill: Generate Detection Report'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_detection_report_workflow
  - secops-mcp_get_security_alerts
  - secops-mcp_list_security_rules
  - soar-mcp_get_case_full_details
---

# Generate Detection Report

## Objective
Produce an evidence-grounded detection rule performance and health report reconciling trigger frequency, TP/FP accuracy, compilation status, and ingestion latency across workflow and SIEM telemetry sources.

## Scope
Covers multi-source metric reconciliation and structured reporting for YARA-L 2.0 (`YL2`) rules. Always inspect tool schemas with `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<rule_id>`: Detection rule identifier(s) to evaluate.
- `<report_timeframe_days>`: Lookback window in days (default 90).
- `<case_id>`: Optional SOAR case ID for incident or tuning correlation.

## Tools
- `workflows`: `run_detection_report_workflow`, `run_detection_rule_validation_workflow`
- `secops-mcp`: `list_security_rules`, `get_security_alerts`, `search_security_events`
- `secops-soar`: `get_case_full_details`, `post_case_comment`
- `write_report`

## Workflow Steps
1. **Stage A (Rule Definition & Case Context)**: Retrieve rule metadata and logic summary via `list_security_rules`. If `<case_id>` is provided, fetch linked SOAR context using `get_case_full_details`.
2. **Stage B (Multi-Source Metric Reconciliation)**: Execute `run_detection_report_workflow` and `run_detection_rule_validation_workflow`, then cross-check recent alert volume with `get_security_alerts` and `search_security_events`. Calculate `Daily Trigger Frequency = Total Detections / <report_timeframe_days>` and report both workflow scores if they differ.
3. **Stage C (Latency & Telemetry Grounding)**: Compare `metadata.event_timestamp` and `metadata.ingestion_timestamp` on sampled UDM events to estimate detection latency; if raw timestamps are unavailable, explicitly state that latency is derived from workflow metadata.
4. **Stage D (4-Way Disposition, Benign Admin Override, & Artifact Contract)**:
   - **Benign Admin Override**: If alert volume is driven by verified administrative jump boxes, scheduled automation, or approved maintenance windows (`CHG-...`), classify as `tune_detection` and forbid `CONTAIN_HOST` or `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed unmitigated malicious detections corroborated across >=2 telemetry sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Detections confirm active vulnerability exploitation -> `BLOCK_IOC` and remediate affected service.
   - **`tune_detection`**: High noise or recurring false positives from authorized activity -> recommend targeted `YL2` exclusions (`PROPOSE_RULE_TUNING`) with zero destructive containment.
   - **`benign_or_inconclusive`**: Optimal rule health (>90% accuracy) or no actionable anomalies (`CLOSE_BENIGN`) -> retain rule in production.
   - Save the final report via `write_report` including Executive Summary, Rule ID/Name, Health Metrics, Reconciled Trigger Frequency, and Latency Analysis.
