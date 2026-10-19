---
name: detection-as-code-rule-tuning
description: Use when submitting and verifying rule tuning pull requests in detection-as-code
  repositories.
category: detection
version: 1.0.0
type: Skill
title: 'Skill: Detection-as-Code Rule Tuning Workflow'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
metadata:
  adk_additional_tools:
  - run_detection_as_code_tuning_workflow
---

# Detection-as-Code Rule Tuning Workflow

## Objective
Validate, tune, and verify YARA-L 2.0 (`YL2`) detection rule changes in Detection-as-Code (`DaC`) pull requests by reconciling SOAR false-positive feedback, CI syntax/lint validation, and historical SIEM telemetry before production merge.

## Scope
Applies to automated and analyst-initiated `YL2` rule tuning proposals. Always inspect tool schemas with `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<rule_id>`: Identifier of the YARA-L 2.0 detection rule under review.
- `<case_id>`: Originating SOAR case or pull request reference containing tuning context.

## Tools
- `workflows`: `run_detection_as_code_tuning_workflow`, `run_detection_rule_validation_workflow`
- `secops-mcp`: `list_security_rules`, `get_detection_rule`, `validate_yaral2_rule`, `search_security_events`
- `secops-soar`: `get_case_full_details`, `post_case_comment`
- `write_report`

## Workflow Steps
1. **Stage A (Workflow & Rule Context)**: Execute `run_detection_as_code_tuning_workflow` (and `get_case_full_details` on `<case_id>` if provided) to extract the rule modification, CI lint status, and false-positive root cause. Retrieve current rule logic via `list_security_rules` or `get_detection_rule`.
2. **Stage B (Syntax & Scope Verification)**: Validate modified `YL2` syntax with `validate_yaral2_rule`. Verify exclusions scope narrowly to specific tuples (`principal.hostname`, `principal.user.userid`, `target.process.command_line`) and never blank-allowlist entire RFC-1918 subnets or wildcard hosts.
3. **Stage C (Telemetry & Entity Corroboration)**: Run `run_detection_rule_validation_workflow` and `search_security_events` to sample recent detections, decode any Base64 command lines, and verify the exclusion suppresses only confirmed benign activity without masking true positives.
4. **Stage D (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If activity originates from an authorized jump box, CI/CD runner, or approved maintenance change window (`CHG-...`) with expected command arguments and zero anomalous child shells, classify as `tune_detection` and forbid `CONTAIN_HOST` or `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Tuning review uncovers active malicious execution or credential compromise corroborated across >=2 sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Active service exploitation identified during backtesting -> `BLOCK_IOC`, isolate host, and patch vulnerable service.
   - **`tune_detection`**: Validated benign automation or false positive with passing CI syntax check -> approve `PROPOSE_RULE_TUNING` PR, record TP/FP impact, and execute zero destructive containment actions.
   - **`benign_or_inconclusive`**: CI validation fails or telemetry is insufficient -> block PR merge (`CLOSE_BENIGN`), document required fixes via `post_case_comment`, and save the final report with `write_report`.
