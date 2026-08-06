---
type: "Playbook"
title: "Detection-as-Code Rule Tuning Runbook (Simplified)"
description: "Simplified plain-English runbook to analyze rule performance, reduce false positives, and tune YARA-L rules."
resource: "adk_runbooks/rules-bank/run_books/detection_as_code_rule_tuning_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "detection rule"
    - "YARA-L"
    - "false positive"
    - "rule tuning"
    - "SIEM"
  technical_verbs:
    - "tune"
    - "triage"
---

# Detection-as-Code Rule Tuning Runbook

## Objective
Analyze detection rule performance, identify false positive causes, and tune YARA-L rule logic.

## Inputs
*   `RULE_ID`: Identifier of the YARA-L detection rule to tune.

## Core Steps

1. Analyze Rule Alert Volume & FPs:
   * Get rule alert statistics, false positive ratio, and feedback comments from SOAR.

2. Inspect Match Telemetry:
   * Analyze UDM events that triggered false positive detections.

3. Modify and Test Rule Logic:
   * Add exclusion filters or adjust match thresholds in the YARA-L rule definition.

4. Validate and Deploy:
   * Run test validations against historical data and deploy the tuned rule version.
