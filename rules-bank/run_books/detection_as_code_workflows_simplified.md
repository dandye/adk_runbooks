---
type: "Playbook"
title: "Detection-as-Code Workflows Runbook (Simplified)"
description: "Simplified plain-English runbook outlining the lifecycle for developing and testing detection rules."
resource: "adk_runbooks/rules-bank/run_books/detection_as_code_workflows_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "detection rule"
    - "YARA-L"
    - "pull request"
    - "repository"
    - "SIEM"
  technical_verbs:
    - "tune"
    - "patch"
---

# Detection-as-Code Workflows Runbook

## Objective
Outline the standard lifecycle for writing, testing, reviewing, and deploying detection rules as code.

## Inputs
*   `RULE_NAME`: Name of the detection rule.
*   `REPO_PATH`: Path to detection repository.

## Core Steps

1. Author Rule in YARA-L:
   * Write the detection rule in YARA-L 2.0 format with clear metadata, events, and condition sections.

2. Test Against Synthetic Telemetry:
   * Validate rule syntax and test against synthetic UDM events to confirm expected matches.

3. Peer Review & CI Validation:
   * Submit changes in a pull request and verify automated linting and syntax checks pass.

4. Deploy to SIEM:
   * Deploy verified rule to SIEM in alerting mode.
