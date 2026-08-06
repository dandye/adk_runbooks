---
type: "Playbook"
title: "Meta-Analysis Runbook (Simplified)"
description: "Simplified plain-English runbook to analyze trends and correlations across multiple incidents."
resource: "adk_runbooks/rules-bank/run_books/metaanalysis_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "meta-analysis"
    - "incident"
    - "trend"
    - "TTP"
    - "SIEM"
    - "SOAR case"
  technical_verbs:
    - "triage"
---

# Meta-Analysis Runbook

## Objective
Analyze trends, attack patterns, and recurring root causes across multiple security incidents over time.

## Inputs
*   `ANALYSIS_TIMEFRAME_DAYS`: Lookback period in days (for example, 30 or 90).

## Core Steps

1. Aggregate Incident Data:
   * Get closed cases, root causes, attacker TTPs, and affected asset categories across the timeframe.

2. Identify Statistical Patterns:
   * Calculate frequencies for top initial access vectors, recurring malware families, and noisy detection rules.

3. Form Strategic Recommendations:
   * Propose architecture improvements, security policy updates, or training recommendations.

4. Generate Meta-Analysis Report:
   * Publish the Meta-Analysis findings report.
