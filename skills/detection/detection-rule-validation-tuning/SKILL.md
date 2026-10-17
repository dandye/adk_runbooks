---
name: detection-rule-validation-tuning
description: Use when validating Chronicle YARA-L 2.0 detection rule syntax, reducing false positives, checking retrohunt performance, or tuning rule logic.
category: detection
version: 1.1.0
type: Skill
title: 'Skill: Detection Rule Validation & Tuning Runbook'
generated:
  by: agent:adk-runbooks-rsi
  at: '2026-10-17T00:16:00Z'
metadata:
  adk_additional_tools:
  - run_detection_rule_validation_workflow
  - secops-mcp_get_security_alerts
  - secops-mcp_list_security_rules
  - secops-mcp_get_detection_rule
  - secops-mcp_validate_yaral2_rule
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
  - soar-mcp_google_chronicle_get_rule_details
  - soar-mcp_list_events_by_alert
  - soar-mcp_post_case_comment
---

# Detection Rule Validation & Tuning Runbook

## Objective
Validate Chronicle YARA-L 2.0 detection rule syntax, check retrohunt fidelity against attack and baseline events, and propose tuning changes.

## Scope
Covers single-event and multi-event YARA-L 2.0 rule retrieval, compiler validation, event sampling, and false-positive exclusion tuning. Does not deploy production rules without approval.

## Inputs
- `<rule_id_or_query>`: Rule identifier, usecase name, or candidate YARA-L 2.0 rule text.
- `<case_id>`: Optional SOAR case identifier tracking the review.

## Tools
- **SIEM Rules**: `secops-mcp_list_security_rules`, `secops-mcp_get_detection_rule`, `secops-mcp_validate_yaral2_rule`
- **SIEM Telemetry**: `secops-mcp_search_security_events`, `secops-mcp_get_security_alerts`, `secops-mcp_lookup_entity`
- **SOAR**: `soar-mcp_google_chronicle_get_rule_details`, `soar-mcp_list_events_by_alert`, `soar-mcp_post_case_comment`

## Workflow Steps
- **Stage A (Rule Retrieval & Intent)**:
  1. Call `secops-mcp_list_security_rules(query=<rule_id_or_query>)` and `secops-mcp_get_detection_rule(rule_id=<rule_id_or_query>)` to get the YARA-L 2.0 rule text and `meta:` fields.
  2. Identify targeted log types, event variables, `match:` window, `outcome:` risk score, and MITRE ATT&CK technique.
- **Stage B (Compiler & Syntax Validation)**:
  1. Call `secops-mcp_validate_yaral2_rule(rule_text=<rule_text>)` on the retrieved or candidate YARA-L 2.0 rule text.
  2. Verify `valid: true` and check required `meta:`, `events:`, and `condition:` sections, balanced braces, explicit UDM paths (never `.ip` or `.hash` aliases), and parenthesized `or` groups instead of inline `in (...)` tuples.
- **Stage C (Retrohunt & Noise Sampling)**:
  1. Call `secops-mcp_search_security_events` over `hours_back=168` matching the rule predicates to inspect attack events and benign baseline noise.
  2. Call `secops-mcp_lookup_entity` on noisy hosts or principals to check if routine admin traffic causes false positives.
  3. If tuning is needed, draft an updated YARA-L 2.0 rule and re-run `secops-mcp_validate_yaral2_rule` until `valid: true`.
- **Stage D (Disposition & Action Matrix)**:
  - **MALICIOUS**: Rule fires on confirmed attack telemetry with `valid: true`. Document matched hosts, users, IPs, domains, hashes, and validated rule text via `soar-mcp_post_case_comment`.
  - **SUSPICIOUS**: Rule compiles (`valid: true`) but matches dual-use admin behavior needing narrower predicates. Post tuned candidate rule via `soar-mcp_post_case_comment`; do not auto-deploy or close.
  - **INCONCLUSIVE**: Rule fails compilation (`valid: false`) or log source is absent. Document compiler errors via `soar-mcp_post_case_comment`; do not deploy.
  - **BENIGN**: Rule alerts only on authorized baseline activity. Propose explicit exclusions, verify with `secops-mcp_validate_yaral2_rule`, and post findings via `soar-mcp_post_case_comment`.
