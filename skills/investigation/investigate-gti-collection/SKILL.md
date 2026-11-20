---
name: investigate-gti-collection
description: Use when investigating a Google Threat Intelligence (GTI) Collection
  ID for threat context.
category: investigation
version: 1.0.0
type: Skill
title: 'Skill: Investigate Google Threat Intelligence Collection ID (Enhanced)'
generated:
  by: process:google-labs-jules
  at: '2026-08-20T02:00:00Z'
metadata:
  adk_additional_tools:
  - run_investigate_gti_collection_workflow
---

# Investigate Google Threat Intelligence Collection ID (Enhanced)

## Objective
Investigate a Google Threat Intelligence (`GTI`) Collection ID (`<collection_id>`), enrich related indicators and TTPs, correlate against local SIEM/SOAR telemetry across multi-horizon windows, and produce an actionable threat report.

## Scope
Follows Track B (Hypothesis-First CTI Sweep) with workflow-first execution and manual GTI/SIEM fallback. Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<collection_id>`: GTI Collection, Campaign, or Threat Actor identifier to investigate.

## Tools
- `workflows`: `run_investigate_gti_collection_workflow`
- `gti-mcp`: `get_collection_report`, `get_entities_related_to_a_collection`, `get_domain_report`, `get_file_report`, `get_ip_address_report`, `search_threats`, `search_threat_actors`
- `secops-mcp`: `get_ioc_matches`, `lookup_entity`, `search_security_events`
- `secops-soar`: `list_cases`, `post_case_comment`
- `write_report`

## Workflow Steps
1. **Stage A (Workflow Execution & Multi-Horizon CTI Sweep `72h` to `168h`)**: Execute `run_investigate_gti_collection_workflow` with `collection_id=<collection_id>`, and query `get_collection_report` plus `get_entities_related_to_a_collection` across `domains`, `files`, `ip_addresses`, `urls`, and `attack_techniques` (if empty by ID, pivot via `search_threats` or `search_threat_actors`). Sweep `get_ioc_matches` and `search_security_events` at `hours_back=72`; if `72h` returns zero verified hits, automatically widen `hours_back` to `168` (`7` days).
2. **Stage B (Second-Hop Pivot, LOLBin Guard, & Event Verification)**: Enrich matched IOCs with `get_domain_report`, `get_file_report`, and `get_ip_address_report`. Verify `cert_status` on every file hash to separate malicious payloads from signed OS LOLBins (`rundll32.exe`, `wscript.exe`) — never block signed OS binaries. Ignore uncorroborated `events_matched: 1` metadata-only noise lacking event details, and correlate open SOAR cases via `list_cases`.
3. **Stage C (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If matched activity reflects authorized administrative maintenance or RFC-5737 test ranges during an approved `CHG-...` window, select `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed local campaign presence corroborated across >=2 sources -> `CONTAIN_HOST`, `DISABLE_ACCOUNT`, block verified malicious IOCs only, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed exploitation of a collection-linked CVE on an internal asset -> `BLOCK_IOC`, isolate host, and patch.
   - **`tune_detection`**: Benign scanner or admin overlap triggering collection indicators -> `PROPOSE_RULE_TUNING` with zero containment.
   - **`benign_or_inconclusive`**: Clean sweep across `72h` and `168h` (`CLOSE_BENIGN`) -> record proactive defensive posture and save the report via `write_report`.
