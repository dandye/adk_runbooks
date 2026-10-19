---
name: proactive-hunt-gti-campaign
description: Use when initiating threat hunting operations driven by GTI threat campaign
  intelligence.
category: hunting
version: 1.0.0
type: Skill
title: 'Skill: Proactive Threat Hunting based on GTI Campaign/Actor'
generated:
  by: process:google-labs-jules
  at: '2026-08-20T02:00:00Z'
metadata:
  adk_additional_tools:
  - run_proactive_gti_threat_hunt_workflow
  - gti-mcp_get_collection_report
  - gti-mcp_get_collection_timeline_events
  - gti-mcp_get_domain_report
  - gti-mcp_get_entities_related_to_a_collection
  - gti-mcp_get_entities_related_to_a_domain
  - gti-mcp_get_file_behavior_summary
  - secops-mcp_get_ioc_matches
  - secops-mcp_get_security_alerts
  - secops-mcp_lookup_entity
  - secops-mcp_search_security_events
---

# Proactive Threat Hunting based on GTI Campaign/Actor

## Objective
Execute a hypothesis-driven threat hunt from a Google Threat Intelligence (`GTI`) Campaign or Actor Collection (`<collection_id>`), sweeping Chronicle SIEM across multi-horizon windows, pivoting on matched C2 domains, and isolating confirmed patient-zero hosts while protecting signed OS LOLBins.

## Scope
Follows Track B (Broad-to-Narrow Proactive Hunt). Always call `get_mcp_tool_schema` before invoking tools via `execute_mcp_tool`.

## Inputs
- `<collection_id>`: GTI Campaign or Threat Actor Collection ID (or seed C2 domain/report ID).

## Tools
- `workflows`: `run_proactive_gti_threat_hunt_workflow`
- `gti-mcp`: `get_collection_report`, `get_collection_timeline_events`, `get_entities_related_to_a_collection`, `get_domain_report`, `get_entities_related_to_a_domain`, `get_file_report`, `get_file_behavior_summary`, `get_ip_address_report`
- `secops-mcp`: `get_ioc_matches`, `lookup_entity`, `search_security_events`, `get_security_alerts`
- `secops-soar`: `list_cases`, `post_case_comment`
- `write_report`

## Workflow Steps
1. **Stage A (Campaign Extraction & Multi-Horizon SIEM Sweep `72h` to `168h`)**: Execute `run_proactive_gti_threat_hunt_workflow`, `get_collection_report`, `get_collection_timeline_events`, and `get_entities_related_to_a_collection` (`domains`, `files`, `ip_addresses`, `urls`, `attack_techniques`) on `<collection_id>`. Immediately sweep `get_ioc_matches` (`hours_back=72`) and `search_security_events` (`hours_back=72`). If `72` hours returns zero hits, widen `hours_back` to `168` (`7` days) across DNS, network, `PROCESS_LAUNCH`, and `PROCESS_MODULE_LOAD`.
2. **Stage B (Second-Hop Domain Pivot, LOLBin Guard, & Case Correlation)**: For matched C2 domains, pivot via `get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) to collect second-hop payload hashes and search `PROCESS_MODULE_LOAD` over `168` hours. Call `get_file_report` on every matched hash to separate malicious payloads from signed Windows LOLBins (`rundll32.exe`, `wscript.exe` with `VALID_CERTIFICATE`) — never block signed OS binaries. Decode any obfuscated/Base64 command lines (`target.process.command_line`) and check `get_security_alerts` and `list_cases` for unalerted detection gaps.
3. **Stage C (4-Way Disposition, Benign Admin Override, & Reporting)**:
   - **Benign Admin Override**: If activity originates from an authorized jump box, CI/CD runner, or approved `CHG-...` window with verified admin scripts and zero external C2, select `tune_detection` or `benign_or_inconclusive` and forbid `CONTAIN_HOST` and `DISABLE_ACCOUNT`.
   - **`escalate_incident`**: Confirmed campaign execution or C2 beaconing across >=2 sources -> `CONTAIN_HOST` on `<matched_hostname>`, `DISABLE_ACCOUNT`, block verified malicious IOCs only, and escalate to Tier-2 IR.
   - **`contain_and_patch`**: Confirmed exploitation of a campaign-linked vulnerability -> `BLOCK_IOC`, isolate host, and patch.
   - **`tune_detection`**: Authorized scanner or admin activity matching campaign heuristics -> `PROPOSE_RULE_TUNING` with zero containment.
   - **`benign_or_inconclusive`**: Clean sweep across `72h` and `168h` (`CLOSE_BENIGN`) -> document via `post_case_comment` and write the report with `write_report`.
