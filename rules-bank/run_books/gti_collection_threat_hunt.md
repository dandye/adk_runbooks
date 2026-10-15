# Proactive GTI Collection & Campaign Threat Hunt

## Objective

Sweep enterprise telemetry for indicators and execution chains linked to a GTI collection or threat hypothesis to identify Patient Zero, scope, and detection gaps.

## Scope

Covers fleet-wide CTI collection sweeps (GTI reports, C2 domains, and MITRE ATT&CK execution chains) across SIEM, GTI, and SOAR.

## Inputs

*   `<collection_id>`: Target GTI collection or report ID.
*   `<time_frame_hours>`: SIEM lookback in hours (default `72`; widen to `168` on zero hits).
*   `<target_scope_query>`: Optional UDM host-group filter.

## Tools

*   `gti-mcp`: `get_collection_report`, `get_entities_related_to_a_collection`, `get_entities_related_to_a_domain`, `get_domain_report`, `get_file_report`, `get_ip_address_report`
*   `secops-mcp`: `get_ioc_matches`, `search_security_events`, `lookup_entity`, `get_security_alerts`
*   `secops-soar`: `list_cases`, `update_case_comment`, `isolate_host`, `block_indicator`, `close_case`

## Workflow Steps

### Stage A: CTI Collection & Second-Hop Indicator Expansion

1.  Query `gti-mcp.get_collection_report` and `gti-mcp.get_entities_related_to_a_collection` on `<collection_id>` across `domains`, `files`, `ip_addresses`, and `attack_techniques`.
2.  For C2 domains, query `gti-mcp.get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) to collect second-hop payload hashes.

### Stage B: Multi-Horizon SIEM Sweep (`72h` to `168h`)

3.  Query `secops-mcp.get_ioc_matches` and `secops-mcp.search_security_events` for extracted domains, IPs, and hashes over `<time_frame_hours>` (`72` hours).
4.  If `72` hours returns zero events, widen `hours_back` to `168` hours (`7` days) and search `PROCESS_MODULE_LOAD` and `PROCESS_LAUNCH` events for communicating file hashes.

### Stage C: LOLBin Filtering, Patient-Zero Lineage, & Case Correlation

5.  Query `gti-mcp.get_file_report` on matched hashes to separate malicious payloads from signed OS LOLBins (e.g., `rundll32.exe`, `wscript.exe`) or benign web files.
6.  On matched hosts (`<matched_hostname>`), inspect parent-child lineage (`wscript.exe` spawning `rundll32.exe` DLL load), call `secops-mcp.lookup_entity`, and query `secops-soar.list_cases` for related or unalerted cases.

### Stage D: Hunt Verdict, Containment, & Detection-Gap Handoff

7.  Apply a verdict:
    *   **MALICIOUS:** Campaign C2 or payload execution confirmed on `<matched_hostname>`. Call `isolate_host` on `<matched_hostname>`, `block_indicator` on verified C2 domains, IPs, and payload hashes (never block signed OS LOLBins), and `update_case_comment` documenting Patient Zero and detection gaps.
    *   **SUSPICIOUS:** Unconfirmed LOLBin/TTP outlier or critical-asset activity where isolation is prohibited. Call `update_case_comment` with YARA-L 2.0 (`YL2`) detection criteria. Never call `isolate_host` or `close_case`.
    *   **INCONCLUSIVE:** Tool outage. Pivot to local telemetry, set `INCONCLUSIVE`, and call `update_case_comment`.
    *   **BENIGN:** Zero malicious hits across `72h` and `168h`, or authorized activity. Call `update_case_comment` and `close_case`.
