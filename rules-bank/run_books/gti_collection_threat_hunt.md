# Proactive GTI Collection & Campaign Threat Hunt

## Objective

Proactively sweep enterprise telemetry for indicators and execution chains linked to a Google Threat Intelligence (GTI) collection or campaign report to identify Patient Zero, lateral scope, and detection gaps.

## Scope

Covers fleet-wide proactive threat hunts starting from a GTI collection ID, C2 domain seed, or MITRE ATT&CK technique across SIEM, GTI, and SOAR.

## Inputs

*   `<collection_id>`: The target GTI collection or report identifier.
*   `<time_frame_hours>`: Initial SIEM lookback window in hours (default `72`, widened to `168` on zero hits).
*   `<target_scope_query>`: Optional UDM filter narrowing the host population.

## Tools

*   `gti-mcp`: `get_collection_report`, `get_entities_related_to_a_collection`, `get_entities_related_to_a_domain`, `get_domain_report`, `get_file_report`, `get_ip_address_report`
*   `secops-mcp`: `get_ioc_matches`, `search_security_events`, `lookup_entity`, `get_security_alerts`
*   `secops-soar`: `list_cases`, `update_case_comment`, `isolate_host`, `block_indicator`, `close_case`

## Workflow Steps

### Stage A: CTI Collection & Second-Hop Indicator Expansion

1.  Query `gti-mcp.get_collection_report` and `gti-mcp.get_entities_related_to_a_collection` on `<collection_id>` across `domains`, `files`, `ip_addresses`, and `attack_techniques`.
2.  For high-risk C2 domains, query `gti-mcp.get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) to collect second-hop payload hashes.

### Stage B: Multi-Horizon SIEM Sweep (`72h` to `168h`)

3.  Query `secops-mcp.get_ioc_matches` and `secops-mcp.search_security_events` for extracted domains, IPs, and hashes over `<time_frame_hours>` (`72` hours).
4.  If `72` hours returns zero events, widen `hours_back` to `168` hours (`7` days) and search `PROCESS_MODULE_LOAD` and `PROCESS_LAUNCH` events for communicating file hashes.

### Stage C: LOLBin Filtering, Patient-Zero Lineage, & Case Correlation

5.  Query `gti-mcp.get_file_report` on every matched hash to separate malicious payloads from legitimate signed OS LOLBins (e.g., `rundll32.exe`, `wscript.exe`) or benign web files.
6.  For every matched host (`<matched_hostname>`), inspect parent-child execution lineage (`wscript.exe` spawning `rundll32.exe` DLL load), call `secops-mcp.lookup_entity`, and query `secops-soar.list_cases` for related or unalerted SOAR cases.

### Stage D: Hunt Verdict, Containment, & Detection-Gap Handoff

7.  Apply a verdict and execute the matching action:
    *   **MALICIOUS:** Verified campaign C2 or payload execution confirmed on `<matched_hostname>`. Execute `isolate_host` on `<matched_hostname>`, `block_indicator` on verified malicious C2 domains, IPs, and payload hashes (never block signed OS LOLBins), and `update_case_comment` documenting Patient Zero and any unalerted detection gap.
    *   **SUSPICIOUS:** Low-prevalence LOLBin or TTP anomaly without confirmed malicious payload reputation, or activity on a critical server where unverified isolation is prohibited. Call `update_case_comment` with recommended YARA-L 2.0 (`YL2`) detection criteria. Do not call `isolate_host` or `close_case`.
    *   **INCONCLUSIVE:** A GTI or SIEM tool returns a service outage. Pivot to available local telemetry, set verdict to `INCONCLUSIVE`, and call `update_case_comment`. Do not contain or close.
    *   **BENIGN:** Zero malicious matches across both `72h` and `168h` windows, or all hits verified as authorized administration. Document the clean sweep via `update_case_comment` and `close_case` when closing a dedicated hunt ticket.
