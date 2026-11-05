# Proactive GTI Collection & Campaign Threat Hunt

## Objective

Sweep enterprise telemetry for indicators and execution chains linked to a GTI collection or threat hypothesis to identify Patient Zero, scope, and detection gaps.

## Scope

Covers fleet-wide CTI collection sweeps (GTI reports, C2 domains, and MITRE ATT&CK execution chains) across SIEM, GTI, and SOAR.

## Inputs

*   `<collection_id>`: Target GTI collection, report ID, or seed C2 domain.
*   `<time_frame_hours>`: SIEM lookback in hours (default `72`; widen to `168` on zero hits).
*   `<target_scope_query>`: Optional UDM host-group filter.

## Tools

*   GTI: `get_collection_report`, `get_entities_related_to_a_collection`, `get_entities_related_to_a_domain`, `get_domain_report`, `get_file_report`, `get_ip_address_report`
*   SIEM: `get_ioc_matches`, `search_security_events`, `lookup_entity`, `get_security_alerts`
*   SOAR: `list_cases`, `update_case_comment`, `isolate_host`, `block_indicator`, `close_case`

## Workflow Steps

### Stage A: CTI Collection & Multi-Horizon SIEM Sweep (`72h` to `168h`)

1.  Call `get_collection_report` and `get_entities_related_to_a_collection` on `<collection_id>` (`relationship_name="all"`) to extract domains, hashes, IPs, and TTPs (or `get_domain_report` and `get_entities_related_to_a_domain` for a seed domain).
2.  Call `get_ioc_matches` (`hours_back=72`) and `search_security_events` (`hours_back=72`) for extracted indicators.
3.  If `72` hours returns zero matches, widen `hours_back` to `168` (`7` days) and run `get_ioc_matches` (`hours_back=168`) and `search_security_events` (`hours_back=168`) across DNS, network, `PROCESS_LAUNCH`, and `PROCESS_MODULE_LOAD`.

### Stage B: Second-Hop Domain Pivot, LOLBin Filtering, & Case Correlation

4.  For matched C2 domains, call `get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) for second-hop payload hashes and search `PROCESS_MODULE_LOAD` over `168` hours.
5.  Call `get_file_report` on matched hashes to separate malicious payloads from signed OS LOLBins (`rundll32.exe`, `wscript.exe`) or benign web files.
6.  On `<matched_hostname>`, call `lookup_entity` and `list_cases` to verify lineage, `CHG-...` records, and unalerted cases.

### Stage C: Hunt Verdict, Containment, & Detection-Gap Handoff

7.  Apply a verdict:
    *   **MALICIOUS:** Campaign C2 or payload execution confirmed on `<matched_hostname>`. Call `isolate_host` on `<matched_hostname>`, `block_indicator` on verified C2 domains, IPs, and payload hashes (never block signed OS LOLBins), and `update_case_comment` with Patient Zero and detection gaps.
    *   **SUSPICIOUS:** Unconfirmed LOLBin/TTP outlier or critical-asset activity where isolation is prohibited. Call `update_case_comment` with YARA-L 2.0 (`YL2`) criteria. Never call `isolate_host` or `close_case`.
    *   **INCONCLUSIVE:** Tool outage (`HTTP 503`). Set `INCONCLUSIVE` and call `update_case_comment`.
    *   **BENIGN:** Zero malicious hits across `72h` and `168h`, or authorized `CHG-...` maintenance. Call `update_case_comment` and `close_case`.
