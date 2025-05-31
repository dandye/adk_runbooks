# MCP Tool Best Practices & Usage Guide

This document provides best practices, tips, and important considerations for using Model Context Protocol (MCP) tools, especially those interacting with security platforms like Chronicle SIEM and Google Threat Intelligence (GTI).

## General MCP Tool Usage Principles

-   **Understand Tool Purpose:** Before using a tool, ensure you understand its specific function, inputs, and expected outputs by reviewing its documentation (available via MCP server details).
-   **Iterative Approach:** Use tools step-by-step. Don't assume the outcome of one tool before receiving its results.
-   **Parameter Precision:** Provide accurate and specific parameters. Vague inputs can lead to irrelevant or overwhelming results.
-   **Rate Limits:** Be mindful of API rate limits for underlying services. Refer to `tool_rate_limits.md` if available, or the tool's documentation.
-   **Error Handling:** If a tool call fails, review the error message. It often provides clues for correcting the input or understanding a system issue.

## `secops-mcp` (Chronicle SIEM Interaction)

### 1. `search_security_events`

-   **Purpose:** Search Chronicle event logs using natural language queries, translated into UDM queries.
-   **Best Practices for Natural Language Queries:**
    -   **Be Specific:** Instead of "user activity", try "login events for user 'admin' yesterday".
    -   **Use Timeframes:** Always try to specify a timeframe (e.g., "in the last 6 hours", "today", "between 2023-10-26T00:00:00Z and 2023-10-26T01:00:00Z"). The `hours_back` parameter is crucial.
    -   **Specify Entities:** Include known indicators like IP addresses, hostnames, usernames, file hashes directly in your query.
        -   Example: "Show network connections involving IP 10.0.0.5 to port 445 in the last hour."
    -   **Target UDM Fields (Iterative Refinement):** If initial broad searches fail, try to guide the natural language towards specific UDM fields.
        -   "Events where `principal.ip` is '192.168.1.10'"
        -   "Network traffic where `target.hostname` is 'fileserver01.corp.example.com'"
        -   "DNS lookups for `network.dns.question.name` = 'malicious.example.com'"
    -   **Email Addresses:** Use lowercase for email addresses in queries.
-   **Input Parameters:**
    -   `text` (required): Natural language query.
    -   `hours_back` (optional, default: 24): Crucial for scoping search. Start narrow, then broaden if needed.
    -   `max_events` (optional, default: 100): Adjust if you expect more or fewer results. Max is usually 10,000 for direct UDM queries.
-   **Output Interpretation (`events` object):**
    -   `udm_query`: Review the translated UDM query. Does it match your intent? This is key for troubleshooting.
    -   `events.events`: List of UDM event records. Examine key fields like:
        -   `metadata.event_timestamp`, `metadata.event_type`, `metadata.product_log_id`
        -   `principal.*` (actor/source)
        -   `target.*` (object/destination)
        -   `src.*` (intermediary source)
        -   `about.*` (subject of the event, e.g., a file hash in a malware scan event)
        -   `network.*` (for network events)
        -   `security_result.*` (for security verdicts, classifications)
    -   `events.total_events`: If higher than `max_events` returned, your query was broader. Consider refining or pagination if the tool supported it (this one doesn't directly, but the underlying API might).
-   **Common Data Transformations:**
    -   **Timestamp Conversion:** UDM timestamps are typically RFC3339/ISO8601. Be prepared to convert if comparing with other systems.
    -   **IP to Hostname (and vice-versa):** Results might contain one but not the other. Subsequent lookups might be needed.

### 2. `lookup_entity`

-   **Purpose:** Get a summary of an entity's activity in Chronicle (IP, domain, hash, user).
-   **Best Practices:**
    -   Use for quick context on an indicator.
    -   The `hours_back` parameter (default: 24) significantly affects the summary. Adjust as needed for historical context.
-   **Input Parameters:**
    -   `entity_value` (required): The indicator to look up.
    -   `hours_back` (optional, default: 24).
-   **Output Interpretation:**
    -   Provides first/last seen times *within the window*.
    -   Lists related entities and associated alerts *within the window*.
    -   This is a summary; for raw events, use `search_security_events`.

### 3. `get_security_alerts`

-   **Purpose:** Retrieve recent security alerts directly from Chronicle SIEM.
-   **Best Practices:**
    -   Useful for monitoring new SIEM alerts.
    -   Default `status_filter` excludes "CLOSED" alerts. Modify if you need to see closed alerts.
-   **Input Parameters:**
    -   `hours_back` (default: 24)
    -   `max_alerts` (default: 10)
    -   `status_filter` (default: `feedback_summary.status != "CLOSED"`)
-   **Output Interpretation:**
    -   Provides alert summaries: rule name, time, status, severity.
    -   Use `alert_id` with `get_security_alert_by_id` for full details or `search_security_events` to find underlying UDM events.

## `Google Threat Intelligence MCP` (GTI Interaction)

### 1. `get_file_report`

-   **Purpose:** Get a comprehensive analysis report for a file hash (MD5, SHA1, SHA256).
-   **Input Parameter:**
    -   `hash` (required): The file hash.
-   **Output Interpretation (Key Fields):**
    -   `data.attributes.last_analysis_stats`: Breakdown of AV engine detections (malicious, suspicious, undetected).
    -   `data.attributes.popular_threat_classification`: If available, common threat name/category.
    -   `data.attributes.tags`: Community or analyst tags.
    -   `data.attributes.meaningful_name`: Common name for the malware/tool.
    -   `data.attributes.total_votes`: Harmless vs. malicious votes.
-   **Best Practice:**
    -   A high number of `malicious` detections is a strong indicator.
    -   Review `popular_threat_classification` and `tags` for quick context.

### 2. `get_domain_report` / `get_ip_address_report` / `get_url_report`

-   **Purpose:** Get analysis reports for domains, IPs, or URLs.
-   **Input Parameters:**
    -   `domain` / `ip_address` / `url` (required).
-   **Output Interpretation (Key Fields - similar across types):**
    -   `data.attributes.last_analysis_stats`: Detection breakdown from various engines.
    -   `data.attributes.categories`: Classification of the entity (e.g., "phishing", "malware").
    -   `data.attributes.total_votes`: Harmless vs. malicious.
    -   `data.attributes.whois`: WHOIS registration information (for domains).
    -   `data.attributes.resolutions`: Historical DNS resolutions (for domains/IPs).
-   **Best Practice:**
    -   Pay attention to `last_analysis_stats.malicious` and `categories`.
    -   For domains, recent changes in WHOIS or resolutions can be suspicious.

### 3. `search_threats` (and specific variants like `search_threat_actors`, `search_malware_families`)

-   **Purpose:** Search for threat collections (actors, malware, campaigns, reports, vulnerabilities).
-   **Input Parameters:**
    -   `query` (required): The search term.
    -   `collection_type` (optional but **highly recommended**): Filter by "threat-actor", "malware-family", "campaign", "report", "vulnerability". This significantly improves relevance.
    -   `limit` (default: 5)
    -   `order_by` (default: "relevance-")
-   **Output Interpretation:**
    -   Returns a list of collection objects. Key fields:
        -   `id`: Use this ID with `get_collection_report` for full details or `get_entities_related_to_a_collection` for related IOCs.
        -   `type`: Confirms the collection type.
        -   `attributes.name` / `attributes.title`: Name of the threat.
        -   `attributes.description`: Summary.
-   **Best Practice:**
    -   **Always use `collection_type` if the user's request implies a specific type of threat.**
    -   Start with broader queries, then refine.
    -   Use `order_by: "creation_date-"` to find the latest threats.

## `secops-soar` (SOAR Platform Interaction)

### 1. `list_cases`
-   **Purpose:** Get an overview of SOAR cases.
-   **Output Interpretation:**
    -   Provides case summaries (ID, name, status, priority).
    -   **Triage Note:** Case priority is initial. Full assessment requires `get_case_full_details`.
-   **Next Step:** Use `case_id` with `get_case_full_details`.

### 2. `get_case_full_details`
-   **Purpose:** Aggregate core case info, alerts, and comments.
-   **Output Interpretation:**
    -   `case_details`: Basic case info.
    -   `case_alerts`: Associated alerts.
    -   `case_comments`: Analyst notes.
-   **Next Steps (Critical for Investigation):**
    -   Analyze alerts: Use `list_events_by_alert` for underlying UDM.
    -   Identify entities: Use `get_entities_by_alert_group_identifiers`.
    -   Enrich findings using SIEM (`secops-mcp`) and TI (`Google Threat Intelligence MCP`) tools.

### 3. `list_events_by_alert`
-   **Purpose:** Get underlying UDM events for a SOAR alert.
-   **Input:** `case_id`, `alert_id`.
-   **Output:** List of UDM events. Analyze these for ground truth.

---

*This document is a living guide. Please contribute new best practices and tool-specific advice as it's discovered.*

---

## References and Inspiration

-   The effective use of tools is a foundational component for AI agents as described in:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
-   Understanding tool capabilities and outputs is essential for many metrics within the PICERL framework, particularly in the Identification, Containment, and Eradication phases:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
