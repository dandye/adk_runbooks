# Indicator Handling Protocols

This document outlines standardized initial investigation steps, preferred tools, and key questions for different types of indicators. It is designed to guide both human analysts and AI agents in the initial phase of indicator-based investigation.

## Indicator Classification (based on "Blueprint for AI Agents in Cybersecurity")

1.  **Atomic Indicators:** Basic elements like IP addresses, domain names, email addresses, file hashes.
2.  **Computed Indicators:** Information derived from data analysis, like malware file sizes or encoded strings (less common for direct initial investigation, often a result of deeper analysis).
3.  **Behavioral Indicators:** Patterns of behavior, tactics, techniques, and procedures (TTPs) used by threat actors.

## Protocols by Indicator Type

### 1. Atomic Indicator: IP Address

-   **Objective:** Determine the reputation, ownership, and recent activity associated with the IP address.
-   **Key Questions:**
    -   Is this IP address known malicious or suspicious?
    -   Who owns this IP address (ASN, geolocation)?
    -   What internal assets have communicated with this IP? When and how?
    -   Is this IP internal or external? (Cross-reference `asset_inventory_guidelines.md` and `network_map.md`)
    -   Are there any existing alerts or cases related to this IP?

```{note}
When dealing with dynamic IP addresses, focus on associated domains or ASNs for broader context.
```

-   **Standard Initial Investigation Flow (Orchestrating Atomic Runbooks):**

    1.  **External Reputation and Ownership Assessment:**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/ip_address/rb_ip_get_gti_report.md`
            -   Input: `ip_address`
            -   Outputs: `gti_ip_report`, `malicious_score`, `categories`, `output_status`, etc.
        -   IF `output_status` is "Failure" OR (`output_status` is "Success" AND `malicious_score` is low/inconclusive AND further context needed) THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/ip_address/rb_ip_get_secops_threat_intel.md`
                -   Input: `ip_address`, `gti_confidence` (from previous step)
                -   Outputs: `secops_ti_summary`, `output_status`, etc.

    2.  **Internal Activity Assessment (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/ip_address/rb_ip_lookup_entity_chronicle.md`
            -   Input: `ip_address`, `hours_back` (e.g., 72)
            -   Outputs: `chronicle_entity_summary`, `related_alerts_count`, `output_status`, etc.
        -   IF `output_status` is "Success" AND (`related_alerts_count` > 0 OR summary indicates significant activity) THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/ip_address/rb_ip_search_network_traffic_chronicle.md`
                -   Input: `ip_address`, `hours_back` (e.g., 24-48), `additional_query_terms` (if specific ports/protocols are of interest)
                -   Outputs: `udm_events`, `total_events_matched`, etc.
        -   ELSE IF `output_status` is "NoInfoFound" AND external reputation was medium/high THEN
            -   *AI/Analyst Note:* Absence of internal logs for a potentially risky external IP might be significant. Consider logging gaps or very recent activity.

    3.  **Check SOAR for Existing Cases/Alerts:**
        -   *(Assuming a future atomic runbook `rb_soar_search_entity_by_ip.md` or similar. For now, this remains a direct tool call concept).*
        -   **Tool:** `secops-soar - search_entity`
            -   **Input:** `term` = IP Address, `type` = ["IP Address"]
        -   IF cases/alerts found THEN
            -   Execute `secops-soar - get_case_full_details` for relevant `case_id`.
            -   Correlate findings with current investigation.

    4.  **Consolidate Findings & Next Steps:**
        -   Based on outputs from the above atomic runbooks (GTI risk, SecOps TI risk, internal activity levels, existing SOAR cases), determine overall risk and appropriate next actions (e.g., escalate, monitor, close as benign, proceed to containment runbooks).

---

### 2. Atomic Indicator: Domain Name / FQDN

-   **Objective:** Determine the reputation, resolution history, and usage of the domain.
-   **Key Questions:**
    -   Is this domain known malicious or suspicious?
    -   What IP addresses does/did this domain resolve to?
    -   What internal assets have accessed or resolved this domain?
    -   Are there any existing alerts or cases related to this domain?

-   **Standard Initial Investigation Flow (Orchestrating Atomic Runbooks):**

    1.  **External Reputation and Resolution History:**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/domain/rb_domain_get_gti_report.md`
            -   Input: `domain_name`
            -   Outputs: `gti_domain_report`, `malicious_score`, `categories`, `resolutions`, `output_status`, etc.
        -   IF `output_status` is "Failure" OR (`output_status` is "Success" AND `malicious_score` is low/inconclusive AND further context needed) THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/domain/rb_domain_get_secops_threat_intel.md`
                -   Input: `domain_name`, `gti_confidence`
                -   Outputs: `secops_ti_summary`, `output_status`, etc.

    2.  **Internal Activity Assessment (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/domain/rb_domain_lookup_entity_chronicle.md`
            -   Input: `domain_name`, `hours_back`
            -   Outputs: `chronicle_entity_summary`, `resolved_ips_in_summary`, etc.
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/domain/rb_domain_search_dns_chronicle.md`
            -   Input: `domain_name`, `hours_back`
            -   Outputs: `dns_query_events`, `clients_resolving_domain`, `resolved_ips_from_dns`, etc.
        -   IF `resolved_ips_from_dns` is not empty OR `resolved_ips_in_summary` is not empty THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/domain/rb_domain_search_network_traffic_chronicle.md`
                -   Input: `domain_name`, `resolved_ips` (combine lists from previous steps), `hours_back`
                -   Outputs: `network_traffic_events`, etc.
            -   For each unique IP in `resolved_ips_from_dns` and `resolved_ips_in_summary`:
                -   Consider executing IP-specific atomic runbooks: `RB-ATOM-IP-001`, `RB-ATOM-IP-003`.

    3.  **Check SOAR for Existing Cases/Alerts:**
        -   *(Assuming a future atomic runbook `rb_soar_search_entity_by_domain.md` or similar).*
        -   **Tool:** `secops-soar - search_entity`
            -   **Input:** `term` = Domain Name, `type` = ["Hostname", "URL"]
        -   IF cases/alerts found THEN
            -   Execute `secops-soar - get_case_full_details`.

    4.  **Consolidate Findings & Next Steps:**
        -   Determine overall risk based on GTI, SecOps TI, internal DNS/network activity, and existing SOAR cases.

---

### 3. Atomic Indicator: File Hash (SHA256, MD5, SHA1)

-   **Objective:** Determine the malware family (if any), prevalence, and execution history of the file.
-   **Key Questions:**
    -   Is this file hash known malicious? What kind of threat?
    -   Has this file been seen on any internal assets?
    -   What processes are associated with this file hash?
    -   Are there any existing alerts or cases related to this file hash?

-   **Standard Initial Investigation Flow (Orchestrating Atomic Runbooks):**

    1.  **External Reputation Assessment:**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/hash/rb_hash_get_gti_report.md`
            -   Input: `file_hash`
            -   Outputs: `gti_file_report`, `malicious_score`, `threat_classification`, `output_status`, etc.
        -   IF `output_status` is "Failure" OR `output_status` is "NotFound" OR (`output_status` is "Success" AND `malicious_score` is low/inconclusive AND further context needed) THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/hash/rb_hash_get_secops_threat_intel.md`
                -   Input: `file_hash`, `gti_confidence`
                -   Outputs: `secops_ti_summary`, `output_status`, etc.

    2.  **Internal Activity Assessment (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/hash/rb_hash_lookup_entity_chronicle.md`
            -   Input: `file_hash`, `hours_back`
            -   Outputs: `chronicle_entity_summary`, `hosts_observed_count`, etc.
        -   IF `hosts_observed_count` > 0 OR summary indicates sightings THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/hash/rb_hash_search_process_events_chronicle.md`
                -   Input: `file_hash`, `hash_type_udm_field` (e.g., `principal.process.file.sha256`), `hours_back`
                -   Outputs: `process_events`, `affected_hosts`, `executed_commands`, etc.

    3.  **Check SOAR for Existing Cases/Alerts:**
        -   *(Assuming a future atomic runbook `rb_soar_search_entity_by_hash.md` or similar).*
        -   **Tool:** `secops-soar - search_entity`
            -   **Input:** `term` = File Hash, `type` = ["FileHash"] (or appropriate SOAR entity type)
        -   IF cases/alerts found THEN
            -   Execute `secops-soar - get_case_full_details`.

    4.  **Consolidate Findings & Next Steps:**
        -   Determine overall risk based on GTI, SecOps TI, internal sightings, execution context, and existing SOAR cases.

---

### 4. Atomic Indicator: URL

-   **Objective:** Determine the reputation, categorization, and internal access patterns related to a specific URL.
-   **Key Questions:**
    -   Is this URL known malicious (phishing, malware C2, etc.)?
    -   What is the final destination of the URL if redirections occur?
    -   Which internal hosts have accessed this URL?
    -   Are there existing alerts or cases related to this URL or its domain?

-   **Standard Initial Investigation Flow (Orchestrating Atomic Runbooks):**

    1.  **External Reputation Assessment:**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/url/rb_url_get_gti_report.md`
            -   Input: `url`
            -   Outputs: `gti_url_report`, `malicious_score`, `categories`, `final_url`, `output_status`, etc.
        -   IF `output_status` is "Failure" OR (`output_status` is "Success" AND `malicious_score` is low/inconclusive AND further context needed) THEN
            -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/url/rb_url_get_secops_threat_intel.md`
                -   Input: `url`, `gti_confidence`
                -   Outputs: `secops_ti_summary`, `output_status`, etc.
        -   *AI/Analyst Note:* If `final_url` is different from input `url`, consider running reputation checks on `final_url` as well.
        -   Extract domain from `url` (and `final_url` if different) and initiate domain reputation checks (e.g., `RB-ATOM-DOMAIN-001`).

    2.  **Internal Activity Assessment (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/url/rb_url_search_chronicle.md`
            -   Input: `url`, `hours_back`, `search_strategy` (e.g., "ExactURL" or "DomainAndPath"), `resolved_ips_for_url_domain` (if known from domain checks).
            -   Outputs: `url_related_events`, `source_hosts_accessing_url`, etc.

    3.  **Check SOAR for Existing Cases/Alerts:**
        -   *(Assuming a future atomic runbook `rb_soar_search_entity_by_url.md` or similar).*
        -   **Tool:** `secops-soar - search_entity`
            -   **Input:** `term` = URL, `type` = ["URL"]
        -   IF cases/alerts found THEN
            -   Execute `secops-soar - get_case_full_details`.

    4.  **Consolidate Findings & Next Steps:**
        -   Determine overall risk based on URL reputation, domain reputation, internal access patterns, and existing SOAR cases.

---

### 5. Atomic Indicator: Username

-   **Objective:** Assess user activity for signs of compromise or misuse, including login patterns, process executions, and alerts.
-   **Key Questions:**
    -   Are there any unusual login activities (time, location, frequency, failed attempts)?
    -   Has the user executed any suspicious processes or commands?
    -   Are there alerts specifically tied to this user's activity?
    -   Is the observed activity consistent with the user's role and typical behavior (cross-reference `baseline_behavior.md` if available for roles)?

-   **Standard Initial Investigation Flow (Orchestrating Atomic Runbooks):**

    1.  **Initial Activity Summary (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/user/rb_user_lookup_entity_chronicle.md`
            -   Input: `username`, `hours_back`
            -   Outputs: `chronicle_entity_summary`, `related_alerts_count`, `accessed_hosts_count`, etc.

    2.  **Detailed Login Activity Search (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/user/rb_user_search_login_activity_chronicle.md`
            -   Input: `username`, `hours_back`, `login_outcome_filter` (e.g., "Any" or "Failed" initially)
            -   Outputs: `login_events`, `source_ips_logins`, `target_systems_logins`, etc.
        -   *AI/Analyst Note:* Correlate `source_ips_logins` with IP reputation checks (`RB-ATOM-IP-001`).

    3.  **Detailed Process Activity Search (Chronicle SIEM):**
        -   Execute Atomic Runbook: `../../Projects/adk_runbooks_debugging/rules-bank/atomic_runbooks/user/rb_user_search_process_activity_chronicle.md`
            -   Input: `username`, `hours_back`, `target_hostname` (if focusing on a specific system from login analysis), `process_name_filter` (if looking for specific malware/tools).
            -   Outputs: `process_events`, `executed_commands`, `involved_hosts`, etc.
        -   *AI/Analyst Note:* Analyze `executed_commands` for known suspicious patterns (reference `analytical_query_patterns.md`).

    4.  **Check SOAR for Existing Cases/Alerts:**
        -   *(Assuming a future atomic runbook `rb_soar_search_entity_by_user.md` or similar).*
        -   **Tool:** `secops-soar - search_entity`
            -   **Input:** `term` = Username, `type` = ["User"] (or appropriate SOAR entity type)
        -   IF cases/alerts found THEN
            -   Execute `secops-soar - get_case_full_details`.

    5.  **Consolidate Findings & Next Steps:**
        -   Determine overall risk based on login patterns, process activity, associated alerts, and existing SOAR cases. Consider account disablement or password reset procedures if compromise is suspected.

---

### 6. Behavioral Indicators (TTPs)

-   **Objective:** Understand the context of the TTP, search for related activity, and identify potential detection gaps. This is often more complex and may involve multiple steps from the "Reactive Threat Hunting AI Agent" blueprint.
-   **Key Questions:**
    -   What specific alert or observation triggered this TTP investigation?
    -   What are the atomic/computed indicators associated with this observed behavior?
    -   Has this TTP been observed historically in the environment?
    -   Are there existing detection rules for this TTP? (Cross-reference `detection_strategy.md`)
    -   What assets or users are potentially involved?

-   **Initial Guiding Steps (AI Agent might orchestrate these):**

    1.  **Decompose the Alert/Observation:**
        -   Identify all atomic indicators (IPs, domains, hashes, users) from the source alert/log.
        -   Investigate each atomic indicator using the protocols above.
    2.  **Historical Search for TTP Elements (SIEM):**
        -   **Tool:** `secops-mcp - search_security_events`
        -   **Query Construction:** This is highly dependent on the TTP. Queries should be crafted to look for patterns described by the TTP.
            -   Example TTP (T1059.001 - PowerShell): Search for suspicious PowerShell command lines, parent processes, or network connections from PowerShell.
            -   "PowerShell execution with encoded commands in the last 7 days"
            -   "Parent process 'winword.exe' launching 'powershell.exe'"
        -   Refer to `analytical_query_patterns.md` for common TTP-related query structures.
    3.  **Detection Gap Analysis:**
        -   If the TTP was observed but did not trigger a specific detection rule, flag this as a potential gap.
        -   Consult `detection_strategy.md` to see if this TTP is a known target for detection.
        -   Follow process in `detection_improvement_process.md` to report gap.
    4.  **Correlate Findings:**
        -   Aggregate findings from atomic indicator checks and TTP searches.
        -   Build a timeline of activity.
        -   Identify potentially compromised assets or accounts.

---

## General Principles for AI Agent Usage:

-   **Context is Key:** Agents should always try to enrich findings with context from other `rules-bank` documents (e.g., `asset_inventory_guidelines.md`, `network_map.md`, `internal_threat_profile.md`).
-   **Update Case/Ticket:** All findings and steps taken should be documented in the relevant SOAR case or ticketing system (e.g., using `secops-soar - post_case_comment`).
-   **Iterative Refinement:** The initial steps here are starting points. Further investigation will be guided by the results of these initial checks.
-   **Human Escalation Points:** Define clear triggers for when an AI agent should escalate to a human analyst (e.g., high-confidence critical threat, ambiguity requiring human judgment, tool errors). These can be defined in more specific runbooks.

---

## References and Inspiration

-   The "Indicator Classification" (Atomic, Computed, Behavioral) is adopted from:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
-   The structured approach to investigation aligns with general incident response best practices and supports metrics outlined in:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
