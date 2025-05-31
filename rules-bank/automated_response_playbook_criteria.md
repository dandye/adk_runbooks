# Automated Response Playbook Criteria

This document outlines criteria for triggering automated response actions by AI agents or SOAR playbooks. It details pre-conditions, safety checks, and rollback procedures to ensure automated responses are executed safely and effectively. This expands on the original `approved_remediations.md`.

## Guiding Principles for Automated Response

1.  **Safety First:** Automation should minimize risk. Critical systems or actions with high potential impact require human oversight.
2.  **High Confidence:** Automated actions should be based on high-confidence triggers.
3.  **Reversibility:** Where possible, automated actions should have clear rollback procedures.
4.  **Context-Awareness:** Automation should leverage contextual information from the `rules-bank` (e.g., asset criticality from `asset_inventory_guidelines.md`, network segments from `network_map.md`).
5.  **Clear Logging:** All automated actions, triggers, and outcomes must be thoroughly logged in the SOAR case.

## Automated Response Criteria Examples

### Playbook: Isolate Host (EDR)

-   **Objective:** Automatically isolate a compromised host using EDR capabilities.
-   **Trigger Conditions (ALL must be met):**
    -   High-confidence EDR alert (e.g., confirmed ransomware execution, critical severity malware).
    -   AND File hash associated with the alert has a `malicious` count > 10 in `Google Threat Intelligence MCP - get_file_report`.
    -   AND/OR Domain/IP contacted by the host has `malicious` count > 5 in GTI or is categorized as C2/malware.
-   **Pre-conditions:**
    -   Host is NOT listed in `critical_servers_do_not_isolate.lst` (a hypothetical list of essential servers like domain controllers, core application servers that should be referenced from `asset_inventory_guidelines.md`).
    -   EDR agent is responsive on the host.
-   **Target_MTTI_Reduction_Factor:** Aim for 75% reduction in time to isolation compared to manual process.
-   **Validation_Procedure_for_AI:**
    -   Query EDR for host isolation status post-action. Expected: Isolated.
    -   Attempt a test network connection (e.g., ICMP ping if allowed, or specific port check) from a designated internal test VM to the isolated host. Expected: Connection fails or times out.
-   **Safety Checks / Confirmation Steps:**
    -   If host is tagged as "Production" or "High Value Asset" in `asset_inventory_guidelines.md`, create a high-priority SOAR task for human analyst approval before isolation.
    -   Post a comment to the SOAR case: "Attempting automated isolation of host [HOSTNAME] ([IP_ADDRESS]) due to [REASON/ALERT_NAME]."
-   **Rollback Procedure:**
    -   Manual: Analyst removes host from isolation in EDR console.
    -   Automated (if EDR supports API for this): Playbook step to remove host from network containment.
-   **Success Metric:** EDR confirms host is isolated. AI validation procedures pass. SOAR case updated.
-   **Failure Handling:** If EDR action fails or AI validation fails, update SOAR case with error and escalate to human analyst.

---

### Playbook: Block Malicious IP/Domain (Firewall/Proxy)

-   **Objective:** Automatically block a confirmed malicious IP address or domain at the network perimeter.
-   **Trigger Conditions (ANY of the following):**
    -   IP/Domain identified in a "Critical" severity alert AND `Google Threat Intelligence MCP` report shows `malicious` count > 10 (or specific tags like "C2", "Phishing_Infrastructure").
    -   IP/Domain is part of a `secops-mcp - get_ioc_matches` result with high confidence TI source.
    -   Multiple internal hosts are observed communicating with the IP/Domain for suspicious activity (e.g., beaconing pattern detected by SIEM rule).
-   **Pre-conditions:**
    -   IP/Domain is NOT listed in `global_allowlist_ips.lst` or `global_allowlist_domains.lst` (referenced from `whitelists.md`).
    -   IP/Domain is NOT associated with a critical business partner or service (requires a `critical_partner_ips_domains.lst` to be maintained).
-   **Safety Checks / Confirmation Steps:**
    -   Post a comment to the SOAR case: "Attempting automated block of [IP/DOMAIN] due to [REASON]."
    -   If the IP/Domain is associated with a service tagged "Business Critical" in any internal documentation, require human approval.
-   **Target_MTTI_Reduction_Factor:** Aim for 90% reduction in time to block compared to manual process.
-   **Validation_Procedure_for_AI:**
    -   Query firewall/proxy API for blocklist status of the IP/Domain. Expected: Present in blocklist.
    -   (If feasible and safe) Attempt a test connection from an isolated test VM to the blocked IP/Domain. Expected: Connection blocked.
-   **Rollback Procedure:**
    -   Manual: Analyst removes IP/Domain from firewall/proxy blocklist.
    -   Automated: Playbook step to remove IP/Domain from blocklist via API.
-   **Success Metric:** Firewall/proxy confirms block is active. AI validation procedures pass. SOAR case updated.
-   **Failure Handling:** If block action fails or AI validation fails, update SOAR case with error and escalate.

---

### Playbook: Disable User Account (Active Directory)

-   **Objective:** Automatically disable a user account suspected of compromise.
-   **Trigger Conditions (ALL must be met):**
    -   Multiple high-confidence alerts associated with the user account (e.g., impossible travel, multiple failed logins followed by success from unusual location, EDR alert for malicious activity under user context).
    -   AND `secops-mcp - lookup_entity` for the user shows anomalous activity patterns compared to baseline (if `baseline_behavior.md` for users is developed).
-   **Pre-conditions:**
    -   Account is NOT a service account listed in `critical_service_accounts.lst` (unless specific override criteria are met).
    -   Account is NOT on a "do not disable" list for VIPs/executives without explicit Tier 3/Management approval.
-   **Safety Checks / Confirmation Steps:**
    -   Post a comment to the SOAR case: "Attempting automated disable of user account [USERNAME] due to [REASON]."
    -   Send a notification to the IT helpdesk and security management distribution list.
    -   If the account has administrative privileges, require human approval via SOAR task before disabling.
-   **Target_MTTI_Reduction_Factor:** Aim for 80% reduction in time to disable account compared to manual process.
-   **Validation_Procedure_for_AI:**
    -   Query Active Directory (via appropriate MCP tool if available, or log analysis for AD changes) for account status. Expected: Disabled/Locked.
    -   (If feasible) Attempt a test authentication with the credentials (ensure this is done securely and doesn't trigger further alerts). Expected: Authentication failure due to disabled account.
-   **Rollback Procedure:**
    -   Manual: IT administrator re-enables the account in Active Directory.
    -   Automated: Playbook step to re-enable account (requires careful permission management for the SOAR service account).
-   **Success Metric:** Active Directory confirms account is disabled. AI validation procedures pass. SOAR case updated.
-   **Failure Handling:** If disable action fails or AI validation fails, update SOAR case with error and escalate.

---

## Maintenance and Review

-   These criteria must be reviewed and updated regularly (e.g., quarterly) or as new tools, threats, or internal policies emerge.
-   Any automated action that results in an unintended negative impact must trigger an immediate review and refinement of these criteria.
-   New automated playbooks must have their criteria documented here before deployment.

---

## References and Inspiration

-   The emphasis on safe, well-vetted, and reversible automated actions is inspired by principles discussed in:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
-   The inclusion of `Target_MTTI_Reduction_Factor` and `Validation_Procedure_for_AI` aligns with the need to measure AI's contribution to "Containment Accuracy" and "MTTI/MTTR" as highlighted in the PICERL framework:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
