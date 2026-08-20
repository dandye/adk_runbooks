# Lokibot C2 Malware Investigation Report: Case 33279

## 1. Executive Summary

This report details the investigation into SOAR Case #33279, which involves confirmed Lokibot C2 (Command and Control) activity. The investigation identified that the host at IP address `10.205.11.19` was communicating with a known Lokibot C2 server at `35.213.146.136` (`scarfponcho.com`). The activity was detected by multiple Google Chronicle detection rules. Immediate manual containment of the compromised host and blocking of the malicious indicators are required to prevent data exfiltration and potential lateral movement.

## 2. Case Details

*   **SOAR Case ID:** 33279
*   **Alerts:**
    *   `MALWARE_WIN_LOKIBOT_C2` (ID: 488837)
    *   `SW_MALWARE_WIN_LOKIBOT_C2` (ID: 488702)
    *   `SW_MALWARE_WIN_LOKIBOT_C2` (ID: 488701)
*   **Description:** "Identify default Lokibot C2 Traffic"
*   **Risk Score:** 90-95 (Critical)
*   **Initial Analyst Notes:** Previous comments indicate that automated containment actions failed, requiring manual intervention.

## 3. Indicators of Compromise (IOCs)

| Type | Indicator |
| :--- | :--- |
| **Source IP** | `10.205.11.19` |
| **Destination IP** | `35.213.146.136` |
| **Domain** | `scarfponcho.com` |
| **URL** | `http://scarfponcho.com/notsite/five/fre.php` |
| **User** | `ZENYA-RIGHT` |
| **Malware** | Lokibot |
| **MITRE ATT&CK**| T1071.001 - Application Layer Protocol: Web Protocols|

## 4. Investigation Findings

The investigation began by analyzing the alerts associated with case 33279. All three alerts, triggered by Google Chronicle detection rules, pointed to the same underlying event: a network connection from the internal host `10.205.11.19` to the external URL `http://scarfponcho.com/notsite/five/fre.php`.

*   **Root Cause Analysis:** The alert names and descriptions explicitly identify this traffic as characteristic of the Lokibot information-stealing malware. It is concluded that the host `10.205.11.19` is infected with Lokibot and was attempting to communicate with its C2 server for data exfiltration or to receive further commands. The user `ZENYA-RIGHT` was associated with this activity.

*   **Enrichment:**
    *   **Internal Entities:** A lookup on `10.205.11.19` confirmed it as an internal asset. A lookup for the user `ZENYA-RIGHT` yielded no results, suggesting the user information may be from a log source not fully correlated with the SIEM's entity model.
    *   **External Entities:** Attempts to enrich the external IP, domain, and URL using Google Threat Intelligence (GTI) failed due to a tool configuration error (`WrongCredentialsError`). However, the high confidence of the Chronicle detection rules provides sufficient evidence to treat these indicators as malicious.

*   **Lateral Movement & Impact:** Lokibot is known for stealing credentials from various applications (browsers, email clients, FTP clients). The primary impact is the exfiltration of sensitive data. If the stolen credentials belong to privileged accounts, the risk of lateral movement is critically high, as the attacker could use them to access other systems across the network.

## 5. Recommendations

Based on the findings, the following actions are recommended:

### Immediate Containment:
1.  **Isolate Host:** Immediately disconnect the host `10.205.11.19` from the network to prevent further C2 communication and lateral movement.
2.  **Block Indicators:** Block the IP address `35.213.146.136` and the domain `scarfponcho.com` at the network perimeter (firewall/proxy).
3.  **Disable User Account:** Disable the user account `ZENYA-RIGHT` and any other user accounts that have recently logged into the compromised host, pending password resets.

### Eradication & Recovery:
1.  **Forensic Analysis:** Perform a forensic analysis on the compromised host `10.205.11.19` to understand the initial infection vector and the full scope of the malware's activity.
2.  **Re-image Host:** Re-image the compromised host from a known-good baseline. Do not attempt to clean the existing installation.
3.  **Credential Reset:** Force a password reset for all users who have used the compromised machine.
4.  **Tooling Fix:** Investigate and resolve the `WrongCredentialsError` for the GTI tools to ensure future enrichment capabilities.

### Operational Metrics & Token Statistics (Non-Graph Execution)

* **ADK Session ID:** `ac4d5383-b9d3-4435-9f20-b72a8620ce00`
* **Execution Mode:** Autonomous Multi-Agent Tool Loop (No Graph Workflow)
* **Total Execution Turns:** 12
* **Total Tool Invocations:** 11

#### Token Consumption Summary

| Metric | Token Count |
|:---|:---|
| **Prompt Tokens (Up / Ingested Context)** | **1,879,840** |
| **Output / Candidates Tokens (Down / Generated)** | **1,536** |
| **Total Cumulative Tokens (All Models)** | **1,884,197** |

#### Per-Agent Metrics Breakdown

| Agent | Turns | Tool Calls | Prompt Tokens (In) | Output Tokens (Out) |
|:---|:---:|:---:|:---:|:---:|
| `soc_analyst_tier2` | 9 | 10 | 1,630,846 | 1,521 |
| `manager` | 2 | 1 | 248,994 | 15 |
| `user` | 1 | 0 | 0 | 0 |

#### Tool Invocations Chronology

1. **`[manager]`** $\rightarrow$ `transfer_to_agent` (`agent_name: "soc_analyst_tier2"`)
2. **`[soc_analyst_tier2]`** $\rightarrow$ `soar-mcp_get_case_full_details` (`case_id: "33279"`)
3. **`[soc_analyst_tier2]`** $\rightarrow$ `soar-mcp_list_events_by_alert` (`case_id: "33279"`, `alert_id: "488701"`)
4. **`[soc_analyst_tier2]`** $\rightarrow$ `soar-mcp_list_events_by_alert` (`case_id: "33279"`, `alert_id: "488702"`)
5. **`[soc_analyst_tier2]`** $\rightarrow$ `soar-mcp_list_events_by_alert` (`case_id: "33279"`, `alert_id: "488837"`)
6. **`[soc_analyst_tier2]`** $\rightarrow$ `secops-mcp_lookup_entity` (`entity_value: "10.205.11.19"`)
7. **`[soc_analyst_tier2]`** $\rightarrow$ `secops-mcp_lookup_entity` (`entity_value: "ZENYA-RIGHT"`)
8. **`[soc_analyst_tier2]`** $\rightarrow$ `gti-mcp_get_ip_address_report` (`ip_address: "35.213.146.136"`)
9. **`[soc_analyst_tier2]`** $\rightarrow$ `gti-mcp_get_domain_report` (`domain: "scarfponcho.com"`)
10. **`[soc_analyst_tier2]`** $\rightarrow$ `gti-mcp_get_url_report` (`url: "http://scarfponcho.com/notsite/five/fre.php"`)
11. **`[soc_analyst_tier2]`** $\rightarrow$ `write_report` (`report_name: "lokibot_c2_investigation_report_case_33279.md"`)
