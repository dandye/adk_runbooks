# Log Source Overview

This document identifies critical log sources for security monitoring, their primary ingestion methods, typical retention periods, and how AI agents can assist in monitoring their health and coverage.

## Purpose

-   Provide a centralized inventory of essential log sources.
-   Inform analysts and AI agents about data availability for investigations.
-   Support the "Preparation" phase of the PICERL AI Performance Framework by enabling monitoring of log source coverage.

## Critical Log Sources

| Log Source Category      | Specific Source Example(s)        | Primary Ingestion Method / Platform | Typical Retention (Chronicle) | Key UDM Types / Parsers                                  | Notes                                                                 |
| :----------------------- | :-------------------------------- | :---------------------------------- | :---------------------------- | :------------------------------------------------------- | :-------------------------------------------------------------------- |
| **Endpoint Security**    | EDR (e.g., CrowdStrike, SentinelOne) | Chronicle Forwarder / API           | 12 Months                     | `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `FILE_MODIFICATION` | Crucial for host-level visibility.                                  |
| **Network Security**     | Firewall (e.g., Palo Alto, Fortinet) | Syslog to Chronicle Forwarder / API | 12 Months                     | `NETWORK_CONNECTION`, `NETWORK_FLOW`                     | Perimeter and internal segmentation traffic.                        |
|                          | IDS/IPS (e.g., Suricata, Zeek)    | Syslog / PCAP to Chronicle          | 12 Months                     | `NETWORK_CONNECTION`, `NETWORK_FLOW`, `SECURITY_ALERT`   | Deep packet inspection insights.                                    |
|                          | DNS Logs (e.g., BIND, Windows DNS)  | Chronicle Forwarder                 | 12 Months                     | `NETWORK_DNS`                                            | Essential for tracking domain resolutions.                          |
| **Identity & Access**  | Active Directory Domain Controllers | Chronicle Forwarder (WinEventLog)   | 12 Months                     | `USER_LOGIN`, `USER_UNCATEGORIZED` (for Kerberos, NTLM)  | Security events 4624, 4625, 4768, 4769, 4771, 4776.         |
|                          | Cloud IAM (e.g., GCP Cloud Audit) | Native GCP Integration to Chronicle | 12 Months                     | `USER_LOGIN`, `GCP_IAM_ANALYSIS`                         | Cloud identity and access patterns.                                 |
|                          | VPN Concentrators                 | Syslog to Chronicle Forwarder       | 12 Months                     | `USER_LOGIN`, `NETWORK_CONNECTION`                       | Remote access activity.                                             |
| **Cloud Infrastructure** | GCP Cloud Audit Logs              | Native GCP Integration to Chronicle | 12 Months                     | `GCP_AUDIT_LOG` (Admin Activity, Data Access, System Event) | API calls, resource changes, data access.                         |
|                          | AWS CloudTrail                    | S3 to Chronicle / API               | 12 Months                     | `AWS_CLOUDTRAIL`                                         | AWS API calls and account activity.                                 |
|                          | Azure Activity Logs               | Event Hub to Chronicle / API        | 12 Months                     | `AZURE_ACTIVITY_LOG`                                     | Azure resource management and service health.                       |
| **Application Logs**     | Critical Business App X           | Custom Parser / Chronicle Forwarder | 6 Months                      | `GENERIC_EVENT` or custom UDM                            | Depends on application; focus on auth and transaction logs.       |
|                          | Web Server Logs (Apache, Nginx)   | Chronicle Forwarder                 | 6-12 Months                   | `NETWORK_HTTP`                                           | Access patterns, errors, potential web attacks.                   |
| **Email Security**       | Email Gateway (e.g., Proofpoint)  | API / Syslog to Chronicle           | 12 Months                     | `EMAIL_TRANSACTION`, `EMAIL_ATTACHMENT`                  | Phishing attempts, malware delivery.                                |
|                          | Microsoft 365 / Google Workspace  | Native Integration / API            | 12 Months                     | `OFFICE_ACTIVITY`, `GSUITE_ALERT`                        | Email activity, DLP, admin actions.                               |
| **Vulnerability Mgmt**   | SCC / Tenable / Qualys            | API to SOAR / Data Lake             | N/A (reports)                 | N/A (findings, not events)                               | Context for asset risk, not typically real-time events in SIEM. |

*Note: Retention periods are examples and should be confirmed with actual Chronicle configuration.*

## AI-Monitored Log Source Health & Coverage

To ensure AI agents have the necessary visibility for effective operation, they can be tasked with monitoring log source health and coverage.

-   **Monitoring Tasks for AI Agents:**
    1.  **Regular Health Checks:**
        -   *Action:* Periodically query Chronicle (e.g., every 1-4 hours) for the latest `metadata.collected_timestamp` or `metadata.event_timestamp` for each critical log source/parser listed above.
        -   *Tool:* `secops-mcp - search_security_events`
        -   *Example Query Text:* "Show latest event for parser 'WINDOWS_EVENT_LOGS' in the last 10 minutes" (adjust time window based on expected latency).
        -   *Alert Condition:* If `metadata.collected_timestamp` for a critical source is older than a defined threshold (e.g., > 1 hour beyond expected latency), generate an internal alert/ticket for investigation by platform engineers.
    2.  **Asset Coverage Verification:**
        -   *Action:* Periodically compare the list of active assets in `asset_inventory_guidelines.md` (especially critical ones) against assets observed sending logs to Chronicle within a defined window (e.g., last 24-48 hours).
        -   *Tool:* `secops-mcp - search_security_events` (to get unique hostnames/IPs from logs) and comparison logic.
        -   *Example Query Text (to get observed hosts):* "List unique principal.hostname from all events in the last 24 hours" (may need to be more targeted by log source type).
        -   *Alert Condition:* If critical assets from inventory are not found in recent logs, flag as a coverage gap.
    3.  **Parser Error Monitoring (If Applicable):**
        -   *Action:* If Chronicle provides metrics or logs for parser errors/unmapped fields, AI agent can monitor these.
        -   *Alert Condition:* Significant increase in parsing errors for a specific log source.

-   **Reporting:**
    -   AI agent should report identified health issues or coverage gaps to a designated channel (e.g., SOAR case, dedicated Slack channel, ticketing system for platform engineering).
    -   Reports should include:
        -   Timestamp of the check.
        -   Affected log source(s) or asset(s).
        -   Last known healthy timestamp (if applicable).
        -   Link to relevant query or evidence.

-   **Metric Contribution (PICERL - Preparation Phase):**
    -   This AI-driven monitoring directly contributes to the "Log Source Coverage (AI-Monitored)" metric.
    -   Helps ensure the "Visibility, Data Gaps" key focus for AI (as per PICERL article) is addressed.

## Maintenance

-   This document should be reviewed and updated quarterly or when significant changes occur in the logging infrastructure or critical asset inventory.
-   Verify ingestion methods and parser names with Chronicle administrators.

---

## References and Inspiration

-   The AI-Monitored Log Source Health & Coverage section aligns with the "Preparation" phase metrics discussed in:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
