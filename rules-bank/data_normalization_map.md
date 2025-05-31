# Data Normalization Map

This document provides mappings for common data fields across various log sources and tools to a standardized (e.g., UDM - Unified Data Model) or common internal representation. This helps AI agents correlate data and construct queries effectively.

## Purpose

-   Address field name variability across different security tools and log sources.
-   Enable consistent data interpretation for AI-driven analysis and automation.
-   Facilitate accurate cross-tool correlation.

## Mappings

### Network Indicators

| Common Concept        | UDM Field (Chronicle)         | Generic SIEM Field 1 | Generic SIEM Field 2 | EDR Field           | Firewall Log Field   | Notes                                                                 |
| :-------------------- | :---------------------------- | :------------------- | :------------------- | :------------------ | :------------------- | :-------------------------------------------------------------------- |
| **Source IP Address** | `principal.ip` / `src.ip`   | `source_ip`          | `client_ip`          | `local_address`     | `src_ip`             | `principal.ip` for originating actor, `src.ip` for network source.    |
| **Destination IP Address** | `target.ip` / `dst.ip`     | `destination_ip`     | `server_ip`          | `remote_address`    | `dst_ip`             | `target.ip` for ultimate target, `dst.ip` for network destination. |
| **Source Port**       | `principal.port` / `src.port` | `source_port`        | `client_port`        | `local_port`      | `src_port`           |                                                                       |
| **Destination Port**  | `target.port` / `dst.port`   | `destination_port`   | `server_port`        | `remote_port`     | `dst_port`           |                                                                       |
| **Hostname**          | `principal.hostname` / `target.hostname` / `src.hostname` | `hostname`           | `device_name`        | `machine_name`      | `host`               | Context-dependent (source, target, observer).                       |
| **Domain Name**       | `target.url` (for FQDNs in URLs) / `network.dns.question.name` | `domain`             | `query_name`         | `requested_domain`  | `dns_query`          | Often extracted or part of a larger field.                          |
| **URL**               | `target.url` / `about.url`    | `url`                | `request_url`        | `http_url`          | `full_url`           | `about.url` can be used if the URL is the subject of the event.     |
| **Protocol**          | `network.ip_protocol` / `network.application_protocol` | `protocol`           | `transport_protocol` | `net_protocol`    | `proto`              | E.g., TCP, UDP, ICMP (for ip_protocol); HTTP, DNS (for app_protocol). |

### User/Account Indicators

| Common Concept    | UDM Field (Chronicle)      | Active Directory Field | Linux Log Field | Cloud IAM Field        | Notes                                           |
| :---------------- | :------------------------- | :--------------------- | :-------------- | :--------------------- | :---------------------------------------------- |
| **Username**      | `principal.user.userid` / `target.user.userid` | `sAMAccountName`       | `user`          | `principalEmail`       |                                                 |
| **User Domain**   | (Often part of `userid`)   | `userPrincipalName` (domain part) | N/A             | (Often part of email)  |                                                 |
| **Process Name**  | `principal.process.file.full_path` / `target.process.file.full_path` | `ProcessName`          | `comm`          | `executable.name`    | Includes path if available.                     |
| **File Hash (SHA256)** | `principal.process.file.sha256` / `target.file.sha256` | `FileHash`             | N/A             | `file.sha256`          | Other hashes: `md5`, `sha1`.                  |
| **File Path**     | `target.file.full_path`    | `FileName`             | `path`          | `resource.name` (for GCS) |                                                 |

## Usage by AI Agents

1.  **Query Construction:** When an AI agent needs to search across multiple data sources for an indicator (e.g., an IP address), it should consult this map to find the relevant field names for each target system.
2.  **Data Correlation:** When comparing events from different tools, the agent can use this map to identify equivalent fields, enabling more accurate correlation.
3.  **Enrichment:** During enrichment, if an agent receives data (e.g., from a threat intelligence feed) with a generic field name like "ip_address", it can use this map to understand how to query internal systems for that IP.

## Maintenance

-   This map should be updated as new log sources or security tools are integrated.
-   Regularly review and validate mappings to ensure accuracy.
-   Consider adding mappings for other common entities like MAC addresses, registry keys, service names, etc., as needed.

---

## References and Inspiration

-   The need for data normalization to enable effective AI agent operation across multiple systems is highlighted in:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. (Specifically, the "Data Normalisation Challenge" section). [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
