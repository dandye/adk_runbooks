# Analytical Query Patterns for AI Agents

This document serves as a "cookbook" for AI agents, providing templates for common analytical questions and their corresponding query structures for key security tools, with a primary focus on Chronicle SIEM (UDM queries via `secops-mcp - search_security_events`).

## Objective

-   To assist AI agents in translating high-level investigative goals or analytical questions into specific, effective queries.
-   To provide a quick reference for common search patterns.
-   To standardize query structures for frequently asked questions during investigations.

## Query Pattern Format

Each pattern will include:
-   **Analytical Question:** The high-level question the agent is trying to answer.
-   **Tool(s):** The recommended MCP tool(s) to use.
-   **Key Parameters/Inputs:** Important parameters for the tool.
-   **Query Template(s):** Example query structures. Placeholders are denoted with `{placeholder_name}`.
-   **Key UDM Fields to Examine (for SIEM queries):** Important fields in the results to focus on.
-   **Notes/Considerations:** Additional tips or context.

---

## Chronicle SIEM Query Patterns (`secops-mcp - search_security_events`)

### 1. Activity by IP Address

-   **Analytical Question:** What network activity has involved IP address `{ip_address}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query incorporating the IP and timeframe.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show all network connections involving IP `{ip_address}` in the last `{hours}` hours."
    -   "List events where principal.ip is `{ip_address}` or target.ip is `{ip_address}` in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type`
    -   `principal.ip`, `principal.port`, `principal.hostname`
    -   `target.ip`, `target.port`, `target.hostname`, `target.url`
    -   `network.application_protocol`, `network.direction`, `network.bytes_sent`, `network.bytes_received`
    -   `security_result.action`
-   **Notes/Considerations:**
    -   Can also use `secops-mcp - lookup_entity` for a summary first.
    -   Specify direction if known (e.g., "outbound connections from `{ip_address}`").

---

### 2. Activity by Hostname

-   **Analytical Question:** What activity has been observed on/from/to host `{hostname}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Find all events related to hostname `{hostname}` in the last `{hours}` hours."
    -   "Show process activity and network connections for `{hostname}` in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `principal.hostname`, `target.hostname`, `src.hostname`
    -   `principal.user.userid` (users on that host)
    -   `principal.process.file.full_path`, `principal.process.command_line`
    -   `network.*` fields for network activity.
-   **Notes/Considerations:**
    -   Ensure hostname is accurate (FQDN vs. short name).
    -   Combine with other indicators if available (e.g., "activity for user `{user}` on host `{hostname}`").

---

### 3. User Login Activity

-   **Analytical Question:** What are the login attempts (successful and failed) for user `{username}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show login events for user `{username}` in the last `{hours}` hours."
    -   "List successful and failed logins for `{username}` across all systems in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `USER_LOGIN`, `USER_UNCATEGORIZED`)
    -   `principal.user.userid`, `target.user.userid` (depending on log source)
    -   `principal.hostname` (source of login attempt)
    -   `target.hostname` (system logged into)
    -   `security_result.action` (e.g., `ALLOW`, `BLOCK`, `FAIL`)
    -   `security_result.description` (reason for failure)
    -   `src.ip` (source IP of login attempt)
-   **Notes/Considerations:**
    -   Login event types and field details can vary significantly by log source (Windows, Linux, VPN, Cloud).
    -   Look for patterns: logins from unusual IPs/geolocations, multiple failed attempts followed by success.

---

### 4. File Hash Observations / Executions

-   **Analytical Question:** Has file hash `{file_hash}` (SHA256/MD5/SHA1) been observed or executed in the environment in the last `{days}` days?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: (`{days}` * 24)
-   **Query Template (Natural Language for `text` parameter):**
    -   "Find events involving file hash `{file_hash}` in the last `{days}` days."
    -   "Show process launch events for SHA256 hash `{file_hash}` in the past `{days}` days."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `PROCESS_LAUNCH`, `FILE_OPEN`, `SCAN_FILE`)
    -   `principal.process.file.sha256` (or `.md5`, `.sha1`)
    -   `target.file.sha256` (or `.md5`, `.sha1`)
    -   `about.file.sha256` (or `.md5`, `.sha1`)
    -   `principal.hostname` (host where file was seen/executed)
    -   `principal.user.userid` (user context)
    -   `principal.process.command_line`
-   **Notes/Considerations:**
    -   Specify the hash type if known (e.g., "SHA256 hash").
    -   Can also use `secops-mcp - lookup_entity` for a quick summary.

---

### 5. DNS Queries for a Specific Domain

-   **Analytical Question:** Which internal hosts have performed DNS lookups for domain `{domain_name}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show DNS lookups for domain `{domain_name}` in the last `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`
    -   `network.dns.question.name` (should match `{domain_name}`)
    -   `network.dns.answers.rdata` (resolved IP addresses)
    -   `principal.ip` / `principal.hostname` (client performing the lookup)
-   **Notes/Considerations:**
    -   Useful for tracking connections to potentially malicious domains.

---

### 6. Connections to a Specific Port

-   **Analytical Question:** What internal hosts have made connections to destination port `{port_number}` (external or internal) in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "List network connections to destination port `{port_number}` in the last `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`
    -   `principal.ip` / `principal.hostname` (source of connection)
    -   `target.ip` / `target.hostname` (destination of connection)
    -   `target.port` (should match `{port_number}`)
    -   `network.application_protocol`
-   **Notes/Considerations:**
    -   Filter by `network.direction` = "OUTBOUND" if looking for internal clients connecting out.
    -   Filter by specific `target.ip` or `principal.ip` to narrow down.

---

### 7. PowerShell Command Line Activity

-   **Analytical Question:** Are there any suspicious PowerShell command line executions in the last `{hours}` hours? (e.g., containing "Invoke-Expression", "iex", "encodedcommand", specific download strings)
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Find PowerShell process launch events with 'Invoke-Expression' in the command line in the last `{hours}` hours."
    -   "Show PowerShell executions containing 'encodedcommand' in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`
    -   `principal.hostname`
    -   `principal.user.userid`
    -   `principal.process.file.full_path` (should contain `powershell.exe`)
    -   `principal.process.command_line` (examine for suspicious keywords, obfuscation)
    -   `principal.process.parent_process.file.full_path` (parent process)
-   **Notes/Considerations:**
    -   This often requires looking for specific keywords or patterns indicative of malicious PowerShell usage.
    -   Refer to MITRE ATT&CK T1059.001 for common suspicious patterns.

---

### 8. Process Parent-Child Relationships

-   **Analytical Question:** What child processes has `{process_name}` spawned on host `{hostname}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show child processes spawned by `{process_name}` on host `{hostname}` in the last `{hours}` hours."
    -   "Find process launch events where parent process is `{process_name}` on `{hostname}` in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `PROCESS_LAUNCH`)
    -   `principal.hostname` (should match `{hostname}`)
    -   `principal.process.file.full_path` (child process)
    -   `principal.process.command_line` (child process arguments)
    -   `principal.process.parent_process.file.full_path` (should contain `{process_name}`)
    -   `principal.process.parent_process.command_line`
    -   `principal.user.userid` (user context)
-   **Notes/Considerations:**
    -   Useful for investigating suspicious parent processes like Office applications spawning cmd.exe/powershell.exe.
    -   Look for unusual parent-child relationships that may indicate process injection or living-off-the-land techniques.

---

### 9. File Creation/Modification in Suspicious Locations

-   **Analytical Question:** Have any files been created or modified in suspicious directories (e.g., temp folders, startup folders) in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show file creation events in temp directories or startup folders in the last `{hours}` hours."
    -   "Find files created in C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `FILE_CREATION`, `FILE_MODIFICATION`)
    -   `target.file.full_path` (examine path for suspicious locations)
    -   `target.file.sha256` (for further analysis)
    -   `principal.hostname` (affected host)
    -   `principal.user.userid` (user context)
    -   `principal.process.file.full_path` (process that created/modified the file)
-   **Notes/Considerations:**
    -   Common suspicious paths: temp folders, startup folders, System32, browser download directories.
    -   Look for files with suspicious extensions (.scr, .pif, .bat, .vbs) or executable files in non-standard locations.

---

### 10. Registry Modifications

-   **Analytical Question:** What registry modifications have occurred related to `{registry_key_pattern}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show registry modification events for keys containing `{registry_key_pattern}` in the last `{hours}` hours."
    -   "Find registry changes in Run keys or persistence locations in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `REGISTRY_MODIFICATION`)
    -   `target.registry.registry_key` (modified registry key)
    -   `target.registry.registry_value_name` (value name)
    -   `target.registry.registry_value_data` (new value data)
    -   `principal.hostname` (affected host)
    -   `principal.user.userid` (user context)
    -   `principal.process.file.full_path` (process making the change)
-   **Notes/Considerations:**
    -   Focus on persistence mechanisms: Run keys, Services, WMI subscriptions, Scheduled Tasks.
    -   Common suspicious keys: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run, HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.

---

### 11. Network Traffic to Suspicious Domains/IPs

-   **Analytical Question:** Has any internal host communicated with known bad IPs/domains from threat intelligence in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query incorporating specific indicators.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show network connections to IP addresses in the range `{suspicious_ip_range}` in the last `{hours}` hours."
    -   "Find HTTP/HTTPS connections to domains containing `{suspicious_domain_pattern}` in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `NETWORK_CONNECTION`)
    -   `principal.ip` / `principal.hostname` (internal source)
    -   `target.ip` / `target.hostname` (external destination)
    -   `target.url` (for HTTP connections)
    -   `network.application_protocol`
    -   `security_result.action` (allowed/blocked)
-   **Notes/Considerations:**
    -   Cross-reference with threat intelligence feeds or IOC lists.
    -   Look for patterns: beaconing behavior, data exfiltration volumes, command and control traffic.

---

### 12. Lateral Movement Indicators

-   **Analytical Question:** Are there signs of lateral movement involving user `{username}` or from host `{source_hostname}` in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show remote login events and network connections from `{source_hostname}` to other internal hosts in the last `{hours}` hours."
    -   "Find WMI, PSExec, or RDP activity involving user `{username}` across multiple hosts in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `USER_LOGIN`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`)
    -   `principal.hostname` / `target.hostname` (source and destination hosts)
    -   `principal.user.userid` / `target.user.userid` (user accounts involved)
    -   `principal.process.file.full_path` (look for psexec.exe, wmiprvse.exe, mstsc.exe)
    -   `network.application_protocol` (SMB, RDP, WinRM)
    -   `target.port` (445 for SMB, 3389 for RDP, 5985/5986 for WinRM)
-   **Notes/Considerations:**
    -   Look for authentication events followed by process execution or file access on remote hosts.
    -   Time correlation is key - events should occur in logical sequence across different hosts.

---

### 13. Data Staging and Exfiltration Patterns

-   **Analytical Question:** Are there signs of data staging or large file transfers that might indicate data exfiltration in the last `{hours}` hours?
-   **Tool(s):** `secops-mcp - search_security_events`
-   **Key Parameters/Inputs:**
    -   `text`: Natural language query.
    -   `hours_back`: `{hours}`
-   **Query Template (Natural Language for `text` parameter):**
    -   "Show file operations creating large files or archives in unusual locations in the last `{hours}` hours."
    -   "Find network connections with high data transfer volumes to external IPs in the past `{hours}` hours."
-   **Key UDM Fields to Examine:**
    -   `metadata.event_timestamp`, `metadata.event_type` (e.g., `FILE_CREATION`, `NETWORK_CONNECTION`)
    -   `target.file.full_path` (look for .zip, .rar, .7z files)
    -   `target.file.size` (large file sizes)
    -   `network.bytes_sent` / `network.bytes_received` (large data transfers)
    -   `principal.hostname` (source host)
    -   `target.ip` (external destination for network events)
    -   `principal.user.userid` (user context)
-   **Notes/Considerations:**
    -   Look for archiving tools (7zip.exe, winrar.exe) followed by network transfers.
    -   Consider normal business hours and typical data transfer patterns for your organization.

---

## General Notes for AI Agent Querying:

-   **Iterative Refinement:** Start with broader queries if unsure, then narrow down based on initial results.
-   **Time Windows:** Be mindful of `hours_back`. Too short might miss activity; too long might be slow or return too much data. Default to 24-72 hours for initial checks unless otherwise specified.
-   **UDM Knowledge:** A deeper understanding of UDM fields will allow for more precise natural language queries that translate effectively.
-   **Cross-Referencing:** Always cross-reference findings with other `rules-bank` documents (e.g., `asset_inventory_guidelines.md`, `network_map.md`, `whitelists.md`) for contextualization.

---

## References and Inspiration

-   The structured approach to query generation supports the AI agent's role in investigation as outlined in:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
-   Effective querying is fundamental to many metrics within the PICERL framework, such as MTTD, MTTT, and AI Decision Accuracy:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
