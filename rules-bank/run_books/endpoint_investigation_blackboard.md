# Endpoint Investigation Runbook (Blackboard)

## Overview
This runbook guides endpoint/host-based security event analysis for investigations using the SOC blackboard system.

## Prerequisites
- Access to Chronicle SIEM/EDR data
- Understanding of Windows/Linux system internals
- Knowledge of common attack techniques and TTPs
- Access to investigation blackboard

## Phase 1: Context Gathering
1. Read network_analysis findings for relevant IPs and hosts
2. Read investigation_metadata for target systems and timeframes
3. Identify key endpoints for detailed analysis

## Phase 2: Process Analysis
1. Process execution analysis:
   - Suspicious process names or paths
   - Unsigned or rare executables
   - Process injection indicators
   - Unusual parent-child relationships
   
2. Command line analysis:
   - PowerShell usage and encoded commands
   - WMI queries and remote execution
   - System administration tool usage
   - Suspicious command line parameters

## Phase 3: File System Analysis
1. File creation/modification events:
   - Executable drops in temp directories
   - Files created in system directories
   - Large file operations (staging)
   - File extension anomalies
   
2. Persistence analysis:
   - Registry run keys
   - Startup folder modifications
   - Scheduled tasks creation
   - Service installations

## Phase 4: Network Context Correlation
1. Correlate process execution with network connections
2. Identify processes responsible for suspicious network traffic
3. Map file system changes to network communications

## Phase 5: Lateral Movement Detection
1. Remote logon events and credential usage
2. Administrative tool execution (PsExec, WMI, etc.)
3. File sharing and remote file access
4. Privilege escalation attempts

## Phase 6: Finding Documentation
Write findings to 'endpoint_behaviors' knowledge area with:
- Host/endpoint identifiers
- Process details (PID, path, command line)
- File system changes
- Registry modifications
- Timeline of events
- Risk assessment and confidence level

## Finding Types to Detect
- **malware_execution**: Suspicious process execution
- **persistence_mechanism**: Autostart/persistence techniques
- **privilege_escalation**: Elevation of privileges attempts
- **lateral_movement**: Movement between systems
- **credential_access**: Credential dumping/theft
- **data_staging**: File compression/staging for exfiltration
- **defense_evasion**: Anti-forensics or hiding techniques
- **living_off_land**: Abuse of legitimate tools

## Sample Chronicle Queries for Endpoints
- `metadata.event_type = "PROCESS_LAUNCH" AND target.process.file.full_path CONTAINS "suspicious_path"`
- `metadata.event_type = "FILE_CREATION" AND target.file.full_path CONTAINS "\\Temp\\"`
- `metadata.event_type = "REGISTRY_MODIFICATION" AND target.registry.registry_key_path CONTAINS "Run"`
- `metadata.event_type = "NETWORK_CONNECTION" AND principal.process.file.full_path = "process_path"`

## Blackboard Integration
- Read investigation_metadata for target hosts and timeframes
- Read network_analysis findings to correlate with endpoint events
- Read log_correlations for additional context
- Write all endpoint findings to 'endpoint_behaviors' knowledge area
- Use confidence levels: low, medium, high based on evidence strength
- Tag findings appropriately: [malware, persistence, lateral_movement, etc.]

## Investigation Context
Review blackboard for:
- Target hostnames/IPs from initial indicators
- Network connections identified by network analyzer
- Suspicious timeframes for targeted analysis
- Related findings from other investigators

Start by understanding what systems and timeframes to focus on from other findings.

## Tool Usage
You have access to:
- MCP Security tools (Chronicle, GTI, SOAR)
- Blackboard tools (blackboard_read, blackboard_write, blackboard_query)
- Reporting tools (write_report, get_current_time)

Always correlate endpoint events with network findings and provide detailed context.