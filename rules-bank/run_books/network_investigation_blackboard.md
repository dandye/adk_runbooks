# Network Investigation Runbook (Blackboard)

## Overview
This runbook guides network traffic analysis for security investigations using the SOC blackboard system.

## Prerequisites
- Access to Chronicle SIEM
- Access to threat intelligence tools (VirusTotal/GTI)
- Understanding of network protocols and traffic patterns
- Access to investigation blackboard

## Phase 1: Initial Assessment
1. Review initial indicators from blackboard metadata
2. Identify relevant time windows for analysis
3. Query Chronicle for baseline network activity

## Phase 2: Traffic Pattern Analysis
1. Analyze volume patterns:
   - Unusual data transfer volumes
   - Off-hours network activity
   - Bandwidth spikes or sustained high usage
   
2. Connection analysis:
   - External connections to suspicious IPs
   - Unusual ports or protocols
   - Failed connection attempts
   
3. DNS analysis:
   - DNS queries to suspicious domains
   - DNS tunneling indicators
   - Domain generation algorithm (DGA) patterns

## Phase 3: Threat Intelligence Enrichment
1. Check IPs and domains against threat intelligence
2. Identify known malicious infrastructure
3. Map to known threat actor campaigns
4. Check for C2 infrastructure indicators

## Phase 4: Correlation with Other Findings
1. Read endpoint and log findings from blackboard
2. Correlate network activity with endpoint events
3. Identify coordinated activities across systems

## Phase 5: Finding Documentation
Write findings to 'network_analysis' knowledge area with:
- Clear description of suspicious activity
- Supporting evidence and queries used
- Confidence level based on evidence strength
- Relevant tags for correlation
- Risk assessment for each finding

## Finding Types to Detect
- **data_exfiltration**: Large outbound data transfers
- **c2_communication**: Command and control traffic
- **lateral_movement**: Internal network scanning/movement
- **protocol_anomaly**: Unusual protocol usage
- **dns_suspicious**: Suspicious DNS activity
- **geographic_anomaly**: Connections to unusual locations
- **beaconing**: Regular periodic communications
- **port_scanning**: Network reconnaissance activity

## Sample Chronicle Queries
- `metadata.event_type = "NETWORK_CONNECTION" AND network.ip_address = "IP_ADDRESS"`
- `metadata.event_type = "DNS" AND network.dns.questions.name = "DOMAIN"`
- `network.sent_bytes > 1000000 OR network.received_bytes > 1000000`

## Blackboard Integration
- Read initial indicators from investigation_metadata knowledge area
- Read findings from other areas for context (endpoint_behaviors, log_correlations)
- Write all network findings to 'network_analysis' knowledge area
- Use appropriate confidence levels: low, medium, high
- Tag findings for correlation: [data_exfiltration, c2, lateral_movement, etc.]

## Investigation Context Access
The blackboard contains:
- investigation_metadata: Initial indicators and investigation parameters
- Other knowledge areas with findings from different investigators

Always start by reading the investigation context to understand what to investigate.

## Tool Usage
You have access to:
- MCP Security tools (Chronicle, GTI, SOAR)
- Blackboard tools (blackboard_read, blackboard_write, blackboard_query)
- Reporting tools (write_report, get_current_time)

Always include confidence levels and supporting evidence in findings.