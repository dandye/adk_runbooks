# Log Correlation Investigation Runbook (Blackboard)

## Overview
This runbook guides the correlation of security events across multiple log sources for SOC blackboard investigations.

## Prerequisites
- Access to Chronicle SIEM and multiple log sources
- Understanding of log formats and event types
- Knowledge of authentication patterns and anomalies
- Access to investigation blackboard

## Phase 1: Context Analysis
1. Read all existing blackboard findings for context
2. Extract key indicators: users, IPs, hostnames, timeframes
3. Identify relevant log sources and systems

## Phase 2: Authentication Analysis
1. Failed logon patterns:
   - Multiple failed attempts from single source
   - Failed attempts across multiple systems
   - Account lockout events
   - Password spray indicators

2. Successful authentication analysis:
   - Unusual login times or locations
   - Service account anomalies
   - Privilege escalation events
   - MFA bypass attempts

## Phase 3: Access Pattern Analysis
1. User behavior analysis:
   - Access to unusual resources
   - Time-based anomalies
   - Geographic impossibilities
   - Permission usage patterns

2. System access correlation:
   - Cross-system access patterns
   - Lateral movement indicators
   - Administrative tool usage
   - Remote access events

## Phase 4: System Activity Correlation
1. Service and process events:
   - Unusual service startups
   - Process execution patterns
   - System configuration changes
   - Security tool tampering

2. Network correlation:
   - Authentication to network events
   - Process to connection mapping
   - Data access patterns

## Phase 5: Timeline Reconstruction
1. Build event sequences:
   - Order events chronologically
   - Identify event clusters
   - Find causality chains
   - Detect timing anomalies

2. Cross-system timeline:
   - Correlate events across hosts
   - Map authentication to activity
   - Identify coordination patterns

## Phase 6: Finding Documentation
Write findings to 'log_correlations' knowledge area with:
- Correlated event descriptions
- Supporting log evidence
- Timeline relationships
- Anomaly indicators
- Confidence assessments

## Finding Types to Detect
- **auth_anomaly**: Authentication pattern anomalies
- **access_violation**: Unauthorized access attempts
- **behavioral_anomaly**: Deviation from normal patterns
- **privilege_abuse**: Misuse of elevated privileges
- **timeline_anomaly**: Suspicious timing patterns
- **coordination_pattern**: Coordinated activities

## Sample Chronicle Queries
- `metadata.event_type = "USER_LOGIN" AND (security_result.summary = "FAILURE" OR "SUCCESS")`
- `metadata.event_type = "ADMIN_EVENT" AND principal.user.userid = "username"`
- `metadata.event_type = "RESOURCE_ACCESS" AND target.resource.name CONTAINS "sensitive"`

## Blackboard Integration
- Read all knowledge areas for correlation candidates
- Focus on authentication and access events
- Write all correlations to 'log_correlations' area
- Support timeline reconstruction efforts
- Tag findings for pattern identification

Always correlate events across multiple systems and timeframes.