# Timeline Reconstruction Runbook (Blackboard)

## Overview
This runbook guides the construction of comprehensive event timelines for SOC blackboard investigations.

## Prerequisites
- Access to all blackboard knowledge areas
- Understanding of attack lifecycle phases
- Knowledge of timestamp formats and timezones
- Access to investigation blackboard

## Phase 1: Event Collection
1. Read all blackboard findings:
   - Network events with timestamps
   - Endpoint activities and processes
   - Authentication and access logs
   - IOC observations
   - Log correlations

2. Extract temporal information:
   - Event timestamps
   - Duration indicators
   - Sequence markers
   - Relative time references

## Phase 2: Timestamp Normalization
1. Standardize time formats:
   - Convert to UTC
   - Resolve timezone differences
   - Handle missing timestamps
   - Interpolate approximate times

2. Validate chronology:
   - Check for impossible sequences
   - Identify time conflicts
   - Resolve discrepancies

## Phase 3: Timeline Construction
1. Build master timeline:
   - Order all events chronologically
   - Include confidence levels
   - Note data sources
   - Preserve context

2. Event categorization:
   - Group by system/host
   - Classify by activity type
   - Tag with attack phase
   - Mark critical events

## Phase 4: Pattern Analysis
1. Identify event clusters:
   - Rapid sequences
   - Coordinated activities
   - Burst patterns
   - Quiet periods

2. Attack phase mapping:
   - Initial reconnaissance
   - Initial access/compromise
   - Persistence establishment
   - Privilege escalation
   - Lateral movement
   - Data collection
   - Exfiltration
   - Cleanup/anti-forensics

## Phase 5: Gap Analysis
1. Identify missing periods:
   - Unexplained gaps
   - Deleted logs
   - Anti-forensic activities
   - Collection limitations

2. Critical moment identification:
   - First compromise indicator
   - Privilege escalation points
   - Lateral movement initiation
   - Data access moments
   - Exfiltration start

## Phase 6: Timeline Documentation
Write to 'timeline_events' knowledge area:
- Complete chronological sequence
- Event clusters and patterns
- Attack phase mappings
- Critical moments
- Timeline gaps and uncertainties

## Finding Types
- **timeline_sequence**: Chronological event ordering
- **event_cluster**: Related events in time window
- **attack_phase**: Kill chain phase identification
- **critical_moment**: Key investigation points
- **timeline_gap**: Missing or unclear periods
- **temporal_anomaly**: Time-based irregularities

## Timeline Visualization Format
For each event include:
- Timestamp (UTC)
- Event description
- Source system/log
- Confidence level
- Attack phase
- Related findings

## Blackboard Integration
- Read all knowledge areas for events
- Focus on timestamp extraction
- Write timeline to 'timeline_events' area
- Support investigation narrative
- Enable phase-based analysis

Always maintain chronological accuracy and note uncertainties.