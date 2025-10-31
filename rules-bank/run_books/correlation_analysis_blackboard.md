# Correlation Analysis Runbook (Blackboard)

## Overview
This runbook guides the analysis of all blackboard findings to identify patterns, correlations, and relationships.

## Prerequisites
- Access to all blackboard knowledge areas
- Understanding of attack patterns and TTPs
- Statistical analysis capabilities
- Access to investigation blackboard

## Phase 1: Data Collection and Preparation
1. Read all blackboard knowledge areas:
   - Network analysis findings
   - Endpoint behavior observations
   - Log correlation results
   - IOC enrichment data
   - Timeline event sequences
   - Threat intelligence

2. Extract correlation candidates:
   - Common entities (IPs, hosts, users, files)
   - Overlapping timeframes
   - Related indicators and artifacts
   - Shared confidence levels and tags

## Phase 2: Entity Relationship Analysis
1. Map entity connections:
   - IP to host relationships
   - User to system access patterns
   - File to process relationships
   - Network to endpoint correlations

2. Build relationship graphs:
   - Direct connections
   - Indirect relationships
   - Transitive associations
   - Hidden connections

## Phase 3: Attack Chain Reconstruction
1. Sequence related events:
   - Order by timeline
   - Group by attack phase
   - Link cause and effect
   - Identify attack flow

2. Map to attack frameworks:
   - MITRE ATT&CK alignment
   - Kill chain progression
   - TTP identification
   - Technique variations

## Phase 4: Pattern Recognition
1. Statistical analysis:
   - Frequency patterns
   - Temporal clustering
   - Behavioral baselines
   - Anomaly detection

2. Coordinated activity detection:
   - Multi-system events
   - Synchronized timing
   - Automated patterns
   - Human-operated indicators

## Phase 5: Risk Scoring
1. Calculate threat levels:
   - Combine confidence scores
   - Weight by impact
   - Factor sophistication
   - Assess persistence

2. Prioritize findings:
   - Critical correlations
   - High-confidence patterns
   - Immediate threats
   - Investigation gaps

## Phase 6: Correlation Documentation
Write findings to 'correlation_results' knowledge area:
- Identified patterns and relationships
- Attack chain sequences
- Risk scores and assessments
- Statistical confidence levels
- Actionable insights
- Investigation recommendations

## Finding Types
- **attack_chain**: Complete attack sequence
- **entity_relationship**: Connected entities
- **pattern_correlation**: Related patterns
- **temporal_correlation**: Time-based relationships
- **risk_assessment**: Aggregate threat scores
- **hidden_connection**: Non-obvious relationships

## Analysis Techniques
1. **Cross-reference Analysis**: Compare findings across all areas
2. **Timeline Correlation**: Align events chronologically
3. **Entity Mapping**: Track entities across systems
4. **Pattern Matching**: Identify repeated behaviors
5. **Statistical Analysis**: Calculate correlation strength

## Confidence Scoring
- High: Multiple corroborating sources
- Medium: Clear relationships with some gaps
- Low: Potential connections needing validation

## Blackboard Integration
- Read ALL knowledge areas comprehensively
- Focus on multi-source correlations
- Write results to 'correlation_results' area
- Provide investigation summary
- Generate actionable recommendations

Always seek hidden connections and non-obvious patterns.