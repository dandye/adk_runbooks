# IOC Enrichment Investigation Runbook (Blackboard)

## Overview
This runbook guides the enrichment of indicators of compromise (IOCs) with threat intelligence for SOC blackboard investigations.

## Prerequisites
- Access to threat intelligence platforms (VirusTotal, Chronicle)
- Understanding of threat actor TTPs and campaigns
- Knowledge of MITRE ATT&CK framework
- Access to investigation blackboard

## Phase 1: IOC Extraction
1. Read all blackboard findings for indicators:
   - IP addresses from network analysis
   - File hashes from endpoint analysis
   - Domains and URLs from various sources
   - Email addresses, usernames, etc.

2. Prioritize IOCs by:
   - Confidence level from source findings
   - Uniqueness and specificity
   - Potential impact level

## Phase 2: Reputation Analysis
1. VirusTotal analysis:
   - File hash reputation and detection rates
   - URL/domain reputation and categories
   - IP address reputation and geolocation
   - Related samples and infrastructure

2. Chronicle threat intelligence:
   - IOC first/last seen timestamps
   - Associated campaigns and actors
   - Geographic distribution
   - Prevalence and rarity scores

## Phase 3: Attribution Analysis
1. Campaign correlation:
   - Match IOCs to known campaigns
   - Identify threat actor groups
   - Timeline correlation with campaign activity
   - Infrastructure overlap analysis

2. TTP mapping:
   - Map observed behaviors to MITRE ATT&CK
   - Identify technique variations
   - Correlate with threat actor TTPs
   - Build attack chain narrative

## Phase 4: Related Indicator Discovery
1. Infrastructure expansion:
   - Related domains and subdomains
   - IP address ranges and ASNs
   - SSL certificate commonalities
   - WHOIS registration patterns

2. Malware family analysis:
   - Variant identification
   - Code similarity analysis
   - Behavior pattern matching
   - Evolution timeline

## Phase 5: Risk Assessment
1. Threat scoring:
   - Combine reputation scores
   - Factor in campaign sophistication
   - Consider targeting relevance
   - Calculate overall risk level

2. Impact analysis:
   - Assess potential damage
   - Identify critical systems at risk
   - Evaluate detection capabilities
   - Recommend response priorities

## Phase 6: Finding Documentation
Write enrichments to 'ioc_enrichments' and threat intel to 'threat_intelligence':
- IOC reputation and risk scores
- Threat actor attribution
- Campaign associations
- MITRE ATT&CK mappings
- Related indicators and infrastructure
- Recommended actions

## Finding Types
- **ioc_reputation**: Reputation analysis results
- **threat_attribution**: Actor/campaign attribution
- **mitre_mapping**: ATT&CK technique identification
- **related_indicators**: Connected IOCs and infrastructure
- **malware_family**: Malware classification
- **campaign_analysis**: Campaign timeline and TTPs

## Blackboard Integration
- Read network_analysis and endpoint_behaviors for IOCs
- Read investigation_metadata for context
- Write enrichments to 'ioc_enrichments' knowledge area
- Write threat intelligence to 'threat_intelligence' knowledge area
- Support findings from other investigators with intelligence context
- Tag findings for correlation: [reputation, attribution, mitre, etc.]

Prioritize enrichment of high-confidence IOCs from other investigators.

## Tool Usage
You have access to:
- MCP Security tools (Chronicle, GTI, SOAR)
- Blackboard tools (blackboard_read, blackboard_write, blackboard_query)
- Reporting tools (write_report, get_current_time)

Focus on actionable intelligence that supports investigation conclusions.