# GTI MCP Tools Reference

This document lists all available Google Threat Intelligence (GTI) MCP tools from the `mcp_security_debugging` project.

## File Analysis Tools
- `get_file_report` - Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256)
- `get_entities_related_to_a_file` - Retrieve entities related to a file hash (domains, IPs, URLs, etc.)
- `get_file_behavior_report` - Retrieve the file behavior report for a specific file behavior ID
- `get_file_behavior_summary` - Get a summary of all file behavior reports from all sandboxes
- `analyse_file` - Upload and analyze a file in VirusTotal

## Search Tools
- `search_iocs` - Search Indicators of Compromise (IoCs) in GTI platform
- `search_threats` - Search for threats in GTI
- `search_campaigns` - Search for threat campaigns
- `search_threat_actors` - Search for threat actors
- `search_malware_families` - Search for malware families
- `search_software_toolkits` - Search for software toolkits
- `search_threat_reports` - Search for threat reports
- `search_vulnerabilities` - Search for vulnerabilities

## Collection Tools
- `get_collection_report` - Get a comprehensive report for a GTI collection
- `get_entities_related_to_a_collection` - Get entities related to a collection
- `get_collection_timeline_events` - Get timeline events for a collection
- `get_collection_mitre_tree` - Get MITRE ATT&CK tree for a collection

## Network Analysis Tools
- `get_domain_report` - Get a comprehensive domain analysis report
- `get_entities_related_to_a_domain` - Get entities related to a domain
- `get_ip_address_report` - Get a comprehensive IP address analysis report
- `get_entities_related_to_an_ip_address` - Get entities related to an IP address
- `get_url_report` - Get a comprehensive URL analysis report
- `get_entities_related_to_an_url` - Get entities related to a URL

## Threat Profile Tools
- `list_threat_profiles` - List available threat profiles
- `get_threat_profile` - Get details of a specific threat profile
- `get_threat_profile_recommendations` - Get recommendations for a threat profile
- `get_threat_profile_associations_timeline` - Get associations timeline for a threat profile

## Intelligence Tools
- `get_hunting_ruleset` - Get a hunting ruleset object from GTI
- `get_entities_related_to_a_hunting_ruleset` - Get entities related to a hunting ruleset

## Usage in CTI Researcher Agent

The CTI Researcher agent has full access to these tools. When using the agent:
- For file hash analysis: Use `get_file_report` with the file hash
- For IOC searches: Use `search_iocs` with appropriate query parameters
- For threat actor research: Use `search_threat_actors`
- For campaign investigation: Use `search_campaigns`
- For network indicators: Use the appropriate domain/IP/URL report tools

Note: The correct MCP server path is `/Users/dandye/Projects/mcp_security_debugging/server/gti/gti_mcp`