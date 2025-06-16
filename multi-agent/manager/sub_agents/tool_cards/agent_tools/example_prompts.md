# Example Prompts for SOC Analyst Tier 2 Agent Tools

This document provides example prompts that would trigger the use of the various tools available to the SOC Analyst Tier 2 agent.

---

### Native Tools

**1. `create_alert_triage_form`**

*   "Create a new alert triage form for a suspicious login attempt."
*   "I need to triage a malware alert. Can you create the form for me?"
*   "Generate a triage form with the following details: severity high, alert type phishing."

**2. `return_alert_form`**

*   (Agent-initiated) This tool is typically used by the agent to present the form to the user, not directly triggered by a user prompt.

**3. `start_triage`**

*   "Start triage for ID soc_triage_1234567."
*   "Begin the investigation for triage request soc_triage_9876543."
*   "Let's proceed with the analysis for soc_triage_1122334."

---

### SecOps MCP Tools

**1. `search_security_events`**

*   "Search for all network connections from IP address 192.168.1.100 in the last 24 hours."
*   "Find any login failures for the user 'admin' since yesterday."
*   "Show me all events related to the file hash 'e4d909c290d0...'"

**2. `get_security_alerts`**

*   "List all open security alerts."
*   "Are there any new critical alerts in the last hour?"
*   "Show me the latest alerts from the CrowdStrike source system."

**3. `get_security_alert_by_id`**

*   "Get the details for alert ID 'alert-12345'."
*   "I need more information on alert 'chronicle-alert-xyz'."
*   "Pull up the record for alert 'siem-alert-abc'."

**4. `do_update_security_alert`**

*   "Update alert 'alert-12345' to status 'Closed' with the comment 'False positive'."
*   "Change the severity of alert 'alert-67890' to 'High'."
*   "Set the verdict for alert 'alert-abcde' to 'True_Positive'."

**5. `lookup_entity`**

*   "Enrich the IP address 8.8.8.8."
*   "What can you tell me about the domain 'evil.com'?"
*   "Look up the user 'jdoe' in the SIEM."

**6. `list_security_rules`**

*   "List all available security rules."
*   "Show me the definitions of all our detection rules."
*   "Can I get a list of the currently configured rules in Chronicle?"

**7. `search_security_rules`**

*   "Search for security rules that detect 'mimikatz'."
*   "Find all rules related to 'lateral movement'."
*   "Show me rules that use the 'USER_LOGIN' event type."

**8. `get_rule_detections`**

*   "Get all detections for rule 'ru_12345'."
*   "Show me the alerting detections for rule 'ru_67890'."
*   "List the historical detections for the 'Suspicious PowerShell' rule."

**9. `list_rule_errors`**

*   "Are there any execution errors for rule 'ru_12345'?"
*   "Check for errors in the 'New Rule' I just deployed."
*   "Why isn't rule 'ru_67890' generating any detections?"

**10. `get_ioc_matches`**

*   "Have there been any IoC matches in the last 24 hours?"
*   "Show me any recent hits from our threat intelligence feeds."
*   "List all IoC matches for the last 3 days."

**11. `get_threat_intel`**

*   "What is the threat actor APT41?"
*   "Tell me about the malware 'Emotet'."
*   "What is CVE-2021-44228?"

---

### GTI MCP Tools

**1. `get_collection_report`**

*   "Get the report for collection 'report--6e90...'"
*   "I need the details for the threat collection 'threat-actor--1234...'"
*   "Pull up the collection report for 'campaign--abcd...'"

**2. `get_entities_related_to_a_collection`**

*   "What are the domains related to campaign 'campaign--abcd...'?"
*   "List the IP addresses associated with threat actor 'threat-actor--1234...'"
*   "Show me the files related to malware family 'malware-family--efgh...'"

**3. `search_threats`**

*   "Search for threats related to 'FIN7'."
*   "Find all malware families that target the financial industry."
*   "Show me the latest campaigns."

**4. `search_campaigns`**

*   "Search for campaigns related to the 'SolarWinds' compromise."
*   "Find all campaigns that use 'Cobalt Strike'."
*   "Show me the latest phishing campaigns."

**5. `search_threat_actors`**

*   "Search for the threat actor 'APT28'."
*   "Find all threat actors that are sponsored by a nation-state."
*   "Show me the threat actors that target the energy sector."

**6. `search_malware_families`**

*   "Search for the malware family 'Ryuk'."
*   "Find all ransomware families."
*   "Show me the latest banking trojans."

**7. `search_software_toolkits`**

*   "Search for the software toolkit 'Metasploit'."
*   "Find all legitimate tools that are commonly used by attackers."
*   "Show me the latest remote access trojans (RATs)."

**8. `search_threat_reports`**

*   "Search for threat reports about 'APT41'."
*   "Find all reports that mention 'CVE-2021-44228'."
*   "Show me the latest reports from Google's Threat Analysis Group (TAG)."

**9. `search_vulnerabilities`**

*   "Search for the vulnerability 'CVE-2021-44228'."
*   "Find all critical vulnerabilities that affect Apache."
*   "Show me the latest vulnerabilities in Microsoft Exchange."

**10. `get_collection_timeline_events`**

*   "Get the timeline of events for campaign 'campaign--abcd...'"
*   "Show me the timeline for threat actor 'threat-actor--1234...'"
*   "What is the event timeline for the 'SolarWinds' campaign?"

**11. `get_collection_mitre_tree`**

*   "Get the MITRE ATT&CK mapping for threat actor 'APT28'."
*   "Show me the TTPs for the malware family 'Ryuk'."
*   "What are the MITRE techniques used in the 'SolarWinds' campaign?"

**12. `get_file_report`**

*   "Get the report for the file with hash 'e4d909c290d0...'"
*   "Analyze the file with SHA256 hash '...'"
*   "What can you tell me about this file hash?"

**13. `get_entities_related_to_a_file`**

*   "What are the domains contacted by the file with hash 'e4d909c290d0...'?"
*   "List the IP addresses that this file has been downloaded from."
*   "Show me the dropped files for this malware sample."

**14. `get_file_behavior_report`**

*   "Get the behavior report for the file with hash 'e4d909c290d0...' in the 'Windows 7' sandbox."
*   "Show me the network behavior for this file."
*   "What did this file do when it was executed?"

**15. `get_file_behavior_summary`**

*   "Get the behavior summary for the file with hash 'e4d909c290d0...'"
*   "Summarize the behavior of this malware sample."
*   "What is the overall behavior of this file across all sandboxes?"

**16. `analyse_file`**

*   "Analyze the file at '/path/to/malicious.exe'."
*   "Upload and analyze this suspicious file."
*   "I have a file I need you to analyze."

**17. `search_iocs`**

*   "Search for the IoC '1.2.3.4'."
*   "Find all files with a high number of positive detections."
*   "Show me the latest URLs that have been submitted."

**18. `get_hunting_ruleset`**

*   "Get the hunting ruleset with ID 'hr_12345'."
*   "Show me the Yara rules in this ruleset."
*   "What is the content of this hunting ruleset?"

**19. `get_entities_related_to_a_hunting_ruleset`**

*   "What files have matched the hunting ruleset 'hr_12345'?"
*   "Show me the notifications for this ruleset."
*   "List the files that have been flagged by these Yara rules."

**20. `get_domain_report`**

*   "Get the report for the domain 'google.com'."
*   "Analyze the domain 'evil.com'."
*   "What can you tell me about this domain?"

**21. `get_entities_related_to_a_domain`**

*   "What are the subdomains of 'google.com'?"
*   "List the IP addresses that have resolved to 'evil.com'."
*   "Show me the communicating files for this domain."

**22. `get_ip_address_report`**

*   "Get the report for the IP address '8.8.8.8'."
*   "Analyze the IP address '1.2.3.4'."
*   "What can you tell me about this IP?"

**23. `get_entities_related_to_an_ip_address`**

*   "What are the domains that have resolved to '8.8.8.8'?"
*   "List the communicating files for the IP address '1.2.3.4'."
*   "Show me the URLs hosted at this IP."

**24. `list_threat_profiles`**

*   "List all my threat profiles."
*   "Show me the available threat profiles."
*   "Can I get a list of my configured threat profiles?"

**25. `get_threat_profile`**

*   "Get the threat profile with ID 'tp_12345'."
*   "Show me the details of my 'Financial Services' threat profile."
*   "What are the interests configured for this threat profile?"

**26. `get_threat_profile_recommendations`**

*   "Get the recommendations for my 'Financial Services' threat profile."
*   "Show me the recommended threats for profile 'tp_12345'."
*   "What are the latest recommendations for my threat profile?"

**27. `get_threat_profile_associations_timeline`**

*   "Get the associations timeline for my 'Financial Services' threat profile."
*   "Show me the timeline of associations for profile 'tp_12345'."
*   "What is the history of associations for this threat profile?"

**28. `get_url_report`**

*   "Get the report for the URL 'http://example.com/malicious.html'."
*   "Analyze the URL 'http://evil.com/phishing'."
*   "What can you tell me about this URL?"

**29. `get_entities_related_to_an_url`**

*   "What are the domains contacted by the URL 'http://example.com/malicious.html'?"
*   "List the IP addresses that this URL redirects to."
*   "Show me the downloaded files for this URL."

---

### SOAR MCP Tools

**1. `list_cases`**

*   "List all open cases."
*   "Show me the latest cases."
*   "Can I get a list of all the cases in the SOAR?"

**2. `post_case_comment`**

*   "Add the comment 'Investigating now' to case 'case-12345'."
*   "Post a comment to case 'case-67890' with my findings."
*   "I need to add a note to this case."

**3. `list_alerts_by_case`**

*   "List all alerts for case 'case-12345'."
*   "Show me the alerts associated with this case."
*   "What are the alerts for case 'case-67890'?"

**4. `list_alert_group_identifiers_by_case`**

*   "List the alert group identifiers for case 'case-12345'."
*   "Show me the alert groups for this case."
*   "What are the group identifiers for the alerts in this case?"

**5. `list_events_by_alert`**

*   "List the events for alert 'alert-12345' in case 'case-12345'."
*   "Show me the raw events for this alert."
*   "What are the underlying events for this alert?"

**6. `change_case_priority`**

*   "Change the priority of case 'case-12345' to 'High'."
*   "Update the priority of this case to 'Critical'."
*   "This case is not as important, change the priority to 'Low'."

**7. `get_entities_by_alert_group_identifiers`**

*   "Get the entities for the alert group 'group-12345' in case 'case-12345'."
*   "Show me the entities associated with these alert groups."
*   "What are the entities for this alert group?"

**8. `get_entity_details`**

*   "Get the details for the entity '1.2.3.4' of type 'IP Address' in the 'Production' environment."
*   "Show me the details for this entity."
*   "What can you tell me about this entity?"

**9. `search_entity`**

*   "Search for the entity '1.2.3.4'."
*   "Find all entities of type 'Hostname' that are suspicious."
*   "Show me all internal assets that are not enriched."

**10. `get_case_full_details`**

*   "Get the full details for case 'case-12345'."
*   "Show me everything about this case."
*   "I need a complete overview of this case."

---

### SCC MCP Tools

**1. `top_vulnerability_findings`**

*   "List the top vulnerability findings for the project 'my-gcp-project'."
*   "Show me the most critical vulnerabilities in my project."
*   "What are the top 20 vulnerabilities in this project?"

**2. `get_finding_remediation`**

*   "Get the remediation steps for the finding with ID 'finding-12345' in project 'my-gcp-project'."
*   "How do I fix the vulnerability on resource '//container.googleapis.com/...'?"
*   "What are the next steps for this finding?"
