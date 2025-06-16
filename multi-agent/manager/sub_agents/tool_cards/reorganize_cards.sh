#!/bin/bash

# Script to reorganize tool cards into MCP and agent-specific categories

# MCP tool cards (actual MCP server tools)
mcp_tools=(
    "gti_mcp_analyse_file.md"
    "gti_mcp_get_collection_mitre_tree.md"
    "gti_mcp_get_collection_report.md"
    "gti_mcp_get_collection_timeline_events.md"
    "gti_mcp_get_domain_report.md"
    "gti_mcp_get_entities_related_to_a_collection.md"
    "gti_mcp_get_entities_related_to_a_domain.md"
    "gti_mcp_get_entities_related_to_a_file.md"
    "gti_mcp_get_entities_related_to_a_hunting_ruleset.md"
    "gti_mcp_get_entities_related_to_an_ip_address.md"
    "gti_mcp_get_entities_related_to_an_url.md"
    "gti_mcp_get_file_behavior_report.md"
    "gti_mcp_get_file_behavior_summary.md"
    "gti_mcp_get_file_report.md"
    "gti_mcp_get_hunting_ruleset.md"
    "gti_mcp_get_ip_address_report.md"
    "gti_mcp_get_threat_profile.md"
    "gti_mcp_get_threat_profile_associations_timeline.md"
    "gti_mcp_get_threat_profile_recommendations.md"
    "gti_mcp_get_url_report.md"
    "gti_mcp_list_threat_profiles.md"
    "gti_mcp_search_campaigns.md"
    "gti_mcp_search_iocs.md"
    "gti_mcp_search_malware_families.md"
    "gti_mcp_search_software_toolkits.md"
    "gti_mcp_search_threat_actors.md"
    "gti_mcp_search_threat_reports.md"
    "gti_mcp_search_threats.md"
    "gti_mcp_search_vulnerabilities.md"
    "scc_mcp_get_finding_remediation.md"
    "scc_mcp_top_vulnerability_findings.md"
    "secops_mcp_do_update_security_alert.md"
    "secops_mcp_get_ioc_matches.md"
    "secops_mcp_get_rule_detections.md"
    "secops_mcp_get_security_alert_by_id.md"
    "secops_mcp_get_security_alerts.md"
    "secops_mcp_get_threat_intel.md"
    "secops_mcp_list_rule_errors.md"
    "secops_mcp_list_security_rules.md"
    "secops_mcp_lookup_entity.md"
    "secops_mcp_search_security_events.md"
    "secops_mcp_search_security_rules.md"
    "soar_mcp_change_case_priority.md"
    "soar_mcp_get_case_full_details.md"
    "soar_mcp_get_entities_by_alert_group_identifiers.md"
    "soar_mcp_get_entity_details.md"
    "soar_mcp_list_alert_group_identifiers_by_case.md"
    "soar_mcp_list_alerts_by_case.md"
    "soar_mcp_list_cases.md"
    "soar_mcp_list_events_by_alert.md"
    "soar_mcp_post_case_comment.md"
    "soar_mcp_search_entity.md"
)

# Agent-specific tool cards (forms, workflows, etc.)
agent_tools=(
    "create_alert_triage_form.md"
    "create_advanced_investigation_form.md"
    "create_detection_rule.md"
    "create_detection_rule_form.md"
    "create_incident_response_form.md"
    "create_research_request_form.md"
    "example_prompts.md"
    "initiate_advanced_investigation.md"
    "initiate_incident_response.md"
    "return_advanced_investigation_form.md"
    "return_alert_form.md"
    "return_detection_rule_form.md"
    "return_incident_response_form.md"
    "return_research_form.md"
    "start_research.md"
    "start_triage.md"
)

echo "Organizing MCP tool cards..."
for tool in "${mcp_tools[@]}"; do
    if [ -f "$tool" ]; then
        mv "$tool" "mcp_tools/" 2>/dev/null && echo "  Moved $tool to mcp_tools/"
    fi
done

echo -e "\nOrganizing agent-specific tool cards..."
for tool in "${agent_tools[@]}"; do
    if [ -f "$tool" ]; then
        mv "$tool" "agent_tools/" 2>/dev/null && echo "  Moved $tool to agent_tools/"
    fi
done

echo -e "\nReorganization complete!"
echo "MCP tools: $(ls mcp_tools/ | wc -l) files"
echo "Agent tools: $(ls agent_tools/ | wc -l) files"