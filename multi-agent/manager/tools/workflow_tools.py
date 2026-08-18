"""
ADK Graph Workflow Tool Wrappers for Gemini Agents.

Exposes ALL 36 ADK Graph Workflows as executable agent tools for ADK Agent instances.
"""

from typing import Optional, List, Any


def run_advanced_threat_hunting_workflow(hypothesis: str, case_id: str = "", timeframe_hours: int = 168) -> str:
    """Executes ADK Graph Workflow: advanced_threat_hunting_workflow."""
    from ..workflows.advanced_threat_hunting_workflow import (
        AdvancedHuntInput,
        advanced_hunt_router,
        document_advanced_hunt_report_node,
        execute_advanced_siem_hunt_node,
        extract_advanced_hunt_node,
        handle_clean_hypothesis_branch,
        handle_confirmed_pattern_branch
    )
    inp = AdvancedHuntInput(case_id=case_id, hypothesis=hypothesis, timeframe_hours=timeframe_hours)
    curr = extract_advanced_hunt_node(inp)
    curr = execute_advanced_siem_hunt_node(curr)
    route_ev = advanced_hunt_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CONFIRMED_THREAT_PATTERN":
        out = handle_confirmed_pattern_branch(curr)
    elif route_name == "CLEAN_HYPOTHESIS":
        out = handle_clean_hypothesis_branch(curr)
    else:
        out = handle_confirmed_pattern_branch(curr)
    final = document_advanced_hunt_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_alert_report_workflow(alert_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: alert_report_workflow."""
    from ..workflows.alert_report_workflow import (
        AlertReportInput,
        extract_alert_payload_node,
        fetch_alert_and_rule_telemetry_node,
        threat_intelligence_enrichment_node,
        alert_triage_decision_router,
        handle_critical_tp_triage_branch,
        handle_high_incident_triage_branch,
        handle_standard_triage_branch,
        document_alert_report_node
    )
    inp = AlertReportInput(case_id=case_id, alert_id=alert_id)
    payload = extract_alert_payload_node(inp)
    telemetry = fetch_alert_and_rule_telemetry_node(payload)
    enrichment = threat_intelligence_enrichment_node(telemetry)
    route_ev = alert_triage_decision_router(enrichment)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CRITICAL_TRUE_POSITIVE_TRIAGE":
        out = handle_critical_tp_triage_branch(enrichment)
    elif route_name == "HIGH_SEVERITY_INCIDENT_TRIAGE":
        out = handle_high_incident_triage_branch(enrichment)
    else:
        out = handle_standard_triage_branch(enrichment)
    final = document_alert_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_apt_threat_hunt_workflow(threat_actor_name: str, case_id: str = "", timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: apt_threat_hunt_workflow."""
    from ..workflows.apt_threat_hunt_workflow import (
        APTHuntInput,
        apt_hunt_router,
        document_apt_report_node,
        extract_apt_payload_node,
        fetch_apt_threat_intel_node,
        handle_confirmed_apt_campaign_branch,
        handle_no_apt_activity_branch,
        search_apt_siem_events_node
    )
    inp = APTHuntInput(case_id=case_id, threat_actor_name=threat_actor_name, timeframe_days=timeframe_days)
    curr = extract_apt_payload_node(inp)
    curr = fetch_apt_threat_intel_node(curr)
    curr = search_apt_siem_events_node(curr)
    route_ev = apt_hunt_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CONFIRMED_APT_CAMPAIGN":
        out = handle_confirmed_apt_campaign_branch(curr)
    elif route_name == "NO_APT_ACTIVITY":
        out = handle_no_apt_activity_branch(curr)
    else:
        out = handle_confirmed_apt_campaign_branch(curr)
    final = document_apt_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_basic_ioc_enrichment_workflow(ioc_value: str, ioc_type: str = "IP", case_id: str = "", siem_search_hours: int = 24) -> str:
    """Executes ADK Graph Workflow: basic_ioc_enrichment_workflow."""
    from ..workflows.basic_ioc_enrichment_workflow import (
        IOCEnrichmentInput,
        extract_ioc_node,
        ioc_type_router,
        enrich_ip_branch,
        enrich_domain_branch,
        enrich_hash_branch,
        enrich_url_branch,
        siem_search_node,
        ioc_risk_router,
        handle_high_risk_ioc_branch,
        handle_low_risk_ioc_branch,
        document_ioc_enrichment_node,
    )
    inp = IOCEnrichmentInput(ioc_value=ioc_value, ioc_type=ioc_type, case_id=case_id, siem_search_hours=siem_search_hours)
    p = extract_ioc_node(inp)
    tr = ioc_type_router(p)
    route_name = getattr(getattr(tr, "actions", None), "route", None) or getattr(tr, "route", "")
    if route_name == "IP_BRANCH":
        en = enrich_ip_branch(p)
    elif route_name == "DOMAIN_BRANCH":
        en = enrich_domain_branch(p)
    elif route_name == "HASH_BRANCH":
        en = enrich_hash_branch(p)
    else:
        en = enrich_url_branch(p)
    s = siem_search_node(en)
    rr = ioc_risk_router(s)
    r_name = getattr(getattr(rr, "actions", None), "route", None) or getattr(rr, "route", "")
    out = handle_high_risk_ioc_branch(s) if r_name == "HIGH_RISK_THREAT" else handle_low_risk_ioc_branch(s)
    final = document_ioc_enrichment_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    return str(final)

def run_case_report_workflow(case_id: str) -> str:
    """Executes ADK Graph Workflow: case_report_workflow."""
    from ..workflows.case_report_workflow import (
        CaseReportInput,
        case_report_type_router,
        document_case_report_node,
        extract_case_report_payload_node,
        fetch_full_case_details_node,
        handle_executive_case_report_branch,
        handle_standard_case_report_branch
    )
    inp = CaseReportInput(case_id=case_id)
    curr = extract_case_report_payload_node(inp)
    curr = fetch_full_case_details_node(curr)
    route_ev = case_report_type_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "EXECUTIVE_CASE_REPORT":
        out = handle_executive_case_report_branch(curr)
    elif route_name == "STANDARD_CASE_REPORT":
        out = handle_standard_case_report_branch(curr)
    else:
        out = handle_executive_case_report_branch(curr)
    final = document_case_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_close_duplicate_cases_workflow(primary_case_id: str, similarity_days_back: int = 7, confirm_close: bool = True) -> str:
    """Executes ADK Graph Workflow: close_duplicate_cases_workflow."""
    from ..workflows.close_duplicate_cases_workflow import (
        DuplicateCasesInput,
        document_closure_report_node,
        duplicate_case_router,
        extract_primary_case_node,
        find_similar_cases_node,
        handle_close_duplicates_branch,
        handle_skip_closure_branch
    )
    inp = DuplicateCasesInput(primary_case_id=primary_case_id, similarity_days_back=similarity_days_back, confirm_close=confirm_close)
    curr = extract_primary_case_node(inp)
    curr = find_similar_cases_node(curr)
    route_ev = duplicate_case_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CLOSE_DUPLICATES":
        out = handle_close_duplicates_branch(curr)
    elif route_name == "SKIP_CLOSURE":
        out = handle_skip_closure_branch(curr)
    else:
        out = handle_close_duplicates_branch(curr)
    final = document_closure_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_cloud_vulnerability_triage_workflow(finding_id: str, resource_name: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: cloud_vulnerability_triage_workflow."""
    from ..workflows.cloud_vulnerability_triage_workflow import (
        CloudVulnInput,
        document_vuln_report_node,
        extract_vuln_node,
        handle_immediate_patch_branch,
        handle_standard_remediation_branch,
        query_scc_findings_node,
        vuln_severity_router
    )
    inp = CloudVulnInput(finding_id=finding_id, resource_name=resource_name, case_id=case_id)
    curr = extract_vuln_node(inp)
    curr = query_scc_findings_node(curr)
    route_ev = vuln_severity_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "IMMEDIATE_PATCH":
        out = handle_immediate_patch_branch(curr)
    elif route_name == "STANDARD_REMEDIATION":
        out = handle_standard_remediation_branch(curr)
    else:
        out = handle_immediate_patch_branch(curr)
    final = document_vuln_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_compare_gti_collection_workflow(collection_id: str, case_id: str = "", lookback_days: int = 30) -> str:
    """Executes ADK Graph Workflow: compare_gti_collection_workflow."""
    from ..workflows.compare_gti_collection_workflow import (
        GTICollectionInput,
        document_gti_report_node,
        extract_collection_node,
        fetch_gti_collection_iocs_node,
        gti_overlap_router,
        handle_campaign_matched_branch,
        handle_no_match_branch,
        match_siem_events_node
    )
    inp = GTICollectionInput(collection_id=collection_id, case_id=case_id, lookback_days=lookback_days)
    curr = extract_collection_node(inp)
    curr = fetch_gti_collection_iocs_node(curr)
    curr = match_siem_events_node(curr)
    route_ev = gti_overlap_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CAMPAIGN_MATCHED":
        out = handle_campaign_matched_branch(curr)
    elif route_name == "NO_MATCH":
        out = handle_no_match_branch(curr)
    else:
        out = handle_campaign_matched_branch(curr)
    final = document_gti_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_compromised_user_irp_workflow(user_id: str, case_id: str = "", confirm_account_disable: bool = True) -> str:
    """Executes ADK Graph Workflow: compromised_user_irp_workflow."""
    from ..workflows.compromised_user_irp_workflow import (
        CompromisedUserIRPInput,
        assess_user_compromise_impact_node,
        document_user_irp_report_node,
        extract_user_irp_payload_node,
        handle_disable_account_branch,
        handle_monitoring_only_branch,
        user_containment_router
    )
    inp = CompromisedUserIRPInput(case_id=case_id, user_id=user_id, confirm_account_disable=confirm_account_disable)
    curr = extract_user_irp_payload_node(inp)
    curr = assess_user_compromise_impact_node(curr)
    route_ev = user_containment_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "DISABLE_ACCOUNT_REVOKE_SESSIONS":
        out = handle_disable_account_branch(curr)
    elif route_name == "MONITORING_ONLY":
        out = handle_monitoring_only_branch(curr)
    else:
        out = handle_disable_account_branch(curr)
    final = document_user_irp_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_create_investigation_report_workflow(case_id: str, include_timeline: bool = True, include_ioc_table: bool = True) -> str:
    """Executes ADK Graph Workflow: create_investigation_report_workflow."""
    from ..workflows.create_investigation_report_workflow import (
        InvestigationReportInput,
        document_final_report_node,
        extract_report_payload_node,
        fetch_soar_case_details_node,
        handle_detailed_technical_branch,
        handle_executive_summary_branch,
        report_type_router
    )
    inp = InvestigationReportInput(case_id=case_id, include_timeline=include_timeline, include_ioc_table=include_ioc_table)
    curr = extract_report_payload_node(inp)
    curr = fetch_soar_case_details_node(curr)
    route_ev = report_type_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "EXECUTIVE_SUMMARY":
        out = handle_executive_summary_branch(curr)
    elif route_name == "DETAILED_TECHNICAL":
        out = handle_detailed_technical_branch(curr)
    else:
        out = handle_executive_summary_branch(curr)
    final = document_final_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_credential_access_hunt_workflow(target_hostname: str = "", lookback_hours: int = 72) -> str:
    """Executes ADK Graph Workflow: credential_access_hunt_workflow."""
    from ..workflows.credential_access_hunt_workflow import (
        CredentialHuntInput,
        document_hunt_report_node,
        extract_hunt_payload_node,
        handle_clean_hunt_branch,
        handle_confirmed_dumping_branch,
        hunt_threat_router,
        search_lsass_events_node
    )
    inp = CredentialHuntInput(target_hostname=target_hostname, lookback_hours=lookback_hours)
    curr = extract_hunt_payload_node(inp)
    curr = search_lsass_events_node(curr)
    route_ev = hunt_threat_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CONFIRMED_CREDENTIAL_DUMPING":
        out = handle_confirmed_dumping_branch(curr)
    elif route_name == "CLEAN_HUNT":
        out = handle_clean_hunt_branch(curr)
    else:
        out = handle_confirmed_dumping_branch(curr)
    final = document_hunt_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_deep_dive_ioc_analysis_workflow(ioc_value: str, ioc_type: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: deep_dive_ioc_analysis_workflow."""
    from ..workflows.deep_dive_ioc_analysis_workflow import (
        DeepDiveIOCInput,
        deep_dive_threat_router,
        document_deep_dive_report_node,
        extract_deep_dive_payload_node,
        handle_apt_branch,
        handle_benign_deep_dive_branch,
        handle_commodity_branch,
        query_gti_deep_dive_node
    )
    inp = DeepDiveIOCInput(ioc_value=ioc_value, ioc_type=ioc_type, case_id=case_id)
    curr = extract_deep_dive_payload_node(inp)
    curr = query_gti_deep_dive_node(curr)
    route_ev = deep_dive_threat_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ADVANCED_PERSISTENT_THREAT":
        out = handle_apt_branch(curr)
    elif route_name == "COMMODITY_MALWARE":
        out = handle_commodity_branch(curr)
    elif route_name == "BENIGN":
        out = handle_benign_deep_dive_branch(curr)
    else:
        out = handle_apt_branch(curr)
    final = document_deep_dive_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_demo_soc_t2_workflow(case_id: str) -> str:
    """Executes ADK Graph Workflow: demo_soc_t2_workflow."""
    from ..workflows.demo_soc_t2_workflow import (
        DemoSOCT2Input,
        analyze_soc_t2_case_node,
        demo_soc_t2_router,
        document_demo_soc_t2_report_node,
        extract_demo_soc_t2_payload_node,
        handle_escalate_tier_3_branch,
        handle_resolve_tier_2_branch
    )
    inp = DemoSOCT2Input(case_id=case_id)
    curr = extract_demo_soc_t2_payload_node(inp)
    curr = analyze_soc_t2_case_node(curr)
    route_ev = demo_soc_t2_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ESCALATE_TIER_3":
        out = handle_escalate_tier_3_branch(curr)
    elif route_name == "RESOLVE_TIER_2":
        out = handle_resolve_tier_2_branch(curr)
    else:
        out = handle_escalate_tier_3_branch(curr)
    final = document_demo_soc_t2_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_detection_as_code_tuning_workflow(rule_file_path: str, case_id: str = "", commit_sha: str = "") -> str:
    """Executes ADK Graph Workflow: detection_as_code_tuning_workflow."""
    from ..workflows.detection_as_code_tuning_workflow import (
        DACRuleTuningInput,
        dac_ci_router,
        document_dac_report_node,
        extract_dac_payload_node,
        handle_block_ci_failure_branch,
        handle_merge_production_branch,
        run_dac_ci_pipeline_node
    )
    inp = DACRuleTuningInput(case_id=case_id, rule_file_path=rule_file_path, commit_sha=commit_sha)
    curr = extract_dac_payload_node(inp)
    curr = run_dac_ci_pipeline_node(curr)
    route_ev = dac_ci_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "MERGE_PRODUCTION":
        out = handle_merge_production_branch(curr)
    elif route_name == "BLOCK_CI_FAILURE":
        out = handle_block_ci_failure_branch(curr)
    else:
        out = handle_merge_production_branch(curr)
    final = document_dac_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_detection_report_workflow(rule_id: str, case_id: str = "", timeframe_days: int = 7) -> str:
    """Executes ADK Graph Workflow: detection_report_workflow."""
    from ..workflows.detection_report_workflow import (
        DetectionReportInput,
        detection_report_router,
        document_detection_report_node,
        extract_detection_report_payload_node,
        fetch_detection_stats_node,
        handle_high_noise_branch,
        handle_optimal_performance_branch
    )
    inp = DetectionReportInput(case_id=case_id, rule_id=rule_id, timeframe_days=timeframe_days)
    curr = extract_detection_report_payload_node(inp)
    curr = fetch_detection_stats_node(curr)
    route_ev = detection_report_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "HIGH_NOISE_LEVEL":
        out = handle_high_noise_branch(curr)
    elif route_name == "OPTIMAL_PERFORMANCE":
        out = handle_optimal_performance_branch(curr)
    else:
        out = handle_high_noise_branch(curr)
    final = document_detection_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_detection_rule_validation_workflow(rule_id: str, rule_name: str = "", validation_days: int = 14) -> str:
    """Executes ADK Graph Workflow: detection_rule_validation_workflow."""
    from ..workflows.detection_rule_validation_workflow import (
        RuleValidationInput,
        document_rule_report_node,
        extract_rule_payload_node,
        handle_deploy_prod_branch,
        handle_reject_syntax_branch,
        handle_tune_fp_branch,
        rule_tuning_router,
        validate_yara_l_rule_node
    )
    inp = RuleValidationInput(rule_id=rule_id, rule_name=rule_name, validation_days=validation_days)
    curr = extract_rule_payload_node(inp)
    curr = validate_yara_l_rule_node(curr)
    route_ev = rule_tuning_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "REJECT_COMPILATION_ERROR":
        out = handle_reject_syntax_branch(curr)
    elif route_name == "TUNE_FILTER_FP":
        out = handle_tune_fp_branch(curr)
    elif route_name == "DEPLOY_PRODUCTION":
        out = handle_deploy_prod_branch(curr)
    else:
        out = handle_reject_syntax_branch(curr)
    final = document_rule_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_endpoint_triage_workflow(endpoint_id: str, endpoint_type: str, case_id: str, reason_for_triage: str = "", confirm_isolation: bool = False) -> str:
    """Executes ADK Graph Workflow: endpoint_triage_workflow."""
    from ..workflows.endpoint_triage_workflow import (
        EndpointTriageInput,
        assess_compromise_likelihood_node,
        document_endpoint_report_node,
        extract_endpoint_node,
        gather_siem_and_posture_node,
        handle_execute_isolation_branch,
        handle_skip_isolation_branch,
        isolation_router
    )
    inp = EndpointTriageInput(endpoint_id=endpoint_id, endpoint_type=endpoint_type, case_id=case_id, reason_for_triage=reason_for_triage, confirm_isolation=confirm_isolation)
    curr = extract_endpoint_node(inp)
    curr = gather_siem_and_posture_node(curr)
    curr = assess_compromise_likelihood_node(curr)
    route_ev = isolation_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "EXECUTE_ISOLATION":
        out = handle_execute_isolation_branch(curr)
    elif route_name == "SKIP_ISOLATION":
        out = handle_skip_isolation_branch(curr)
    else:
        out = handle_execute_isolation_branch(curr)
    final = document_endpoint_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_group_cases_v2_workflow(case_id: str = "", environment_filter: str = 'ALL', similarity_threshold: float = 0.8) -> str:
    """Executes ADK Graph Workflow: group_cases_v2_workflow."""
    from ..workflows.group_cases_v2_workflow import (
        GroupCasesV2Input,
        compute_v2_case_clusters_node,
        document_group_v2_report_node,
        extract_group_v2_payload_node,
        group_cases_v2_router,
        handle_merge_high_similarity_branch,
        handle_no_merge_required_branch
    )
    inp = GroupCasesV2Input(case_id=case_id, environment_filter=environment_filter, similarity_threshold=similarity_threshold)
    curr = extract_group_v2_payload_node(inp)
    curr = compute_v2_case_clusters_node(curr)
    route_ev = group_cases_v2_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "MERGE_HIGH_SIMILARITY_CASES":
        out = handle_merge_high_similarity_branch(curr)
    elif route_name == "NO_MERGE_REQUIRED":
        out = handle_no_merge_required_branch(curr)
    else:
        out = handle_merge_high_similarity_branch(curr)
    final = document_group_v2_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_group_cases_workflow(target_case_ids: List[str], case_id: str = "", grouping_criteria: str = 'Shared_IOCs_and_Users') -> str:
    """Executes ADK Graph Workflow: group_cases_workflow."""
    from ..workflows.group_cases_workflow import (
        GroupCasesInput,
        case_grouping_router,
        cluster_similar_cases_node,
        document_grouping_report_node,
        extract_group_payload_node,
        handle_group_cases_merged_branch,
        handle_no_grouping_needed_branch
    )
    inp = GroupCasesInput(case_id=case_id, target_case_ids=target_case_ids or ["test_item"], grouping_criteria=grouping_criteria)
    curr = extract_group_payload_node(inp)
    curr = cluster_similar_cases_node(curr)
    route_ev = case_grouping_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "GROUP_CASES_MERGED":
        out = handle_group_cases_merged_branch(curr)
    elif route_name == "NO_GROUPING_NEEDED":
        out = handle_no_grouping_needed_branch(curr)
    else:
        out = handle_group_cases_merged_branch(curr)
    final = document_grouping_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_investigate_case_external_tools_workflow(case_id: str, external_tool: str) -> str:
    """Executes ADK Graph Workflow: investigate_case_external_tools_workflow."""
    from ..workflows.investigate_case_external_tools_workflow import (
        ExternalInvestigationInput,
        document_external_report_node,
        external_tool_router,
        extract_ext_payload_node,
        handle_close_external_branch,
        handle_escalate_external_branch,
        query_external_tool_node
    )
    inp = ExternalInvestigationInput(case_id=case_id, external_tool=external_tool)
    curr = extract_ext_payload_node(inp)
    curr = query_external_tool_node(curr)
    route_ev = external_tool_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ESCALATE_TIER2":
        out = handle_escalate_external_branch(curr)
    elif route_name == "CLOSE_BENIGN":
        out = handle_close_external_branch(curr)
    else:
        out = handle_escalate_external_branch(curr)
    final = document_external_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_investigate_gti_collection_workflow(collection_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: investigate_gti_collection_workflow."""
    from ..workflows.investigate_gti_collection_workflow import (
        GTICollectionInvestigationInput,
        document_gti_collection_report_node,
        extract_gti_collection_payload_node,
        fetch_gti_collection_report_node,
        gti_collection_investigation_router,
        handle_active_campaign_branch,
        handle_no_siem_match_branch
    )
    inp = GTICollectionInvestigationInput(case_id=case_id, collection_id=collection_id)
    curr = extract_gti_collection_payload_node(inp)
    curr = fetch_gti_collection_report_node(curr)
    route_ev = gti_collection_investigation_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ACTIVE_CAMPAIGN_DETECTED":
        out = handle_active_campaign_branch(curr)
    elif route_name == "NO_SIEM_MATCH":
        out = handle_no_siem_match_branch(curr)
    else:
        out = handle_active_campaign_branch(curr)
    final = document_gti_collection_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_ioc_containment_workflow(ioc_value: str, ioc_type: str, case_id: str, confirm_action: bool = True) -> str:
    """Executes ADK Graph Workflow: ioc_containment_workflow."""
    from ..workflows.ioc_containment_workflow import (
        ContainmentInput,
        containment_type_router,
        document_containment_report_node,
        extract_containment_payload_node,
        handle_abort_containment_branch,
        handle_hash_quarantine_branch,
        handle_network_block_branch,
        verify_gti_reputation_node
    )
    inp = ContainmentInput(ioc_value=ioc_value, ioc_type=ioc_type, case_id=case_id, confirm_action=confirm_action)
    curr = extract_containment_payload_node(inp)
    curr = verify_gti_reputation_node(curr)
    route_ev = containment_type_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "NETWORK_BLOCK_BRANCH":
        out = handle_network_block_branch(curr)
    elif route_name == "HASH_QUARANTINE_BRANCH":
        out = handle_hash_quarantine_branch(curr)
    elif route_name == "ABORT_CONTAINMENT":
        out = handle_abort_containment_branch(curr)
    else:
        out = handle_network_block_branch(curr)
    final = document_containment_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_ioc_threat_hunt_workflow(ioc_list: List[str], case_id: str = "", lookback_days: int = 30) -> str:
    """Executes ADK Graph Workflow: ioc_threat_hunt_workflow."""
    from ..workflows.ioc_threat_hunt_workflow import (
        IOCThreatHuntInput,
        document_ioc_hunt_report_node,
        execute_ioc_siem_search_node,
        extract_ioc_hunt_payload_node,
        handle_ioc_matches_found_branch,
        handle_no_ioc_matches_branch,
        ioc_hunt_router
    )
    inp = IOCThreatHuntInput(case_id=case_id, ioc_list=ioc_list or ["test_item"], lookback_days=lookback_days)
    curr = extract_ioc_hunt_payload_node(inp)
    curr = execute_ioc_siem_search_node(curr)
    route_ev = ioc_hunt_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "IOC_MATCHES_FOUND":
        out = handle_ioc_matches_found_branch(curr)
    elif route_name == "NO_IOC_MATCHES":
        out = handle_no_ioc_matches_branch(curr)
    else:
        out = handle_ioc_matches_found_branch(curr)
    final = document_ioc_hunt_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_lateral_movement_hunt_workflow(source_hostname: str = "", lookback_hours: int = 48) -> str:
    """Executes ADK Graph Workflow: lateral_movement_hunt_workflow."""
    from ..workflows.lateral_movement_hunt_workflow import (
        LateralMovementInput,
        document_lateral_report_node,
        extract_lat_move_payload_node,
        handle_clean_lateral_hunt_branch,
        handle_high_lateral_movement_branch,
        lateral_movement_router,
        search_psexec_wmi_events_node
    )
    inp = LateralMovementInput(source_hostname=source_hostname, lookback_hours=lookback_hours)
    curr = extract_lat_move_payload_node(inp)
    curr = search_psexec_wmi_events_node(curr)
    route_ev = lateral_movement_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "HIGH_LATERAL_MOVEMENT":
        out = handle_high_lateral_movement_branch(curr)
    elif route_name == "CLEAN_HUNT":
        out = handle_clean_lateral_hunt_branch(curr)
    else:
        out = handle_high_lateral_movement_branch(curr)
    final = document_lateral_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_malware_irp_workflow(target_host: str, case_id: str = "", file_hash: str = "", confirm_host_isolation: bool = True) -> str:
    """Executes ADK Graph Workflow: malware_irp_workflow."""
    from ..workflows.malware_irp_workflow import (
        MalwareIRPInput,
        assess_malware_incident_scope_node,
        document_malware_irp_report_node,
        extract_malware_irp_payload_node,
        handle_isolate_host_branch,
        handle_scoping_only_branch,
        malware_irp_containment_router
    )
    inp = MalwareIRPInput(case_id=case_id, target_host=target_host, file_hash=file_hash, confirm_host_isolation=confirm_host_isolation)
    curr = extract_malware_irp_payload_node(inp)
    curr = assess_malware_incident_scope_node(curr)
    route_ev = malware_irp_containment_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ISOLATE_HOST_AND_BLOCK_IOCS":
        out = handle_isolate_host_branch(curr)
    elif route_name == "SCOPING_ONLY":
        out = handle_scoping_only_branch(curr)
    else:
        out = handle_isolate_host_branch(curr)
    final = document_malware_irp_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_malware_triage_workflow(file_hash: str, case_id: str, alert_group_id: str = "", time_frame_hours: int = 72) -> str:
    """Executes ADK Graph Workflow: malware_triage_workflow."""
    from ..workflows.malware_triage_workflow import (
        MalwareTriageInput,
        check_siem_execution_node,
        document_malware_report_node,
        enrich_gti_file_node,
        extract_hash_node,
        handle_benign_branch,
        handle_malicious_threat_branch,
        malware_threat_router
    )
    inp = MalwareTriageInput(file_hash=file_hash, case_id=case_id, alert_group_id=alert_group_id, time_frame_hours=time_frame_hours)
    curr = extract_hash_node(inp)
    curr = enrich_gti_file_node(curr)
    curr = check_siem_execution_node(curr)
    route_ev = malware_threat_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "MALICIOUS_THREAT":
        out = handle_malicious_threat_branch(curr)
    elif route_name == "BENIGN_OR_UNKNOWN":
        out = handle_benign_branch(curr)
    else:
        out = handle_malicious_threat_branch(curr)
    final = document_malware_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_metaanalysis_workflow(target_case_ids: List[str], case_id: str = "", timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: metaanalysis_workflow."""
    from ..workflows.metaanalysis_workflow import (
        MetaAnalysisInput,
        document_meta_analysis_report_node,
        extract_meta_analysis_payload_node,
        handle_isolated_incidents_branch,
        handle_systemic_risk_branch,
        meta_analysis_router,
        synthesize_cross_case_patterns_node
    )
    inp = MetaAnalysisInput(case_id=case_id, target_case_ids=target_case_ids or ["test_item"], timeframe_days=timeframe_days)
    curr = extract_meta_analysis_payload_node(inp)
    curr = synthesize_cross_case_patterns_node(curr)
    route_ev = meta_analysis_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "SYSTEMIC_RISK_IDENTIFIED":
        out = handle_systemic_risk_branch(curr)
    elif route_name == "ISOLATED_INCIDENTS":
        out = handle_isolated_incidents_branch(curr)
    else:
        out = handle_systemic_risk_branch(curr)
    final = document_meta_analysis_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_phishing_irp_workflow(phishing_subject: str, sender_email: str, case_id: str = "", confirm_purge_inbox: bool = True) -> str:
    """Executes ADK Graph Workflow: phishing_irp_workflow."""
    from ..workflows.phishing_irp_workflow import (
        PhishingIRPInput,
        assess_phishing_incident_scope_node,
        document_phishing_irp_report_node,
        extract_phishing_irp_payload_node,
        handle_analysis_only_branch,
        handle_purge_inboxes_branch,
        phishing_irp_containment_router
    )
    inp = PhishingIRPInput(case_id=case_id, phishing_subject=phishing_subject, sender_email=sender_email, confirm_purge_inbox=confirm_purge_inbox)
    curr = extract_phishing_irp_payload_node(inp)
    curr = assess_phishing_incident_scope_node(curr)
    route_ev = phishing_irp_containment_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "PURGE_INBOXES_AND_BLOCK_DOMAINS":
        out = handle_purge_inboxes_branch(curr)
    elif route_name == "ANALYSIS_ONLY":
        out = handle_analysis_only_branch(curr)
    else:
        out = handle_purge_inboxes_branch(curr)
    final = document_phishing_irp_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_post_incident_review_workflow(incident_case_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: post_incident_review_workflow."""
    from ..workflows.post_incident_review_workflow import (
        PIRInput,
        compute_incident_metrics_node,
        document_pir_report_node,
        extract_pir_payload_node,
        handle_action_items_created_branch,
        handle_pir_archived_branch,
        pir_outcome_router
    )
    inp = PIRInput(case_id=case_id, incident_case_id=incident_case_id)
    curr = extract_pir_payload_node(inp)
    curr = compute_incident_metrics_node(curr)
    route_ev = pir_outcome_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "PIR_ACTION_ITEMS_CREATED":
        out = handle_action_items_created_branch(curr)
    elif route_name == "PIR_ARCHIVED":
        out = handle_pir_archived_branch(curr)
    else:
        out = handle_action_items_created_branch(curr)
    final = document_pir_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_prioritize_investigate_case_workflow(case_id: str) -> str:
    """Executes ADK Graph Workflow: prioritize_investigate_case_workflow."""
    from ..workflows.prioritize_investigate_case_workflow import (
        PrioritizeCaseInput,
        case_risk_router,
        compute_case_risk_score_node,
        document_prioritization_report_node,
        extract_prioritization_payload_node,
        handle_immediate_escalation_branch,
        handle_standard_triage_branch
    )
    inp = PrioritizeCaseInput(case_id=case_id)
    curr = extract_prioritization_payload_node(inp)
    curr = compute_case_risk_score_node(curr)
    route_ev = case_risk_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "IMMEDIATE_ESCALATION":
        out = handle_immediate_escalation_branch(curr)
    elif route_name == "STANDARD_TRIAGE":
        out = handle_standard_triage_branch(curr)
    else:
        out = handle_immediate_escalation_branch(curr)
    final = document_prioritization_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_proactive_gti_threat_hunt_workflow(campaign_or_actor_name: str, case_id: str = "", timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: proactive_gti_threat_hunt_workflow."""
    from ..workflows.proactive_gti_threat_hunt_workflow import (
        ProactiveGTIHuntInput,
        correlate_gti_campaign_siem_node,
        document_proactive_hunt_report_node,
        extract_proactive_payload_node,
        handle_campaign_match_found_branch,
        handle_no_campaign_activity_branch,
        proactive_gti_hunt_router
    )
    inp = ProactiveGTIHuntInput(case_id=case_id, campaign_or_actor_name=campaign_or_actor_name, timeframe_days=timeframe_days)
    curr = extract_proactive_payload_node(inp)
    curr = correlate_gti_campaign_siem_node(curr)
    route_ev = proactive_gti_hunt_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "CAMPAIGN_SIEM_MATCH_FOUND":
        out = handle_campaign_match_found_branch(curr)
    elif route_name == "NO_CAMPAIGN_ACTIVITY":
        out = handle_no_campaign_activity_branch(curr)
    else:
        out = handle_campaign_match_found_branch(curr)
    final = document_proactive_hunt_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_ransomware_irp_workflow(initial_affected_host: str, case_id: str = "", confirm_network_segmentation: bool = True) -> str:
    """Executes ADK Graph Workflow: ransomware_irp_workflow."""
    from ..workflows.ransomware_irp_workflow import (
        RansomwareIRPInput,
        assess_ransomware_spread_impact_node,
        document_ransomware_irp_report_node,
        extract_ransomware_irp_payload_node,
        handle_emergency_segmentation_branch,
        handle_single_host_isolation_branch,
        ransomware_irp_containment_router
    )
    inp = RansomwareIRPInput(case_id=case_id, initial_affected_host=initial_affected_host, confirm_network_segmentation=confirm_network_segmentation)
    curr = extract_ransomware_irp_payload_node(inp)
    curr = assess_ransomware_spread_impact_node(curr)
    route_ev = ransomware_irp_containment_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "EXECUTE_EMERGENCY_NETWORK_SEGMENTATION":
        out = handle_emergency_segmentation_branch(curr)
    elif route_name == "ISOLATE_SINGLE_HOST":
        out = handle_single_host_isolation_branch(curr)
    else:
        out = handle_emergency_segmentation_branch(curr)
    final = document_ransomware_irp_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_suspicious_login_workflow(case_id: str, user_id: str, source_ip: str, alert_id: str = "", hostname: str = "") -> str:
    """Executes ADK Graph Workflow: suspicious_login_workflow."""
    from ..workflows.suspicious_login_workflow import (
        SuspiciousLoginInput,
        analyze_logins_fallback_node,
        document_and_report_node,
        enrich_ip_node,
        enrich_user_node,
        extract_entities_node,
        handle_high_risk_branch,
        handle_low_risk_branch,
        triage_risk_router
    )
    inp = SuspiciousLoginInput(case_id=case_id, alert_id=alert_id, user_id=user_id, source_ip=source_ip, hostname=hostname)
    curr = extract_entities_node(inp)
    curr = enrich_user_node(curr)
    curr = enrich_ip_node(curr)
    curr = analyze_logins_fallback_node(curr)
    route_ev = triage_risk_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "LOW_RISK_BENIGN":
        out = handle_low_risk_branch(curr)
    elif route_name == "HIGH_RISK_SUSPICIOUS":
        out = handle_high_risk_branch(curr)
    else:
        out = handle_low_risk_branch(curr)
    final = document_and_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_timeline_process_analysis_workflow(case_id: str, target_hostname: str = "", timeframe_hours: int = 48) -> str:
    """Executes ADK Graph Workflow: timeline_process_analysis_workflow."""
    from ..workflows.timeline_process_analysis_workflow import (
        TimelineAnalysisInput,
        document_timeline_report_node,
        extract_timeline_payload_node,
        handle_malicious_tree_branch,
        handle_normal_execution_branch,
        reconstruct_process_tree_node,
        timeline_process_router
    )
    inp = TimelineAnalysisInput(case_id=case_id, target_hostname=target_hostname, timeframe_hours=timeframe_hours)
    curr = extract_timeline_payload_node(inp)
    curr = reconstruct_process_tree_node(curr)
    route_ev = timeline_process_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "MALICIOUS_PROCESS_TREE":
        out = handle_malicious_tree_branch(curr)
    elif route_name == "NORMAL_PROCESS_EXECUTION":
        out = handle_normal_execution_branch(curr)
    else:
        out = handle_malicious_tree_branch(curr)
    final = document_timeline_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_triage_alerts_workflow(alert_ids: List[str], case_id: str = "") -> str:
    """Executes ADK Graph Workflow: triage_alerts_workflow."""
    from ..workflows.triage_alerts_workflow import (
        TriageAlertsInput,
        alerts_disposition_router,
        document_alerts_triage_report_node,
        enrich_and_assess_alerts_node,
        extract_alerts_payload_node,
        handle_close_fp_alerts_branch,
        handle_escalate_incident_branch
    )
    inp = TriageAlertsInput(alert_ids=alert_ids or ["test_item"], case_id=case_id)
    curr = extract_alerts_payload_node(inp)
    curr = enrich_and_assess_alerts_node(curr)
    route_ev = alerts_disposition_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "ESCALATE_INCIDENT":
        out = handle_escalate_incident_branch(curr)
    elif route_name == "CLOSE_FALSE_POSITIVE":
        out = handle_close_fp_alerts_branch(curr)
    else:
        out = handle_escalate_incident_branch(curr)
    final = document_alerts_triage_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def run_ueba_report_workflow(user_id: str, case_id: str = "", timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: ueba_report_workflow."""
    from ..workflows.ueba_report_workflow import (
        UEBAReportInput,
        compute_ueba_anomalies_node,
        document_ueba_report_node,
        extract_ueba_payload_node,
        handle_high_risk_user_branch,
        handle_standard_user_branch,
        ueba_behavior_router
    )
    inp = UEBAReportInput(case_id=case_id, user_id=user_id, timeframe_days=timeframe_days)
    curr = extract_ueba_payload_node(inp)
    curr = compute_ueba_anomalies_node(curr)
    route_ev = ueba_behavior_router(curr)
    route_name = getattr(getattr(route_ev, "actions", None), "route", None) or getattr(route_ev, "route", "")
    if route_name == "HIGH_RISK_USER_ANOMALY":
        out = handle_high_risk_user_branch(curr)
    elif route_name == "STANDARD_USER_PROFILE":
        out = handle_standard_user_branch(curr)
    else:
        out = handle_high_risk_user_branch(curr)
    final = document_ueba_report_node(out)
    if hasattr(final, "soar_comment") and final.soar_comment:
        return str(final.soar_comment)
    if hasattr(final, "soar_comment_text") and final.soar_comment_text:
        return str(final.soar_comment_text)
    if hasattr(final, "report_markdown") and final.report_markdown:
        return str(final.report_markdown)
    return str(final)


def get_all_workflow_tools():
    """Returns a list of all 36 executable ADK Graph Workflow tool functions."""
    return [
        run_advanced_threat_hunting_workflow,
        run_alert_report_workflow,
        run_apt_threat_hunt_workflow,
        run_basic_ioc_enrichment_workflow,
        run_case_report_workflow,
        run_close_duplicate_cases_workflow,
        run_cloud_vulnerability_triage_workflow,
        run_compare_gti_collection_workflow,
        run_compromised_user_irp_workflow,
        run_create_investigation_report_workflow,
        run_credential_access_hunt_workflow,
        run_deep_dive_ioc_analysis_workflow,
        run_demo_soc_t2_workflow,
        run_detection_as_code_tuning_workflow,
        run_detection_report_workflow,
        run_detection_rule_validation_workflow,
        run_endpoint_triage_workflow,
        run_group_cases_v2_workflow,
        run_group_cases_workflow,
        run_investigate_case_external_tools_workflow,
        run_investigate_gti_collection_workflow,
        run_ioc_containment_workflow,
        run_ioc_threat_hunt_workflow,
        run_lateral_movement_hunt_workflow,
        run_malware_irp_workflow,
        run_malware_triage_workflow,
        run_metaanalysis_workflow,
        run_phishing_irp_workflow,
        run_post_incident_review_workflow,
        run_prioritize_investigate_case_workflow,
        run_proactive_gti_threat_hunt_workflow,
        run_ransomware_irp_workflow,
        run_suspicious_login_workflow,
        run_timeline_process_analysis_workflow,
        run_triage_alerts_workflow,
        run_ueba_report_workflow
    ]
