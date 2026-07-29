"""
ADK Graph Workflow Tool Wrappers for Gemini Agents.

Exposes ALL 36 ADK Graph Workflows as executable agent tools for ADK Agent instances.
"""

from typing import Optional, List
from ..workflows import (
    build_suspicious_login_workflow,
    build_malware_triage_workflow,
    build_basic_ioc_enrichment_workflow,
    build_endpoint_triage_workflow,
    build_ioc_containment_workflow,
    build_close_duplicate_cases_workflow,
    build_cloud_vulnerability_triage_workflow,
    build_compare_gti_collection_workflow,
    build_create_investigation_report_workflow,
    build_deep_dive_ioc_analysis_workflow,
    build_detection_rule_validation_workflow,
    build_credential_access_hunt_workflow,
    build_investigate_case_external_tools_workflow,
    build_lateral_movement_hunt_workflow,
    build_triage_alerts_workflow,
    build_advanced_threat_hunting_workflow,
    build_alert_report_workflow,
    build_apt_threat_hunt_workflow,
    build_timeline_process_analysis_workflow,
    build_case_report_workflow,
    build_detection_as_code_tuning_workflow,
    build_detection_report_workflow,
    build_group_cases_workflow,
    build_investigate_gti_collection_workflow,
    build_ioc_threat_hunt_workflow,
    build_post_incident_review_workflow,
    build_prioritize_investigate_case_workflow,
    build_proactive_gti_threat_hunt_workflow,
    build_ueba_report_workflow,
    build_compromised_user_irp_workflow,
    build_malware_irp_workflow,
    build_phishing_irp_workflow,
    build_ransomware_irp_workflow,
    build_demo_soc_t2_workflow,
    build_group_cases_v2_workflow,
    build_metaanalysis_workflow,
)


def run_suspicious_login_triage_workflow(user_id: str, source_ip: str, hostname: str = "", case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Suspicious Login Alert Triage."""
    from ..workflows.suspicious_login_workflow import (
        SuspiciousLoginInput,
        extract_entities_node,
        enrich_user_node,
        enrich_ip_node,
        analyze_logins_fallback_node,
        triage_risk_router,
        handle_low_risk_branch,
        handle_high_risk_branch,
        document_and_report_node,
    )
    inp = SuspiciousLoginInput(case_id=case_id, user_id=user_id, source_ip=source_ip, hostname=hostname)
    e = extract_entities_node(inp)
    u = enrich_user_node(e)
    ip = enrich_ip_node(u)
    a = analyze_logins_fallback_node(ip)
    r = triage_risk_router(a)
    out = handle_low_risk_branch(a) if r.actions.route == "LOW_RISK_BENIGN" else handle_high_risk_branch(a)
    return document_and_report_node(out).soar_comment


def run_malware_triage_workflow(file_hash: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Malware File Hash Triage."""
    from ..workflows.malware_triage_workflow import (
        MalwareTriageInput,
        extract_malware_payload_node,
        enrich_hash_gti_node,
        query_siem_executions_node,
        malware_threat_router,
        handle_malicious_threat_branch,
        handle_benign_clean_branch,
        document_malware_report_node,
    )
    inp = MalwareTriageInput(case_id=case_id, file_hash=file_hash)
    p = extract_malware_payload_node(inp)
    g = enrich_hash_gti_node(p)
    s = query_siem_executions_node(g)
    r = malware_threat_router(s)
    out = handle_malicious_threat_branch(s) if r.actions.route == "MALICIOUS_THREAT" else handle_benign_clean_branch(s)
    return document_malware_report_node(out).soar_comment


def run_basic_ioc_enrichment_workflow(ioc_value: str, ioc_type: str = "IP", case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Basic IOC Enrichment."""
    from ..workflows.basic_ioc_enrichment_workflow import (
        BasicIOCEnrichmentInput,
        extract_ioc_payload_node,
        ioc_type_router,
        enrich_ip_ioc_branch,
        enrich_domain_ioc_branch,
        enrich_hash_ioc_branch,
        assess_ioc_threat_score_node,
        ioc_risk_router,
        handle_high_risk_threat_branch,
        handle_low_risk_benign_branch,
        document_ioc_enrichment_report_node,
    )
    inp = BasicIOCEnrichmentInput(case_id=case_id, ioc_value=ioc_value, ioc_type=ioc_type)
    p = extract_ioc_payload_node(inp)
    tr = ioc_type_router(p)
    if tr.actions.route == "IP_BRANCH":
        en = enrich_ip_ioc_branch(p)
    elif tr.actions.route == "DOMAIN_BRANCH":
        en = enrich_domain_ioc_branch(p)
    else:
        en = enrich_hash_ioc_branch(p)
    score = assess_ioc_threat_score_node(en)
    rr = ioc_risk_router(score)
    out = handle_high_risk_threat_branch(score) if rr.actions.route == "HIGH_RISK_THREAT" else handle_low_risk_benign_branch(score)
    return document_ioc_enrichment_report_node(out).soar_comment_text


def run_endpoint_triage_workflow(hostname: str, case_id: str = "", isolate_if_high_risk: bool = True) -> str:
    """Executes ADK Graph Workflow: Basic Endpoint Triage & Isolation."""
    from ..workflows.endpoint_triage_workflow import (
        EndpointTriageInput,
        extract_endpoint_payload_node,
        query_endpoint_telemetry_node,
        endpoint_isolation_router,
        handle_execute_isolation_branch,
        handle_monitor_only_branch,
        document_endpoint_triage_report_node,
    )
    inp = EndpointTriageInput(case_id=case_id, hostname=hostname, isolate_if_high_risk=isolate_if_high_risk)
    p = extract_endpoint_payload_node(inp)
    t = query_endpoint_telemetry_node(p)
    r = endpoint_isolation_router(t)
    out = handle_execute_isolation_branch(t) if r.actions.route == "EXECUTE_ISOLATION" else handle_monitor_only_branch(t)
    return document_endpoint_triage_report_node(out).soar_comment


def run_ioc_containment_workflow(ioc_value: str, ioc_type: str = "IP Address", case_id: str = "", reference_list_name: str = "Chronicle_Blocklist") -> str:
    """Executes ADK Graph Workflow: IOC Containment."""
    from ..workflows.ioc_containment_workflow import (
        IOCContainmentInput,
        extract_containment_payload_node,
        ioc_containment_type_router,
        handle_network_block_branch,
        handle_endpoint_hash_block_branch,
        document_containment_report_node,
    )
    inp = IOCContainmentInput(case_id=case_id, ioc_value=ioc_value, ioc_type=ioc_type, reference_list_name=reference_list_name)
    p = extract_containment_payload_node(inp)
    r = ioc_containment_type_router(p)
    out = handle_network_block_branch(p) if r.actions.route == "NETWORK_BLOCK_BRANCH" else handle_endpoint_hash_block_branch(p)
    return document_containment_report_node(out).soar_comment


def run_close_duplicate_cases_workflow(target_case_id: str, candidate_case_ids: List[str]) -> str:
    """Executes ADK Graph Workflow: Close Duplicate or Similar Cases."""
    from ..workflows.close_duplicate_cases_workflow import (
        CloseDuplicateInput,
        extract_duplicate_payload_node,
        compare_case_similarities_node,
        duplicate_closure_router,
        handle_auto_close_duplicates_branch,
        handle_keep_cases_open_branch,
        document_duplicate_closure_report_node,
    )
    inp = CloseDuplicateInput(target_case_id=target_case_id, candidate_case_ids=candidate_case_ids)
    p = extract_duplicate_payload_node(inp)
    comp = compare_case_similarities_node(p)
    r = duplicate_closure_router(comp)
    out = handle_auto_close_duplicates_branch(comp) if r.actions.route == "AUTO_CLOSE_DUPLICATES" else handle_keep_cases_open_branch(comp)
    return document_duplicate_closure_report_node(out)


def run_cloud_vulnerability_triage_workflow(asset_id: str, vulnerability_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Cloud Vulnerability Triage and Contextualization."""
    from ..workflows.cloud_vulnerability_triage_workflow import (
        CloudVulnerabilityTriageInput,
        extract_vulnerability_payload_node,
        assess_cloud_asset_exposure_node,
        vulnerability_risk_router,
        handle_critical_patch_escalation_branch,
        handle_standard_vulnerability_triage_branch,
        document_vulnerability_triage_report_node,
    )
    inp = CloudVulnerabilityTriageInput(case_id=case_id, asset_id=asset_id, vulnerability_id=vulnerability_id)
    p = extract_vulnerability_payload_node(inp)
    a = assess_cloud_asset_exposure_node(p)
    r = vulnerability_risk_router(a)
    out = handle_critical_patch_escalation_branch(a) if r.actions.route == "CRITICAL_PATCH_ESCALATION" else handle_standard_vulnerability_triage_branch(a)
    return document_vulnerability_triage_report_node(out)


def run_compare_gti_collection_workflow(collection_id: str, candidate_iocs: List[str]) -> str:
    """Executes ADK Graph Workflow: Compare GTI Collection to IOCs & Events."""
    from ..workflows.compare_gti_collection_workflow import (
        CompareGTICollectionInput,
        extract_collection_payload_node,
        query_gti_collection_iocs_node,
        gti_overlap_router,
        handle_high_overlap_threat_branch,
        handle_low_overlap_clean_branch,
        document_collection_comparison_report_node,
    )
    inp = CompareGTICollectionInput(collection_id=collection_id, candidate_iocs=candidate_iocs)
    p = extract_collection_payload_node(inp)
    q = query_gti_collection_iocs_node(p)
    r = gti_overlap_router(q)
    out = handle_high_overlap_threat_branch(q) if r.actions.route == "HIGH_OVERLAP_THREAT" else handle_low_overlap_clean_branch(q)
    return document_collection_comparison_report_node(out)


def run_create_investigation_report_workflow(case_id: str, title: str, summary: str, findings: List[str]) -> str:
    """Executes ADK Graph Workflow: Create Investigation Report."""
    from ..workflows.create_investigation_report_workflow import (
        CreateInvestigationReportInput,
        extract_report_payload_node,
        compile_investigation_sections_node,
        report_completeness_router,
        handle_complete_report_branch,
        handle_incomplete_report_branch,
        document_final_report_node,
    )
    inp = CreateInvestigationReportInput(case_id=case_id, title=title, summary=summary, findings=findings)
    p = extract_report_payload_node(inp)
    c = compile_investigation_sections_node(p)
    r = report_completeness_router(c)
    out = handle_complete_report_branch(c) if r.actions.route == "COMPLETE_REPORT_READY" else handle_incomplete_report_branch(c)
    return document_final_report_node(out)


def run_deep_dive_ioc_analysis_workflow(ioc_value: str, ioc_type: str = "HASH", case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Deep Dive IOC Analysis."""
    from ..workflows.deep_dive_ioc_analysis_workflow import (
        DeepDiveIOCInput,
        extract_deep_dive_payload_node,
        gather_multi_source_intel_node,
        deep_dive_verdict_router,
        handle_malicious_deep_dive_branch,
        handle_suspicious_deep_dive_branch,
        handle_clean_deep_dive_branch,
        document_deep_dive_report_node,
    )
    inp = DeepDiveIOCInput(case_id=case_id, ioc_value=ioc_value, ioc_type=ioc_type)
    p = extract_deep_dive_payload_node(inp)
    g = gather_multi_source_intel_node(p)
    r = deep_dive_verdict_router(g)
    if r.actions.route == "MALICIOUS_DEEP_DIVE":
        out = handle_malicious_deep_dive_branch(g)
    elif r.actions.route == "SUSPICIOUS_DEEP_DIVE":
        out = handle_suspicious_deep_dive_branch(g)
    else:
        out = handle_clean_deep_dive_branch(g)
    return document_deep_dive_report_node(out)


def run_detection_rule_validation_workflow(rule_id: str, test_events_count: int = 50) -> str:
    """Executes ADK Graph Workflow: Detection Rule Validation & Tuning."""
    from ..workflows.detection_rule_validation_workflow import (
        DetectionRuleValidationInput,
        extract_validation_payload_node,
        simulate_rule_detections_node,
        rule_validation_router,
        handle_valid_rule_branch,
        handle_high_fp_rate_branch,
        document_rule_validation_report_node,
    )
    inp = DetectionRuleValidationInput(rule_id=rule_id, test_events_count=test_events_count)
    p = extract_validation_payload_node(inp)
    s = simulate_rule_detections_node(p)
    r = rule_validation_router(s)
    out = handle_valid_rule_branch(s) if r.actions.route == "RULE_VALIDATED_OPTIMAL" else handle_high_fp_rate_branch(s)
    return document_rule_validation_report_node(out)


def run_credential_access_hunt_workflow(target_user: str = "", timeframe_days: int = 7) -> str:
    """Executes ADK Graph Workflow: Guided TTP Hunt - Credential Access."""
    from ..workflows.credential_access_hunt_workflow import (
        CredentialAccessHuntInput,
        extract_cred_hunt_payload_node,
        search_credential_dumping_events_node,
        credential_access_router,
        handle_cred_dump_detected_branch,
        handle_no_cred_dump_branch,
        document_cred_hunt_report_node,
    )
    inp = CredentialAccessHuntInput(target_user=target_user, timeframe_days=timeframe_days)
    p = extract_cred_hunt_payload_node(inp)
    s = search_credential_dumping_events_node(p)
    r = credential_access_router(s)
    out = handle_cred_dump_detected_branch(s) if r.actions.route == "CREDENTIAL_DUMPING_DETECTED" else handle_no_cred_dump_branch(s)
    return document_cred_hunt_report_node(out)


def run_investigate_case_external_tools_workflow(case_id: str, external_tools: List[str] = None) -> str:
    """Executes ADK Graph Workflow: Investigate Case with External Tools."""
    from ..workflows.investigate_case_external_tools_workflow import (
        InvestigateExternalToolsInput,
        extract_external_investigation_payload_node,
        query_external_enrichment_node,
        external_enrichment_router,
        handle_external_threat_found_branch,
        handle_external_clean_branch,
        document_external_investigation_report_node,
    )
    if external_tools is None:
        external_tools = ["VirusTotal", "Shodan", "AlienVault"]
    inp = InvestigateExternalToolsInput(case_id=case_id, external_tools=external_tools)
    p = extract_external_investigation_payload_node(inp)
    q = query_external_enrichment_node(p)
    r = external_enrichment_router(q)
    out = handle_external_threat_found_branch(q) if r.actions.route == "EXTERNAL_THREAT_FOUND" else handle_external_clean_branch(q)
    return document_external_investigation_report_node(out)


def run_lateral_movement_hunt_workflow(source_host: str = "", timeframe_days: int = 7) -> str:
    """Executes ADK Graph Workflow: Lateral Movement Hunt (PsExec / WMI)."""
    from ..workflows.lateral_movement_hunt_workflow import (
        LateralMovementHuntInput,
        extract_lateral_hunt_payload_node,
        search_psexec_wmi_events_node,
        lateral_movement_router,
        handle_lateral_movement_detected_branch,
        handle_no_lateral_movement_branch,
        document_lateral_hunt_report_node,
    )
    inp = LateralMovementHuntInput(source_host=source_host, timeframe_days=timeframe_days)
    p = extract_lateral_hunt_payload_node(inp)
    s = search_psexec_wmi_events_node(p)
    r = lateral_movement_router(s)
    out = handle_lateral_movement_detected_branch(s) if r.actions.route == "LATERAL_MOVEMENT_DETECTED" else handle_no_lateral_movement_branch(s)
    return document_lateral_hunt_report_node(out)


def run_triage_alerts_workflow(environment: str = "ALL", severity: str = "HIGH") -> str:
    """Executes ADK Graph Workflow: Triage Alerts."""
    from ..workflows.triage_alerts_workflow import (
        TriageAlertsInput,
        extract_triage_alerts_payload_node,
        fetch_active_alerts_node,
        alerts_severity_router,
        handle_high_severity_alerts_branch,
        handle_low_severity_alerts_branch,
        document_triage_alerts_report_node,
    )
    inp = TriageAlertsInput(environment=environment, severity=severity)
    p = extract_triage_alerts_payload_node(inp)
    f = fetch_active_alerts_node(p)
    r = alerts_severity_router(f)
    out = handle_high_severity_alerts_branch(f) if r.actions.route == "HIGH_SEVERITY_ALERTS" else handle_low_severity_alerts_branch(f)
    return document_triage_alerts_report_node(out)


def run_advanced_threat_hunting_workflow(hypothesis: str, timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: Advanced Threat Hunting."""
    from ..workflows.advanced_threat_hunting_workflow import (
        AdvancedThreatHuntingInput,
        extract_hunt_hypothesis_payload_node,
        execute_hypothesis_udm_queries_node,
        advanced_hunt_router,
        handle_hypothesis_confirmed_branch,
        handle_hypothesis_disproven_branch,
        document_advanced_hunt_report_node,
    )
    inp = AdvancedThreatHuntingInput(hypothesis=hypothesis, timeframe_days=timeframe_days)
    p = extract_hunt_hypothesis_payload_node(inp)
    e = execute_hypothesis_udm_queries_node(p)
    r = advanced_hunt_router(e)
    out = handle_hypothesis_confirmed_branch(e) if r.actions.route == "HYPOTHESIS_CONFIRMED" else handle_hypothesis_disproven_branch(e)
    return document_advanced_hunt_report_node(out)


def run_alert_report_workflow(alert_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Alert Report Generation."""
    from ..workflows.alert_report_workflow import (
        AlertReportInput,
        extract_alert_report_payload_node,
        gather_alert_metadata_node,
        alert_severity_router,
        handle_critical_alert_branch,
        handle_standard_alert_branch,
        document_alert_report_node,
    )
    inp = AlertReportInput(alert_id=alert_id, case_id=case_id)
    p = extract_alert_report_payload_node(inp)
    g = gather_alert_metadata_node(p)
    r = alert_severity_router(g)
    out = handle_critical_alert_branch(g) if r.actions.route == "CRITICAL_ALERT" else handle_standard_alert_branch(g)
    return document_alert_report_node(out)


def run_apt_threat_hunt_workflow(actor_name: str, timeframe_days: int = 90) -> str:
    """Executes ADK Graph Workflow: APT Threat Hunt."""
    from ..workflows.apt_threat_hunt_workflow import (
        APTThreatHuntInput,
        extract_apt_payload_node,
        query_apt_ttp_matches_node,
        apt_threat_router,
        handle_apt_activity_found_branch,
        handle_no_apt_activity_branch,
        document_apt_hunt_report_node,
    )
    inp = APTThreatHuntInput(actor_name=actor_name, timeframe_days=timeframe_days)
    p = extract_apt_payload_node(inp)
    q = query_apt_ttp_matches_node(p)
    r = apt_threat_router(q)
    out = handle_apt_activity_found_branch(q) if r.actions.route == "APT_ACTIVITY_FOUND" else handle_no_apt_activity_branch(q)
    return document_apt_hunt_report_node(out)


def run_timeline_process_analysis_workflow(case_id: str, target_host: str) -> str:
    """Executes ADK Graph Workflow: Case Event Timeline & Process Analysis."""
    from ..workflows.timeline_process_analysis_workflow import (
        TimelineProcessInput,
        extract_timeline_payload_node,
        build_process_tree_timeline_node,
        timeline_anomaly_router,
        handle_process_anomalies_found_branch,
        handle_clean_timeline_branch,
        document_timeline_report_node,
    )
    inp = TimelineProcessInput(case_id=case_id, target_host=target_host)
    p = extract_timeline_payload_node(inp)
    b = build_process_tree_timeline_node(p)
    r = timeline_anomaly_router(b)
    out = handle_process_anomalies_found_branch(b) if r.actions.route == "ANOMALOUS_PROCESS_TREE" else handle_clean_timeline_branch(b)
    return document_timeline_report_node(out)


def run_case_report_workflow(case_id: str, title: str = "Case Report") -> str:
    """Executes ADK Graph Workflow: Case Report Generation."""
    from ..workflows.case_report_workflow import (
        CaseReportInput,
        extract_case_report_payload_node,
        gather_case_full_details_node,
        case_severity_router,
        handle_high_severity_case_branch,
        handle_normal_case_branch,
        document_case_report_node,
    )
    inp = CaseReportInput(case_id=case_id, title=title)
    p = extract_case_report_payload_node(inp)
    g = gather_case_full_details_node(p)
    r = case_severity_router(g)
    out = handle_high_severity_case_branch(g) if r.actions.route == "HIGH_SEVERITY_CASE" else handle_normal_case_branch(g)
    return document_case_report_node(out)


def run_detection_as_code_tuning_workflow(rule_file_path: str, environment: str = "STAGING") -> str:
    """Executes ADK Graph Workflow: Detection-as-Code Rule Tuning."""
    from ..workflows.detection_as_code_tuning_workflow import (
        DetectionAsCodeInput,
        extract_dac_payload_node,
        run_cicd_rule_validation_node,
        dac_validation_router,
        handle_dac_pass_branch,
        handle_dac_fail_branch,
        document_dac_report_node,
    )
    inp = DetectionAsCodeInput(rule_file_path=rule_file_path, environment=environment)
    p = extract_dac_payload_node(inp)
    r_val = run_cicd_rule_validation_node(p)
    r = dac_validation_router(r_val)
    out = handle_dac_pass_branch(r_val) if r.actions.route == "DAC_VALIDATION_PASS" else handle_dac_fail_branch(r_val)
    return document_dac_report_node(out)


def run_detection_report_workflow(rule_id: str) -> str:
    """Executes ADK Graph Workflow: Detection Report Generation."""
    from ..workflows.detection_report_workflow import (
        DetectionReportInput,
        extract_detection_report_payload_node,
        fetch_detection_stats_node,
        detection_report_router,
        handle_high_noise_branch,
        handle_optimal_performance_branch,
        document_detection_report_node,
    )
    inp = DetectionReportInput(rule_id=rule_id)
    p = extract_detection_report_payload_node(inp)
    f = fetch_detection_stats_node(p)
    r = detection_report_router(f)
    out = handle_high_noise_branch(f) if r.actions.route == "HIGH_NOISE_LEVEL" else handle_optimal_performance_branch(f)
    return document_detection_report_node(out)


def run_group_cases_workflow(target_case_ids: List[str], grouping_criteria: str = "Shared_IOCs_and_Users") -> str:
    """Executes ADK Graph Workflow: Group Cases."""
    from ..workflows.group_cases_workflow import (
        GroupCasesInput,
        extract_group_payload_node,
        cluster_similar_cases_node,
        case_grouping_router,
        handle_group_cases_merged_branch,
        handle_no_grouping_needed_branch,
        document_grouping_report_node,
    )
    inp = GroupCasesInput(target_case_ids=target_case_ids, grouping_criteria=grouping_criteria)
    p = extract_group_payload_node(inp)
    c = cluster_similar_cases_node(p)
    r = case_grouping_router(c)
    out = handle_group_cases_merged_branch(c) if r.actions.route == "GROUP_CASES_MERGED" else handle_no_grouping_needed_branch(c)
    return document_grouping_report_node(out)


def run_investigate_gti_collection_workflow(collection_id: str, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Investigate GTI Collection ID."""
    from ..workflows.investigate_gti_collection_workflow import (
        GTICollectionInvestigationInput,
        extract_gti_collection_payload_node,
        fetch_gti_collection_report_node,
        gti_collection_investigation_router,
        handle_active_campaign_branch,
        handle_no_siem_match_branch,
        document_gti_collection_report_node,
    )
    inp = GTICollectionInvestigationInput(case_id=case_id, collection_id=collection_id)
    p = extract_gti_collection_payload_node(inp)
    f = fetch_gti_collection_report_node(p)
    r = gti_collection_investigation_router(f)
    out = handle_active_campaign_branch(f) if r.actions.route == "ACTIVE_CAMPAIGN_DETECTED" else handle_no_siem_match_branch(f)
    return document_gti_collection_report_node(out)


def run_ioc_threat_hunt_workflow(ioc_list: List[str], lookback_days: int = 30, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: IOC Threat Hunt."""
    from ..workflows.ioc_threat_hunt_workflow import (
        IOCThreatHuntInput,
        extract_ioc_hunt_payload_node,
        execute_ioc_siem_search_node,
        ioc_hunt_router,
        handle_ioc_matches_found_branch,
        handle_no_ioc_matches_branch,
        document_ioc_hunt_report_node,
    )
    inp = IOCThreatHuntInput(case_id=case_id, ioc_list=ioc_list, lookback_days=lookback_days)
    p = extract_ioc_hunt_payload_node(inp)
    e = execute_ioc_siem_search_node(p)
    r = ioc_hunt_router(e)
    out = handle_ioc_matches_found_branch(e) if r.actions.route == "IOC_MATCHES_FOUND" else handle_no_ioc_matches_branch(e)
    return document_ioc_hunt_report_node(out)


def run_post_incident_review_workflow(incident_case_id: str) -> str:
    """Executes ADK Graph Workflow: Post Incident Review (PIR)."""
    from ..workflows.post_incident_review_workflow import (
        PIRInput,
        extract_pir_payload_node,
        compute_incident_metrics_node,
        pir_outcome_router,
        handle_action_items_created_branch,
        handle_pir_archived_branch,
        document_pir_report_node,
    )
    inp = PIRInput(incident_case_id=incident_case_id)
    p = extract_pir_payload_node(inp)
    c = compute_incident_metrics_node(p)
    r = pir_outcome_router(c)
    out = handle_action_items_created_branch(c) if r.actions.route == "PIR_ACTION_ITEMS_CREATED" else handle_pir_archived_branch(c)
    return document_pir_report_node(out)


def run_prioritize_investigate_case_workflow(case_id: str) -> str:
    """Executes ADK Graph Workflow: Prioritize & Investigate a Case."""
    from ..workflows.prioritize_investigate_case_workflow import (
        PrioritizeCaseInput,
        extract_prioritization_payload_node,
        compute_case_risk_score_node,
        case_risk_router,
        handle_immediate_escalation_branch,
        handle_standard_triage_branch,
        document_prioritization_report_node,
    )
    inp = PrioritizeCaseInput(case_id=case_id)
    p = extract_prioritization_payload_node(inp)
    c = compute_case_risk_score_node(p)
    r = case_risk_router(c)
    out = handle_immediate_escalation_branch(c) if r.actions.route == "IMMEDIATE_ESCALATION" else handle_standard_triage_branch(c)
    return document_prioritization_report_node(out)


def run_proactive_gti_threat_hunt_workflow(campaign_or_actor_name: str, timeframe_days: int = 30, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: Proactive Threat Hunting based on GTI Campaign or Actor."""
    from ..workflows.proactive_gti_threat_hunt_workflow import (
        ProactiveGTIHuntInput,
        extract_proactive_payload_node,
        correlate_gti_campaign_siem_node,
        proactive_gti_hunt_router,
        handle_campaign_match_found_branch,
        handle_no_campaign_activity_branch,
        document_proactive_hunt_report_node,
    )
    inp = ProactiveGTIHuntInput(case_id=case_id, campaign_or_actor_name=campaign_or_actor_name, timeframe_days=timeframe_days)
    p = extract_proactive_payload_node(inp)
    c = correlate_gti_campaign_siem_node(p)
    r = proactive_gti_hunt_router(c)
    out = handle_campaign_match_found_branch(c) if r.actions.route == "CAMPAIGN_SIEM_MATCH_FOUND" else handle_no_campaign_activity_branch(c)
    return document_proactive_hunt_report_node(out)


def run_ueba_report_workflow(user_id: str, timeframe_days: int = 30, case_id: str = "") -> str:
    """Executes ADK Graph Workflow: UEBA Report Analysis."""
    from ..workflows.ueba_report_workflow import (
        UEBAReportInput,
        extract_ueba_payload_node,
        compute_ueba_anomalies_node,
        ueba_behavior_router,
        handle_high_risk_user_branch,
        handle_standard_user_branch,
        document_ueba_report_node,
    )
    inp = UEBAReportInput(case_id=case_id, user_id=user_id, timeframe_days=timeframe_days)
    p = extract_ueba_payload_node(inp)
    c = compute_ueba_anomalies_node(p)
    r = ueba_behavior_router(c)
    out = handle_high_risk_user_branch(c) if r.actions.route == "HIGH_RISK_USER_ANOMALY" else handle_standard_user_branch(c)
    return document_ueba_report_node(out)


def run_compromised_user_irp_workflow(user_id: str, case_id: str = "", confirm_account_disable: bool = True) -> str:
    """Executes ADK Graph Workflow: Compromised User Account Response IRP."""
    from ..workflows.compromised_user_irp_workflow import (
        CompromisedUserIRPInput,
        extract_user_irp_payload_node,
        assess_user_compromise_impact_node,
        user_containment_router,
        handle_disable_account_branch,
        handle_monitoring_only_branch,
        document_user_irp_report_node,
    )
    inp = CompromisedUserIRPInput(case_id=case_id, user_id=user_id, confirm_account_disable=confirm_account_disable)
    p = extract_user_irp_payload_node(inp)
    a = assess_user_compromise_impact_node(p)
    r = user_containment_router(a)
    out = handle_disable_account_branch(a) if r.actions.route == "DISABLE_ACCOUNT_REVOKE_SESSIONS" else handle_monitoring_only_branch(a)
    return document_user_irp_report_node(out)


def run_malware_irp_workflow(target_host: str, file_hash: str = "", case_id: str = "", confirm_host_isolation: bool = True) -> str:
    """Executes ADK Graph Workflow: Malware Incident Response IRP."""
    from ..workflows.malware_irp_workflow import (
        MalwareIRPInput,
        extract_malware_irp_payload_node,
        assess_malware_incident_scope_node,
        malware_irp_containment_router,
        handle_isolate_host_branch,
        handle_scoping_only_branch,
        document_malware_irp_report_node,
    )
    inp = MalwareIRPInput(case_id=case_id, target_host=target_host, file_hash=file_hash, confirm_host_isolation=confirm_host_isolation)
    p = extract_malware_irp_payload_node(inp)
    s = assess_malware_incident_scope_node(p)
    r = malware_irp_containment_router(s)
    out = handle_isolate_host_branch(s) if r.actions.route == "ISOLATE_HOST_AND_BLOCK_IOCS" else handle_scoping_only_branch(s)
    return document_malware_irp_report_node(out)


def run_phishing_irp_workflow(phishing_subject: str, sender_email: str, case_id: str = "", confirm_purge_inbox: bool = True) -> str:
    """Executes ADK Graph Workflow: Phishing Response IRP."""
    from ..workflows.phishing_irp_workflow import (
        PhishingIRPInput,
        extract_phishing_irp_payload_node,
        assess_phishing_incident_scope_node,
        phishing_irp_containment_router,
        handle_purge_inboxes_branch,
        handle_analysis_only_branch,
        document_phishing_irp_report_node,
    )
    inp = PhishingIRPInput(case_id=case_id, phishing_subject=phishing_subject, sender_email=sender_email, confirm_purge_inbox=confirm_purge_inbox)
    p = extract_phishing_irp_payload_node(inp)
    s = assess_phishing_incident_scope_node(p)
    r = phishing_irp_containment_router(s)
    out = handle_purge_inboxes_branch(s) if r.actions.route == "PURGE_INBOXES_AND_BLOCK_DOMAINS" else handle_analysis_only_branch(s)
    return document_phishing_irp_report_node(out)


def run_ransomware_irp_workflow(initial_affected_host: str, case_id: str = "", confirm_network_segmentation: bool = True) -> str:
    """Executes ADK Graph Workflow: Ransomware Emergency Incident Response Plan (IRP)."""
    from ..workflows.ransomware_irp_workflow import (
        RansomwareIRPInput,
        extract_ransomware_irp_payload_node,
        assess_ransomware_spread_impact_node,
        ransomware_irp_containment_router,
        handle_emergency_segmentation_branch,
        handle_single_host_isolation_branch,
        document_ransomware_irp_report_node,
    )
    inp = RansomwareIRPInput(case_id=case_id, initial_affected_host=initial_affected_host, confirm_network_segmentation=confirm_network_segmentation)
    p = extract_ransomware_irp_payload_node(inp)
    s = assess_ransomware_spread_impact_node(p)
    r = ransomware_irp_containment_router(s)
    out = handle_emergency_segmentation_branch(s) if r.actions.route == "EXECUTE_EMERGENCY_NETWORK_SEGMENTATION" else handle_single_host_isolation_branch(s)
    return document_ransomware_irp_report_node(out)


def run_demo_soc_t2_workflow(case_id: str) -> str:
    """Executes ADK Graph Workflow: SOC Analyst Tier 2 Demo."""
    from ..workflows.demo_soc_t2_workflow import (
        DemoSOCT2Input,
        extract_demo_soc_t2_payload_node,
        analyze_soc_t2_case_node,
        demo_soc_t2_router,
        handle_escalate_tier_3_branch,
        handle_resolve_tier_2_branch,
        document_demo_soc_t2_report_node,
    )
    inp = DemoSOCT2Input(case_id=case_id)
    p = extract_demo_soc_t2_payload_node(inp)
    a = analyze_soc_t2_case_node(p)
    r = demo_soc_t2_router(a)
    out = handle_escalate_tier_3_branch(a) if r.actions.route == "ESCALATE_TIER_3" else handle_resolve_tier_2_branch(a)
    return document_demo_soc_t2_report_node(out)


def run_group_cases_v2_workflow(environment_filter: str = "ALL", similarity_threshold: float = 0.8) -> str:
    """Executes ADK Graph Workflow: Group Cases v2."""
    from ..workflows.group_cases_v2_workflow import (
        GroupCasesV2Input,
        extract_group_v2_payload_node,
        compute_v2_case_clusters_node,
        group_cases_v2_router,
        handle_merge_high_similarity_branch,
        handle_no_merge_required_branch,
        document_group_v2_report_node,
    )
    inp = GroupCasesV2Input(environment_filter=environment_filter, similarity_threshold=similarity_threshold)
    p = extract_group_v2_payload_node(inp)
    c = compute_v2_case_clusters_node(p)
    r = group_cases_v2_router(c)
    out = handle_merge_high_similarity_branch(c) if r.actions.route == "MERGE_HIGH_SIMILARITY_CASES" else handle_no_merge_required_branch(c)
    return document_group_v2_report_node(out)


def run_metaanalysis_workflow(target_case_ids: List[str], timeframe_days: int = 30) -> str:
    """Executes ADK Graph Workflow: Meta-Analysis."""
    from ..workflows.metaanalysis_workflow import (
        MetaAnalysisInput,
        extract_meta_analysis_payload_node,
        synthesize_cross_case_patterns_node,
        meta_analysis_router,
        handle_systemic_risk_branch,
        handle_isolated_incidents_branch,
        document_meta_analysis_report_node,
    )
    inp = MetaAnalysisInput(target_case_ids=target_case_ids, timeframe_days=timeframe_days)
    p = extract_meta_analysis_payload_node(inp)
    s = synthesize_cross_case_patterns_node(p)
    r = meta_analysis_router(s)
    out = handle_systemic_risk_branch(s) if r.actions.route == "SYSTEMIC_RISK_IDENTIFIED" else handle_isolated_incidents_branch(s)
    return document_meta_analysis_report_node(out)


def get_all_workflow_tools() -> list:
    """Returns a list of all 36 executable workflow tools for ADK Agents."""
    return [
        run_suspicious_login_triage_workflow,
        run_malware_triage_workflow,
        run_basic_ioc_enrichment_workflow,
        run_endpoint_triage_workflow,
        run_ioc_containment_workflow,
        run_close_duplicate_cases_workflow,
        run_cloud_vulnerability_triage_workflow,
        run_compare_gti_collection_workflow,
        run_create_investigation_report_workflow,
        run_deep_dive_ioc_analysis_workflow,
        run_detection_rule_validation_workflow,
        run_credential_access_hunt_workflow,
        run_investigate_case_external_tools_workflow,
        run_lateral_movement_hunt_workflow,
        run_triage_alerts_workflow,
        run_advanced_threat_hunting_workflow,
        run_alert_report_workflow,
        run_apt_threat_hunt_workflow,
        run_timeline_process_analysis_workflow,
        run_case_report_workflow,
        run_detection_as_code_tuning_workflow,
        run_detection_report_workflow,
        run_group_cases_workflow,
        run_investigate_gti_collection_workflow,
        run_ioc_threat_hunt_workflow,
        run_post_incident_review_workflow,
        run_prioritize_investigate_case_workflow,
        run_proactive_gti_threat_hunt_workflow,
        run_ueba_report_workflow,
        run_compromised_user_irp_workflow,
        run_malware_irp_workflow,
        run_phishing_irp_workflow,
        run_ransomware_irp_workflow,
        run_demo_soc_t2_workflow,
        run_group_cases_v2_workflow,
        run_metaanalysis_workflow,
    ]
