"""
Test runner for the Suspicious Login Graph Workflow in ADK 2.x.
"""

import os
from pathlib import Path
from manager.workflows.suspicious_login_workflow import build_suspicious_login_workflow, SuspiciousLoginInput


def test_low_risk_case():
    print("=== Testing Low Risk Suspicious Login Workflow ===")
    workflow = build_suspicious_login_workflow(use_llm_analyzer=False)
    
    input_payload = SuspiciousLoginInput(
        case_id="CASE-1001",
        user_id="alice.smith@example.com",
        source_ip="192.168.1.50",
        hostname="corp-laptop-alice",
    )
    
    # Run graph node logic step by step or via Workflow execution
    print(f"Workflow '{workflow.name}' created with graph edges.")
    from manager.workflows.suspicious_login_workflow import (
        extract_entities_node,
        enrich_user_node,
        enrich_ip_node,
        analyze_logins_fallback_node,
        triage_risk_router,
        handle_low_risk_branch,
        handle_high_risk_branch,
        document_and_report_node,
    )
    
    # Trace deterministic execution path
    entities = extract_entities_node(input_payload)
    user_res = enrich_user_node(entities)
    ip_res = enrich_ip_node(user_res)
    analysis = analyze_logins_fallback_node(ip_res)
    route_event = triage_risk_router(analysis)
    
    print(f"-> Extracted User: {entities.user_id}, IP: {entities.source_ip}")
    print(f"-> IP Summary: {ip_res.ip_summary}")
    print(f"-> Risk Router Route: '{route_event.actions.route}'")
    
    if route_event.actions.route == "LOW_RISK_BENIGN":
        outcome = handle_low_risk_branch(analysis)
    else:
        outcome = handle_high_risk_branch(analysis)
        
    final_report = document_and_report_node(outcome)
    print(f"-> Final Action Taken: {final_report.action_taken}")
    print("\n--- SOAR Comment ---\n" + final_report.soar_comment)
    print("===================================================\n")


def test_high_risk_case():
    print("=== Testing High Risk Suspicious Login Workflow ===")
    workflow = build_suspicious_login_workflow(use_llm_analyzer=False)
    
    input_payload = SuspiciousLoginInput(
        case_id="CASE-9002",
        user_id="bob.jones@example.com",
        source_ip="198.51.100.44",
        hostname="production-db-server",
    )
    
    from manager.workflows.suspicious_login_workflow import (
        extract_entities_node,
        enrich_user_node,
        enrich_ip_node,
        analyze_logins_fallback_node,
        triage_risk_router,
        handle_low_risk_branch,
        handle_high_risk_branch,
        document_and_report_node,
    )
    
    entities = extract_entities_node(input_payload)
    user_res = enrich_user_node(entities)
    ip_res = enrich_ip_node(user_res)
    analysis = analyze_logins_fallback_node(ip_res)
    route_event = triage_risk_router(analysis)
    
    print(f"-> Extracted User: {entities.user_id}, IP: {entities.source_ip}")
    print(f"-> IP Summary: {ip_res.ip_summary}")
    print(f"-> Risk Router Route: '{route_event.actions.route}'")
    
    if route_event.actions.route == "LOW_RISK_BENIGN":
        outcome = handle_low_risk_branch(analysis)
    else:
        outcome = handle_high_risk_branch(analysis)
        
    final_report = document_and_report_node(outcome)
    print(f"-> Final Action Taken: {final_report.action_taken}")
    print("\n--- SOAR Comment ---\n" + final_report.soar_comment)
    print("===================================================\n")


def test_malware_triage_case():
    print("=== Testing Malware Triage Graph Workflow ===")
    from manager.workflows.malware_triage_workflow import (
        build_malware_triage_workflow,
        MalwareTriageInput,
        extract_hash_node,
        enrich_gti_file_node,
        check_siem_execution_node,
        malware_threat_router,
        handle_malicious_threat_branch,
        handle_benign_branch,
        document_malware_report_node,
    )
    
    workflow = build_malware_triage_workflow()
    print(f"Workflow '{workflow.name}' created with graph edges.")
    
    input_payload = MalwareTriageInput(
        file_hash="a1b2c3d4e5f67890badmalwarehash123456789012345678901234567890123456",
        case_id="CASE-MAL-404",
    )
    
    entities = extract_hash_node(input_payload)
    gti_res = enrich_gti_file_node(entities)
    siem_res = check_siem_execution_node(gti_res)
    route_event = malware_threat_router(siem_res)
    
    print(f"-> Extracted File Hash: {entities.file_hash}")
    print(f"-> GTI Detection: {gti_res.detection_ratio} ({gti_res.malware_family})")
    print(f"-> Threat Router Route: '{route_event.actions.route}'")
    
    if route_event.actions.route == "MALICIOUS_THREAT":
        outcome = handle_malicious_threat_branch(siem_res)
    else:
        outcome = handle_benign_branch(siem_res)
        
    final_report = document_malware_report_node(outcome)
    print(f"-> Final Verdict: {final_report.verdict}")
    print(f"-> Affected Hosts: {final_report.affected_hosts}")
    print("\n--- SOAR Comment ---\n" + final_report.soar_comment)
    print("===================================================\n")


def test_basic_ioc_enrichment_case():
    print("=== Testing Basic IOC Enrichment Graph Workflow ===")
    from manager.workflows.basic_ioc_enrichment_workflow import (
        build_basic_ioc_enrichment_workflow,
        IOCEnrichmentInput,
        extract_ioc_node,
        ioc_type_router,
        enrich_domain_branch,
        siem_search_node,
        ioc_risk_router,
        handle_high_risk_ioc_branch,
        document_ioc_enrichment_node,
    )

    wf = build_basic_ioc_enrichment_workflow()
    print(f"Workflow '{wf.name}' created with graph edges.")

    inp = IOCEnrichmentInput(ioc_value="evil-phishing-domain.com", ioc_type="Domain", case_id="CASE-IOC-777")
    payload = extract_ioc_node(inp)
    route_type = ioc_type_router(payload)
    print(f"-> IOC Type Router Branch: '{route_type.actions.route}'")

    enrich_res = enrich_domain_branch(payload)
    siem_res = siem_search_node(enrich_enrichment := enrich_res)
    route_risk = ioc_risk_router(siem_res)
    print(f"-> IOC Risk Router Branch: '{route_risk.actions.route}'")

    outcome = handle_high_risk_ioc_branch(siem_res)
    report = document_ioc_enrichment_node(outcome)
    print(f"-> Assessment: {report.assessment}")
    print("\n--- SOAR Comment Status ---\n" + report.soar_comment_status)
    print("===================================================\n")


def test_endpoint_triage_case():
    print("=== Testing Endpoint Triage & Isolation Graph Workflow ===")
    from manager.workflows.endpoint_triage_workflow import (
        build_endpoint_triage_workflow,
        EndpointTriageInput,
        extract_endpoint_node,
        gather_siem_and_posture_node,
        assess_compromise_likelihood_node,
        isolation_router,
        handle_execute_isolation_branch,
        document_endpoint_report_node,
    )

    wf = build_endpoint_triage_workflow()
    print(f"Workflow '{wf.name}' created with graph edges.")

    inp = EndpointTriageInput(
        endpoint_id="workstation-finance-01",
        endpoint_type="Hostname",
        case_id="CASE-END-505",
        confirm_isolation=True,
    )

    payload = extract_endpoint_node(inp)
    siem_ctx = gather_siem_and_posture_node(payload)
    assessment = assess_compromise_likelihood_node(siem_ctx)
    route_iso = isolation_router(assessment)
    print(f"-> Isolation Router Branch: '{route_iso.actions.route}'")

    outcome = handle_execute_isolation_branch(assessment)
    report = document_endpoint_report_node(outcome)
    print(f"-> Isolation Status: {report.isolation_status}")
    print("\n--- SOAR Comment ---\n" + report.soar_comment)
    print("===================================================\n")


def test_ioc_containment_case():
    print("=== Testing IOC Containment Graph Workflow ===")
    from manager.workflows.ioc_containment_workflow import (
        build_ioc_containment_workflow,
        ContainmentInput,
        extract_containment_payload_node,
        verify_gti_reputation_node,
        containment_type_router,
        handle_network_block_branch,
        document_containment_report_node,
    )

    wf = build_ioc_containment_workflow()
    print(f"Workflow '{wf.name}' created with graph edges.")

    inp = ContainmentInput(
        ioc_value="198.51.100.99",
        ioc_type="IP Address",
        case_id="CASE-CNT-303",
        confirm_action=True,
    )

    payload = extract_containment_payload_node(inp)
    rep_res = verify_gti_reputation_node(payload)
    route_cnt = containment_type_router(rep_res)
    print(f"-> Containment Router Branch: '{route_cnt.actions.route}'")

    outcome = handle_network_block_branch(rep_res)
    report = document_containment_report_node(outcome)
    print(f"-> Action Status: {report.action_status}")
    print("\n--- SOAR Comment ---\n" + report.soar_comment)
    print("===================================================\n")


def test_batch_10_workflows():
    print("=== Testing 10 Additional Graph Workflows ===")
    from manager.workflows import (
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
    )

    wf_list = [
        build_close_duplicate_cases_workflow(),
        build_cloud_vulnerability_triage_workflow(),
        build_compare_gti_collection_workflow(),
        build_create_investigation_report_workflow(),
        build_deep_dive_ioc_analysis_workflow(),
        build_detection_rule_validation_workflow(),
        build_credential_access_hunt_workflow(),
        build_investigate_case_external_tools_workflow(),
        build_lateral_movement_hunt_workflow(),
        build_triage_alerts_workflow(),
    ]

    for wf in wf_list:
        print(f"-> Workflow '{wf.name}' successfully constructed with graph edges.")
    print("===================================================\n")


if __name__ == "__main__":
    test_low_risk_case()
    test_high_risk_case()
    test_malware_triage_case()
    test_basic_ioc_enrichment_case()
    test_endpoint_triage_case()
    test_ioc_containment_case()
    test_batch_10_workflows()
