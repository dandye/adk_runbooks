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


if __name__ == "__main__":
    test_low_risk_case()
    test_high_risk_case()
    test_malware_triage_case()
