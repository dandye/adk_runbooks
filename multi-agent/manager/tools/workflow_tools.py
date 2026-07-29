"""
ADK Graph Workflow Tool Wrappers for Gemini Agents.

Exposes graph workflows as executable agent tools.
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


def get_all_workflow_tools() -> list:
    """Returns a list of all executable workflow tools for ADK Agents."""
    return [
        run_suspicious_login_triage_workflow,
        run_malware_triage_workflow,
        run_endpoint_triage_workflow,
        run_ransomware_irp_workflow,
    ]
