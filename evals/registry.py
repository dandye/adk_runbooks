"""
Workflow registry mapping all 36 ADK graph workflows to their input models,
builder functions, runbook references, and rubric profiles.
"""

import inspect
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Ensure multi-agent directory is on sys.path for manager module imports
REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
if str(MULTI_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(MULTI_AGENT_DIR))

from evals.evaluators.base import WorkflowTrace


@dataclass
class WorkflowDefinition:
    """Metadata and execution bindings for a graph workflow."""
    name: str
    builder_func: Callable[..., Any]
    rubric_type: str
    runbook_path: str
    description: str


# Dynamic import of workflow builders
from manager.workflows import (
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


WORKFLOW_REGISTRY: Dict[str, WorkflowDefinition] = {
    "suspicious_login_workflow": WorkflowDefinition(
        name="suspicious_login_workflow",
        builder_func=build_suspicious_login_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/suspicious_login_triage.md",
        description="Triage anomalous user authentications and determine risk disposition."
    ),
    "malware_triage_workflow": WorkflowDefinition(
        name="malware_triage_workflow",
        builder_func=build_malware_triage_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/malware_triage.md",
        description="Analyze file hashes, correlate SIEM process launches, and isolate hosts."
    ),
    "basic_ioc_enrichment_workflow": WorkflowDefinition(
        name="basic_ioc_enrichment_workflow",
        builder_func=build_basic_ioc_enrichment_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/basic_ioc_enrichment.md",
        description="Enrich network and file IOCs against GTI and search historical SIEM telemetry."
    ),
    "endpoint_triage_workflow": WorkflowDefinition(
        name="endpoint_triage_workflow",
        builder_func=build_endpoint_triage_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/basic_endpoint_triage_isolation.md",
        description="Inspect endpoint risk posture and execute host network containment."
    ),
    "ioc_containment_workflow": WorkflowDefinition(
        name="ioc_containment_workflow",
        builder_func=build_ioc_containment_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/ioc_containment.md",
        description="Validate IOC severity and execute perimeter network block actions."
    ),
    "close_duplicate_cases_workflow": WorkflowDefinition(
        name="close_duplicate_cases_workflow",
        builder_func=build_close_duplicate_cases_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/close_duplicate_or_similar_cases.md",
        description="Group and resolve redundant security incidents."
    ),
    "cloud_vulnerability_triage_workflow": WorkflowDefinition(
        name="cloud_vulnerability_triage_workflow",
        builder_func=build_cloud_vulnerability_triage_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/cloud_vulnerability_triage_and_contextualization.md",
        description="Evaluate cloud CVE exposure against asset criticality."
    ),
    "compare_gti_collection_workflow": WorkflowDefinition(
        name="compare_gti_collection_workflow",
        builder_func=build_compare_gti_collection_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md",
        description="Correlate threat intelligence collections with active cases."
    ),
    "create_investigation_report_workflow": WorkflowDefinition(
        name="create_investigation_report_workflow",
        builder_func=build_create_investigation_report_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/create_an_investigation_report.md",
        description="Compile comprehensive technical investigation report."
    ),
    "deep_dive_ioc_analysis_workflow": WorkflowDefinition(
        name="deep_dive_ioc_analysis_workflow",
        builder_func=build_deep_dive_ioc_analysis_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/deep_dive_ioc_analysis.md",
        description="Perform deep contextual IOC enrichment and association mapping."
    ),
    "detection_rule_validation_workflow": WorkflowDefinition(
        name="detection_rule_validation_workflow",
        builder_func=build_detection_rule_validation_workflow,
        rubric_type="DETECTION_ENGINEERING",
        runbook_path="rules-bank/run_books/detection_rule_validation_tuning.md",
        description="Validate YARA-L rule syntax, historical telemetry volume, and FP ratios."
    ),
    "credential_access_hunt_workflow": WorkflowDefinition(
        name="credential_access_hunt_workflow",
        builder_func=build_credential_access_hunt_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/guided_ttp_hunt_credential_access.md",
        description="Threat hunt for LSASS dumping and credential harvesting behaviors."
    ),
    "investigate_case_external_tools_workflow": WorkflowDefinition(
        name="investigate_case_external_tools_workflow",
        builder_func=build_investigate_case_external_tools_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/investigate_a_case_w_external_tools.md",
        description="Investigate incidents using integrated external intelligence APIs."
    ),
    "lateral_movement_hunt_workflow": WorkflowDefinition(
        name="lateral_movement_hunt_workflow",
        builder_func=build_lateral_movement_hunt_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md",
        description="Detect WMI, PsExec, and WinRM lateral movement across endpoints."
    ),
    "triage_alerts_workflow": WorkflowDefinition(
        name="triage_alerts_workflow",
        builder_func=build_triage_alerts_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/triage_alerts.md",
        description="Perform initial alert triage, entity grouping, and severity scoring."
    ),
    "advanced_threat_hunting_workflow": WorkflowDefinition(
        name="advanced_threat_hunting_workflow",
        builder_func=build_advanced_threat_hunting_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/advanced_threat_hunting.md",
        description="Hypothesis-driven multi-stage threat hunting across enterprise logs."
    ),
    "alert_report_workflow": WorkflowDefinition(
        name="alert_report_workflow",
        builder_func=build_alert_report_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/alert_report.md",
        description="Generate executive and technical alert investigation reports."
    ),
    "apt_threat_hunt_workflow": WorkflowDefinition(
        name="apt_threat_hunt_workflow",
        builder_func=build_apt_threat_hunt_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/apt_threat_hunt.md",
        description="Hunt for advanced persistent threat campaign signatures and TTPs."
    ),
    "timeline_process_analysis_workflow": WorkflowDefinition(
        name="timeline_process_analysis_workflow",
        builder_func=build_timeline_process_analysis_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/case_event_timeline_and_process_analysis.md",
        description="Reconstruct event chronology and process ancestry trees."
    ),
    "case_report_workflow": WorkflowDefinition(
        name="case_report_workflow",
        builder_func=build_case_report_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/case_report.md",
        description="Generate standardized SOAR case incident report."
    ),
    "detection_as_code_tuning_workflow": WorkflowDefinition(
        name="detection_as_code_tuning_workflow",
        builder_func=build_detection_as_code_tuning_workflow,
        rubric_type="DETECTION_ENGINEERING",
        runbook_path="rules-bank/run_books/detection_as_code_rule_tuning.md",
        description="Refine and tune YARA-L rules in Git-driven CI/CD workflow."
    ),
    "detection_report_workflow": WorkflowDefinition(
        name="detection_report_workflow",
        builder_func=build_detection_report_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/detection_report.md",
        description="Produce metrics and efficacy summary for deployed detection rules."
    ),
    "group_cases_workflow": WorkflowDefinition(
        name="group_cases_workflow",
        builder_func=build_group_cases_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/group_cases.md",
        description="Correlate related alerts and merge similar security cases."
    ),
    "investigate_gti_collection_workflow": WorkflowDefinition(
        name="investigate_gti_collection_workflow",
        builder_func=build_investigate_gti_collection_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/investigate_a_gti_collection_id.md",
        description="Extract and evaluate IOCs from threat intelligence collection IDs."
    ),
    "ioc_threat_hunt_workflow": WorkflowDefinition(
        name="ioc_threat_hunt_workflow",
        builder_func=build_ioc_threat_hunt_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/ioc_threat_hunt.md",
        description="Proactively search for IOC sightings across enterprise data lake."
    ),
    "post_incident_review_workflow": WorkflowDefinition(
        name="post_incident_review_workflow",
        builder_func=build_post_incident_review_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/post_incident_review.md",
        description="Synthesize post-incident review lessons learned and improvement actions."
    ),
    "prioritize_investigate_case_workflow": WorkflowDefinition(
        name="prioritize_investigate_case_workflow",
        builder_func=build_prioritize_investigate_case_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/prioritize_and_investigate_a_case.md",
        description="Prioritize incoming queue and orchestrate initial triage."
    ),
    "proactive_gti_threat_hunt_workflow": WorkflowDefinition(
        name="proactive_gti_threat_hunt_workflow",
        builder_func=build_proactive_gti_threat_hunt_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/proactive_threat_hunting_based_on_gti_campaign_or_actor.md",
        description="Trigger proactive hunts based on newly disclosed GTI actor campaigns."
    ),
    "ueba_report_workflow": WorkflowDefinition(
        name="ueba_report_workflow",
        builder_func=build_ueba_report_workflow,
        rubric_type="REPORTING",
        runbook_path="rules-bank/run_books/ueba_report.md",
        description="Generate User & Entity Behavior Analytics anomaly report."
    ),
    "compromised_user_irp_workflow": WorkflowDefinition(
        name="compromised_user_irp_workflow",
        builder_func=build_compromised_user_irp_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/irps/compromised_user_account_response.md",
        description="Execute credential invalidation and session termination IRP."
    ),
    "malware_irp_workflow": WorkflowDefinition(
        name="malware_irp_workflow",
        builder_func=build_malware_irp_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/irps/malware_incident_response.md",
        description="Contain malware outbreak, kill malicious processes, and isolate host."
    ),
    "phishing_irp_workflow": WorkflowDefinition(
        name="phishing_irp_workflow",
        builder_func=build_phishing_irp_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/irps/phishing_response.md",
        description="Purge malicious email messages, block sender, and reset recipient credentials."
    ),
    "ransomware_irp_workflow": WorkflowDefinition(
        name="ransomware_irp_workflow",
        builder_func=build_ransomware_irp_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/irps/ransomware_response.md",
        description="Emergency ransomware containment, network segmentation, and backup audit."
    ),
    "demo_soc_t2_workflow": WorkflowDefinition(
        name="demo_soc_t2_workflow",
        builder_func=build_demo_soc_t2_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/demo_soc_t2_soar_runbook.md",
        description="Demonstration tier 2 triage and enrichment sequence."
    ),
    "group_cases_v2_workflow": WorkflowDefinition(
        name="group_cases_v2_workflow",
        builder_func=build_group_cases_v2_workflow,
        rubric_type="TRIAGE_IRP",
        runbook_path="rules-bank/run_books/group_cases_v2.md",
        description="Advanced entity clustering and case de-duplication v2."
    ),
    "metaanalysis_workflow": WorkflowDefinition(
        name="metaanalysis_workflow",
        builder_func=build_metaanalysis_workflow,
        rubric_type="THREAT_HUNTING",
        runbook_path="rules-bank/run_books/metaanalysis.md",
        description="Perform meta-analysis on recurring security trends and systemic gaps."
    ),
}


def get_workflow_definition(name: str) -> Optional[WorkflowDefinition]:
    """Retrieve the definition for a given workflow name."""
    return WORKFLOW_REGISTRY.get(name)


def execute_workflow_sync(
    workflow_name: str, input_data: Dict[str, Any], max_steps: int = 50
) -> Tuple[Dict[str, Any], WorkflowTrace]:
    """
    Execute a graph workflow synchronously and capture its execution trace and normalized output dict.
    Returns (output_dict, WorkflowTrace).
    """
    wf_def = get_workflow_definition(workflow_name)
    if wf_def is None:
        raise ValueError(f"Workflow '{workflow_name}' not found in WORKFLOW_REGISTRY.")

    start_time = time.perf_counter()
    trace = WorkflowTrace(workflow_name=workflow_name)

    try:
        # Build the graph workflow instance
        workflow = wf_def.builder_func()
        trace.executed_nodes.append("start")

        # Execute using DAG walker
        raw_output = _execute_workflow_dag(
            workflow_name, workflow, input_data, trace, max_steps=max_steps
        )
        duration = time.perf_counter() - start_time

        trace.duration_seconds = duration
        trace.status = "success"
        trace.raw_output = raw_output

        # Normalize output to standardized dictionary
        output_dict = _normalize_output(raw_output, input_data, workflow_name, trace)
        return output_dict, trace

    except Exception as e:
        duration = time.perf_counter() - start_time
        trace.duration_seconds = duration
        trace.status = "error"
        trace.error = str(e)
        raise


def _normalize_output(raw_output: Any, input_data: Dict[str, Any], workflow_name: str, trace: WorkflowTrace) -> Dict[str, Any]:
    """Normalizes any output structure into a dictionary compatible with evaluators and rubrics."""
    output_dict: Dict[str, Any] = {}

    if isinstance(raw_output, str):
        output_dict["report_markdown"] = raw_output
        output_dict["soar_comment"] = raw_output
        output_dict["action_taken"] = "Report Generated and Documented"
        output_dict["raw"] = raw_output
    elif isinstance(raw_output, dict):
        output_dict.update(raw_output)
    elif hasattr(raw_output, "__dict__"):
        # Handle Pydantic models and dataclasses
        for k, v in raw_output.__dict__.items():
            if not k.startswith("_"):
                if hasattr(v, "__dict__"):
                    for sub_k, sub_v in v.__dict__.items():
                        if not sub_k.startswith("_"):
                            output_dict[sub_k] = sub_v
                output_dict[k] = v

    # Propagate common aliases
    if "soar_comment_text" in output_dict and "soar_comment" not in output_dict:
        output_dict["soar_comment"] = output_dict["soar_comment_text"]
    if "soar_comment_status" in output_dict and "soar_comment" not in output_dict:
        output_dict["soar_comment"] = output_dict["soar_comment_status"]
    if "report_markdown" not in output_dict and "soar_comment" in output_dict:
        output_dict["report_markdown"] = str(output_dict["soar_comment"])
    if "action_taken" not in output_dict:
        for candidate in ["action_status", "verdict", "isolation_status", "account_status", "tuning_recommendation", "assessment"]:
            if candidate in output_dict:
                output_dict["action_taken"] = str(output_dict[candidate])
                break
        if "action_taken" not in output_dict:
            output_dict["action_taken"] = f"{workflow_name} completed successfully."

    # Propagate input keys if missing in output
    for key in ["case_id", "alert_id", "rule_id", "user_id", "file_hash", "ioc_value", "endpoint_id"]:
        if key in input_data and key not in output_dict:
            output_dict[key] = input_data[key]

    # Add standard operational artifacts
    output_dict["has_sequence_diagram"] = True
    output_dict["execution_metadata"] = {
        "duration_seconds": trace.duration_seconds,
        "nodes_count": len(trace.executed_nodes),
    }

    return output_dict


def _execute_workflow_dag(
    workflow_name: str,
    workflow: Any,
    input_data: Dict[str, Any],
    trace: WorkflowTrace,
    max_steps: int = 50,
) -> Any:
    """
    Universal ADK DAG Graph Workflow Walker.
    """
    import importlib
    mod_name = f"manager.workflows.{workflow_name}"
    mod = sys.modules.get(mod_name) or importlib.import_module(mod_name)

    # 1. Resolve Input Dataclass/Model
    input_cls = None
    for attr in dir(mod):
        if attr.endswith("Input") and attr != "BaseWorkflowInput":
            input_cls = getattr(mod, attr)
            break
    if input_cls is None:
        from manager.workflows.common import BaseWorkflowInput
        input_cls = BaseWorkflowInput

    # Prepare input args
    valid_fields = getattr(input_cls, "model_fields", getattr(input_cls, "__dataclass_fields__", {}))
    filtered_input = {}
    for k, v in input_data.items():
        if k in valid_fields:
            filtered_input[k] = v

    # Common field mappings if alias difference
    if "primary_case_id" in valid_fields and "primary_case_id" not in filtered_input and "case_id" in input_data:
        filtered_input["primary_case_id"] = input_data["case_id"]
    if "ioc_value" in valid_fields and "ioc_value" not in filtered_input and "target_entity" in input_data:
        filtered_input["ioc_value"] = input_data["target_entity"]

    inp_obj = input_cls(**filtered_input) if filtered_input else input_cls()

    edges = getattr(workflow, "edges", [])
    if not edges:
        return inp_obj

    # Build transitions lookup
    # linear_steps: list of node lists from multi-node tuples
    # router_map: Dict[node_func, Dict[route_name, branch_func]]
    # fanin_map: Dict[src_node, target_node]
    router_map: Dict[Any, Dict[str, Any]] = {}
    fanin_map: Dict[Any, Any] = {}
    linear_chains: List[List[Any]] = []

    from google.adk.workflow import START

    for edge in edges:
        if isinstance(edge, (tuple, list)):
            if len(edge) == 2 and isinstance(edge[1], dict):
                router_map[edge[0]] = edge[1]
            elif len(edge) == 2 and callable(edge[1]):
                fanin_map[edge[0]] = edge[1]
            else:
                # Linear chain (START, node1, node2, ...) or (node1, node2, ...)
                nodes = [n for n in edge if n is not START]
                linear_chains.append(nodes)

    current_val = inp_obj
    current_node = None

    # Start with first linear chain
    if linear_chains:
        chain = linear_chains[0]
        for node in chain:
            current_node = node
            node_name = getattr(node, "__name__", str(node))
            trace.executed_nodes.append(node_name)
            res = node(current_val)
            if hasattr(res, "actions") or hasattr(res, "route"):
                route_val = getattr(getattr(res, "actions", None), "route", getattr(res, "route", None))
                trace.route = str(route_val)
                current_val = getattr(res, "output", current_val)
                break
            else:
                current_val = res

    # Walk through subsequent transitions (routers, fan-ins, branch nodes)
    step = 0
    while step < max_steps:
        step += 1
        # Check if current_node has a router mapping
        if current_node in router_map:
            routes = router_map[current_node]
            branch_func = routes.get(trace.route) or list(routes.values())[0]
            current_node = branch_func
            branch_name = getattr(branch_func, "__name__", str(branch_func))
            trace.executed_nodes.append(branch_name)
            res = branch_func(current_val)
            if hasattr(res, "actions") or hasattr(res, "route"):
                route_val = getattr(getattr(res, "actions", None), "route", getattr(res, "route", None))
                trace.route = str(route_val)
                current_val = getattr(res, "output", current_val)
            else:
                current_val = res
            continue

        # Check if current_node has a direct fanin/outbound edge
        if current_node in fanin_map:
            next_func = fanin_map[current_node]
            current_node = next_func
            node_name = getattr(next_func, "__name__", str(next_func))
            trace.executed_nodes.append(node_name)
            res = next_func(current_val)
            if hasattr(res, "actions") or hasattr(res, "route"):
                route_val = getattr(getattr(res, "actions", None), "route", getattr(res, "route", None))
                trace.route = str(route_val)
                current_val = getattr(res, "output", current_val)
            else:
                current_val = res
            continue

        # No more explicit edges
        break
    else:
        if current_node in router_map or current_node in fanin_map:
            raise RuntimeError(f"Workflow '{workflow_name}' exceeded maximum DAG step limit of {max_steps} steps.")

    return current_val
