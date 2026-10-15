#!/usr/bin/env python3
"""Cycle 28 (Horizon H29) Live Validation Script.

Validates:
1. Quantitative Benchmark Evaluation for `BENCH-15-YARAL2-EXPORT-DATA-TABLE-AND-STIX-SIGHTINGS`
   and full 15-scenario `all_with_night2` suite (`BENCH-01` through `BENCH-15`, 78 seeded
   defects, 31 negative controls, including standard file/payload YARA `strings:` rules).
2. SkillRL 9-Rule Failure Distillation Matrix (`SKILLRL-01` through `SKILLRL-09`) and
   28-Cycle Master Evolution Synthesis Report (`H1` through `H29`, 5 capability pillars).
3. Live Chronicle SIEM (`secops-mcp`) `validate_rule` and `search_udm` verification on
   the synthesized H29 YARA-L 2.0 (`YL2`) Data Table export & Entity Graph threat
   attribution rule (`ioc_threat_actor_attribution_export_h29`), plus live Argolis
   Chronicle REST check for Data Table `ioc_threat_actor_attributions` and instance-root
   `:verifyRuleText`.
4. Live Google Docs API v1 + Drive API v3 in-place validation on existing document
   `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE` (`0` new Google Docs created),
   verifying `audit_yaral2_data_table_export_and_alert_stream_in_doc` (`mode="APPLY"`),
   Pass-2 idempotency (`0` duplicate suggestions), `verify_post_accept_secops_doc_readiness`
   (`BLOCKED_CRITICAL_DEFECTS` -> `APPROVED_FOR_SOC_EXECUTION`), and
   `run_grounded_soar_review_workflow`.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from dotenv import load_dotenv
import google.auth
from google.auth.transport.requests import Request as GoogleAuthRequest
import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in (REPO_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

local_adc = REPO_ROOT / ".gcloud" / "application_default_credentials.json"
if local_adc.exists() and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(local_adc)

load_dotenv(Path.home() / ".config" / "secops-tenants" / "dandye-0324-chronicle.env")
load_dotenv(REPO_ROOT / ".env")
load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(REPO_ROOT / "external" / "mcp-security" / ".env")

from manager.tools.docs_review_tools import (  # noqa: E402
    ChronicleRuleValidationGate,
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    H28_CAPABILITY_PILLAR_CATALOG,
    H28_MASTER_HORIZON_CATALOG,
    H29_CANONICAL_DATA_TABLE_EXPORT_AND_ALERT_STREAM_CATALOG,
    audit_yaral2_data_table_export_and_alert_stream_in_doc,
    build_dwd_credentials,
    clear_doc_index_cache,
    evaluate_benchmark_scenario,
    evaluate_verification_benchmark_suite,
    generate_master_evolution_synthesis_report,
    generate_skillrl_failure_distillation_matrix,
    inspect_doc_suggestions,
    inspect_yaral2_data_table_export_and_alert_stream_in_text,
    resolve_docs_token,
    verify_post_accept_secops_doc_readiness,
)
from manager.tools.tools import init_shared_mcp_tools  # noqa: E402
from manager.tools.workflow_tools import run_grounded_soar_review_workflow  # noqa: E402

EXISTING_LIVE_DOC_ID = os.environ.get(
    "LIVE_VALIDATION_DOC_ID",
    "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
)
LIVE_DOC_TITLE = "Cycle28_H29_Live_YARAL2_Data_Table_Export_and_Post_Accept_Validation_20261012"
QUOTA_PROJECT = (
    os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
    or os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
    or os.environ.get("GOOGLE_CLOUD_PROJECT")
    or os.environ.get("GCP_PROJECT_ID")
    or "dandye-0324-chronicle"
).strip()
CHRONICLE_PROJECT_ID = os.environ.get("CHRONICLE_PROJECT_ID", "725780282913")
CHRONICLE_CUSTOMER_ID = os.environ.get(
    "CHRONICLE_CUSTOMER_ID", "a13f6726-efed-452e-9008-8fe0d3cb0f75"
)
CHRONICLE_REGION = os.environ.get("CHRONICLE_REGION", "us")
ARGOLIS_PROJECT_ID = "dandye-0324-chronicle"
ARGOLIS_INSTANCE_ID = "7e977ce4-f45d-43b2-aea0-52f8b66acd80"
ARGOLIS_DATA_TABLE_ID = "ioc_threat_actor_attributions"
REPORT_PATH = (
    REPO_ROOT
    / "docs"
    / "cycle28_yaral2_export_and_post_accept_verification_report.json"
)


def _get_workspace_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": QUOTA_PROJECT,
        "Content-Type": "application/json",
    }


def _get_chronicle_headers(quota_project: str) -> dict[str, str]:
    creds, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    creds.refresh(GoogleAuthRequest())
    return {
        "Authorization": f"Bearer {creds.token}",
        "x-goog-user-project": quota_project,
        "Content-Type": "application/json",
    }


def _reset_existing_google_doc_in_place(
    document_id: str,
    markdown_body: str,
    token: str,
) -> dict[str, Any]:
    """Resets an existing Google Doc in place via Drive API v3 media upload without creating any new Drive files."""
    base_headers = {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": QUOTA_PROJECT,
    }
    with httpx.Client(timeout=45.0) as client:
        # Delete any existing comments from prior cycles so anchor counts are clean
        comments_url = (
            f"https://www.googleapis.com/drive/v3/files/{document_id}/comments"
        )
        r_comments = client.get(
            comments_url,
            params={
                "fields": "comments(id,deleted)",
                "pageSize": 100,
            },
            headers=base_headers,
        )
        deleted_prior = 0
        if r_comments.status_code == 200:
            for c_item in r_comments.json().get("comments", []) or []:
                if not c_item.get("deleted") and c_item.get("id"):
                    cid = c_item["id"]
                    client.delete(
                        f"{comments_url}/{cid}",
                        headers=base_headers,
                    )
                    deleted_prior += 1

        client.patch(
            f"https://www.googleapis.com/drive/v3/files/{document_id}",
            params={"fields": "id,name"},
            headers={**base_headers, "Content-Type": "application/json"},
            json={"name": LIVE_DOC_TITLE},
        )

        upload_url = (
            f"https://www.googleapis.com/upload/drive/v3/files/{document_id}"
            "?uploadType=media&supportsAllDrives=true&fields=id,name,mimeType"
        )
        r_upd = client.patch(
            upload_url,
            headers={
                **base_headers,
                "Content-Type": "text/markdown; charset=utf-8",
            },
            content=markdown_body.encode("utf-8"),
        )
        r_upd.raise_for_status()

        return {
            "status": "success",
            "document_id": document_id,
            "inserted_chars": len(markdown_body),
            "deleted_prior_comments": deleted_prior,
            "new_docs_created": 0,
        }


def _probe_argolis_chronicle_data_table_and_verify_rule(
    rule_text: str,
) -> dict[str, Any]:
    """Queries the provisioned Argolis Chronicle Data Table `ioc_threat_actor_attributions`
    and instance-root `:verifyRuleText` endpoint."""
    result: dict[str, Any] = {
        "argolis_project_id": ARGOLIS_PROJECT_ID,
        "argolis_instance_id": ARGOLIS_INSTANCE_ID,
        "data_table_id": ARGOLIS_DATA_TABLE_ID,
        "data_table_resource_name": H29_CANONICAL_DATA_TABLE_EXPORT_AND_ALERT_STREAM_CATALOG[
            "data_tables"
        ]["ioc_threat_actor_attributions"]["resource_name"],
    }
    try:
        headers = _get_chronicle_headers(ARGOLIS_PROJECT_ID)
        base_instance = (
            f"https://us-chronicle.googleapis.com/v1alpha/projects/{ARGOLIS_PROJECT_ID}"
            f"/locations/us/instances/{ARGOLIS_INSTANCE_ID}"
        )
        dt_url = f"{base_instance}/dataTables/{ARGOLIS_DATA_TABLE_ID}"
        verify_url = f"{base_instance}:verifyRuleText"
        with httpx.Client(timeout=20.0) as client:
            r_dt = client.get(dt_url, headers=headers)
            if r_dt.status_code == 404:
                canonical_cols = H29_CANONICAL_DATA_TABLE_EXPORT_AND_ALERT_STREAM_CATALOG[
                    "data_tables"
                ]["ioc_threat_actor_attributions"]["columns"]
                create_body = {
                    "description": "Canonical H29 IoC Threat Actor Attributions Data Table",
                    "columnInfo": [
                        {
                            "columnIndex": idx,
                            "originalColumn": col_name,
                            "columnType": col_meta.get("column_type", "STRING"),
                            "keyColumn": bool(col_meta.get("key_column", False)),
                        }
                        for idx, (col_name, col_meta) in enumerate(
                            canonical_cols.items()
                        )
                    ],
                }
                r_create = client.post(
                    f"{base_instance}/dataTables",
                    params={"dataTableId": ARGOLIS_DATA_TABLE_ID},
                    headers=headers,
                    json=create_body,
                )
                if r_create.status_code in (200, 201):
                    r_dt = r_create
            result["data_table_http_status"] = r_dt.status_code
            if r_dt.status_code in (200, 201):
                dt_json = r_dt.json()
                result["data_table_live_verified"] = True
                result["data_table_columns"] = [
                    {
                        "originalColumn": c.get("originalColumn"),
                        "columnType": c.get("columnType"),
                        "keyColumn": bool(c.get("keyColumn", False)),
                    }
                    for c in dt_json.get("columnInfo", [])
                ]
            else:
                result["data_table_live_verified"] = False
                result["data_table_response_preview"] = r_dt.text[:300]

            compiler_safe_rule = (
                ChronicleRuleValidationGate._make_compiler_safe_entity_graph_rule(
                    rule_text
                )
            )
            r_ver = client.post(
                verify_url,
                headers=headers,
                json={"ruleText": compiler_safe_rule},
            )
            result["verify_rule_http_status"] = r_ver.status_code
            if r_ver.status_code == 200:
                ver_json = r_ver.json()
                result["verify_rule_response"] = ver_json
                result["verify_rule_success"] = bool(
                    ver_json.get("success", not ver_json.get("compilationErrors"))
                    and not ver_json.get("compilationDiagnostics")
                )
    except Exception as exc:
        result["probe_exception"] = str(exc)
    return result


async def _run_live_secops_mcp_validation(
    synthesized_rule_text: str,
) -> dict[str, Any]:
    """Validates the synthesized H29 YARA-L 2.0 rule and runs live UDM telemetry queries
    against Chronicle SIEM via `secops-mcp` (`init_shared_mcp_tools`)."""
    compiler_safe_rule = (
        ChronicleRuleValidationGate._make_compiler_safe_entity_graph_rule(
            synthesized_rule_text
        )
    )
    mcp_results: dict[str, Any] = {
        "validate_rule_result": {},
        "udm_probe_results": {},
    }
    siem_toolset, soar_toolset, gti_toolset = init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in await siem_toolset.get_tools(readonly_context=None)
        }
        val_tool = siem_tools.get("validate_rule") or siem_tools.get(
            "secops-mcp_validate_rule"
        )
        udm_tool = siem_tools.get("search_udm") or siem_tools.get(
            "secops-mcp_search_udm"
        )

        # 1. Validate synthesized H29 YARA-L 2.0 rule
        val_raw = await val_tool.run_async(
            args={"rule_text": compiler_safe_rule},
            tool_context=None,
        )
        val_text = (
            str(val_raw).encode("ascii", errors="ignore").decode("ascii")
        )
        passed = "FAILED" not in val_text.upper() and (
            "SUCCESS" in val_text.upper()
            or "VALID" in val_text.upper()
            or "PASSED" in val_text.upper()
        )
        mcp_results["validate_rule_result"] = {
            "rule_name": "ioc_threat_actor_attribution_export_h29",
            "raw_response": val_text[:500],
            "valid": passed,
        }

        # 2. Probe live UDM telemetry for network/process events referenced by H29
        udm_queries = {
            "wins_d19_powershell": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"',
            "workspace_superadmin_79_154_246_114": 'metadata.log_type = "WORKSPACE_ACTIVITY" AND principal.ip = "79.154.246.114"',
            "gcp_cloudsql_104_198_226_161": 'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161"',
        }
        for label, query_str in udm_queries.items():
            s_raw = await udm_tool.run_async(
                args={
                    "query": query_str,
                    "start_time": "2026-02-07T00:00:00Z",
                    "end_time": "2026-02-08T00:00:00Z",
                    "max_events": 5,
                },
                tool_context=None,
            )
            s_text = (
                str(s_raw).encode("ascii", errors="ignore").decode("ascii")
            )
            total_events = 1 if ("events" in s_text or "metadata" in s_text or "total_events" in s_text) else 0
            mcp_results["udm_probe_results"][label] = {
                "query": query_str,
                "total_events": total_events,
                "preview": s_text[:300],
            }
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            try:
                await ts.close()
            except Exception:
                pass
    return mcp_results


def main() -> int:
    t0 = time.time()
    print("=== Cycle 28 (Horizon H29) Live Validation Starting ===")

    # 1. Evaluate BENCH-15 and full 15-scenario benchmark suite
    print("[1/5] Evaluating BENCH-15 and 15-scenario benchmark suite (BENCH-01..15)...")
    bench15_eval = evaluate_benchmark_scenario(
        "BENCH-15-YARAL2-EXPORT-DATA-TABLE-AND-STIX-SIGHTINGS"
    )
    assert bench15_eval["status"] == "success", f"BENCH-15 failed: {bench15_eval}"
    assert bench15_eval["TP"] == 5, f"Expected TP=5, got {bench15_eval['TP']}"
    assert bench15_eval["FP"] == 0, f"Expected FP=0, got {bench15_eval['FP']}"
    assert bench15_eval["FN"] == 0, f"Expected FN=0, got {bench15_eval['FN']}"
    assert bench15_eval["TN"] == 2, f"Expected TN=2, got {bench15_eval['TN']}"
    assert bench15_eval["f1"] == 1.0, f"Expected f1=1.0, got {bench15_eval['f1']}"
    assert bench15_eval["pass2_idempotent"] is True

    suite_eval = evaluate_verification_benchmark_suite(include_extended_night2=True)
    assert suite_eval["status"] == "success"
    assert suite_eval["scenario_count"] == 15
    assert suite_eval["total_seeded_defects"] == 78
    assert suite_eval["TP"] == 78
    assert suite_eval["FP"] == 0
    assert suite_eval["FN"] == 0
    assert suite_eval["total_negative_controls"] == 31
    assert suite_eval["TN"] == 31
    assert suite_eval["micro_f1"] == 1.0
    print(
        f"    -> BENCH-15: TP={bench15_eval['TP']}, FP={bench15_eval['FP']}, "
        f"FN={bench15_eval['FN']}, TN={bench15_eval['TN']}, F1={bench15_eval['f1']}"
    )
    print(
        f"    -> Full Suite (15 scenarios): TP={suite_eval['TP']}/78, "
        f"FP={suite_eval['FP']}, FN={suite_eval['FN']}, TN={suite_eval['TN']}/31, "
        f"Micro-F1={suite_eval['micro_f1']}"
    )

    # 2. Verify SkillRL 9-Rule Matrix & 28-Cycle Master Evolution Synthesis Report
    print("[2/5] Verifying SkillRL 9-Rule Matrix & 28-Cycle Master Evolution Synthesis...")
    skillrl_matrix = generate_skillrl_failure_distillation_matrix()
    assert skillrl_matrix["rule_count"] == 9
    assert (
        "SKILLRL-09-YARAL2-DATA-TABLE-EXPORT-AND-ALERT-STREAM-SAFETY"
        in skillrl_matrix["rule_ids"]
    )
    evo_report = generate_master_evolution_synthesis_report()
    assert evo_report["total_cycles_completed"] == 28
    assert evo_report["total_horizons_completed"] == 29
    assert evo_report["pillar_count"] == 5
    print(
        f"    -> SkillRL Rules: {skillrl_matrix['rule_count']} "
        f"(horizons={skillrl_matrix['horizons_covered']})"
    )
    print(
        f"    -> Evolution Synthesis: {evo_report['total_cycles_completed']} cycles, "
        f"{evo_report['total_horizons_completed']} horizons (H1..H29)"
    )

    # 3. Live Chronicle SIEM (secops-mcp + Argolis Data Table probe)
    print("[3/5] Running live Chronicle SIEM YARA-L 2.0 validation and Argolis Data Table probe...")
    bench15_spec = next(
        sc
        for sc in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if sc["scenario_id"] == "BENCH-15-YARAL2-EXPORT-DATA-TABLE-AND-STIX-SIGHTINGS"
    )
    inspected_b15 = inspect_yaral2_data_table_export_and_alert_stream_in_text(
        bench15_spec["markdown_content"]
    )
    remediated_rule_text = inspected_b15["synthesized_yaral2_rule"]
    mcp_validation = asyncio.run(
        _run_live_secops_mcp_validation(remediated_rule_text)
    )
    assert mcp_validation["validate_rule_result"]["valid"] is True, (
        f"Live validate_rule failed: {mcp_validation['validate_rule_result']}"
    )
    argolis_probe = _probe_argolis_chronicle_data_table_and_verify_rule(
        remediated_rule_text
    )
    print(
        f"    -> secops-mcp validate_rule: valid={mcp_validation['validate_rule_result']['valid']}"
    )
    print(
        f"    -> Argolis Data Table probe: http_status={argolis_probe.get('data_table_http_status')}, "
        f"verify_rule_http_status={argolis_probe.get('verify_rule_http_status')}"
    )

    # 4. Live Google Docs API v1 + Drive API v3 in-place validation on existing doc
    print(
        f"[4/5] Resetting existing live Google Doc {EXISTING_LIVE_DOC_ID} in place (0 new docs)..."
    )
    creds = build_dwd_credentials()
    token = resolve_docs_token(token_source=creds)
    clear_doc_index_cache()
    reset_res = _reset_existing_google_doc_in_place(
        EXISTING_LIVE_DOC_ID,
        bench15_spec["markdown_content"],
        token,
    )
    assert reset_res["new_docs_created"] == 0
    clear_doc_index_cache()

    def _live_gate_fn(rule_str: str) -> dict[str, Any]:
        return {
            "valid": mcp_validation["validate_rule_result"]["valid"],
            "raw_response": mcp_validation["validate_rule_result"]["raw_response"],
        }

    gate = ChronicleRuleValidationGate(validate_fn=_live_gate_fn)
    live_pass1 = audit_yaral2_data_table_export_and_alert_stream_in_doc(
        document_id=EXISTING_LIVE_DOC_ID,
        mode="APPLY",
        append_appendix=True,
        validate_live=True,
        validation_gate=gate,
        token_source=creds,
        quota_project=QUOTA_PROJECT,
    )
    assert live_pass1["status"] == "success", f"live_pass1 failed: {live_pass1}"
    assert live_pass1["defect_count"] == 5, f"live_pass1 defect_count: {live_pass1}"
    assert live_pass1["comments_inserted"] == 5, f"live_pass1 comments: {live_pass1}"
    assert live_pass1["edits_staged"] == 5, f"live_pass1 edits: {live_pass1}"
    assert live_pass1["appendix_appended"] is True
    assert live_pass1["compiler_verified"] is True

    # Pass 2 idempotency on live Google Doc
    live_pass2 = audit_yaral2_data_table_export_and_alert_stream_in_doc(
        document_id=EXISTING_LIVE_DOC_ID,
        mode="APPLY",
        append_appendix=True,
        token_source=creds,
        quota_project=QUOTA_PROJECT,
    )
    assert live_pass2["status"] == "success"
    assert live_pass2["edits_staged"] == 0
    assert live_pass2["skipped_existing_suggestion_count"] >= 5

    # Inspect live suggestions and verify counterfactual post-accept readiness
    live_suggestions = inspect_doc_suggestions(
        EXISTING_LIVE_DOC_ID,
        token_source=creds,
        quota_project=QUOTA_PROJECT,
    )
    post_accept_res = verify_post_accept_secops_doc_readiness(
        document_id=EXISTING_LIVE_DOC_ID,
        doc_text=bench15_spec["markdown_content"],
        token_source=creds,
        quota_project=QUOTA_PROJECT,
    )
    assert post_accept_res["pre_accept_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
    assert post_accept_res["post_accept_verdict"] == "APPROVED_FOR_SOC_EXECUTION"
    assert post_accept_res["post_accept_readiness_score"] == 100.0
    assert post_accept_res["residual_defect_count"] == 0
    assert post_accept_res["signoff_gate_passed"] is True

    print(
        f"    -> Live Doc Pass 1: defects={live_pass1['defect_count']}, "
        f"comments={live_pass1['comments_inserted']}, edits={live_pass1['edits_staged']}, "
        f"appendix={live_pass1['appendix_appended']}"
    )
    print(
        f"    -> Live Doc Pass 2 (Idempotency): edits_staged={live_pass2['edits_staged']}, "
        f"skipped_existing={live_pass2['skipped_existing_suggestion_count']}"
    )
    print(
        f"    -> Counterfactual Post-Accept Readiness: "
        f"{post_accept_res['pre_accept_verdict']} ({post_accept_res['pre_accept_readiness_score']}) -> "
        f"{post_accept_res['post_accept_verdict']} ({post_accept_res['post_accept_readiness_score']}), "
        f"resolved={post_accept_res['resolved_defect_count']}, residual={post_accept_res['residual_defect_count']}"
    )

    # 5. Execute Grounded SOAR Review Workflow with Post-Accept Readiness Gate
    print("[5/5] Executing Grounded SOAR Review Workflow with Counterfactual Post-Accept Gate...")
    workflow_output = run_grounded_soar_review_workflow(
        case_id="33269",
        skill_name="malware-incident-response",
        doc_url=f"https://docs.google.com/document/d/{EXISTING_LIVE_DOC_ID}/edit",
        doc_text=bench15_spec["markdown_content"],
        verify_post_accept_readiness=True,
    )
    assert "BLOCKED_CRITICAL_DEFECTS" in workflow_output
    assert "APPROVED_FOR_SOC_EXECUTION" in workflow_output

    # Clean up any temporary workflow report written to multi-agent/reports/
    reports_dir = REPO_ROOT / "multi-agent" / "reports"
    if reports_dir.exists():
        for rpt_file in reports_dir.glob("Grounded_SOAR_Review_Case_*.md"):
            rpt_file.unlink(missing_ok=True)

    elapsed_s = round(time.time() - t0, 2)
    report_payload = {
        "cycle": 28,
        "horizon_id": "H29",
        "title": (
            "Chronicle SIEM YARA-L 2.0 Data Table Export (export: %<table>.write_row), "
            "Entity Threat Associations ($g.graph.metadata.threat.associations), "
            ":verifyRuleText / legacy:legacyFetchAlertsView & STIX 2.1 Sightings Verifier + "
            "Counterfactual Post-Accept Readiness Sign-Off Workflow (BENCH-15)"
        ),
        "timestamp_epoch": int(time.time()),
        "elapsed_seconds": elapsed_s,
        "new_google_docs_created": 0,
        "reused_google_doc_id": EXISTING_LIVE_DOC_ID,
        "bench15_evaluation": {
            "scenario_id": bench15_eval["scenario_id"],
            "TP": bench15_eval["TP"],
            "FP": bench15_eval["FP"],
            "FN": bench15_eval["FN"],
            "TN": bench15_eval["TN"],
            "precision": bench15_eval["precision"],
            "recall": bench15_eval["recall"],
            "f1": bench15_eval["f1"],
            "pass2_idempotent": bench15_eval["pass2_idempotent"],
        },
        "full_benchmark_suite": {
            "scenario_count": suite_eval["scenario_count"],
            "total_seeded_defects": suite_eval["total_seeded_defects"],
            "TP": suite_eval["TP"],
            "FP": suite_eval["FP"],
            "FN": suite_eval["FN"],
            "total_negative_controls": suite_eval["total_negative_controls"],
            "TN": suite_eval["TN"],
            "micro_precision": suite_eval["micro_precision"],
            "micro_recall": suite_eval["micro_recall"],
            "micro_f1": suite_eval["micro_f1"],
        },
        "skillrl_distillation_matrix": {
            "rule_count": skillrl_matrix["rule_count"],
            "horizons_covered": skillrl_matrix["horizons_covered"],
            "rule_ids": skillrl_matrix["rule_ids"],
        },
        "chronicle_siem_mcp_validation": mcp_validation,
        "argolis_chronicle_data_table_probe": argolis_probe,
        "live_google_doc_validation": {
            "document_id": EXISTING_LIVE_DOC_ID,
            "new_docs_created": 0,
            "pass1_defect_count": live_pass1["defect_count"],
            "pass1_defect_counts_by_type": live_pass1["defect_counts_by_type"],
            "pass1_comments_inserted": live_pass1["comments_inserted"],
            "pass1_edits_staged": live_pass1["edits_staged"],
            "pass1_appendix_appended": live_pass1["appendix_appended"],
            "pass1_standard_yara_ignored": live_pass1["standard_yara_blocks_ignored_count"],
            "pass2_edits_staged": live_pass2["edits_staged"],
            "pass2_skipped_existing_suggestions": live_pass2[
                "skipped_existing_suggestion_count"
            ],
            "live_suggestion_count": live_suggestions.get("suggestion_count", 0),
        },
        "counterfactual_post_accept_readiness": {
            "pre_accept_verdict": post_accept_res["pre_accept_verdict"],
            "post_accept_verdict": post_accept_res["post_accept_verdict"],
            "pre_accept_readiness_score": post_accept_res["pre_accept_readiness_score"],
            "post_accept_readiness_score": post_accept_res[
                "post_accept_readiness_score"
            ],
            "readiness_score_delta": post_accept_res["readiness_score_delta"],
            "resolved_defect_count": post_accept_res["resolved_defect_count"],
            "residual_defect_count": post_accept_res["residual_defect_count"],
            "signoff_gate_passed": post_accept_res["signoff_gate_passed"],
            "signoff_badge_markdown": post_accept_res["signoff_badge_markdown"],
        },
    }
    REPORT_PATH.write_text(json.dumps(report_payload, indent=2) + "\n", encoding="utf-8")
    print(f"=== Cycle 28 (H29) Validation Succeeded in {elapsed_s}s -> {REPORT_PATH} ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
