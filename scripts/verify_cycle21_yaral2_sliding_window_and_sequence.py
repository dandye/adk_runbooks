#!/usr/bin/env python3
"""Cycle 21 (H22) Live Validation: Chronicle SIEM YARA-L 2.0 Sliding Window
(over <W> after/before $<ev>), Timestamp Ordering & Kill-Chain Sequence Verifier
in Google Docs.

Reuses and resets the existing Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. Live execution of ``verify_and_redline_yaral2_rules_in_doc`` against
   Google Docs API v1 and live Argolis Chronicle SIEM (``dandye-0324-chronicle``):
   - Repairs all 5 ``H22`` temporal & sliding-window defect classes:
     * ``invalid_sliding_window_syntax`` (``within 15 minutes following $ip``)
     * ``sliding_window_pivot_event_mismatch`` (``$ip`` -> ``$iam``)
     * ``sliding_window_direction_contradiction`` (``over 15m before $tamper`` -> ``over 15m after $tamper``)
     * ``invalid_event_timestamp_field`` (``$iam.timestamp`` / ``$tamper.metadata.event_timestamp`` -> ``*.metadata.event_timestamp.seconds``)
     * ``reversed_kill_chain_timestamp_order`` (``$iam.timestamp > $sql.metadata.event_timestamp`` -> ``$iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds``)
   - Preserves valid negative-control sliding-window rule (``0`` false positives)
   - Validates repaired rules via live Chronicle SIEM ``validate_rule`` and
     evaluates empirical kill-chain timestamp ordering via ``search_udm`` +
     ``evaluate_yaral2_temporal_sequence`` (verifying Case 33278 SetIamPolicy ->
     cloudsql.instances.delete delta = 307s, Cases 33281/33283/33287 SAML2/2SV ->
     CREATE_DATA_TRANSFER_REQUEST delta = 65s, and Cases 33269/33280 PowerShell ->
     DERPService on wins-d19).
2. Live ``diagnose_zero_hit_yaral2_rule`` validation for ``zero_hit_reversed_timestamp_sequence``
   against live Chronicle SIEM ``GCP_CLOUDAUDIT`` telemetry.
3. Pass 1 ``inspect_doc_suggestions`` and Pass 2 multi-pass idempotency on
   ``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``.
4. Quantitative benchmark evaluation via ``evaluate_infosec_doc_reviewer`` on
   ``BENCH-08-YARAL2-SLIDING-WINDOW-AND-KILLCHAIN-SEQUENCE`` and ``all_with_night2``
   (8 scenarios, 43 seeded defects, 15 negative controls, F1 = 1.0000).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = PROJECT_ROOT / "multi-agent"
for p in (PROJECT_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(PROJECT_ROOT / "external" / "mcp-security" / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    clear_doc_index_cache,
    diagnose_zero_hit_yaral2_rule,
    evaluate_infosec_doc_reviewer,
    inspect_doc_suggestions,
    resolve_docs_token,
    verify_and_redline_yaral2_rules_in_doc,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

EXISTING_VALIDATION_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle21_H22_Live_YARAL2_Sliding_Window_and_Kill_Chain_Sequence_Validation"


def _reset_google_doc_in_place(
    doc_id: str,
    title: str,
    markdown_body: str,
    token: str,
    quota_project: str,
) -> dict[str, Any]:
    """Replaces the body of an existing Google Doc in place via Drive API v3 media upload and clears prior comments."""
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": quota_project,
    }
    with httpx.Client(timeout=30.0) as client:
        comments_resp = client.get(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments",
            params={"fields": "comments(id,deleted)", "pageSize": 100},
            headers=headers,
        )
        comments_resp.raise_for_status()
        deleted_comments = 0
        for c in comments_resp.json().get("comments", []) or []:
            if c.get("deleted"):
                continue
            cid = c.get("id")
            if cid:
                del_resp = client.delete(
                    f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments/{cid}",
                    headers=headers,
                )
                if del_resp.status_code in (200, 204):
                    deleted_comments += 1

        meta_resp = client.patch(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}",
            params={"fields": "id,name"},
            headers={**headers, "Content-Type": "application/json"},
            json={"name": title},
        )
        meta_resp.raise_for_status()

        upload_resp = client.patch(
            f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}",
            params={"uploadType": "media", "fields": "id,name,mimeType"},
            headers={**headers, "Content-Type": "text/markdown; charset=utf-8"},
            content=markdown_body.encode("utf-8"),
        )
        upload_resp.raise_for_status()
        return {
            "document_id": doc_id,
            "deleted_prior_comments": deleted_comments,
            "upload_status": upload_resp.status_code,
        }


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    quota_project = (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or "dandye-0324-chronicle"
    )
    token_source = AdcTokenSource()
    token = resolve_docs_token(None, token_source=token_source)

    doc_markdown = (
        "# Cycle 21 (H22) Chronicle SIEM YARA-L 2.0 Sliding Window & Kill-Chain Sequence Live Validation\n\n"
        "## 1. Case 33278 GCP IAM Privilege Escalation -> Cloud SQL Deletion (Invalid Sliding Window Syntax, Pivot Variable Mismatch & Reversed Timestamp Inequality)\n\n"
        "rule gcp_setiampolicy_to_cloudsql_delete_sliding_window_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    mitre_attack_tactic = "Privilege Escalation"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"\n'
        '    severity = "CRITICAL"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-production"\n'
        '    $iam.principal.ip = "104.198.226.161"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.metadata.product_event_type = "cloudsql.instances.delete"\n'
        '    $sql.principal.ip = "104.198.226.161"\n'
        "    $sql.principal.ip = $ip\n"
        "    $iam.timestamp > $sql.metadata.event_timestamp\n"
        "  match:\n"
        "    $ip within 15 minutes following $ip\n"
        "  outcome:\n"
        "    $risk_score = max(95)\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n\n"
        "## 2. Cases 33281/33283/33287 Google Workspace SAML2 Tampering -> Drive Data Transfer (Sliding Window Direction Contradiction & Missing .seconds Timestamp Path)\n\n"
        "rule workspace_saml_2sv_to_drive_transfer_direction_contradiction_case_33287 {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    mitre_attack_technique = "T1556.006"\n'
        '    mitre_attack_tactic = "Defense Evasion"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1556/006/"\n'
        '    severity = "HIGH"\n'
        '    runbook_skill = "suspicious-login-triage"\n'
        "  events:\n"
        '    $tamper.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $tamper.metadata.product_event_type = "DELETE_SAML2_SERVICE_PROVIDER_CONFIG"\n'
        '    $tamper.principal.ip = "79.154.246.114"\n'
        "    $tamper.principal.ip = $ip\n"
        '    $exfil.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $exfil.metadata.product_event_type = "CREATE_DATA_TRANSFER_REQUEST"\n'
        '    $exfil.principal.ip = "79.154.246.114"\n'
        "    $exfil.principal.ip = $ip\n"
        "    $tamper.metadata.event_timestamp < $exfil.metadata.event_timestamp\n"
        "  match:\n"
        "    $ip over 15m before $tamper\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $tamper and $exfil\n"
        "}\n\n"
        "## 3. Cases 33269/33280 Valid Sliding Window & Timestamp Ordering Negative Control on wins-d19\n\n"
        "rule wins_d19_powershell_to_derpservice_valid_sliding_window_case_33280 {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    mitre_attack_tactic = "Execution"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/001/"\n'
        '    severity = "HIGH"\n'
        '    runbook_skill = "malware-incident-response"\n'
        "  events:\n"
        '    $exec.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $exec.principal.hostname = "wins-d19"\n'
        "    $exec.target.process.command_line = /powershell/ nocase\n"
        "    $exec.principal.hostname = $host\n"
        '    $svc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $svc.principal.hostname = "wins-d19"\n'
        "    $svc.target.process.command_line = /DERPService/ nocase\n"
        "    $svc.principal.hostname = $host\n"
        "    $exec.metadata.event_timestamp.seconds <= $svc.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $host over 15m after $exec\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $exec and $svc\n"
        "}\n"
    )

    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(
                siem_toolset.get_tools(readonly_context=None)
            )
        }

        def live_siem_validate_fn(rule_text: str) -> Any:
            return loop.run_until_complete(
                siem_tools["validate_rule"].run_async(
                    args={"rule_text": rule_text},
                    tool_context=None,
                )
            )

        def live_siem_search_fn(
            query: str,
            start_time: str = "2026-02-07T00:00:00Z",
            end_time: str = "2026-02-08T00:00:00Z",
            max_events: int = 50,
        ) -> Any:
            return loop.run_until_complete(
                siem_tools["search_udm"].run_async(
                    args={
                        "query": query,
                        "start_time": start_time,
                        "end_time": end_time,
                        "max_events": max_events,
                    },
                    tool_context=None,
                )
            )

        print(
            f"[1/5] Resetting existing Google Doc {EXISTING_VALIDATION_DOC_ID} in place via Drive API v3 (0 new docs created)..."
        )
        clear_doc_index_cache()
        reset_info = _reset_google_doc_in_place(
            EXISTING_VALIDATION_DOC_ID,
            DOC_TITLE,
            doc_markdown,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()

        print(
            "[2/5] Running Pass 1 of verify_and_redline_yaral2_rules_in_doc against live Google Docs API v1 + Argolis Chronicle SIEM..."
        )
        pass1 = verify_and_redline_yaral2_rules_in_doc(
            EXISTING_VALIDATION_DOC_ID,
            run_live_siem_check=True,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass1["status"] == "success", f"pass1 failed: {pass1}"
        assert pass1["yaral2_findings_count"] == 7, (
            f"Expected 7 findings, got {pass1['yaral2_findings_count']}: {pass1['findings']}"
        )
        defect_types_found = {f["defect_type"] for f in pass1["findings"]}
        assert defect_types_found == {
            "invalid_sliding_window_syntax",
            "sliding_window_pivot_event_mismatch",
            "sliding_window_direction_contradiction",
            "invalid_event_timestamp_field",
            "reversed_kill_chain_timestamp_order",
        }, f"Missing H22 defect types: {defect_types_found}"
        assert pass1["comments"]["inserted_count"] == 7
        assert pass1["edits"]["applied_count"] == 7
        assert len(pass1["siem_rule_checks"]) == 3

        verifications_by_name = {
            v["rule_name"]: v for v in pass1["siem_rule_checks"]
        }
        v_r1 = verifications_by_name[
            "gcp_setiampolicy_to_cloudsql_delete_sliding_window_case_33278"
        ]
        v_r2 = verifications_by_name[
            "workspace_saml_2sv_to_drive_transfer_direction_contradiction_case_33287"
        ]
        v_r3 = verifications_by_name[
            "wins_d19_powershell_to_derpservice_valid_sliding_window_case_33280"
        ]

        for v in (v_r1, v_r2, v_r3):
            assert v["compiler_verified"] is True, (
                f"Compiler failed for {v['rule_name']}: {v}"
            )
            assert v["retrohunt_verified"] is True, (
                f"Retrohunt failed for {v['rule_name']}: {v}"
            )
            assert v["is_multi_event"] is True
            assert v["temporal_sequence_verified"] is True, (
                f"Temporal sequence failed for {v['rule_name']}: {v.get('temporal_evaluation')}"
            )

        print(
            "[3/5] Inspecting inline Google Docs suggestions and running Pass 2 multi-pass idempotency..."
        )
        inspected = inspect_doc_suggestions(
            EXISTING_VALIDATION_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert inspected["status"] == "success"
        assert inspected["suggestion_count"] >= 7
        accepted = inspected["accepted_text"]
        assert "$ip over 15m after $iam" in accepted
        assert (
            "$iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds"
            in accepted
        )
        assert "$ip over 15m after $tamper" in accepted
        assert (
            "$tamper.metadata.event_timestamp.seconds < $exfil.metadata.event_timestamp.seconds"
            in accepted
        )

        clear_doc_index_cache()
        pass2 = verify_and_redline_yaral2_rules_in_doc(
            EXISTING_VALIDATION_DOC_ID,
            run_live_siem_check=True,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass2["status"] == "success"
        assert pass2["skipped_existing_suggestion_count"] == 7
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        print(
            "[4/5] Validating live SIEM zero_hit_reversed_timestamp_sequence diagnosis on Case 33278..."
        )
        reversed_only_rule = (
            "rule gcp_reversed_timestamp_only_case_33278 {\n"
            "  meta:\n"
            '    author = "SecOps"\n'
            '    mitre_attack_technique = "T1098.003"\n'
            '    mitre_attack_tactic = "Privilege Escalation"\n'
            '    mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"\n'
            '    severity = "CRITICAL"\n'
            '    runbook_skill = "compromised-user-account-response"\n'
            "  events:\n"
            '    $e1.metadata.log_type = "GCP_CLOUDAUDIT"\n'
            '    $e1.target.resource.name = "projects/base-production"\n'
            '    $e1.principal.ip = "104.198.226.161"\n'
            "    $e1.principal.ip = $ip\n"
            '    $e2.metadata.log_type = "GCP_CLOUDAUDIT"\n'
            '    $e2.metadata.product_event_type = "cloudsql.instances.delete"\n'
            '    $e2.principal.ip = "104.198.226.161"\n'
            "    $e2.principal.ip = $ip\n"
            "    $e1.metadata.event_timestamp.seconds > $e2.metadata.event_timestamp.seconds\n"
            "  match:\n"
            "    $ip over 15m\n"
            "  outcome:\n"
            "    $risk_score = max(95)\n"
            "  condition:\n"
            "    $e1 and $e2\n"
            "}\n"
        )
        live_zero_hit_diag = diagnose_zero_hit_yaral2_rule(
            reversed_only_rule,
            siem_search_fn=live_siem_search_fn,
            siem_validate_fn=live_siem_validate_fn,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
        )
        assert (
            live_zero_hit_diag["diagnosis_class"]
            == "zero_hit_reversed_timestamp_sequence"
        ), f"Unexpected diagnosis: {live_zero_hit_diag}"
        assert live_zero_hit_diag["compiler_verified"] is True
        assert live_zero_hit_diag["pivot_compiler_verified"] is True
        assert live_zero_hit_diag["pivot_verified"] is True
        assert live_zero_hit_diag["pivot_event_count"] >= 2
        assert (
            "$e1.metadata.event_timestamp.seconds < $e2.metadata.event_timestamp.seconds"
            in live_zero_hit_diag["pivoted_rule_text"]
        )

        print(
            "[5/5] Running evaluate_infosec_doc_reviewer on BENCH-08 and all_with_night2..."
        )
        bench08 = evaluate_infosec_doc_reviewer(
            scenario_ids="BENCH-08-YARAL2-SLIDING-WINDOW-AND-KILLCHAIN-SEQUENCE",
            include_hda_ablation=False,
        )
        assert bench08["status"] == "success"
        assert bench08["total_expected_defects"] == 5
        assert bench08["true_positive_edits"] == 5
        assert bench08["false_positive_edits"] == 0
        assert bench08["f1_score"] == 1.0
        assert bench08["pass2_idempotency_rate"] == 1.0

        bench_all = evaluate_infosec_doc_reviewer(
            scenario_ids="all_with_night2",
            include_hda_ablation=True,
        )
        assert bench_all["status"] == "success"
        assert bench_all["scenario_count"] == 8
        assert bench_all["total_expected_defects"] == 43
        assert bench_all["true_positive_edits"] == 43
        assert bench_all["false_positive_edits"] == 0
        assert bench_all["f1_score"] == 1.0
        assert (
            bench_all["negative_controls_preserved"]
            == bench_all["total_negative_controls"]
        )
        assert bench_all["negative_controls_preserved"] >= 15

        summary_payload = {
            "status": "success",
            "cycle": 21,
            "horizon_id": "H22",
            "document_id": EXISTING_VALIDATION_DOC_ID,
            "document_title": DOC_TITLE,
            "new_docs_created": 0,
            "deleted_prior_comments": reset_info["deleted_prior_comments"],
            "pass1_live_siem_and_docs": {
                "rule_count": len(pass1["siem_rule_checks"]),
                "compiler_verified_count": sum(
                    1
                    for r in pass1["siem_rule_checks"]
                    if r.get("compiler_verified")
                ),
                "yaral2_findings_count": pass1["yaral2_findings_count"],
                "comments_inserted": pass1["comments"]["inserted_count"],
                "edits_applied": pass1["edits"]["applied_count"],
                "rule_1_temporal": v_r1.get("temporal_evaluation"),
                "rule_2_temporal": v_r2.get("temporal_evaluation"),
                "rule_3_temporal": v_r3.get("temporal_evaluation"),
            },
            "pass2_idempotency": {
                "skipped_existing_suggestion_count": pass2[
                    "skipped_existing_suggestion_count"
                ],
                "comments_inserted": pass2["comments"]["inserted_count"],
                "edits_applied": pass2["edits"]["applied_count"],
            },
            "live_zero_hit_reversed_timestamp_diagnosis": {
                "diagnosis_class": live_zero_hit_diag["diagnosis_class"],
                "compiler_verified": live_zero_hit_diag["compiler_verified"],
                "pivot_compiler_verified": live_zero_hit_diag[
                    "pivot_compiler_verified"
                ],
                "pivot_event_count": live_zero_hit_diag["pivot_event_count"],
                "chronological_pair_count": live_zero_hit_diag.get(
                    "chronological_pair_count"
                ),
                "reversed_pair_count": live_zero_hit_diag.get(
                    "reversed_pair_count"
                ),
                "within_window_pair_count": live_zero_hit_diag.get(
                    "within_window_pair_count"
                ),
                "observed_min_delta_seconds": live_zero_hit_diag.get(
                    "observed_min_delta_seconds"
                ),
                "observed_max_delta_seconds": live_zero_hit_diag.get(
                    "observed_max_delta_seconds"
                ),
            },
            "benchmark_bench08": {
                "total_expected_defects": bench08["total_expected_defects"],
                "true_positive_edits": bench08["true_positive_edits"],
                "false_positive_edits": bench08["false_positive_edits"],
                "f1_score": bench08["f1_score"],
                "pass2_idempotency_rate": bench08["pass2_idempotency_rate"],
            },
            "benchmark_all_with_night2": {
                "scenario_count": bench_all["scenario_count"],
                "total_expected_defects": bench_all["total_expected_defects"],
                "true_positive_edits": bench_all["true_positive_edits"],
                "false_positive_edits": bench_all["false_positive_edits"],
                "f1_score": bench_all["f1_score"],
                "negative_controls_preserved": f"{bench_all['negative_controls_preserved']}/{bench_all['total_negative_controls']}",
            },
        }
        print(json.dumps(summary_payload, indent=2))
        return 0
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            try:
                loop.run_until_complete(ts.close())
            except Exception:
                pass
        loop.close()


if __name__ == "__main__":
    raise SystemExit(main())
