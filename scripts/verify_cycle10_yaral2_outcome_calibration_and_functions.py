#!/usr/bin/env python3
"""Cycle 10 (H17) Live Validation Script: YARA-L 2.0 outcome: Threshold Calibration,
if() Conditional Scoring & net.ip_in_range_cidr() Function Verifier in Google Docs.

Validates against live Argolis Chronicle SIEM (project `dandye-0324-chronicle`)
and live Google Docs API v1 / Google Drive API v3:

1. Direct SIEM Compiler + CIDR Function + Outcome Conditional + Threshold Calibration:
   - Rule 1 (`gcp_iam_cidr_and_conditional_outcome_case_33278` -- Case 33278 GCP IAM
     privilege escalation from `104.198.226.0/24`): Contains a non-YARA-L Splunk CIDR
     call (`cidrmatch("104.198.226.0/24", $iam.ip)` ->
     `net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")`), a SQL
     `CASE WHEN $iam.resource.name = "projects/base-production" THEN 85 ELSE 40 END`
     expression in `outcome:` (->
     `max(if($iam.target.resource.name = "projects/base-production", 85, 40))`), and
     uncalibrated `condition:` outcome thresholds (`$event_count >= 10 and $risk_score >= 95`)
     that suppress 100% of detections despite matching live Case 33278 UDM telemetry.
   - Rule 2 (`wins_d19_multi_event_uncalibrated_threshold_case_33280` -- Cases 33280/33285
     `wins-d19` LOLBin -> DERPService multi-event correlation): Compiles cleanly in
     Chronicle `validate_rule` and correlates `> 0` events across `$cmd` and `$svc` on
     `wins-d19`, but has an uncalibrated `condition:` threshold (`$svc_count >= 3` when
     only 1 `DERPService` service-creation event occurred), which is diagnosed as
     `uncalibrated_outcome_threshold` and calibrated to `$svc_count >= 1`.
   - Rule 3 (`gcp_iam_calibrated_outcome_control` -- Valid CIDR + `max(if(...))` +
     calibrated threshold control): Valid YARA-L 2.0 rule with
     `net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")`,
     `max(if($iam.target.resource.name = "projects/base-production", 85, 40))`, and
     satisfied thresholds (`$event_count >= 1 and $risk_score >= 50`) -> 0 findings
     (0 false positives).
2. Google Doc (`Cycle10_H17_Live_YARAL2_Outcome_Calibration_and_Functions_Validation`):
   - Verifies Pass 1 stages 5 comments and 5 `writeMode="SUGGEST"` edits
     (`inspect_doc_suggestions` `suggestion_count == 5`).
   - Verifies all 3 rules in `accepted_text` compile cleanly in Chronicle SIEM
     (`compiler_verified=True`), match `> 0` historical UDM events, and satisfy all
     `condition:` outcome thresholds (`all_thresholds_satisfied=True`).
   - Runs Pass 2 of `verify_and_redline_yaral2_rules_in_doc` on the same Google Doc
     to verify idempotency (`yaral2_findings_count == 0`,
     `skipped_existing_suggestion_count == 5`).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = PROJECT_ROOT / "multi-agent"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MULTI_AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(MULTI_AGENT_DIR))

load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(PROJECT_ROOT / "external" / "mcp-security" / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    _build_utf16_index_map,
    _iter_yaral2_rule_blocks,
    clear_doc_index_cache,
    create_google_doc,
    find_yaral2_rule_spans,
    inspect_doc_suggestions,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)

START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"
DEFAULT_CYCLE10_DOC_ID = os.environ.get(
    "CYCLE10_DOC_ID", "1ecsjbpYCrJhIz5LUiFCZjAkf24LPi-yKQBuOktDCd6U"
)

RULE_1_GCP_CIDR_CONDITIONAL_AND_UNCALIBRATED = (
    "rule gcp_iam_cidr_and_conditional_outcome_case_33278 {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Detects GCP IAM activity from 104.198.226.0/24 with conditional project risk scoring"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    cidrmatch("104.198.226.0/24", $iam.ip)\n'
    "    $iam.principal.ip = $src_ip\n"
    "  match:\n"
    "    $src_ip over 15m\n"
    "  outcome:\n"
    "    $event_count = count_distinct($iam.metadata.id)\n"
    '    $risk_score = CASE WHEN $iam.resource.name = "projects/base-production" THEN 85 ELSE 40 END\n'
    "  condition:\n"
    "    $iam and $event_count >= 10 and $risk_score >= 95\n"
    "}"
)

RULE_2_WINS_D19_MULTI_EVENT_UNCALIBRATED = (
    "rule wins_d19_multi_event_uncalibrated_threshold_case_33280 {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Correlates cmd.exe discovery with DERPService creation on wins-d19"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $cmd.principal.hostname = "wins-d19"\n'
    "    re.regex($cmd.target.process.command_line, `.*cmd.*`) nocase\n"
    "    $cmd.principal.hostname = $host\n"
    "    re.regex($svc.target.process.command_line, `.*DERPService.*`) nocase\n"
    "    $svc.principal.hostname = $host\n"
    "  match:\n"
    "    $host over 15m\n"
    "  outcome:\n"
    "    $cmd_count = count_distinct($cmd.metadata.id)\n"
    "    $svc_count = count_distinct($svc.metadata.id)\n"
    "  condition:\n"
    "    $cmd and $svc and $svc_count >= 3\n"
    "}"
)

RULE_3_GCP_CALIBRATED_CONTROL = (
    "rule gcp_iam_calibrated_outcome_control {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Verified CIDR, conditional if() outcome, and calibrated threshold control rule"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")\n'
    "    $iam.principal.ip = $src_ip\n"
    "  match:\n"
    "    $src_ip over 15m\n"
    "  outcome:\n"
    "    $event_count = count_distinct($iam.metadata.id)\n"
    '    $risk_score = max(if($iam.target.resource.name = "projects/base-production", 85, 40))\n'
    "  condition:\n"
    "    $iam and $event_count >= 1 and $risk_score >= 50\n"
    "}"
)


def main() -> int:
    print(
        "=== Cycle 10 (H17): Live YARA-L 2.0 outcome: Threshold Calibration, "
        "if() Conditional Scoring & net.ip_in_range_cidr() Validation ==="
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    folder_id = os.environ.get("GOOGLE_DRIVE_FOLDER_ID") or os.environ.get(
        "DRIVE_REPORTS_FOLDER_ID"
    )

    print("Initializing Argolis Chronicle SIEM MCP toolset...")
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(
                siem_toolset.get_tools(readonly_context=None)
            )
        }
        print(
            f"Discovered {len(siem_tools)} SIEM tools "
            f"(validate_rule={'validate_rule' in siem_tools}, "
            f"search_udm={'search_udm' in siem_tools})"
        )

        def live_siem_validate_fn(rule_text: str) -> Any:
            return loop.run_until_complete(
                siem_tools["validate_rule"].run_async(
                    args={"rule_text": rule_text},
                    tool_context=None,
                )
            )

        def live_siem_search_fn(
            query: str,
            start_time: str = START_TIME,
            end_time: str = END_TIME,
            max_events: int = 20,
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

        # Step 1: Direct SIEM validation on the 3 YARA-L 2.0 rules
        v1 = verify_yaral2_rule_with_siem(
            RULE_1_GCP_CIDR_CONDITIONAL_AND_UNCALIBRATED,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v1["compiler_verified"] is True, f"Rule 1 failed compiler: {v1}"
        assert len(v1["findings"]) == 2, (
            f"Expected 2 static findings on Rule 1, got {len(v1['findings'])}: {v1['findings']}"
        )
        diag1 = v1.get("zero_hit_diagnosis") or {}
        assert diag1.get("failure_reason") == "uncalibrated_outcome_threshold", (
            f"Rule 1 threshold calibration diagnosis failed: {diag1}"
        )
        assert diag1.get("pivot_compiler_verified") is True, (
            f"Rule 1 calibrated pivot failed compiler: {diag1}"
        )
        assert int(diag1.get("pivot_event_count") or 0) > 0, (
            f"Rule 1 calibrated pivot matched 0 events: {diag1}"
        )

        v2 = verify_yaral2_rule_with_siem(
            RULE_2_WINS_D19_MULTI_EVENT_UNCALIBRATED,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v2["compiler_verified"] is True, f"Rule 2 failed compiler: {v2}"
        assert len(v2["findings"]) == 0, (
            f"Expected 0 static findings on Rule 2, got {len(v2['findings'])}: {v2['findings']}"
        )
        diag2 = v2.get("zero_hit_diagnosis") or {}
        assert diag2.get("failure_reason") == "uncalibrated_outcome_threshold", (
            f"Rule 2 threshold calibration diagnosis failed: {diag2}"
        )
        assert diag2.get("recommended_yaral2_predicate") == "$svc_count >= 1", (
            f"Expected $svc_count >= 1 on Rule 2, got {diag2}"
        )
        assert diag2.get("pivot_compiler_verified") is True, (
            f"Rule 2 calibrated pivot failed compiler: {diag2}"
        )

        v3 = verify_yaral2_rule_with_siem(
            RULE_3_GCP_CALIBRATED_CONTROL,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v3["compiler_verified"] is True, f"Rule 3 failed compiler: {v3}"
        assert len(v3["findings"]) == 0, f"Expected 0 findings on Rule 3, got {v3['findings']}"
        assert v3["retrohunt_event_count"] > 0, f"Rule 3 matched 0 events: {v3}"
        assert (v3.get("outcome_evaluation") or {}).get("all_thresholds_satisfied") is True
        print(
            f"[1/4] Direct SIEM CIDR, Conditional Outcome & Threshold Calibration Passed:\n"
            f"      - Rule 1 ({v1['rule_name']}): 2 static findings (cidrmatch, CASE WHEN) + "
            f"{len(diag1.get('uncalibrated_comparisons') or [])} uncalibrated outcome threshold pivots -> "
            f"outcome_values={(v1.get('outcome_evaluation') or {}).get('outcome_values')}, "
            f"pivot_compiler_verified={diag1.get('pivot_compiler_verified')}, "
            f"pivot_event_count={diag1.get('pivot_event_count')}\n"
            f"      - Rule 2 ({v2['rule_name']}): 0 static findings + 1 uncalibrated multi-event threshold pivot "
            f"('{(diag2.get('failing_predicate') or {}).get('comparison_text')}' -> '{diag2.get('recommended_yaral2_predicate')}') -> "
            f"outcome_values={(v2.get('outcome_evaluation') or {}).get('outcome_values')}, "
            f"pivot_compiler_verified={diag2.get('pivot_compiler_verified')}, "
            f"correlated_event_count={v2['retrohunt_event_count']}\n"
            f"      - Rule 3 ({v3['rule_name']}): 0 findings (control), compiler_verified={v3['compiler_verified']}, "
            f"outcome_values={(v3.get('outcome_evaluation') or {}).get('outcome_values')}, "
            f"all_thresholds_satisfied=True, retrohunt_event_count={v3['retrohunt_event_count']}"
        )

        clear_doc_index_cache()
        doc_title = "Cycle10_H17_Live_YARAL2_Outcome_Calibration_and_Functions_Validation"
        doc_id = os.environ.get("CYCLE10_DOC_ID", DEFAULT_CYCLE10_DOC_ID)
        create_new = os.environ.get("CREATE_NEW_DOC") == "1" or not doc_id

        if create_new:
            markdown_content = (
                "# Cycle 10 (H17): YARA-L 2.0 outcome: Threshold Calibration, if() & net.ip_in_range_cidr()\n\n"
                "## Rule 1: Case 33278 GCP IAM CIDR + CASE WHEN Outcome + Uncalibrated Thresholds\n\n"
                f"{RULE_1_GCP_CIDR_CONDITIONAL_AND_UNCALIBRATED}\n\n"
                "## Rule 2: Cases 33280/33285 Host wins-d19 Multi-Event Uncalibrated Outcome Threshold\n\n"
                + RULE_2_WINS_D19_MULTI_EVENT_UNCALIBRATED.replace("`", "\\`")
                + "\n\n"
                "## Rule 3: Valid CIDR, Conditional if() Outcome, and Calibrated Threshold Control\n\n"
                f"{RULE_3_GCP_CALIBRATED_CONTROL}\n"
            )
            create_res = create_google_doc(
                title=doc_title,
                content=markdown_content,
                folder_id=folder_id,
            )
            assert create_res.get("status") == "success", f"create_google_doc failed: {create_res}"
            doc_id = str(create_res["document_id"])
            view_url = str(
                create_res.get("viewUrl")
                or f"https://docs.google.com/document/d/{doc_id}/edit"
            )
            print(f"[2/4] Created Google Doc: {doc_title} ({doc_id})")
            pass1 = verify_and_redline_yaral2_rules_in_doc(
                doc_id,
                run_live_siem_check=True,
                diagnose_zero_hit_retrohunt=True,
                start_time=START_TIME,
                end_time=END_TIME,
                max_events=20,
                siem_validate_fn=live_siem_validate_fn,
                siem_search_fn=live_siem_search_fn,
            )
            assert pass1.get("status") == "success", f"Pass 1 failed: {pass1}"
            assert pass1["yaral2_findings_count"] == 5, (
                f"Expected 5 findings in Pass 1, got {pass1}"
            )
            assert pass1["zero_hit_yaral2_findings_count"] == 3
            assert pass1["skipped_existing_suggestion_count"] == 0
            assert pass1["comments"]["inserted_count"] == 5
            assert pass1["edits"]["applied_count"] == 5
        else:
            view_url = f"https://docs.google.com/document/d/{doc_id}/edit"
            print(
                f"[2/4] Reusing Cycle 10 Validation Google Doc (Pass 1 already applied 5 comments & 5 Suggested Edits): {doc_id}"
            )

        # Step 3: Inspect pending suggestions and verify accepted_text rules compile, match > 0 events, and satisfy all outcome thresholds
        inspected = inspect_doc_suggestions(doc_id)
        assert inspected.get("status") == "success", f"inspect_doc_suggestions failed: {inspected}"
        assert inspected["suggestion_count"] == 5, (
            f"Expected 5 pending suggestions on {doc_id}, got {inspected['suggestion_count']}"
        )
        accepted_text = str(inspected["accepted_text"])

        accepted_map = _build_utf16_index_map(accepted_text)
        _, _, remaining_static = find_yaral2_rule_spans(accepted_text, accepted_map)
        assert len(remaining_static) == 0, (
            f"Expected 0 remaining static defects, got {remaining_static}"
        )

        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 3
        accepted_rule_results: list[dict[str, Any]] = []
        for blk in accepted_blocks:
            v_res = verify_yaral2_rule_with_siem(
                str(blk["rule_text"]),
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=True,
                start_time=START_TIME,
                end_time=END_TIME,
                max_events=20,
                siem_validate_fn=live_siem_validate_fn,
                siem_search_fn=live_siem_search_fn,
            )
            assert v_res["compiler_verified"] is True, f"Accepted rule failed compiler: {v_res}"
            assert v_res["retrohunt_event_count"] > 0, f"Accepted rule matched 0 events: {v_res}"
            outcome_eval = v_res.get("outcome_evaluation") or {}
            assert outcome_eval.get("all_thresholds_satisfied") is True, (
                f"Accepted rule still has unsatisfied outcome thresholds: {v_res}"
            )
            accepted_rule_results.append(
                {
                    "rule_name": v_res["rule_name"],
                    "compiler_verified": v_res["compiler_verified"],
                    "retrohunt_event_count": v_res["retrohunt_event_count"],
                    "outcome_values": outcome_eval.get("outcome_values", {}),
                    "all_thresholds_satisfied": outcome_eval.get(
                        "all_thresholds_satisfied", True
                    ),
                }
            )
        print(
            f"[3/4] Accepted-Text Projection Verified: suggestion_count={inspected['suggestion_count']}, "
            f"remaining_static_defects=0, all 3 rules compiler_verified=True, retrohunt_event_count > 0, "
            f"and all_thresholds_satisfied=True"
        )

        # Step 4: Pass 2 Idempotency
        pass2 = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert pass2.get("status") == "success"
        assert pass2["yaral2_findings_count"] == 0, f"Expected 0 findings on Pass 2, got {pass2}"
        assert pass2["zero_hit_yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 5, (
            f"Expected 5 skipped existing suggestions on Pass 2, got {pass2['skipped_existing_suggestion_count']}"
        )
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0
        print(
            f"[4/4] Pass 2 Idempotency Verified: yaral2_findings_count={pass2['yaral2_findings_count']}, "
            f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
        )

        summary = {
            "cycle": 10,
            "horizon_id": "H17",
            "document_id": doc_id,
            "title": doc_title,
            "viewUrl": view_url,
            "char_count": pass2["char_count"],
            "pass1_yaral2_findings_count": 5,
            "pass1_zero_hit_yaral2_findings_count": 3,
            "pass1_comments_inserted": 5,
            "pass1_edits_applied": 5,
            "accepted_suggestion_count": inspected["suggestion_count"],
            "accepted_rule_results": accepted_rule_results,
            "pass2_yaral2_findings_count": pass2["yaral2_findings_count"],
            "pass2_skipped_existing_suggestion_count": pass2[
                "skipped_existing_suggestion_count"
            ],
        }
        print("\n=== SUMMARY JSON ===")
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            if ts is not None:
                try:
                    loop.run_until_complete(ts.close())
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
