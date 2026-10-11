#!/usr/bin/env python3
"""Cycle 9 (H16) Live Validation Script: Multi-Event YARA-L 2.0 outcome: Risk-Score /
Aggregation Variable & Non-Existence (!$e2) Correlation Verifier in Google Docs.

Validates against live Argolis Chronicle SIEM (project `dandye-0324-chronicle`)
and live Google Docs API v1 / Google Drive API v3:

1. Direct SIEM Compiler + Non-Existence (!$e2) Set-Difference Retrohunt & Zero-Hit Positive Stream Pivot:
   - Rule 1 (`gcp_iam_unapproved_privilege_escalation` -- Case 33278 GCP IAM privilege
     escalation without a change-approval event): Contains invalid `outcome:` SQL/Splunk
     aggregation names (`avg(85)` -> `max`, `distinct_count($iam.metadata.id)` ->
     `count_distinct`), an unaggregated event field in `outcome:` with an unprefixed
     UDM field (`$target_resources = $iam.resource.name` ->
     `array_distinct($iam.target.resource.name)`), invalid condition negation syntax
     (`not $approval` -> `!$approval`), an undeclared outcome variable in a condition
     threshold comparison (`$hit_count >= 1` -> `$event_count >= 1`), and a zero-hit
     positive stream predicate (`$iam.target.resource.name = "projects/base-analytics"`
     -> `"projects/base-production"`).
   - Rule 2 (`wins_d19_lolbin_to_derpservice_outcome` -- Cases 33280/33285 `wins-d19`
     LOLBin -> DERPService multi-event correlation with `outcome:` risk score and
     aggregations): Contains invalid `outcome:` aggregation names (`average(90)` ->
     `max`, `count_unique($cmd.metadata.id)` -> `count_distinct`) and an unaggregated
     `outcome:` event field (`$service_cmds = $svc.target.process.command_line` ->
     `array_distinct($svc.target.process.command_line)`), while referencing valid
     `$cmd_count >= 1` in `condition:` (0 false positives on valid outcome variable).
   - Rule 3 (`gcp_iam_verified_non_existence_outcome_baseline` -- Valid non-existence
     and `outcome:` correlation control): Valid non-existence YARA-L 2.0 rule with
     `outcome:` (`max`, `count_distinct`, `array_distinct`) and
     `condition: $iam and !$approval and $event_count >= 1 and $risk_score >= 50`
     (must produce 0 false positives, compile cleanly, and match > 0 events via
     set-difference retrohunt).
2. Google Doc (`Cycle9_H16_Live_YARAL2_Outcome_and_NonExistence_Validation`):
   - Verifies Pass 1 staged 9 comments and 9 `writeMode="SUGGEST"` edits
     (`inspect_doc_suggestions` `suggestion_count == 9`).
   - Verifies all 3 rules in `accepted_text` compile cleanly in Chronicle SIEM
     (`compiler_verified=True`) and correlate `> 0` events across streams
     (`retrohunt_event_count > 0`).
   - Runs Pass 2 of `verify_and_redline_yaral2_rules_in_doc` on the same Google Doc
     to verify idempotency (`yaral2_findings_count == 0`,
     `skipped_existing_suggestion_count == 9`).
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
    diagnose_zero_hit_yaral2_rule,
    find_yaral2_rule_spans,
    inspect_doc_suggestions,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)

START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"
DEFAULT_CYCLE9_DOC_ID = "1Q6-KGbAfilD8hYmQNVdUSB2uherC2sHHrxmDXxMRqDs"

RULE_1_GCP_NON_EXISTENCE_OUTCOME = (
    "rule gcp_iam_unapproved_privilege_escalation {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Detects GCP IAM policy activity without an accompanying change-approval event"\n'
    '    severity = "CRITICAL"\n'
    "  events:\n"
    '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    $iam.target.resource.name = "projects/base-analytics"\n'
    "    $iam.principal.ip = $ip\n"
    '    $approval.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    $approval.target.resource.name = "projects/change-approval-system"\n'
    "    $approval.principal.ip = $ip\n"
    "  match:\n"
    "    $ip over 15m\n"
    "  outcome:\n"
    "    $risk_score = avg(85)\n"
    "    $event_count = distinct_count($iam.metadata.id)\n"
    "    $target_resources = $iam.resource.name\n"
    "  condition:\n"
    "    $iam and not $approval and $hit_count >= 1\n"
    "}"
)

RULE_2_WINS_D19_OUTCOME = (
    "rule wins_d19_lolbin_to_derpservice_outcome {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Correlates cmd.exe discovery with DERPService creation on wins-d19 with outcome risk score"\n'
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
    "    $risk_score = average(90)\n"
    "    $cmd_count = count_unique($cmd.metadata.id)\n"
    "    $service_cmds = $svc.target.process.command_line\n"
    "  condition:\n"
    "    $cmd and $svc and $cmd_count >= 1\n"
    "}"
)

RULE_3_GCP_NON_EXISTENCE_CONTROL = (
    "rule gcp_iam_verified_non_existence_outcome_baseline {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Verified non-existence and outcome aggregation control rule for GCP IAM"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    $iam.target.resource.name = "projects/base-production"\n'
    "    $iam.principal.ip = $ip\n"
    '    $approval.metadata.log_type = "GCP_CLOUDAUDIT"\n'
    '    $approval.target.resource.name = "projects/change-approval-system"\n'
    "    $approval.principal.ip = $ip\n"
    "  match:\n"
    "    $ip over 15m\n"
    "  outcome:\n"
    "    $risk_score = max(85)\n"
    "    $event_count = count_distinct($iam.metadata.id)\n"
    "    $target_resources = array_distinct($iam.target.resource.name)\n"
    "  condition:\n"
    "    $iam and !$approval and $event_count >= 1 and $risk_score >= 50\n"
    "}"
)


def main() -> int:
    print(
        "=== Cycle 9 (H16): Live YARA-L 2.0 outcome: Aggregation & "
        "Non-Existence (!$e2) Correlation Validation ==="
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

        # Step 1: Direct SIEM validation on the 3 YARA-L 2.0 outcome & non-existence rules
        v1 = verify_yaral2_rule_with_siem(
            RULE_1_GCP_NON_EXISTENCE_OUTCOME,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v1["compiler_verified"] is True, f"Rule 1 failed compiler: {v1}"
        assert len(v1["findings"]) == 5, (
            f"Expected 5 static findings on Rule 1, got {len(v1['findings'])}: {v1['findings']}"
        )
        diag1 = v1.get("zero_hit_diagnosis") or {}
        assert diag1.get("diagnosis_class") == "value_format_mismatch", (
            f"Rule 1 zero-hit diagnosis failed: {diag1}"
        )
        assert diag1.get("pivot_compiler_verified") is True, (
            f"Rule 1 pivot failed compiler: {diag1}"
        )
        assert int(diag1.get("pivot_event_count") or 0) > 0, (
            f"Rule 1 pivot correlated 0 events: {diag1}"
        )

        v2 = verify_yaral2_rule_with_siem(
            RULE_2_WINS_D19_OUTCOME,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v2["compiler_verified"] is True, f"Rule 2 failed compiler: {v2}"
        assert len(v2["findings"]) == 3, (
            f"Expected 3 static findings on Rule 2, got {len(v2['findings'])}: {v2['findings']}"
        )
        assert v2["retrohunt_event_count"] > 0, f"Rule 2 correlated 0 events: {v2}"

        v3 = verify_yaral2_rule_with_siem(
            RULE_3_GCP_NON_EXISTENCE_CONTROL,
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
        assert v3["retrohunt_event_count"] > 0, f"Rule 3 correlated 0 events: {v3}"
        r3_retro = v3.get("multi_event_retrohunt") or {}
        assert r3_retro.get("is_non_existence") is True
        print(
            f"[1/4] Direct SIEM Outcome & Non-Existence Verification Passed:\n"
            f"      - Rule 1 ({v1['rule_name']}): 5 static findings + 1 zero-hit positive stream pivot "
            f"('{diag1.get('recommended_yaral2_predicate')}') -> pivot_compiler_verified={diag1.get('pivot_compiler_verified')}, "
            f"shared_join_values={diag1.get('shared_join_values')}, pivot_event_count={diag1.get('pivot_event_count')}\n"
            f"      - Rule 2 ({v2['rule_name']}): 3 static outcome findings -> compiler_verified={v2['compiler_verified']}, "
            f"shared_join_values={(v2.get('multi_event_retrohunt') or {}).get('shared_join_values')}, "
            f"correlated_event_count={v2['retrohunt_event_count']}\n"
            f"      - Rule 3 ({v3['rule_name']}): 0 findings (control), compiler_verified={v3['compiler_verified']}, "
            f"is_non_existence={r3_retro.get('is_non_existence')}, "
            f"shared_join_values={r3_retro.get('shared_join_values')}, "
            f"correlated_event_count={v3['retrohunt_event_count']}"
        )

        clear_doc_index_cache()
        doc_title = "Cycle9_H16_Live_YARAL2_Outcome_and_NonExistence_Validation"
        doc_id = os.environ.get("CYCLE9_DOC_ID", DEFAULT_CYCLE9_DOC_ID)
        create_new = os.environ.get("CREATE_NEW_DOC") == "1" or not doc_id

        if create_new:
            markdown_content = (
                "# Cycle 9 (H16): Multi-Event YARA-L 2.0 outcome: & Non-Existence (!$e2) Rules\n\n"
                "## Rule 1: Case 33278 GCP Unapproved IAM Privilege Escalation (Non-Existence + Outcome)\n\n"
                f"{RULE_1_GCP_NON_EXISTENCE_OUTCOME}\n\n"
                "## Rule 2: Cases 33280/33285 Host wins-d19 LOLBin to DERPService Outcome Aggregations\n\n"
                + RULE_2_WINS_D19_OUTCOME.replace("`", "\\`")
                + "\n\n"
                "## Rule 3: Valid Non-Existence and Outcome Aggregation Control\n\n"
                f"{RULE_3_GCP_NON_EXISTENCE_CONTROL}\n"
            )
            create_res = create_google_doc(
                title=doc_title,
                content=markdown_content,
                folder_id=folder_id,
            )
            assert create_res.get("status") == "success", f"create_google_doc failed: {create_res}"
            doc_id = str(create_res["document_id"])
            view_url = str(create_res.get("viewUrl") or f"https://docs.google.com/document/d/{doc_id}/edit")
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
            assert pass1["yaral2_findings_count"] == 9, f"Expected 9 findings in Pass 1, got {pass1}"
            assert pass1["zero_hit_yaral2_findings_count"] == 1
            assert pass1["skipped_existing_suggestion_count"] == 0
            assert pass1["comments"]["inserted_count"] == 9
            assert pass1["edits"]["applied_count"] == 9
        else:
            view_url = f"https://docs.google.com/document/d/{doc_id}/edit"
            print(
                f"[2/4] Reusing Cycle 9 Validation Google Doc (Pass 1 already applied 9 comments & 9 Suggested Edits): {doc_id}"
            )

        # Step 3: Inspect pending suggestions and verify accepted_text rules compile and correlate > 0 events
        inspected = inspect_doc_suggestions(doc_id)
        assert inspected.get("status") == "success", f"inspect_doc_suggestions failed: {inspected}"
        assert inspected["suggestion_count"] == 9, (
            f"Expected 9 pending suggestions on {doc_id}, got {inspected['suggestion_count']}"
        )
        accepted_text = str(inspected["accepted_text"])

        accepted_map = _build_utf16_index_map(accepted_text)
        _, _, remaining_static = find_yaral2_rule_spans(accepted_text, accepted_map)
        assert len(remaining_static) == 0, f"Expected 0 remaining static defects, got {remaining_static}"

        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 3
        accepted_rule_results: list[dict[str, Any]] = []
        for blk in accepted_blocks:
            v_res = verify_yaral2_rule_with_siem(
                str(blk["rule_text"]),
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=False,
                start_time=START_TIME,
                end_time=END_TIME,
                max_events=20,
                siem_validate_fn=live_siem_validate_fn,
                siem_search_fn=live_siem_search_fn,
            )
            assert v_res["compiler_verified"] is True, f"Accepted rule failed compiler: {v_res}"
            assert v_res["retrohunt_event_count"] > 0, f"Accepted rule matched 0 events: {v_res}"
            retro = v_res.get("multi_event_retrohunt") or {}
            accepted_rule_results.append(
                {
                    "rule_name": v_res["rule_name"],
                    "compiler_verified": v_res["compiler_verified"],
                    "is_non_existence": retro.get("is_non_existence", False),
                    "correlated_event_count": v_res["retrohunt_event_count"],
                    "shared_join_values": retro.get("shared_join_values", []),
                    "suppressed_join_values": retro.get("suppressed_join_values", []),
                    "per_event_counts": retro.get("per_event_counts", {}),
                }
            )
        print(
            f"[3/4] Accepted-Text Projection Verified: suggestion_count={inspected['suggestion_count']}, "
            f"remaining_static_defects=0, all 3 rules compiler_verified=True and correlated_event_count > 0"
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
        assert pass2["skipped_existing_suggestion_count"] == 9, (
            f"Expected 9 skipped existing suggestions on Pass 2, got {pass2['skipped_existing_suggestion_count']}"
        )
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0
        print(
            f"[4/4] Pass 2 Idempotency Verified: yaral2_findings_count={pass2['yaral2_findings_count']}, "
            f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
        )

        summary = {
            "cycle": 9,
            "horizon_id": "H16",
            "document_id": doc_id,
            "title": doc_title,
            "viewUrl": view_url,
            "char_count": pass2["char_count"],
            "pass1_yaral2_findings_count": 9,
            "pass1_zero_hit_yaral2_findings_count": 1,
            "pass1_comments_inserted": 9,
            "pass1_edits_applied": 9,
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
