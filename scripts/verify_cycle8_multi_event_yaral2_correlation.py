#!/usr/bin/env python3
"""Cycle 8 (H15) Live Validation Script: Multi-Event YARA-L 2.0 Correlation Join,
Match-Window & Per-Stream SIEM Retrohunt Verifier Inside Google Docs.

Validates against live Argolis Chronicle SIEM (project `dandye-0324-chronicle`)
and live Google Docs API v1 / Google Drive API v3:

1. Direct SIEM Compiler + Per-Stream Multi-Event Correlation & Zero-Hit Join Pivot:
   - Rule 1 (`gcp_iam_to_cloudsql_destructive_chain` -- Case 33278 GCP privilege
     escalation -> Cloud SQL activity): Contains standard YARA `strings:` instead
     of YARA-L 2.0 `events:`, unprefixed UDM fields (`$iam.log_type`,
     `$iam.resource.name`, `$sql.log_type`), a cross-event join semantic type
     contradiction (`$iam.principal.ip = $ip` vs `$sql.principal.hostname = $ip`),
     an undeclared `match:` placeholder variable and invalid window syntax
     (`match: $src_ip within 15 minutes`), and a multi-event condition variable
     mismatch (`condition: $iam and $sql_event`).
   - Rule 2 (`wins_d19_lolbin_to_derpservice_correlation` -- Cases 33280/33285
     `wins-d19` LOLBin -> DERPService chain): Syntactically valid multi-event
     YARA-L 2.0 rule that compiles cleanly and matches events on both streams
     individually, but returns 0 shared join keys because `$svc` bound
     `$svc.target.hostname = $host` instead of `$svc.principal.hostname = $host`
     (`cross_event_join_entity_role_swap`).
   - Rule 3 (`wins_d19_verified_multi_event_baseline` -- Valid multi-event
     YARA-L 2.0 correlation control): Valid multi-event YARA-L 2.0 rule binding
     `$e1.principal.hostname = $host` and `$e2.principal.hostname = $host` with
     `match: $host over 15m` and `condition: $e1 and $e2` (must remain untouched).
2. Google Doc (`Cycle8_H15_Live_Multi_Event_YARAL2_Correlation_Validation`,
   `1JudnoRtmpGPGTQbOa2mZdDiXgAwcCMDxnQ8IU672lR8`):
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
DEFAULT_CYCLE8_DOC_ID = "1JudnoRtmpGPGTQbOa2mZdDiXgAwcCMDxnQ8IU672lR8"

RULE_1_GCP_CORRELATION = (
    "rule gcp_iam_to_cloudsql_destructive_chain {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Correlates GCP IAM policy modification with Cloud SQL activity by source IP"\n'
    '    severity = "CRITICAL"\n'
    "  strings:\n"
    '    $iam.log_type = "GCP_CLOUDAUDIT"\n'
    '    $iam.resource.name = "projects/base-production"\n'
    "    $iam.principal.ip = $ip\n"
    '    $sql.log_type = "GCP_CLOUDAUDIT"\n'
    "    $sql.principal.hostname = $ip\n"
    "  match:\n"
    "    $src_ip within 15 minutes\n"
    "  condition:\n"
    "    $iam and $sql_event\n"
    "}"
)

RULE_2_WINS_D19_JOIN_ROLE_SWAP = (
    "rule wins_d19_lolbin_to_derpservice_correlation {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Correlates cmd.exe discovery with DERPService creation on wins-d19"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $cmd.principal.hostname = "wins-d19"\n'
    "    re.regex($cmd.target.process.command_line, `.*cmd.*`) nocase\n"
    "    $cmd.principal.hostname = $host\n"
    "    re.regex($svc.target.process.command_line, `.*DERPService.*`) nocase\n"
    "    $svc.target.hostname = $host\n"
    "  match:\n"
    "    $host over 15m\n"
    "  condition:\n"
    "    $cmd and $svc\n"
    "}"
)

RULE_3_WINS_D19_CONTROL = (
    "rule wins_d19_verified_multi_event_baseline {\n"
    "  meta:\n"
    '    author = "SecOps Autonomous Agent"\n'
    '    description = "Verified multi-event correlation control on wins-d19"\n'
    '    severity = "HIGH"\n'
    "  events:\n"
    '    $e1.principal.hostname = "wins-d19"\n'
    "    re.regex($e1.target.process.command_line, `.*cmd.*`) nocase\n"
    "    $e1.principal.hostname = $host\n"
    "    re.regex($e2.target.process.command_line, `.*DERPService.*`) nocase\n"
    "    $e2.principal.hostname = $host\n"
    "  match:\n"
    "    $host over 15m\n"
    "  condition:\n"
    "    $e1 and $e2\n"
    "}"
)


def main() -> int:
    print(
        "=== Cycle 8 (H15): Live Multi-Event YARA-L 2.0 Correlation Join, "
        "Match-Window & Per-Stream SIEM Retrohunt Validation ==="
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

        # Step 1: Direct SIEM validation on the 3 multi-event YARA-L 2.0 rules
        v1 = verify_yaral2_rule_with_siem(
            RULE_1_GCP_CORRELATION,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v1["compiler_verified"] is True, f"Rule 1 failed compiler: {v1}"
        assert len(v1["findings"]) == 8, f"Expected 8 static findings on Rule 1, got {len(v1['findings'])}"
        assert v1["retrohunt_event_count"] > 0, f"Rule 1 correlated 0 events: {v1}"

        d2 = diagnose_zero_hit_yaral2_rule(
            RULE_2_WINS_D19_JOIN_ROLE_SWAP,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert d2["diagnosis_class"] == "cross_event_join_entity_role_swap", f"Rule 2 diagnosis failed: {d2}"
        assert d2["recommended_span_replacement"] == "$svc.principal.hostname"
        assert d2["shared_join_values"] == ["wins-d19"]
        assert d2["pivot_compiler_verified"] is True
        assert d2["pivot_event_count"] > 0

        v3 = verify_yaral2_rule_with_siem(
            RULE_3_WINS_D19_CONTROL,
            run_retrohunt_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert v3["compiler_verified"] is True
        assert len(v3["findings"]) == 0
        assert v3["retrohunt_event_count"] > 0
        print(
            f"[1/4] Direct SIEM Multi-Event Verification Passed:\n"
            f"      - Rule 1 ({v1['rule_name']}): 8 static findings -> compiler_verified={v1['compiler_verified']}, "
            f"shared_join_values={(v1.get('multi_event_retrohunt') or {}).get('shared_join_values')}, "
            f"correlated_event_count={v1['retrohunt_event_count']}\n"
            f"      - Rule 2 ({d2['rule_name']}): diagnosis={d2['diagnosis_class']}, "
            f"pivot='{d2['recommended_yaral2_predicate']}', pivot_compiler_verified={d2['pivot_compiler_verified']}, "
            f"shared_join_values={d2['shared_join_values']}, pivot_event_count={d2['pivot_event_count']}\n"
            f"      - Rule 3 ({v3['rule_name']}): 0 findings, compiler_verified={v3['compiler_verified']}, "
            f"correlated_event_count={v3['retrohunt_event_count']}"
        )

        clear_doc_index_cache()
        doc_title = "Cycle8_H15_Live_Multi_Event_YARAL2_Correlation_Validation"
        doc_id = os.environ.get("CYCLE8_DOC_ID", DEFAULT_CYCLE8_DOC_ID)
        create_new = os.environ.get("CREATE_NEW_DOC") == "1" or not doc_id

        if create_new:
            markdown_content = (
                "# Cycle 8 (H15): Multi-Event YARA-L 2.0 Correlation Rules\n\n"
                "## Rule 1: Case 33278 GCP IAM Privilege Escalation to Cloud SQL Deletion\n\n"
                f"{RULE_1_GCP_CORRELATION}\n\n"
                "## Rule 2: Cases 33280/33285 Host wins-d19 LOLBin to DERPService Chain\n\n"
                + RULE_2_WINS_D19_JOIN_ROLE_SWAP.replace("`", "\\`")
                + "\n\n"
                "## Rule 3: Valid Multi-Event YARA-L 2.0 Correlation Control\n\n"
                + RULE_3_WINS_D19_CONTROL.replace("`", "\\`")
                + "\n"
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
            assert pass1["yaral2_findings_count"] == 9
            assert pass1["zero_hit_yaral2_findings_count"] == 1
            assert pass1["skipped_existing_suggestion_count"] == 0
            assert pass1["comments"]["inserted_count"] == 9
            assert pass1["edits"]["applied_count"] == 9
        else:
            view_url = f"https://docs.google.com/document/d/{doc_id}/edit"
            print(
                f"[2/4] Reusing Cycle 8 Validation Google Doc (Pass 1 already applied 9 comments & 9 Suggested Edits): {doc_id}"
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
            accepted_rule_results.append(
                {
                    "rule_name": v_res["rule_name"],
                    "compiler_verified": v_res["compiler_verified"],
                    "correlated_event_count": v_res["retrohunt_event_count"],
                    "shared_join_values": (v_res.get("multi_event_retrohunt") or {}).get(
                        "shared_join_values", []
                    ),
                    "per_event_counts": (v_res.get("multi_event_retrohunt") or {}).get(
                        "per_event_counts", {}
                    ),
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
        assert pass2["yaral2_findings_count"] == 0
        assert pass2["zero_hit_yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 9
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0
        print(
            f"[4/4] Pass 2 Idempotency Verified: yaral2_findings_count={pass2['yaral2_findings_count']}, "
            f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
        )

        summary = {
            "cycle": 8,
            "horizon_id": "H15",
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
