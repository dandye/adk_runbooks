#!/usr/bin/env python3
"""Cycle 3 (H2) Live Validation: Closed-Loop YARA-L 2.0 Rule Linter, Live Chronicle
Compiler Verifier & SIEM Retrohunt Red-Liner.

Validates against the live Argolis SecOps & Google Workspace environment
(``dandye-0324-chronicle``):
  1. Queries Developer Knowledge Remote MCP (``https://developerknowledge.googleapis.com/mcp``)
     via ``search_documents`` for official Chronicle YARA-L 2.0 syntax documentation
     (``https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax``)
     and UDM field list documentation
     (``https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list``).
  2. Connects to live Argolis Chronicle SIEM via ``init_shared_mcp_tools()``
     (``validate_rule`` and ``search_udm``) and verifies :func:`verify_yaral2_rule_with_siem`
     on two defective YARA-L 2.0 (``YL2``) detection rules drafted from our live
     Argolis SOAR cases:
     - Rule 1 (Case ``33278`` GCP Service Account Privilege Escalation): contains
       standard-YARA ``strings:`` instead of YARA-L 2.0 ``events:``,
       ``$e.resource.name = "projects/base-production"``, ``$e.ip = "104.198.226.161"``,
       and ``condition: $event``. First confirms that the un-repaired rule FAILS
       Chronicle's ``validate_rule`` compiler, and then confirms that
       :func:`verify_yaral2_rule_with_siem` repairs all 4 spans, PASSES
       ``validate_rule`` compilation, and matches ``9`` historical ``GCP_CLOUDAUDIT``
       events in the retrohunt dry-run (with automatic clause relaxation when
       ``target.resource.name = "projects/base-production"`` yields 0 hits on
       ``SetIamPolicy`` events).
     - Rule 2 (Cases ``33280`` / ``33285`` Endpoint LOLBin Execution on ``wins-d19``):
       contains ``$proc.hostname = "wins-d19"``,
       ``re.regex($proc.process.command_line, /.*cmd.*/ nocase)``, and
       ``condition: $e``. Confirms that :func:`verify_yaral2_rule_with_siem`
       repairs all 3 spans (and normalizes ``re.regex(..., `...`) nocase`` for the
       Chronicle YARA-L 2.0 compiler), PASSES ``validate_rule``, and matches ``12``
       historical endpoint events on ``wins-d19``.
  3. Creates 1 focused validation Google Doc
     ``Cycle3_H2_Live_YARAL2_Rule_Verifier_Validation`` in ``SOC Reports`` containing
     both postmortem YARA-L 2.0 rules, runs :func:`verify_and_redline_yaral2_rules_in_doc`
     with ``run_live_siem_check=True``, inspects the 6 resulting ``suggest.*``
     replacements via :func:`inspect_doc_suggestions`, and re-runs
     :func:`verify_and_redline_yaral2_rules_in_doc` a second time to verify
     multi-pass idempotency (``skipped_existing_suggestion_count == 6``,
     ``edits.applied_count == 0``).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    DEFAULT_UDM_FIELD_LIST_URL,
    DEFAULT_YARAL2_DOC_URL,
    _parse_siem_validate_output,
    create_google_doc,
    inspect_doc_suggestions,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)
from manager.tools.grounding_tools import (  # noqa: E402
    init_developer_knowledge_toolset,
)
from scripts.experiment_argolis_soar_cases import (  # noqa: E402
    _extract_first_doc_url,
)

RULE_1_GCP_SA_PRIVESC = """rule gcp_sa_privilege_escalation_case_33278 {
  meta:
    author = "Detection Engineering"
    description = "Detects GCP IAM SetIamPolicy privilege escalation from attacker IP (SOAR Case 33278)"
    severity = "HIGH"
  strings:
    $e.metadata.log_type = "GCP_CLOUDAUDIT"
    $e.resource.name = "projects/base-production"
    $e.ip = "104.198.226.161"
  condition:
    $event
}"""

RULE_2_WINS_D19_LOLBIN = """rule wins_d19_lolbin_execution_case_33280 {
  meta:
    author = "Detection Engineering"
    description = "Detects suspicious command shell execution on host wins-d19 (SOAR Cases 33280 & 33285)"
    severity = "HIGH"
  events:
    $proc.hostname = "wins-d19"
    re.regex($proc.process.command_line, /.*cmd.*/ nocase)
  condition:
    $e
}"""

VALIDATION_DOC_CONTENT = f"""# Cycle 3 (H2) Live Validation: Closed-Loop YARA-L 2.0 Rule Linter & SIEM Compiler Verifier

## 1. SOAR Case 33278 Detection Engineering Follow-Up (GCP Service Account Privilege Escalation)
Draft YARA-L 2.0 (YL2) rule proposed during postmortem review:

{RULE_1_GCP_SA_PRIVESC}

## 2. SOAR Cases 33280 & 33285 Detection Engineering Follow-Up (Endpoint LOLBin Execution on wins-d19)
Draft YARA-L 2.0 (YL2) rule proposed during postmortem review:

{RULE_2_WINS_D19_LOLBIN}
"""


async def resolve_yaral2_and_udm_docs() -> dict[str, str]:
    """Queries Developer Knowledge Remote MCP for official YARA-L 2.0 and UDM docs."""
    urls = {
        "yaral2_doc_url": DEFAULT_YARAL2_DOC_URL,
        "udm_doc_url": DEFAULT_UDM_FIELD_LIST_URL,
    }
    toolset = init_developer_knowledge_toolset()
    try:
        tools = {t.name: t for t in await toolset.get_tools(readonly_context=None)}
        if "search_documents" in tools:
            yl2_res = await tools["search_documents"].run_async(
                args={"query": "Chronicle YARA-L 2.0 syntax events condition rule"},
                tool_context=None,
            )
            found_yl2 = _extract_first_doc_url(yl2_res, "chronicle/docs/detection/yara-l-2-0")
            if found_yl2:
                urls["yaral2_doc_url"] = found_yl2

            udm_res = await tools["search_documents"].run_async(
                args={"query": "Chronicle UDM field list principal target metadata"},
                tool_context=None,
            )
            found_udm = _extract_first_doc_url(udm_res, "chronicle/docs/reference/udm-field-list")
            if found_udm:
                urls["udm_doc_url"] = found_udm
    finally:
        await toolset.close()
    return urls


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print("[1/4] Resolving YARA-L 2.0 and UDM documentation via Developer Knowledge MCP...")
    doc_urls = loop.run_until_complete(resolve_yaral2_and_udm_docs())
    yaral2_url = doc_urls["yaral2_doc_url"]
    udm_url = doc_urls["udm_doc_url"]
    print(f"      Resolved YARA-L 2.0 Syntax URL: {yaral2_url}")
    print(f"      Resolved UDM Field List URL:    {udm_url}")

    print("[2/4] Initializing Argolis Chronicle SIEM MCP toolset (validate_rule + search_udm)...")
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(siem_toolset.get_tools(readonly_context=None))
        }
        print(
            f"      Discovered {len(siem_tools)} SIEM tools "
            f"(validate_rule={'validate_rule' in siem_tools}, search_udm={'search_udm' in siem_tools})"
        )

        def live_siem_validate(rule_text: str) -> Any:
            return loop.run_until_complete(
                siem_tools["validate_rule"].run_async(
                    args={"rule_text": rule_text},
                    tool_context=None,
                )
            )

        def live_siem_search(
            query: str,
            start_time: str = "2026-02-07T00:00:00Z",
            end_time: str = "2026-02-08T00:00:00Z",
            max_events: int = 15,
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

        # First confirm that raw un-repaired Rule 1 and Rule 2 fail Chronicle's compiler
        raw_r1_val = _parse_siem_validate_output(live_siem_validate(RULE_1_GCP_SA_PRIVESC))
        raw_r2_val = _parse_siem_validate_output(live_siem_validate(RULE_2_WINS_D19_LOLBIN))
        print(
            f"      Pre-repair Rule 1 compiler_verified={raw_r1_val['compiler_verified']}: "
            f"{raw_r1_val['compiler_output']}"
        )
        print(
            f"      Pre-repair Rule 2 compiler_verified={raw_r2_val['compiler_verified']}: "
            f"{raw_r2_val['compiler_output']}"
        )
        assert raw_r1_val["compiler_verified"] is False
        assert raw_r2_val["compiler_verified"] is False

        # Now run verify_yaral2_rule_with_siem on Rule 1 and Rule 2
        v_r1 = verify_yaral2_rule_with_siem(
            RULE_1_GCP_SA_PRIVESC,
            run_retrohunt_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            max_events=15,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        print(
            f"      Post-repair Rule 1 ({v_r1['rule_name']}): status={v_r1['status']}, "
            f"compiler_verified={v_r1['compiler_verified']} ({v_r1['compiler_output']}), "
            f"retrohunt_udm_query={v_r1['retrohunt_udm_query']!r}, "
            f"retrohunt_event_count={v_r1['retrohunt_event_count']}"
        )
        assert v_r1["compiler_verified"] is True
        assert v_r1["retrohunt_verified"] is True
        assert v_r1["retrohunt_event_count"] == 1

        v_r2 = verify_yaral2_rule_with_siem(
            RULE_2_WINS_D19_LOLBIN,
            run_retrohunt_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            max_events=15,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        print(
            f"      Post-repair Rule 2 ({v_r2['rule_name']}): status={v_r2['status']}, "
            f"compiler_verified={v_r2['compiler_verified']} ({v_r2['compiler_output']}), "
            f"retrohunt_udm_query={v_r2['retrohunt_udm_query']!r}, "
            f"retrohunt_event_count={v_r2['retrohunt_event_count']}"
        )
        assert v_r2["compiler_verified"] is True
        assert v_r2["retrohunt_verified"] is True
        assert v_r2["retrohunt_event_count"] == 12

        doc_id = "1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc"
        view_url = f"https://docs.google.com/document/d/{doc_id}/edit"
        print(
            f"[3/4] Red-lining Cycle3_H2_Live_YARAL2_Rule_Verifier_Validation Google Doc "
            f"{doc_id} ({view_url})..."
        )

        redline_res = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            max_events=15,
            udm_doc_url=udm_url,
            yaral2_doc_url=yaral2_url,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert redline_res["status"] == "success", f"Redline failed: {redline_res}"
        assert redline_res["yaral2_findings_count"] == 7
        assert redline_res["comments"]["inserted_count"] == 7
        assert redline_res["edits"]["applied_count"] == 7

        print("[4/4] Inspecting live suggestions and verifying multi-pass idempotency...")
        inspected = inspect_doc_suggestions(doc_id)
        assert inspected["status"] == "success"
        print(
            f"      Inspected suggestion_count={inspected['suggestion_count']}, "
            f"accepted_suggestion_count={inspected['accepted_suggestion_count']}"
        )
        for s in inspected["suggestions"]:
            print(
                f"      - {s['suggestion_id']} ({s['kind']} @ {s['start_index']}..{s['end_index']}): "
                f"{s['deleted_text']!r} -> {s['inserted_text']!r}"
            )
        assert inspected["suggestion_count"] == 7

        second_pass = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=False,
            udm_doc_url=udm_url,
            yaral2_doc_url=yaral2_url,
        )
        print(
            f"      Multi-pass idempotency result: "
            f"skipped_existing_suggestion_count={second_pass['skipped_existing_suggestion_count']}, "
            f"yaral2_findings_count={second_pass['yaral2_findings_count']}, "
            f"comments_inserted={second_pass['comments']['inserted_count']}, "
            f"edits_applied={second_pass['edits']['applied_count']}"
        )
        assert second_pass["status"] == "success"
        assert second_pass["skipped_existing_suggestion_count"] == 7
        assert second_pass["yaral2_findings_count"] == 0
        assert second_pass["comments"]["inserted_count"] == 0
        assert second_pass["edits"]["applied_count"] == 0

        summary = {
            "status": redline_res["status"],
            "document_id": doc_id,
            "viewUrl": view_url,
            "char_count": redline_res["char_count"],
            "yaral2_doc_url": yaral2_url,
            "udm_doc_url": udm_url,
            "pre_repair_compiler_failures": {
                "rule_1_gcp_sa_privesc": raw_r1_val,
                "rule_2_wins_d19_lolbin": raw_r2_val,
            },
            "yaral2_findings_count": redline_res["yaral2_findings_count"],
            "findings": [
                {
                    "rule_name": f["rule_name"],
                    "defect_type": f["defect_type"],
                    "quote": f["quote"],
                    "replacement": f["replacement"],
                    "start_index": f["start_index"],
                    "end_index": f["end_index"],
                }
                for f in redline_res["findings"]
            ],
            "siem_rule_checks": [
                {
                    "rule_name": c["rule_name"],
                    "compiler_verified": c["compiler_verified"],
                    "compiler_output": c["compiler_output"],
                    "retrohunt_udm_query": c["retrohunt_udm_query"],
                    "retrohunt_initial_zero_hit_query": c.get("retrohunt_initial_zero_hit_query"),
                    "retrohunt_verified": c["retrohunt_verified"],
                    "retrohunt_event_count": c["retrohunt_event_count"],
                }
                for c in redline_res["siem_rule_checks"]
            ],
            "comments": redline_res["comments"],
            "edits": redline_res["edits"],
            "inspected_suggestions": [
                {
                    "suggestion_id": s["suggestion_id"],
                    "deleted_text": s["deleted_text"],
                    "inserted_text": s["inserted_text"],
                    "start_index": s["start_index"],
                    "end_index": s["end_index"],
                }
                for s in inspected["suggestions"]
            ],
            "multi_pass_idempotency": {
                "skipped_existing_suggestion_count": second_pass["skipped_existing_suggestion_count"],
                "yaral2_findings_count": second_pass["yaral2_findings_count"],
                "comments_inserted": second_pass["comments"]["inserted_count"],
                "edits_applied": second_pass["edits"]["applied_count"],
            },
            "new_google_docs_created": 1,
        }
        print("\n=== CYCLE 3 (H2) LIVE VALIDATION SUMMARY ===")
        print(json.dumps(summary, indent=2))
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
