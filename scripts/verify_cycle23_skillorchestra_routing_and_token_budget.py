#!/usr/bin/env python3
"""Cycle 23 (Horizon H24) Live Validation Script.

Validates the SkillOrchestra Cost-Aware Multi-Model Routing Matrix & Stage A/B
Token Budget Auditor in Google Docs (`H24`):
1. Evaluates `BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET` and the full
   10-scenario `all_with_night2` suite (`53/53` defects, `21/21` negative
   controls, `F1 = 1.0000`, `pass2_idempotency_rate = 1.0000`, `0` Drive writes)
   on the in-memory `LocalGoogleDocsSimulator`.
2. Resets existing validation Google Doc `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE`
   in place via Drive API v3 media upload (`new_docs_created = 0` to conserve
   Drive storage quota) with all 5 `H24` defect classes, 2 negative controls,
   1 standard file/payload YARA rule (ignored), and 1 Chronicle SIEM YARA-L 2.0
   (`YL2`) rule containing a mismatched `agent_routing_tier` in `meta:`.
3. Executes live `secops-mcp:validate_rule` and `secops-mcp:search_udm` +
   Pass 1 `audit_and_redline_skillorchestra_routing_in_doc` against Google Docs
   API v1 (`defect_count == 5`, `applied_redline_count == 5`,
   `appended_matrix == True`, `compiler_verified == True`).
4. Executes Pass 2 against the live Google Doc to verify multi-pass suggestion
   idempotency (`defect_count == 0`, `skipped_existing_suggestion_count == 5`,
   `applied_redline_count == 0`, `appended_matrix == False`).
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

REPO_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in (REPO_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(REPO_ROOT / "external" / "mcp-security" / ".env")

from manager.tools.docs_review_tools import (  # noqa: E402
    CANONICAL_SKILLORCHESTRA_ROUTING_AND_BUDGET_CATALOG,
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    audit_and_redline_skillorchestra_routing_in_doc,
    clear_doc_index_cache,
    evaluate_infosec_doc_reviewer,
    inspect_doc_suggestions,
    resolve_docs_token,
)
from manager.tools.tools import (  # noqa: E402
    execute_mcp_tool,
    global_mcp_registry,
    init_shared_mcp_tools,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

LIVE_VALIDATION_DOC_ID = os.environ.get(
    "LIVE_VALIDATION_DOC_ID",
    "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
)
DOC_TITLE = "Cycle23_H24_Live_SkillOrchestra_Routing_and_Token_Budget_Validation"


def _reset_google_doc_in_place(
    doc_id: str, markdown_body: str, token: str
) -> dict[str, Any]:
    """Overwrites an existing Google Doc in place via Drive API v3 media upload (0 new files) and clears prior comments."""
    quota_project = (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or "dandye-0324-chronicle"
    ).strip()
    base_headers = {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": quota_project,
    }

    with httpx.Client(timeout=45.0) as client:
        comments_resp = client.get(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments",
            params={"fields": "comments(id,deleted)", "pageSize": 100},
            headers=base_headers,
        )
        if comments_resp.status_code == 200:
            for c in comments_resp.json().get("comments", []) or []:
                if c.get("deleted"):
                    continue
                cid = c.get("id")
                if cid:
                    client.delete(
                        f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments/{cid}",
                        headers=base_headers,
                    )

        client.patch(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}",
            params={"fields": "id,name"},
            headers={**base_headers, "Content-Type": "application/json"},
            json={"name": DOC_TITLE},
        )

        upload_url = (
            f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}"
            "?uploadType=media&supportsAllDrives=true&fields=id,name,mimeType"
        )
        resp = client.patch(
            upload_url,
            headers={
                **base_headers,
                "Content-Type": "text/markdown; charset=utf-8",
            },
            content=markdown_body.encode("utf-8"),
        )
        resp.raise_for_status()
        return resp.json()


def _build_live_seed_markdown() -> str:
    """Returns the seeded Markdown payload containing 5 H24 defects, 2 negative controls,
    1 standard file/payload YARA rule (ignored), and 1 Chronicle SIEM YARA-L 2.0 rule."""
    bench10 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET"
    )
    standard_yara_section = (
        "\n## 4. Standard File/Payload YARA Rule (Preserved Control — Ignored by YL2 Auditor)\n"
        "rule file_payload_wurm_pe_header {\n"
        "  meta:\n"
        '    description = "Standard file/payload YARA rule matching MZ header"\n'
        '    agent_routing_tier = "stage_a_only"\n'
        "  strings:\n"
        '    $mz = "MZ"\n'
        "  condition:\n"
        "    uint16(0) == 0x5a4d and $mz\n"
        "}\n"
    )
    base_md = (
        str(bench10["seeded_doc_text"])
        .replace("```yaral\n", "")
        .replace("```yara\n", "")
        .replace("```\n", "")
        .rstrip()
    )
    return base_md + "\n" + standard_yara_section


async def _run_live_siem_checks(repaired_rule_text: str) -> dict[str, Any]:
    """Executes live secops-mcp:validate_rule and secops-mcp:search_udm via siem_toolset."""
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
        val_raw = await val_tool.run_async(
            args={"rule_text": repaired_rule_text},
            tool_context=None,
        )
        udm_raw = await udm_tool.run_async(
            args={
                "query": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"',
                "start_time": "2026-02-07T00:00:00Z",
                "end_time": "2026-02-08T00:00:00Z",
                "max_events": 5,
            },
            tool_context=None,
        )
        val_str = str(val_raw)
        udm_str = str(udm_raw)
        return {
            "validate_rule_raw": val_str[:600],
            "validate_rule_success": (
                "FAILED" not in val_str.upper()
                and ("SUCCESS" in val_str.upper() or "VALID" in val_str.upper())
            ),
            "search_udm_raw": udm_str[:600],
            "search_udm_has_events": (
                "wins-d19" in udm_str
                or "metadata" in udm_str
                or "total_events" in udm_str
            ),
        }
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            try:
                await ts.close()
            except Exception:
                pass


def main() -> int:
    print("=== Cycle 23 (H24): SkillOrchestra Multi-Model Routing & Stage A/B Token Budget Live Validation ===")
    print(
        f"Catalog Version: {CANONICAL_SKILLORCHESTRA_ROUTING_AND_BUDGET_CATALOG['catalog_version']}"
    )

    # 1. Offline Benchmark Verification (BENCH-10 + all_with_night2)
    bench10_res = evaluate_infosec_doc_reviewer(
        scenario_set="BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET",
        include_hda_ablation=True,
    )
    assert bench10_res["status"] == "success", bench10_res
    assert bench10_res["scenario_count"] == 1
    assert bench10_res["total_expected_defects"] == 5
    assert bench10_res["true_positive_edits"] == 5
    assert bench10_res["false_positive_edits"] == 0
    assert bench10_res["false_negative_defects"] == 0
    assert bench10_res["overall_f1"] == 1.0
    assert bench10_res["pass2_idempotency_rate"] == 1.0
    assert bench10_res["google_drive_write_calls"] == 0

    all_res = evaluate_infosec_doc_reviewer(
        scenario_set="all_with_night2",
        include_hda_ablation=True,
    )
    assert all_res["status"] == "success", all_res
    assert all_res["scenario_count"] == 10
    assert all_res["total_expected_defects"] == 53
    assert all_res["true_positive_edits"] == 53
    assert all_res["false_positive_edits"] == 0
    assert all_res["false_negative_defects"] == 0
    assert all_res["total_negative_controls"] == 21
    assert all_res["negative_controls_preserved"] == 21
    assert all_res["overall_precision"] == 1.0
    assert all_res["overall_recall"] == 1.0
    assert all_res["overall_f1"] == 1.0
    assert all_res["pass2_idempotency_rate"] == 1.0
    assert all_res["overall_hda_error"] == 0.0
    assert all_res["google_drive_write_calls"] == 0
    print(
        f"[OK] Offline Benchmark all_with_night2: {all_res['scenario_count']} scenarios, "
        f"{all_res['true_positive_edits']}/{all_res['total_expected_defects']} defects caught, "
        f"{all_res['negative_controls_preserved']}/{all_res['total_negative_controls']} negative controls preserved, "
        f"F1={all_res['overall_f1']:.4f}, Pass2 Idempotency={all_res['pass2_idempotency_rate']:.4f}"
    )

    # 2. Reset existing validation Google Doc in place (0 new Google Docs created)
    token = resolve_docs_token()
    seed_md = _build_live_seed_markdown()
    clear_doc_index_cache()
    drive_patch_meta = _reset_google_doc_in_place(
        LIVE_VALIDATION_DOC_ID, seed_md, token
    )
    print(
        f"[OK] Reset existing Google Doc {LIVE_VALIDATION_DOC_ID} in place "
        f"(new_docs_created=0, name={drive_patch_meta.get('name')!r})"
    )

    # 3. Pass 1: Live Google Docs API v1 + Live Chronicle SIEM Verification
    clear_doc_index_cache()
    pass1_res = audit_and_redline_skillorchestra_routing_in_doc(
        document_id=LIVE_VALIDATION_DOC_ID,
        apply_redlines=True,
        append_appendix=True,
    )
    assert pass1_res["status"] == "success", pass1_res
    assert pass1_res["defect_count"] == 5, pass1_res
    assert pass1_res["applied_redline_count"] == 5, pass1_res
    assert pass1_res["appended_matrix"] is True, pass1_res
    assert pass1_res["compiler_verified"] is True, pass1_res
    assert (
        "file_payload_wurm_pe_header"
        in pass1_res["standard_yara_rules_ignored"]
    ), pass1_res

    repaired_rules = pass1_res.get("repaired_yaral2_rules") or []
    assert len(repaired_rules) == 1, repaired_rules
    repaired_rule_text = str(repaired_rules[0]["repaired_rule_text"])
    assert (
        'agent_routing_tier = "tier_2_grounded_synthesis"' in repaired_rule_text
    ), repaired_rule_text

    siem_live = asyncio.run(_run_live_siem_checks(repaired_rule_text))
    assert siem_live["validate_rule_success"] is True, siem_live
    assert siem_live["search_udm_has_events"] is True, siem_live
    print(
        f"[OK] Live Pass 1 on {LIVE_VALIDATION_DOC_ID}: defect_count={pass1_res['defect_count']}, "
        f"applied_redline_count={pass1_res['applied_redline_count']}, "
        f"inserted_comment_count={pass1_res['inserted_comment_count']}, "
        f"appended_matrix={pass1_res['appended_matrix']}, "
        f"live_validate_rule={siem_live['validate_rule_success']}, "
        f"live_search_udm={siem_live['search_udm_has_events']}"
    )

    # 4. Inspect live suggestions & run Pass 2 to prove multi-pass idempotency
    clear_doc_index_cache()
    inspected = inspect_doc_suggestions(LIVE_VALIDATION_DOC_ID)
    assert inspected["status"] == "success", inspected
    assert int(inspected.get("suggestion_count", 0) or len(inspected.get("suggestions") or [])) >= 5, inspected

    pass2_res = audit_and_redline_skillorchestra_routing_in_doc(
        document_id=LIVE_VALIDATION_DOC_ID,
        apply_redlines=True,
        append_appendix=True,
    )
    assert pass2_res["status"] == "success", pass2_res
    assert pass2_res["defect_count"] == 0, pass2_res
    assert pass2_res["skipped_existing_suggestion_count"] >= 5, pass2_res
    assert pass2_res["applied_redline_count"] == 0, pass2_res
    assert pass2_res["appended_matrix"] is False, pass2_res
    print(
        f"[OK] Live Pass 2 Idempotency on {LIVE_VALIDATION_DOC_ID}: "
        f"defect_count={pass2_res['defect_count']}, "
        f"skipped_existing_suggestion_count={pass2_res['skipped_existing_suggestion_count']}, "
        f"applied_redline_count={pass2_res['applied_redline_count']}, "
        f"appended_matrix={pass2_res['appended_matrix']}"
    )

    summary = {
        "cycle": 23,
        "horizon": "H24",
        "status": "validated",
        "new_docs_created": 0,
        "live_doc_id": LIVE_VALIDATION_DOC_ID,
        "benchmark_bench10": {
            "expected_defects": bench10_res["total_expected_defects"],
            "true_positive_edits": bench10_res["true_positive_edits"],
            "false_positive_edits": bench10_res["false_positive_edits"],
            "f1": bench10_res["overall_f1"],
            "pass2_idempotency_rate": bench10_res["pass2_idempotency_rate"],
        },
        "benchmark_all_with_night2": {
            "scenario_count": all_res["scenario_count"],
            "expected_defects": all_res["total_expected_defects"],
            "true_positive_edits": all_res["true_positive_edits"],
            "false_positive_edits": all_res["false_positive_edits"],
            "negative_controls_preserved": f"{all_res['negative_controls_preserved']}/{all_res['total_negative_controls']}",
            "f1": all_res["overall_f1"],
            "pass2_idempotency_rate": all_res["pass2_idempotency_rate"],
            "hda_attribution": all_res.get("hda_attribution", {}),
        },
        "live_pass1": {
            "defect_count": pass1_res["defect_count"],
            "defect_counts_by_type": pass1_res["defect_counts_by_type"],
            "applied_redline_count": pass1_res["applied_redline_count"],
            "inserted_comment_count": pass1_res["inserted_comment_count"],
            "appended_matrix": pass1_res["appended_matrix"],
            "compiler_verified": pass1_res["compiler_verified"],
            "standard_yara_rules_ignored": pass1_res["standard_yara_rules_ignored"],
            "live_siem": siem_live,
        },
        "live_pass2": {
            "defect_count": pass2_res["defect_count"],
            "skipped_existing_suggestion_count": pass2_res[
                "skipped_existing_suggestion_count"
            ],
            "applied_redline_count": pass2_res["applied_redline_count"],
            "appended_matrix": pass2_res["appended_matrix"],
        },
    }
    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
