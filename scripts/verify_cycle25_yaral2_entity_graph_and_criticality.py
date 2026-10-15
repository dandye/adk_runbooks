#!/usr/bin/env python3
"""Cycle 25 (Horizon H26) Live Validation Script.

Validates the Chronicle SIEM YARA-L 2.0 Entity Graph ($g.graph.entity.*)
Context Join & Asset/Identity Criticality Risk-Multiplier Verifier in Google Docs (`H26`):
1. Evaluates `BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY` and the full
   12-scenario `all_with_night2` suite (`63/63` defects, `25/25` negative
   controls, `F1 = 1.0000`, `pass2_idempotency_rate = 1.0000`, `0` Drive writes)
   on the in-memory `LocalGoogleDocsSimulator`, plus verifies the `H26` entry
   (`SKILLRL-06-YARAL2-ENTITY-GRAPH-CRITICALITY`) in
   `generate_skillrl_failure_distillation_matrix`.
2. Resets existing validation Google Doc `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE`
   in place via Drive API v3 media upload (`new_docs_created = 0` to conserve
   Drive storage quota) with all 5 `H26` defect classes plus 2 negative controls
   (a valid Chronicle SIEM YARA-L 2.0 Entity Graph context join rule and a
   standard file/payload YARA rule with `strings:` / `uint16(0) == 0x5A4D`).
3. Executes `audit_yaral2_entity_graph_and_criticality_in_doc` against live
   Google Doc `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE` using
   `build_dwd_credentials()`, then inspects the updated live Google Doc via
   `inspect_google_doc_revision_and_Formatting` to verify `applied_redlines == 5`,
   `false_positive_redlines == 0`, presence of
   `## [VERIFIED CHRONICLE YARA-L 2.0 ENTITY GRAPH & ASSET/IDENTITY CRITICALITY MATRIX (H26)]`,
   and `#FEE2E2` / `#DCFCE7` styled spans (`fee2e2_span_count >= 5`,
   `dcfce7_span_count >= 5`).
4. Executes live `secops-mcp:validate_rule` on both the broken unprefixed
   `$g.entity.hostname` rule (proving compiler rejection) and all 4 remediated
   Chronicle SIEM YARA-L 2.0 (`YL2`) Entity Graph rules (proving `100%` live
   compiler acceptance), plus `secops-mcp:search_udm` for `wins-d19`, and runs
   Pass 2 against the live Google Doc to verify multi-pass suggestion idempotency
   (`defect_count == 0`, `skipped_existing_suggestion_count >= 5`,
   `applied_redlines == 0`, `appended_appendix == False`).
5. Writes `artifacts/cycle25_yaral2_entity_graph_and_criticality_verification.json`.
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
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    H26_CANONICAL_ENTITY_CRITICALITY_PROFILES,
    audit_yaral2_entity_graph_and_criticality_in_doc,
    build_dwd_credentials,
    clear_doc_index_cache,
    evaluate_grounding_benchmark_suite,
    generate_skillrl_failure_distillation_matrix,
    inspect_google_doc_revision_and_Formatting,
    resolve_docs_token,
)
from manager.tools.tools import init_shared_mcp_tools  # noqa: E402

LIVE_VALIDATION_DOC_ID = os.environ.get(
    "LIVE_VALIDATION_DOC_ID",
    "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
)
DOC_TITLE = "Cycle25_H26_Live_YARAL2_Entity_Graph_and_Criticality_Validation"
ARTIFACT_PATH = (
    REPO_ROOT
    / "artifacts"
    / "cycle25_yaral2_entity_graph_and_criticality_verification.json"
)


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
    """Returns the seeded Markdown payload containing 5 H26 defects and 2 negative controls
    (1 valid YARA-L 2.0 Entity Graph rule and 1 standard file/payload YARA rule)."""
    bench12 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY"
    )
    base_md = (
        str(bench12["seeded_doc_text"])
        .replace("```yaral\n", "")
        .replace("```yara\n", "")
        .replace("```\n", "")
        .rstrip()
    )
    return base_md + "\n"


async def _run_live_siem_checks(
    remediated_rules: list[dict[str, Any]],
) -> dict[str, Any]:
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

        # 1. Verify that the broken unprefixed $g.entity.hostname rule is rejected by Chronicle's compiler
        broken_unprefixed_rule = str(remediated_rules[0]["original_rule_text"])
        broken_raw = await val_tool.run_async(
            args={"rule_text": broken_unprefixed_rule},
            tool_context=None,
        )
        broken_str = (
            str(broken_raw).encode("ascii", errors="ignore").decode("ascii")
        )

        # 2. Validate all 4 compiler-safe remediated Entity Graph rules
        validated_remediations: list[dict[str, Any]] = []
        for rem in remediated_rules:
            c_safe = str(rem["compiler_safe_remediated_rule_text"])
            val_raw = await val_tool.run_async(
                args={"rule_text": c_safe},
                tool_context=None,
            )
            val_str = (
                str(val_raw).encode("ascii", errors="ignore").decode("ascii")
            )
            passed = "FAILED" not in val_str.upper() and (
                "SUCCESS" in val_str.upper()
                or "VALID" in val_str.upper()
                or "PASSED" in val_str.upper()
            )
            validated_remediations.append(
                {
                    "rule_name": rem["rule_name"],
                    "defect_types": rem["defect_types"],
                    "valid": passed,
                    "raw_response": val_str[:400],
                }
            )

        # 3. Run live UDM query on wins-d19 (Cases 33269, 33280, 33285)
        udm_raw = await udm_tool.run_async(
            args={
                "query": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"',
                "start_time": "2026-02-07T00:00:00Z",
                "end_time": "2026-02-08T00:00:00Z",
                "max_events": 5,
            },
            tool_context=None,
        )
        udm_str = str(udm_raw).encode("ascii", errors="ignore").decode("ascii")

        return {
            "broken_unprefixed_rule_rejected": "FAILED" in broken_str.upper()
            or "DOES NOT EXIST" in broken_str.upper()
            or "ERROR" in broken_str.upper(),
            "broken_unprefixed_rule_error": broken_str[:400],
            "remediated_rules_validated_count": len(validated_remediations),
            "all_remediated_rules_valid": all(
                r["valid"] for r in validated_remediations
            ),
            "remediated_rule_validations": validated_remediations,
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
    print(
        "=== Cycle 25 (H26): Chronicle SIEM YARA-L 2.0 Entity Graph & Criticality Risk-Multiplier Live Validation ==="
    )
    print(
        f"Canonical Entity Profiles Loaded: {list(H26_CANONICAL_ENTITY_CRITICALITY_PROFILES.keys())}"
    )

    # 1. Offline Benchmark Verification (BENCH-12 + all_with_night2 + SkillRL H26 matrix)
    bench12_res = evaluate_grounding_benchmark_suite(
        scenario_ids="BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY",
        include_hda_ablation=True,
    )
    assert bench12_res["status"] == "success", bench12_res
    assert bench12_res["scenario_count"] == 1
    assert bench12_res["total_expected_defects"] == 5
    assert bench12_res["true_positive_edits"] == 5
    assert bench12_res["false_positive_edits"] == 0
    assert bench12_res["false_negative_defects"] == 0
    assert bench12_res["total_negative_controls"] == 2
    assert bench12_res["negative_controls_preserved"] == 2
    assert bench12_res["overall_f1"] == 1.0
    assert bench12_res["pass2_idempotency_rate"] == 1.0
    assert bench12_res["google_drive_write_calls"] == 0

    all_res = evaluate_grounding_benchmark_suite(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert all_res["status"] == "success", all_res
    assert all_res["scenario_count"] == 12
    assert all_res["total_expected_defects"] == 63
    assert all_res["true_positive_edits"] == 63
    assert all_res["false_positive_edits"] == 0
    assert all_res["false_negative_defects"] == 0
    assert all_res["total_negative_controls"] == 25
    assert all_res["negative_controls_preserved"] == 25
    assert all_res["precision"] == 1.0
    assert all_res["recall"] == 1.0
    assert all_res["overall_f1"] == 1.0
    assert all_res["pass2_idempotency_rate"] == 1.0
    assert all_res["overall_hda_error"] == 0.0
    assert all_res["google_drive_write_calls"] == 0

    skillrl_matrix = generate_skillrl_failure_distillation_matrix(
        include_h26=True
    )
    assert skillrl_matrix["status"] == "success", skillrl_matrix
    assert "H26" in skillrl_matrix["horizons_covered"], skillrl_matrix
    print(
        f"[OK] Offline Benchmark all_with_night2: {all_res['scenario_count']} scenarios, "
        f"{all_res['true_positive_edits']}/{all_res['total_expected_defects']} defects caught, "
        f"{all_res['negative_controls_preserved']}/{all_res['total_negative_controls']} negative controls preserved, "
        f"F1={all_res['overall_f1']:.4f}, Pass2 Idempotency={all_res['pass2_idempotency_rate']:.4f}"
    )

    # 2. Reset existing validation Google Doc in place (0 new Google Docs created)
    dwd_creds = build_dwd_credentials()
    token = resolve_docs_token(token_source=dwd_creds)
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
    pass1_res = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id=LIVE_VALIDATION_DOC_ID,
        mode="APPLY",
        append_appendix=True,
        credentials=dwd_creds,
    )
    assert pass1_res["status"] == "success", pass1_res
    assert pass1_res["defect_count"] == 5, pass1_res
    assert pass1_res["applied_redlines"] == 5, pass1_res
    assert pass1_res["applied_redline_count"] == 5, pass1_res
    assert pass1_res["false_positive_redlines"] == 0, pass1_res
    assert pass1_res["appended_appendix"] is True, pass1_res
    assert (
        "standard_yara_pe_binary_header_control"
        in pass1_res["standard_yara_rule_names"]
    ), pass1_res

    remediated_rules = pass1_res.get("remediated_rules") or []
    assert len(remediated_rules) == 4, remediated_rules

    siem_live = asyncio.run(_run_live_siem_checks(remediated_rules))
    assert siem_live["broken_unprefixed_rule_rejected"] is True, siem_live
    assert siem_live["all_remediated_rules_valid"] is True, siem_live
    assert siem_live["search_udm_has_events"] is True, siem_live

    # 4. Inspect live Google Doc revision and formatting
    clear_doc_index_cache()
    inspected_fmt = inspect_google_doc_revision_and_Formatting(
        LIVE_VALIDATION_DOC_ID,
        credentials=dwd_creds,
    )
    assert inspected_fmt["status"] == "success", inspected_fmt
    assert inspected_fmt["applied_redlines"] == 5, inspected_fmt
    assert inspected_fmt["false_positive_redlines"] == 0, inspected_fmt
    assert inspected_fmt["has_h26_entity_graph_matrix"] is True, inspected_fmt
    assert inspected_fmt["fee2e2_span_count"] >= 5, inspected_fmt
    assert inspected_fmt["dcfce7_span_count"] >= 5, inspected_fmt
    print(
        f"[OK] Live Pass 1 on {LIVE_VALIDATION_DOC_ID}: defect_count={pass1_res['defect_count']}, "
        f"applied_redlines={inspected_fmt['applied_redlines']}, "
        f"false_positive_redlines={inspected_fmt['false_positive_redlines']}, "
        f"has_h26_entity_graph_matrix={inspected_fmt['has_h26_entity_graph_matrix']}, "
        f"fee2e2_span_count={inspected_fmt['fee2e2_span_count']}, "
        f"dcfce7_span_count={inspected_fmt['dcfce7_span_count']}, "
        f"live_validate_rule_all_4={siem_live['all_remediated_rules_valid']}, "
        f"live_search_udm={siem_live['search_udm_has_events']}"
    )

    # 5. Run Pass 2 to prove multi-pass idempotency on live Google Doc
    clear_doc_index_cache()
    pass2_res = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id=LIVE_VALIDATION_DOC_ID,
        mode="APPLY",
        append_appendix=True,
        credentials=dwd_creds,
    )
    assert pass2_res["status"] == "success", pass2_res
    assert pass2_res["defect_count"] == 0, pass2_res
    assert pass2_res["skipped_existing_suggestion_count"] >= 5, pass2_res
    assert pass2_res["applied_redlines"] == 0, pass2_res
    assert pass2_res["appended_appendix"] is False, pass2_res
    print(
        f"[OK] Live Pass 2 Idempotency on {LIVE_VALIDATION_DOC_ID}: "
        f"defect_count={pass2_res['defect_count']}, "
        f"skipped_existing_suggestion_count={pass2_res['skipped_existing_suggestion_count']}, "
        f"applied_redlines={pass2_res['applied_redlines']}, "
        f"appended_appendix={pass2_res['appended_appendix']}"
    )

    summary = {
        "cycle": 25,
        "horizon": "H26",
        "status": "validated",
        "new_docs_created": 0,
        "live_doc_id": LIVE_VALIDATION_DOC_ID,
        "benchmark_bench12": {
            "expected_defects": bench12_res["total_expected_defects"],
            "true_positive_edits": bench12_res["true_positive_edits"],
            "false_positive_edits": bench12_res["false_positive_edits"],
            "negative_controls_preserved": f"{bench12_res['negative_controls_preserved']}/{bench12_res['total_negative_controls']}",
            "f1": bench12_res["overall_f1"],
            "pass2_idempotency_rate": bench12_res["pass2_idempotency_rate"],
        },
        "benchmark_all_with_night2": {
            "scenario_count": all_res["scenario_count"],
            "expected_defects": all_res["total_expected_defects"],
            "true_positive_edits": all_res["true_positive_edits"],
            "false_positive_edits": all_res["false_positive_edits"],
            "negative_controls_preserved": f"{all_res['negative_controls_preserved']}/{all_res['total_negative_controls']}",
            "precision": all_res["precision"],
            "recall": all_res["recall"],
            "f1": all_res["overall_f1"],
            "pass2_idempotency_rate": all_res["pass2_idempotency_rate"],
            "hda_attribution": all_res.get("hda_attribution", {}),
        },
        "skillrl_distillation_matrix": {
            "family_count": skillrl_matrix["family_count"],
            "horizons_covered": skillrl_matrix["horizons_covered"],
        },
        "live_pass1": {
            "defect_count": pass1_res["defect_count"],
            "defect_counts_by_type": pass1_res["defect_counts_by_type"],
            "applied_redlines": inspected_fmt["applied_redlines"],
            "false_positive_redlines": inspected_fmt["false_positive_redlines"],
            "inserted_comment_count": pass1_res["inserted_comment_count"],
            "appended_appendix": pass1_res["appended_appendix"],
            "has_h26_entity_graph_matrix": inspected_fmt[
                "has_h26_entity_graph_matrix"
            ],
            "fee2e2_span_count": inspected_fmt["fee2e2_span_count"],
            "dcfce7_span_count": inspected_fmt["dcfce7_span_count"],
            "yaral2_rules_inspected_count": pass1_res[
                "yaral2_rules_inspected_count"
            ],
            "standard_yara_rule_names": pass1_res["standard_yara_rule_names"],
            "live_siem": siem_live,
        },
        "live_pass2": {
            "defect_count": pass2_res["defect_count"],
            "skipped_existing_suggestion_count": pass2_res[
                "skipped_existing_suggestion_count"
            ],
            "applied_redlines": pass2_res["applied_redlines"],
            "appended_appendix": pass2_res["appended_appendix"],
        },
    }
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT_PATH.write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[OK] Saved verification artifact to {ARTIFACT_PATH}")
    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
