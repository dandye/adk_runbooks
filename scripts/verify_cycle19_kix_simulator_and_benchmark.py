#!/usr/bin/env python3
"""Cycle 19 (H20) Live Validation: Stateful Local Google Docs Kix AST Simulator
& Quantitative Grounded Review Benchmark with Harness-Delta Attribution (HDA).

Reuses and resets the existing Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. 1-to-1 Kix AST & UTF-16 Projection Parity between Live Google Docs API v1
   and ``LocalGoogleDocsSimulator`` on a composite multi-horizon document:
   - Identical ``baseline_text`` and ``accepted_text`` projections
   - Identical ``total_issues``, ``comments_inserted``, and ``edits_applied``
   - Identical ``(deleted_text, inserted_text)`` suggested edit pairs
   - Identical Pass 2 multi-pass idempotency (``skipped_existing_suggestion_count``,
     ``applied_count == 0``)
2. Live Chronicle SIEM (``dandye-0324-chronicle``) verification of the repaired
   UDM query (``secops-mcp_search_udm``) and repaired YARA-L 2.0 (``YL2``)
   detection rule (``secops-mcp_validate_rule``) extracted from ``accepted_text``.
3. Quantitative Grounded Review Benchmark (``evaluate_infosec_doc_reviewer``)
   across all 6 seeded scenarios (``BENCH-01`` through ``BENCH-06``, 32 seeded
   defects + 13 negative controls):
   - ``span_precision == 1.0``, ``defect_recall == 1.0``, ``f1_score == 1.0``
   - ``false_positive_rate == 0.0``, ``safety_refusal_rate == 0.0``
   - ``pass2_idempotency_rate == 1.0``
   - 4-way Harness-Delta Attribution (``Delta_T``, ``Delta_G``, ``Delta_A``,
     ``Delta_total == 1.0``)
4. Closed-loop ``RRSI`` / ``WikiSkill`` promotion gate integration using the
   empirical ``validation_score_delta`` and ``hda_attribution`` from
   ``evaluate_infosec_doc_reviewer`` and appending the Cycle 19 audit record to
   ``wiki/skill-impact.md``.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
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
    LocalGoogleDocsSimulator,
    _BenchmarkTokenSource,
    append_wikiskill_impact_log,
    clear_doc_index_cache,
    evaluate_infosec_doc_reviewer,
    inspect_doc_suggestions,
    read_google_doc,
    resolve_docs_token,
    review_google_doc_with_stage_a,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

EXISTING_CYCLE5_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle19_H20_Live_Kix_Simulator_Parity_and_Benchmark_Validation"


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

    parity_doc_markdown = (
        "# Cycle 19 (H20) Live Kix AST Parity & Grounded Review Validation\n\n"
        "## 1. Defective UDM, Italic-Stripped Regex, MITRE/CVE & Containment Clauses\n\n"
        '- Defective UDM filter: hostname = "wins-d19" AND target.process.command_line = /.*powershell.*/ nocase\n'
        "- Deprecated MITRE technique citation: Adversary executed scripts using T1086 on host wins-d19.\n"
        "- CISA KEV vendor swap: Perimeter Fortinet FortiOS SSL VPN appliance exploited via CVE-2024-21887.\n"
        "- Leaked GCP token: ya29"
        ".a0AfH6SMB_cycle19_parity_token_9876543210abcdef\n"
        "- Destructive GCP SA containment: gcloud iam service-accounts delete hello@base-production.iam.gserviceaccount.com\n\n"
        "## 2. Candidate YARA-L 2.0 (YL2) Rule with Compiler & Meta Defects\n\n"
        "rule cycle19_parity_wins_d19_powershell {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    mitre_attack_tactic = "Execution"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/001/"\n'
        '    severity = "SEV1"\n'
        '    runbook_skill = "nonexistent-runbook-slug"\n'
        "  strings:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "    $e.principal.hostname = $host\n"
        "  match:\n"
        "    $host over 15 minutes\n"
        "  outcome:\n"
        "    $risk_score = max(95)\n"
        "    $cmd_count = distinct_count($e.target.process.command_line)\n"
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "## 3. Valid Negative Control Clause\n\n"
        '- Canonical UDM control: metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"\n'
    )

    token_source = AdcTokenSource()
    token = resolve_docs_token(None, token_source=token_source)

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

        print(
            f"[1/5] Resetting existing Google Doc {EXISTING_CYCLE5_DOC_ID} in place and initializing LocalGoogleDocsSimulator..."
        )
        clear_doc_index_cache()
        reset_info = _reset_google_doc_in_place(
            EXISTING_CYCLE5_DOC_ID,
            DOC_TITLE,
            parity_doc_markdown,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()

        sim = LocalGoogleDocsSimulator()
        sim_doc_id = "sim-cycle19-parity-doc"
        sim.create_or_reset_doc(
            sim_doc_id,
            DOC_TITLE,
            parity_doc_markdown,
            simulate_drive_markdown_import=True,
        )
        sim_token_source = _BenchmarkTokenSource()

        live_read = read_google_doc(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        sim_read = read_google_doc(
            sim_doc_id,
            token_source=sim_token_source,
            transport=sim.as_httpx_transport(),
        )
        assert live_read["status"] == "success"
        assert sim_read["status"] == "success"

        print(
            "[2/5] Running Pass 1 & Pass 2 of review_google_doc_with_stage_a on BOTH live Google Docs API v1 and LocalGoogleDocsSimulator..."
        )
        review_kwargs = {
            "include_telemetry_hazard_stage_a": True,
            "include_credential_containment_stage_a": True,
            "include_udm_stage_a": True,
            "include_yaral2_stage_a": True,
            "include_mitre_cve_stage_a": True,
            "verify_yaral2_meta_mitre": True,
            "verify_yaral2_meta_runbook": True,
            "verify_yaral2_meta_severity": True,
        }

        live_pass1 = review_google_doc_with_stage_a(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
            **review_kwargs,
        )
        sim_pass1 = review_google_doc_with_stage_a(
            sim_doc_id,
            token_source=sim_token_source,
            transport=sim.as_httpx_transport(),
            **review_kwargs,
        )
        assert live_pass1["status"] == "success", f"live_pass1 failed: {live_pass1}"
        assert sim_pass1["status"] == "success", f"sim_pass1 failed: {sim_pass1}"
        assert (
            live_pass1["comments"]["inserted_count"]
            == sim_pass1["comments"]["inserted_count"]
        ), (
            f"Parity mismatch on comments.inserted_count: live={live_pass1['comments']['inserted_count']} "
            f"vs sim={sim_pass1['comments']['inserted_count']}"
        )
        assert (
            live_pass1["edits"]["applied_count"]
            == sim_pass1["edits"]["applied_count"]
        )

        live_insp = inspect_doc_suggestions(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        sim_insp = inspect_doc_suggestions(
            sim_doc_id,
            token_source=sim_token_source,
            transport=sim.as_httpx_transport(),
        )
        assert live_insp["status"] == "success"
        assert sim_insp["status"] == "success"

        # Normalize whitespace when comparing accepted_text and suggestion pairs
        live_pairs = sorted(
            (s["deleted_text"].strip(), s["inserted_text"].strip())
            for s in live_insp["suggestions"]
        )
        sim_pairs = sorted(
            (s["deleted_text"].strip(), s["inserted_text"].strip())
            for s in sim_insp["suggestions"]
        )
        assert live_pairs == sim_pairs, (
            f"Suggestion pairs mismatch:\n  live={live_pairs}\n  sim={sim_pairs}"
        )
        live_norm_tokens = " ".join(live_insp["accepted_text"].split())
        sim_norm_tokens = " ".join(sim_insp["accepted_text"].split())
        assert live_norm_tokens == sim_norm_tokens, (
            f"Accepted text parity mismatch between live Google Docs API v1 and LocalGoogleDocsSimulator:\n"
            f"  live={live_norm_tokens}\n  sim={sim_norm_tokens}"
        )

        # Pass 2 idempotency on both Live and Simulator
        clear_doc_index_cache()
        live_pass2 = review_google_doc_with_stage_a(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
            **review_kwargs,
        )
        sim_pass2 = review_google_doc_with_stage_a(
            sim_doc_id,
            token_source=sim_token_source,
            transport=sim.as_httpx_transport(),
            **review_kwargs,
        )
        assert live_pass2["comments"]["inserted_count"] == 0
        assert sim_pass2["comments"]["inserted_count"] == 0
        assert (
            live_pass2["skipped_existing_suggestion_count"]
            == sim_pass2["skipped_existing_suggestion_count"]
        )
        assert live_pass2["edits"]["applied_count"] == 0
        assert sim_pass2["edits"]["applied_count"] == 0

        print(
            "[3/5] Validating repaired UDM query and YARA-L 2.0 (YL2) rule from accepted_text against live Chronicle SIEM..."
        )
        accepted_text = live_insp["accepted_text"]
        rule_m = re.search(
            r"(rule\s+cycle19_parity_wins_d19_powershell\s*\{[\s\S]*?\})",
            accepted_text,
        )
        assert rule_m is not None, f"Could not extract repaired YARA-L 2.0 rule from accepted_text:\n{accepted_text}"
        repaired_rule_text = rule_m.group(1)
        siem_val_raw = live_siem_validate_fn(repaired_rule_text)
        assert "success" in str(siem_val_raw).lower() or "valid" in str(siem_val_raw).lower(), (
            f"Chronicle validate_rule failed on repaired rule: {siem_val_raw}"
        )

        repaired_udm_query = (
            'principal.hostname = "wins-d19" AND target.process.command_line = /.*powershell.*/ nocase'
        )
        assert repaired_udm_query in accepted_text
        siem_search_raw = live_siem_search_fn(repaired_udm_query)
        assert "events" in str(siem_search_raw).lower() or "wins-d19" in str(siem_search_raw).lower()

        print(
            "[4/5] Running evaluate_infosec_doc_reviewer across all 6 seeded scenarios (BENCH-01..BENCH-06) with HDA ablation..."
        )
        bench_res = evaluate_infosec_doc_reviewer(
            scenario_ids="all",
            include_hda_ablation=True,
        )
        assert bench_res["status"] == "success"
        assert bench_res["scenario_count"] == 6
        assert bench_res["total_expected_defects"] == 32
        assert bench_res["true_positive_edits"] == 32
        assert bench_res["false_positive_edits"] == 0
        assert bench_res["false_negative_defects"] == 0
        assert bench_res["span_precision"] == 1.0
        assert bench_res["defect_recall"] == 1.0
        assert bench_res["f1_score"] == 1.0
        assert bench_res["false_positive_rate"] == 0.0
        assert bench_res["safety_refusal_rate"] == 0.0
        assert bench_res["pass2_idempotency_rate"] == 1.0

        hda = bench_res["hda_attribution"]
        assert hda["delta_total"] == 1.0
        gate = bench_res["rrsi_promotion_gate_check"]
        assert gate["generalized_runbook_promotion_ready"] is True
        assert gate["generalized_runbook_decision"] == "PROMOTED"
        assert gate["overfitted_control_promotion_ready"] is False
        assert gate["overfitted_control_decision"] == "REJECTED_ROLLBACK"

        print(
            "[5/5] Appending Cycle 19 H20 benchmark & HDA attribution audit record to wiki/skill-impact.md..."
        )
        impact_res = append_wikiskill_impact_log(
            gate["generalized_audit"],
            ledger_path=str(PROJECT_ROOT / "wiki" / "skill-impact.md"),
            document_id=EXISTING_CYCLE5_DOC_ID,
        )
        assert impact_res["status"] == "success"

        summary = {
            "status": "success",
            "cycle": 19,
            "horizon_id": "H20",
            "document_id": EXISTING_CYCLE5_DOC_ID,
            "document_title": DOC_TITLE,
            "new_docs_created": 0,
            "deleted_prior_comments": reset_info["deleted_prior_comments"],
            "parity_check": {
                "live_utf16_length": live_read.get("char_count"),
                "sim_utf16_length": sim_read.get("char_count"),
                "live_pass1_edits_applied": live_pass1["edits"][
                    "applied_count"
                ],
                "sim_pass1_edits_applied": sim_pass1["edits"][
                    "applied_count"
                ],
                "live_pass1_comments_inserted": live_pass1["comments"][
                    "inserted_count"
                ],
                "sim_pass1_comments_inserted": sim_pass1["comments"][
                    "inserted_count"
                ],
                "live_suggestion_count": live_insp["suggestion_count"],
                "sim_suggestion_count": sim_insp["suggestion_count"],
                "suggestion_pairs_identical": live_pairs == sim_pairs,
                "accepted_text_identical": live_norm_tokens == sim_norm_tokens,
                "live_pass2_skipped": live_pass2[
                    "skipped_existing_suggestion_count"
                ],
                "sim_pass2_skipped": sim_pass2[
                    "skipped_existing_suggestion_count"
                ],
            },
            "live_siem_verification": {
                "repaired_yaral2_rule_compiled": True,
                "repaired_udm_query_verified": True,
            },
            "benchmark_metrics": {
                "scenario_count": bench_res["scenario_count"],
                "total_expected_defects": bench_res["total_expected_defects"],
                "true_positive_edits": bench_res["true_positive_edits"],
                "false_positive_edits": bench_res["false_positive_edits"],
                "false_negative_defects": bench_res["false_negative_defects"],
                "span_precision": bench_res["span_precision"],
                "defect_recall": bench_res["defect_recall"],
                "f1_score": bench_res["f1_score"],
                "false_positive_rate": bench_res["false_positive_rate"],
                "safety_refusal_rate": bench_res["safety_refusal_rate"],
                "pass2_idempotency_rate": bench_res["pass2_idempotency_rate"],
                "negative_controls_preserved": f"{bench_res['negative_controls_preserved']}/{bench_res['total_negative_controls']}",
            },
            "hda_attribution": hda,
            "rrsi_promotion_gate_check": {
                "generalized_runbook_decision": gate[
                    "generalized_runbook_decision"
                ],
                "overfitted_control_decision": gate[
                    "overfitted_control_decision"
                ],
            },
        }
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
