#!/usr/bin/env python3
"""Cycle 20 (H21) Live Validation: WAVED Cyber Ontology (akbar-2023)
Weakness-Vulnerability-Exploit-Defense Graph & CWE-to-CVE-to-ATT&CK-to-D3FEND
Span Verifier in Google Docs.

Reuses and resets the existing Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. Live execution of ``verify_and_redline_waved_ontology_in_doc`` against
   Google Docs API v1 on ``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``:
   - Detects all 4 WAVED ontological defect classes:
     * ``CWE_LABEL_MISMATCH`` (``CWE-78 (SQL Injection)``)
     * ``D3FEND_LABEL_MISMATCH`` (``D3-MFA (Network Traffic Filtering)``)
     * ``WAVED_CHAIN_INCONSISTENCY`` (``CVE_CWE_MISMATCH`` pairing ``CVE-2024-3400``
       with ``CWE-89``, and ``ATTACK_D3FEND_MISMATCH`` pairing ``T1078`` with ``D3-DNSAL``)
     * ``YARAL2_WAVED_META_DEFECT`` (mismatched ``cwe_id = "CWE-89"`` and
       ``d3fend_technique = "D3-DNSAL"`` in Chronicle SIEM YARA-L 2.0 ``meta:`` block)
   - Applies atomic ``batchUpdate`` sorted in strict reverse ``startIndex`` order
     with allowlisted ``cwe.mitre.org`` and ``d3fend.mitre.org`` links, green
     highlights on valid 4-layer WAVED spans, and redline strike-throughs +
     ``[WAVED ONTOLOGY CORRECTION: ...]`` annotations on defective spans.
2. Live Stage A ``writeMode="SUGGEST"`` execution via ``review_google_doc_with_stage_a(..., include_waved_ontology_stage_a=True)``
   and ``run_unified_doc_grounding_review`` (Pass 1 & Pass 2 idempotency).
3. Quantitative benchmark evaluation via ``evaluate_infosec_doc_reviewer`` on
   ``BENCH-07-WAVED-ONTOLOGY-CWE-CVE-ATTACK-D3FEND`` and ``all_with_night2``
   (7 scenarios, 38 seeded defects, F1 = 1.0000).
"""

from __future__ import annotations

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

from manager.tools.docs_review_tools import (  # noqa: E402
    clear_doc_index_cache,
    evaluate_infosec_doc_reviewer,
    get_docs_service,
    inspect_doc_suggestions,
    resolve_docs_token,
    review_google_doc_with_stage_a,
    run_unified_doc_grounding_review,
    validate_url_against_domain_allowlist,
    verify_and_redline_waved_ontology_in_doc,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

EXISTING_VALIDATION_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle20_H21_Live_WAVED_Cyber_Ontology_CWE_CVE_ATTACK_D3FEND_Validation"


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


def _collect_ast_links_and_annotations(doc: dict[str, Any]) -> dict[str, Any]:
    """Walks a Google Docs API v1 AST and extracts linked URLs, strikethrough runs, and correction runs."""
    tabs = doc.get("tabs", [])
    body = (
        tabs[0].get("documentTab", {}).get("body", {})
        if tabs
        else doc.get("body", {})
    )
    urls: list[str] = []
    strikethrough_runs: list[str] = []
    correction_runs: list[str] = []

    for elem in body.get("content", []):
        para = elem.get("paragraph")
        if not para:
            continue
        for pe in para.get("elements", []):
            tr = pe.get("textRun")
            if not tr:
                continue
            content = str(tr.get("content") or "")
            style = tr.get("textStyle") or {}
            link_url = (style.get("link") or {}).get("url")
            if link_url:
                urls.append(str(link_url))
            if style.get("strikethrough"):
                strikethrough_runs.append(content.strip())
            if "[WAVED ONTOLOGY CORRECTION:" in content:
                correction_runs.append(content.strip())

    return {
        "linked_urls": urls,
        "strikethrough_runs": strikethrough_runs,
        "correction_runs": correction_runs,
    }


def main() -> int:
    quota_project = (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or "dandye-0324-chronicle"
    )
    token_source = AdcTokenSource()
    token = resolve_docs_token(None, token_source=token_source)

    waved_doc_markdown = (
        "# Cycle 20 (H21) WAVED Cyber Ontology (akbar-2023) Live Validation\n\n"
        "## 1. Valid 4-Layer WAVED Ontological Chains (Negative Controls)\n\n"
        "- Valid Chain 1 (Perimeter Command Injection): CVE-2024-3400 is rooted in CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')), exploited via T1190 (Exploit Public-Facing Application), and countered by D3-ITF (Inbound Traffic Filtering) and D3-NTF (Network Traffic Filtering).\n"
        "- Valid Chain 2 (Citrix Bleed Session Hijacking): CVE-2023-4966 is rooted in CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer), exploited via T1550.004 (Web Session Cookie), and countered by D3-MFA (Multi-factor Authentication) and D3-IAA (Authentication Event Thresholding).\n\n"
        "## 2. Seeded WAVED Ontological Defects (Prose & Cross-Layer Graph)\n\n"
        "- Defect 1 (CWE Label Mismatch): Triage notes mislabeled CWE-78 (SQL Injection) on the GlobalProtect gateway.\n"
        "- Defect 2 (D3FEND Label Mismatch): Containment guidance mislabeled D3-MFA (Network Traffic Filtering) on the identity provider.\n"
        "- Defect 3 (WAVED CVE-to-CWE Chain Break): Advisory states CVE-2024-3400 is caused by root weakness CWE-89 (SQL Injection).\n"
        "- Defect 4 (WAVED ATT&CK-to-D3FEND Countermeasure Break): Playbook recommends mitigating T1078 (Valid Accounts) abuse exclusively via D3-DNSAL (DNS Allowlisting).\n\n"
        "## 3. Chronicle SIEM YARA-L 2.0 (YL2) Rule with WAVED Meta Defects\n\n"
        "rule cycle20_waved_panos_cmdi_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    cve_id = "CVE-2024-3400"\n'
        '    cwe_id = "CWE-89"\n'
        '    mitre_attack_technique = "T1078"\n'
        '    mitre_attack_tactic = "Initial Access"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1078/"\n'
        '    d3fend_technique = "D3-DNSAL"\n'
        '    severity = "HIGH"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $e\n"
        "}\n"
    )

    print(
        f"[1/4] Resetting existing Google Doc {EXISTING_VALIDATION_DOC_ID} in place (0 new docs created)..."
    )
    clear_doc_index_cache()
    reset_1 = _reset_google_doc_in_place(
        EXISTING_VALIDATION_DOC_ID,
        DOC_TITLE,
        waved_doc_markdown,
        token=token,
        quota_project=quota_project,
    )

    print(
        "[2/4] Executing verify_and_redline_waved_ontology_in_doc against live Google Docs API v1..."
    )
    redline_res = verify_and_redline_waved_ontology_in_doc(
        document_id=EXISTING_VALIDATION_DOC_ID,
        apply_redlines=True,
        highlight_valid=True,
        append_summary_section=True,
        token_source=token_source,
        quota_project=quota_project,
    )
    assert redline_res["status"] == "success", f"Unexpected error: {redline_res}"
    assert redline_res["defect_count"] == 6, (
        f"Expected 6 WAVED defects, got {redline_res['defect_count']}"
    )
    assert redline_res["verified_span_count"] >= 8
    assert redline_res["applied_requests_count"] > 0

    # Verify live AST contains cwe.mitre.org and d3fend.mitre.org links, strikethroughs, and corrections
    live_doc_after_redline = (
        get_docs_service(token_source=token_source, quota_project=quota_project)
        .documents()
        .get(documentId=EXISTING_VALIDATION_DOC_ID)
        .execute()
    )
    ast_inspect = _collect_ast_links_and_annotations(live_doc_after_redline)
    assert any("cwe.mitre.org" in u for u in ast_inspect["linked_urls"])
    assert any("d3fend.mitre.org" in u for u in ast_inspect["linked_urls"])
    assert all(
        validate_url_against_domain_allowlist(u)
        for u in ast_inspect["linked_urls"]
    )
    assert len(ast_inspect["strikethrough_runs"]) >= 6
    assert len(ast_inspect["correction_runs"]) == 6

    print(
        "[3/4] Resetting Google Doc in place and running Stage A writeMode='SUGGEST' Pass 1 & Pass 2..."
    )
    clear_doc_index_cache()
    reset_2 = _reset_google_doc_in_place(
        EXISTING_VALIDATION_DOC_ID,
        DOC_TITLE,
        waved_doc_markdown,
        token=token,
        quota_project=quota_project,
    )
    clear_doc_index_cache()

    pass1 = run_unified_doc_grounding_review(
        EXISTING_VALIDATION_DOC_ID,
        include_waved_ontology_stage_a=True,
        token_source=token_source,
        quota_project=quota_project,
    )
    assert pass1["status"] == "success"
    assert pass1["stage_a_waved_ontology_count"] == 6
    assert pass1["waved_ontology_verification"]["defect_count"] == 6
    assert pass1["comments"]["inserted_count"] == 6
    assert pass1["edits"]["applied_count"] == 6

    inspected = inspect_doc_suggestions(
        EXISTING_VALIDATION_DOC_ID,
        token_source=token_source,
        quota_project=quota_project,
    )
    assert inspected["suggestion_count"] == 6
    assert "CWE-78 (OS Command Injection)" in inspected["accepted_text"]
    assert "D3-MFA (Multi-factor Authentication)" in inspected["accepted_text"]
    assert 'cwe_id = "CWE-78"' in inspected["accepted_text"]

    pass2 = review_google_doc_with_stage_a(
        EXISTING_VALIDATION_DOC_ID,
        include_waved_ontology_stage_a=True,
        token_source=token_source,
        quota_project=quota_project,
    )
    assert pass2["status"] == "success"
    assert pass2["skipped_existing_suggestion_count"] == 6
    assert pass2["comments"]["inserted_count"] == 0
    assert pass2["edits"]["applied_count"] == 0

    print(
        "[4/4] Running evaluate_infosec_doc_reviewer on BENCH-07 and all_with_night2..."
    )
    bench_b7 = evaluate_infosec_doc_reviewer(
        scenario_ids="BENCH-07-WAVED-ONTOLOGY-CWE-CVE-ATTACK-D3FEND",
        include_hda_ablation=False,
    )
    assert bench_b7["status"] == "success"
    assert bench_b7["f1_score"] == 1.0
    assert bench_b7["pass2_idempotency_rate"] == 1.0

    bench_all = evaluate_infosec_doc_reviewer(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert bench_all["status"] == "success"
    assert bench_all["scenario_count"] == 7
    assert bench_all["total_expected_defects"] == 38
    assert bench_all["true_positive_edits"] == 38
    assert bench_all["false_positive_edits"] == 0
    assert bench_all["f1_score"] == 1.0

    summary_payload = {
        "status": "success",
        "cycle": 20,
        "horizon_id": "H21",
        "document_id": EXISTING_VALIDATION_DOC_ID,
        "new_docs_created": 0,
        "reset_1": reset_1,
        "direct_waved_redline": {
            "waved_completeness_score": redline_res["waved_completeness_score"],
            "layer_coverage": redline_res["layer_coverage"],
            "defect_count": redline_res["defect_count"],
            "verified_span_count": redline_res["verified_span_count"],
            "applied_requests_count": redline_res["applied_requests_count"],
            "linked_url_count": len(ast_inspect["linked_urls"]),
            "strikethrough_run_count": len(ast_inspect["strikethrough_runs"]),
            "correction_run_count": len(ast_inspect["correction_runs"]),
        },
        "stage_a_suggest_pipeline": {
            "reset_2_deleted_comments": reset_2["deleted_prior_comments"],
            "pass1_waved_findings": pass1["stage_a_waved_ontology_count"],
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "suggestion_count": inspected["suggestion_count"],
            "pass2_skipped_existing_suggestions": pass2[
                "skipped_existing_suggestion_count"
            ],
            "pass2_edits_applied": pass2["edits"]["applied_count"],
        },
        "benchmark_bench07": {
            "total_expected_defects": bench_b7["total_expected_defects"],
            "true_positive_edits": bench_b7["true_positive_edits"],
            "span_precision": bench_b7["span_precision"],
            "defect_recall": bench_b7["defect_recall"],
            "f1_score": bench_b7["f1_score"],
        },
        "benchmark_all_with_night2": {
            "scenario_count": bench_all["scenario_count"],
            "total_expected_defects": bench_all["total_expected_defects"],
            "true_positive_edits": bench_all["true_positive_edits"],
            "f1_score": bench_all["f1_score"],
        },
    }
    print(json.dumps(summary_payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
