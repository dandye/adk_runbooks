#!/usr/bin/env python3
"""Cycle 12 (H12) Live Argolis Chronicle SIEM & Google Docs Validation.

Validates automated YARA-L 2.0 (YL2) ``meta:`` block MITRE ATT&CK tactic/technique
synthesis and consistency red-lining inside a live Google Doc against Argolis
Chronicle SIEM (``dandye-0324-chronicle``) and Google Docs API v1:

1. Finds or creates at most 1 Google Doc
   (``Cycle12_H12_Live_YARAL2_Meta_MITRE_Synthesis_Validation``,
   ``1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0``) in ``SOC Reports``
   seeded with 4 YARA-L 2.0 rules grounded in live Argolis SOAR cases:
   - Rule 1 (``gcp_sa_privilege_escalation_missing_meta_case_33278``):
     omits ``mitre_attack_technique``, ``mitre_attack_tactic``, and
     ``mitre_attack_url`` in ``meta:`` (``missing_meta_mitre_attribution`` ->
     synthesizes ``T1098.003``, ``Persistence / Privilege Escalation``,
     ``https://attack.mitre.org/techniques/T1098/003/``).
   - Rule 2 (``wins_d19_powershell_inconsistent_meta_case_33269``):
     ``meta:`` has ``mitre_attack_technique = "T1059.003"``,
     ``mitre_attack_tactic = "Initial Access"``, and
     ``mitre_attack_url = "https://attack.mitre.org/techniques/T1059.003/"`` on
     PowerShell ``events:`` -> repairs all 3 ``meta:`` spans to ``T1059.001``,
     ``Execution``, and ``https://attack.mitre.org/techniques/T1059/001/``.
   - Rule 3 (``wins_d19_derpservice_cross_family_meta_case_33280``):
     ``meta:`` has ``mitre_attack_technique = "T1059.003"``,
     ``mitre_attack_tactic = "Defense Evasion"``, and dot-separated 404 URL
     ``mitre_attack_url = "https://attack.mitre.org/techniques/T1059.001/"`` on
     ``DERPService`` service creation ``events:`` -> repairs all 3 ``meta:`` spans
     to ``T1543.003``, ``Persistence / Privilege Escalation``, and
     ``https://attack.mitre.org/techniques/T1543/003/``.
   - Rule 4 (``wins_d19_cmd_valid_meta_control``):
     valid ``T1059.003`` + ``Execution`` +
     ``https://attack.mitre.org/techniques/T1059/003/`` control rule -> ``0``
     false-positive findings.
2. Runs Pass 1 of ``verify_and_redline_yaral2_rules_in_doc(..., run_live_siem_check=True,
   verify_meta_mitre=True, synthesize_missing_meta=True)`` and verifies:
   - ``yaral2_findings_count == 7``
   - ``comments.inserted_count == 7``
   - ``edits.applied_count == 7``
   - ``inspect_doc_suggestions`` returns ``suggestion_count == 7`` and every
     rule in ``accepted_text`` passes ``verify_yaral2_rule_with_siem(...,
     verify_meta_mitre=True, synthesize_missing_meta=True)`` with
     ``compiler_verified=True``, ``retrohunt_verified=True``,
     ``retrohunt_event_count > 0``, and ``findings == []``.
3. Runs Pass 2 of ``verify_and_redline_yaral2_rules_in_doc`` and verifies
   multi-pass suggestion idempotency (``skipped_existing_suggestion_count == 7``,
   ``yaral2_findings_count == 0``, ``0`` duplicate edits/comments).
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
from typing import Any

from dotenv import load_dotenv
import httpx

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
from skills.drive_registry import AdcTokenSource, DriveMcpClient  # noqa: E402

DOC_TITLE = "Cycle12_H12_Live_YARAL2_Meta_MITRE_Synthesis_Validation"
DEFAULT_CYCLE12_DOC_ID = "1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0"
START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"

SEED_MARKDOWN = """# Cycle 12 (H12) Live YARA-L 2.0 meta: MITRE ATT&CK Synthesis & Consistency Validation

This document validates deterministic YARA-L 2.0 (`YL2`) `meta:` block MITRE ATT&CK attribution synthesis, cross-family technique disambiguation, tactic consistency checks, dot-to-slash URL normalization, live Chronicle SIEM `validate_rule` compilation, and `search_udm` retrohunt verification across Argolis SOAR cases.

## Rule 1: GCP Service Account Privilege Escalation Missing meta: MITRE Attribution (Case 33278)

rule gcp_sa_privilege_escalation_missing_meta_case_33278 {
  meta:
    author = "Chronicle SOC Detection Engineering"
    severity = "HIGH"
  events:
    $e.metadata.log_type = "GCP_CLOUDAUDIT"
    $e.principal.ip = "104.198.226.161"
    $e.target.resource.name = "projects/base-production"
  condition:
    $e
}

## Rule 2: Windows Host wins-d19 PowerShell Stager with Sibling Technique, Tactic & URL Mismatch (Case 33269)

rule wins_d19_powershell_inconsistent_meta_case_33269 {
  meta:
    author = "Chronicle SOC Detection Engineering"
    severity = "HIGH"
    mitre_attack_technique = "T1059.003"
    mitre_attack_tactic = "Initial Access"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1059.003/"
  events:
    $e.principal.hostname = "wins-d19"
    re.regex($e.target.process.command_line, \\`.\\*(powershell|cmd).\\*\\`) nocase
  condition:
    $e
}

## Rule 3: Windows Host wins-d19 DERPService Creation with Cross-Family Technique, Tactic & Dot-Notation 404 URL (Case 33280)

rule wins_d19_derpservice_cross_family_meta_case_33280 {
  meta:
    author = "Chronicle SOC Detection Engineering"
    severity = "CRITICAL"
    mitre_attack_technique = "T1059.003"
    mitre_attack_tactic = "Defense Evasion"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1059.001/"
  events:
    $e.principal.hostname = "wins-d19"
    re.regex($e.target.process.command_line, \\`.\\*DERPService.\\*\\`) nocase
  condition:
    $e
}

## Rule 4: Valid Windows Command Shell meta: Control Rule (No Defects Expected)

rule wins_d19_cmd_valid_meta_control {
  meta:
    author = "Chronicle SOC Detection Engineering"
    severity = "MEDIUM"
    mitre_attack_technique = "T1059.003"
    mitre_attack_tactic = "Execution"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/003/"
  events:
    $e.principal.hostname = "wins-d19"
    re.regex($e.target.process.command_line, \\`.\\*cmd\\\\.exe.\\*\\`) nocase
  condition:
    $e
}
"""


def _reset_doc_in_place(doc_id: str, headers: dict[str, str]) -> None:
    """Resets a Google Doc's content in place via Drive API v3 media upload and
    deletes any prior test comments so Pass 1 starts from a clean slate."""
    patch_resp = httpx.patch(
        f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}?uploadType=media",
        headers={
            **headers,
            "Content-Type": "text/markdown; charset=utf-8",
        },
        content=SEED_MARKDOWN.encode("utf-8"),
        timeout=30.0,
    )
    patch_resp.raise_for_status()
    try:
        comments_resp = httpx.get(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments",
            headers=headers,
            params={"fields": "comments(id,deleted)"},
            timeout=20.0,
        )
        if comments_resp.status_code == 200:
            for c_item in comments_resp.json().get("comments", []) or []:
                cid = str(c_item.get("id") or "")
                if cid and not c_item.get("deleted"):
                    httpx.delete(
                        f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments/{cid}",
                        headers=headers,
                        timeout=15.0,
                    )
    except Exception:
        pass


def _find_or_create_validation_doc(
    token_source: AdcTokenSource,
    quota_project: str | None,
    reports_folder_id: str | None,
) -> tuple[str, bool]:
    """Finds an existing ``DOC_TITLE`` Google Doc or creates a new one, resetting
    its content in place via Drive API v3 media upload if it already exists."""
    headers = {"Authorization": f"Bearer {token_source()}"}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project

    existing_doc_id = (
        os.environ.get("CYCLE12_DOC_ID", "").strip() or DEFAULT_CYCLE12_DOC_ID
    )
    if existing_doc_id:
        try:
            _reset_doc_in_place(existing_doc_id, headers)
            return existing_doc_id, True
        except Exception:
            pass

    if reports_folder_id:
        try:
            mcp_client = DriveMcpClient(
                token_source=token_source,
                quota_project=quota_project,
            )
            hits = mcp_client.search_in_folder(
                reports_folder_id, title_contains=DOC_TITLE
            )
            for hit in hits:
                fid = str(hit.get("id") or "")
                title = str(hit.get("title") or hit.get("name") or "")
                if fid and title == DOC_TITLE:
                    _reset_doc_in_place(fid, headers)
                    return fid, True
        except Exception:
            pass

    created = create_google_doc(
        title=DOC_TITLE,
        content=SEED_MARKDOWN,
        folder_id=reports_folder_id,
    )
    if created.get("status") != "success":
        raise RuntimeError(f"create_google_doc failed: {created}")
    return str(created["document_id"]), False


def main() -> int:
    print(
        "=== Cycle 12 (H12): Live YARA-L 2.0 meta: Block MITRE ATT&CK "
        "Synthesis & Consistency Validation ==="
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    quota_project = (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or "dandye-0324-chronicle"
    )
    reports_folder_id = os.environ.get("GOOGLE_DRIVE_FOLDER_ID") or os.environ.get(
        "DRIVE_REPORTS_FOLDER_ID"
    )
    token_source = AdcTokenSource()

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

        clear_doc_index_cache()
        doc_id, reused_existing = _find_or_create_validation_doc(
            token_source=token_source,
            quota_project=quota_project,
            reports_folder_id=reports_folder_id,
        )
        clear_doc_index_cache()
        print(
            f"[1/3] Validation Google Doc ready: {DOC_TITLE} ({doc_id}, "
            f"reused_existing={reused_existing})"
        )

        # Pass 1: Run live YARA-L 2.0 meta: MITRE synthesis, consistency linting,
        # Chronicle validate_rule compilation, and search_udm retrohunt verification.
        pass1 = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        assert pass1["yaral2_findings_count"] == 7, (
            f"Expected 7 findings in Pass 1, got {pass1['yaral2_findings_count']}: "
            f"{json.dumps(pass1['findings'], indent=2)}"
        )
        assert pass1["comments"]["inserted_count"] == 7
        assert pass1["edits"]["applied_count"] == 7

        findings_by_rule: dict[str, list[dict[str, Any]]] = {}
        for f_item in pass1["findings"]:
            findings_by_rule.setdefault(str(f_item["rule_name"]), []).append(
                f_item
            )

        assert "wins_d19_cmd_valid_meta_control" not in findings_by_rule
        r1_findings = findings_by_rule[
            "gcp_sa_privilege_escalation_missing_meta_case_33278"
        ]
        assert len(r1_findings) == 1
        assert (
            r1_findings[0]["defect_type"] == "missing_meta_mitre_attribution"
        )
        assert r1_findings[0]["canonical_id"] == "T1098.003"

        r2_findings = findings_by_rule[
            "wins_d19_powershell_inconsistent_meta_case_33269"
        ]
        assert [f["defect_type"] for f in r2_findings] == [
            "meta_mitre_technique_mismatch",
            "meta_mitre_tactic_mismatch",
            "meta_mitre_url_mismatch",
        ]
        assert [f["replacement"] for f in r2_findings] == [
            "T1059.001",
            "Execution",
            "https://attack.mitre.org/techniques/T1059/001/",
        ]

        r3_findings = findings_by_rule[
            "wins_d19_derpservice_cross_family_meta_case_33280"
        ]
        assert [f["defect_type"] for f in r3_findings] == [
            "meta_mitre_technique_mismatch",
            "meta_mitre_tactic_mismatch",
            "meta_mitre_url_mismatch",
        ]
        assert [f["replacement"] for f in r3_findings] == [
            "T1543.003",
            "Persistence / Privilege Escalation",
            "https://attack.mitre.org/techniques/T1543/003/",
        ]
        print(
            "[2/3] Pass 1 Verified: 7 meta: MITRE findings staged as 7 comments "
            "and 7 Suggested Edits across 3 rules (0 false positives on Rule 4)"
        )

        # Inspect pending suggestions and verify all 4 rules in accepted_text
        inspected = inspect_doc_suggestions(doc_id)
        assert inspected["status"] == "success"
        assert inspected["suggestion_count"] == 7, (
            f"Expected 7 pending suggestions, got {inspected['suggestion_count']}"
        )

        accepted_text = str(inspected["accepted_text"])
        accepted_map = _build_utf16_index_map(accepted_text)
        _, _, remaining_static = find_yaral2_rule_spans(
            accepted_text,
            accepted_map,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
        )
        assert len(remaining_static) == 0, (
            f"Expected 0 remaining static/meta defects in accepted_text, got {remaining_static}"
        )

        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 4

        accepted_rule_verifications: list[dict[str, Any]] = []
        for block in accepted_blocks:
            v_res = verify_yaral2_rule_with_siem(
                str(block["rule_text"]),
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=False,
                verify_meta_mitre=True,
                synthesize_missing_meta=True,
                start_time=START_TIME,
                end_time=END_TIME,
                max_events=20,
                siem_validate_fn=live_siem_validate_fn,
                siem_search_fn=live_siem_search_fn,
            )
            assert v_res["compiler_verified"] is True, (
                f"Compiler failed: {v_res}"
            )
            assert v_res["retrohunt_verified"] is True, (
                f"Retrohunt failed: {v_res}"
            )
            assert v_res["retrohunt_event_count"] > 0, (
                f"0 retrohunt hits: {v_res}"
            )
            assert v_res["findings"] == [], (
                f"Residual findings in accepted rule: {v_res['findings']}"
            )
            accepted_rule_verifications.append(
                {
                    "rule_name": v_res["rule_name"],
                    "compiler_verified": v_res["compiler_verified"],
                    "compiler_output": v_res["compiler_output"],
                    "retrohunt_udm_query": v_res["retrohunt_udm_query"],
                    "retrohunt_event_count": v_res["retrohunt_event_count"],
                    "residual_findings_count": len(v_res["findings"]),
                }
            )

        # Pass 2: Verify multi-pass suggestion idempotency
        pass2 = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
            start_time=START_TIME,
            end_time=END_TIME,
            max_events=20,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
        )
        assert pass2["status"] == "success"
        assert pass2["yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 7
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0
        print(
            f"[3/3] Accepted-Text SIEM Verification & Pass 2 Idempotency Verified: "
            f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
        )

        summary = {
            "cycle": 12,
            "horizon_id": "H12",
            "status": "success",
            "document_id": doc_id,
            "document_url": f"https://docs.google.com/document/d/{doc_id}/edit",
            "title": DOC_TITLE,
            "reused_existing_doc": reused_existing,
            "char_count": pass1["char_count"],
            "pass1": {
                "yaral2_findings_count": pass1["yaral2_findings_count"],
                "comments_inserted_count": pass1["comments"]["inserted_count"],
                "edits_applied_count": pass1["edits"]["applied_count"],
                "suggestion_ids": [
                    s["suggestion_id"] for s in inspected["suggestions"]
                ],
                "findings_summary": [
                    {
                        "rule_name": f["rule_name"],
                        "defect_type": f["defect_type"],
                        "meta_key": f.get("meta_key", ""),
                        "start_index": f["start_index"],
                        "end_index": f["end_index"],
                        "quote": f["quote"],
                        "replacement": f["replacement"],
                        "canonical_id": f.get("canonical_id", ""),
                        "tactic": f.get("tactic", ""),
                        "reference_url": f.get("reference_url", ""),
                    }
                    for f in pass1["findings"]
                ],
                "siem_rule_checks": [
                    {
                        "rule_name": rc["rule_name"],
                        "compiler_verified": rc["compiler_verified"],
                        "compiler_output": rc["compiler_output"],
                        "retrohunt_udm_query": rc["retrohunt_udm_query"],
                        "retrohunt_verified": rc["retrohunt_verified"],
                        "retrohunt_event_count": rc["retrohunt_event_count"],
                    }
                    for rc in pass1["siem_rule_checks"]
                ],
            },
            "accepted_projection_verifications": accepted_rule_verifications,
            "pass2_idempotency": {
                "yaral2_findings_count": pass2["yaral2_findings_count"],
                "skipped_existing_suggestion_count": pass2[
                    "skipped_existing_suggestion_count"
                ],
                "comments_inserted_count": pass2["comments"]["inserted_count"],
                "edits_applied_count": pass2["edits"]["applied_count"],
            },
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
