#!/usr/bin/env python3
"""Cycle 17 (H8) Live Validation: Detection Coverage Gap Matrix & Automated
Threat Detection Opportunity (TDO) Red-Liner in Google Docs.

Reuses and resets the existing Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. Empirical Detection Coverage Gap Matrix calculation across 3 Argolis SOAR/SIEM
   campaigns (`CAMP-GCP-CONTROL-PLANE-33278`, `CAMP-WORKSPACE-SUPERADMIN-TAKEOVER`,
   `CAMP-WINS-D19-ENDPOINT`): `total_tdo_count == 5`, `covered_tdo_count == 2`,
   `uncovered_tdo_count == 3`, `coverage_percentage == 40.0`.
2. Non-destructive `writeMode="SUGGEST"` red-lining across 7 findings in 3 defect
   categories with 0 false positives on covered TDOs:
   - 2 `overclaimed_detection_coverage` spans
   - 2 `tdo_log_source_mismatch` spans (`AWS_CLOUDTRAIL` -> `GCP_CLOUDAUDIT`,
     `GCP_CLOUDAUDIT` -> `WORKSPACE_ACTIVITY`)
   - 3 `uncovered_tdo_rule_synthesis` spans staging complete YARA-L 2.0 (`YL2`)
     detection rules (`tdo_gcp_cloudsql_destructive_delete_case_33278`,
     `tdo_workspace_saml_and_2sv_tampering_case_33287`,
     `tdo_wins_d19_derpservice_persistence_case_33280`)
3. Live Chronicle SIEM (`dandye-0324-chronicle`) compilation (`secops-mcp_validate_rule`)
   and historical UDM retrohunt (`secops-mcp_search_udm`) verification across all 3
   synthesized YARA-L 2.0 rules (`compiler_verified == True`, `retrohunt_event_count >= 1`,
   `runbook_skill_valid == True` against the 63-skill `SkillRegistry`).
4. Post-accept Detection Coverage Gap Matrix verification (`accepted_view`):
   `covered_tdo_count == 5`, `uncovered_tdo_count == 0`, `coverage_percentage == 100.0`.
5. Multi-pass suggestion idempotency on Pass 2 (`skipped_existing_suggestion_count == 7`,
   `finding_count == 0`).
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
    analyze_and_redline_detection_coverage_gaps_in_doc,
    build_detection_coverage_gap_matrix,
    clear_doc_index_cache,
    inspect_doc_suggestions,
    read_google_doc,
    resolve_docs_token,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402
from skills.registry import SkillRegistry  # noqa: E402

EXISTING_CYCLE5_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle17_H8_Live_Detection_Coverage_Gap_Matrix_and_TDO_Redliner_Validation"


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

    validation_doc_content = (
        "# Cycle 17 (H8) Live Validation: Detection Coverage Gap Matrix & TDO Red-Liner\n\n"
        "Campaign Scope: SOAR Case 33278 (`CAMP-GCP-CONTROL-PLANE-33278`), "
        "SOAR Case 33281, Case 33283, and Case 33287 (`CAMP-WORKSPACE-SUPERADMIN-TAKEOVER`), "
        "and SOAR Case 33269, Case 33280, and Case 33285 (`CAMP-WINS-D19-ENDPOINT`).\n\n"
        "Executive Coverage Summary: We have achieved 100% detection coverage across all campaign techniques.\n\n"
        "## Deployed Chronicle SIEM YARA-L 2.0 (YL2) Detection Rules\n\n"
        "rule tdo_gcp_iam_setiampolicy_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    description = "Detects GCP SetIamPolicy privilege escalation on projects/base-production (SOAR Case 33278)"\n'
        '    severity = "HIGH"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    mitre_attack_tactic = "Persistence / Privilege Escalation"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.metadata.product_event_type = "SetIamPolicy"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule tdo_wins_d19_powershell_empire_case_33269 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    description = "Detects encoded PowerShell Empire execution on endpoint wins-d19 (SOAR Case 33269)"\n'
        '    severity = "CRITICAL"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    mitre_attack_tactic = "Execution"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/001/"\n'
        '    runbook_skill = "malware-incident-response"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "    re.regex($e.target.process.command_line, \\`.\\*powershell.\\*-(e|en|enc|encodedcommand).\\*\\`) nocase\n"
        "  outcome:\n"
        "    $risk_score = max(95)\n"
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "## Threat Detection Opportunities (TDOs) & Follow-Up Matrix\n\n"
        "- TDO-GCP-IAM-SETIAMPOLICY (MITRE T1098.003): GCP SetIamPolicy Privilege Escalation on projects/base-production. Log Source: GCP_CLOUDAUDIT | Coverage Status: COVERED by rule tdo_gcp_iam_setiampolicy_case_33278.\n"
        "- TDO-GCP-CLOUDSQL-DELETE (MITRE T1485): Destructive Cloud SQL Instance Deletion (prod-customers). Log Source: AWS_CLOUDTRAIL | Coverage Status: COVERED | Action Item: Write YARA-L 2.0 rule for cloudsql.instances.delete.\n"
        "- TDO-WORKSPACE-SAML-2SV-TAMPER (MITRE T1556.006): Google Workspace SAML2 IdP Deletion and 2SV Weakening. Log Source: GCP_CLOUDAUDIT | Action Item: Write YARA-L 2.0 rule for DELETE_SAML2_SERVICE_PROVIDER_CONFIG and CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS.\n"
        "- TDO-WINS-D19-POWERSHELL-EMPIRE (MITRE T1059.001): Encoded PowerShell Empire Execution on wins-d19. Log Source: WINDOWS_SYSMON | Coverage Status: COVERED by rule tdo_wins_d19_powershell_empire_case_33269.\n"
        "- TDO-WINS-D19-DERPSERVICE-PERSISTENCE (MITRE T1543.003): Windows Service Persistence via DERPService.exe on wins-d19. Action Item: Write YARA-L 2.0 rule for C:\\\\Users\\\\Public\\\\DERPService.exe.\n"
    )

    token_source = AdcTokenSource()
    token = resolve_docs_token(None, token_source=token_source)
    skill_registry = SkillRegistry(str(PROJECT_ROOT / "skills"))

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
            f"[1/5] Resetting existing Google Doc {EXISTING_CYCLE5_DOC_ID} in place (0 new docs created)..."
        )
        clear_doc_index_cache()
        reset_info = _reset_google_doc_in_place(
            EXISTING_CYCLE5_DOC_ID,
            DOC_TITLE,
            validation_doc_content,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()

        read_res = read_google_doc(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert read_res["status"] == "success", f"read_google_doc failed: {read_res}"

        print(
            "[2/5] Running Pass 1 of analyze_and_redline_detection_coverage_gaps_in_doc with live Chronicle SIEM check..."
        )
        pass1 = analyze_and_redline_detection_coverage_gaps_in_doc(
            EXISTING_CYCLE5_DOC_ID,
            run_live_siem_check=True,
            synthesize_missing_tdo_rules=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            skill_registry=skill_registry,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        matrix = pass1["coverage_matrix"]
        assert matrix["total_tdo_count"] == 5, f"Expected 5 TDOs, got {matrix}"
        assert matrix["covered_tdo_count"] == 2, f"Expected 2 covered TDOs, got {matrix}"
        assert matrix["uncovered_tdo_count"] == 3, f"Expected 3 uncovered TDOs, got {matrix}"
        assert matrix["coverage_percentage"] == 40.0, f"Expected 40.0%, got {matrix}"

        assert pass1["finding_count"] == 7, f"Expected 7 findings, got {pass1['finding_count']}"
        assert pass1["comments"]["inserted_count"] == 7
        assert pass1["edits"]["applied_count"] == 7
        assert pass1["skipped_existing_suggestion_count"] == 0

        defect_counts: dict[str, int] = {}
        for f in pass1["findings"]:
            dt = f["defect_type"]
            defect_counts[dt] = defect_counts.get(dt, 0) + 1
            assert f["tdo_id"] not in (
                "TDO-GCP-IAM-SETIAMPOLICY",
                "TDO-WINS-D19-POWERSHELL-EMPIRE",
            ), f"False positive on covered TDO: {f}"
        assert defect_counts == {
            "overclaimed_detection_coverage": 2,
            "tdo_log_source_mismatch": 2,
            "uncovered_tdo_rule_synthesis": 3,
        }, f"Unexpected defect distribution: {defect_counts}"

        siem_tdo_results = pass1["siem_tdo_results"]
        assert len(siem_tdo_results) == 3, f"Expected 3 SIEM TDO results, got {siem_tdo_results}"
        for tdo_id, tr in siem_tdo_results.items():
            assert tr["compiler_verified"] is True, f"Compiler verification failed for {tdo_id}: {tr}"
            assert tr["retrohunt_event_count"] >= 1, f"Expected >=1 SIEM event for {tdo_id}, got {tr}"
            assert tr["runbook_skill_valid"] is True, f"Invalid runbook_skill for {tdo_id}: {tr}"
            print(
                f"  -> Synthesized TDO Rule ({tdo_id} -> {tr['rule_name']}): "
                f"compiler_verified={tr['compiler_verified']} "
                f"retrohunt_event_count={tr['retrohunt_event_count']} "
                f"runbook_skill={tr['runbook_skill']} (valid={tr['runbook_skill_valid']})"
            )

        print(
            "[3/5] Inspecting inline suggestions via inspect_doc_suggestions and verifying 100% post-accept TDO coverage..."
        )
        inspected = inspect_doc_suggestions(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert inspected["status"] == "success"
        assert inspected["suggestion_count"] >= 7, (
            f"Expected >=7 inline suggestion spans, got {inspected['suggestion_count']}"
        )
        accepted_text = inspected["accepted_text"]

        post_matrix = build_detection_coverage_gap_matrix(
            accepted_text, skill_registry=skill_registry
        )
        assert post_matrix["total_tdo_count"] == 5
        assert post_matrix["covered_tdo_count"] == 5
        assert post_matrix["uncovered_tdo_count"] == 0
        assert post_matrix["coverage_percentage"] == 100.0
        print(
            f"  -> Post-Accept Coverage Matrix: {post_matrix['covered_tdo_count']}/{post_matrix['total_tdo_count']} "
            f"TDOs covered ({post_matrix['coverage_percentage']}%)"
        )

        print(
            "[4/5] Running Pass 2 of analyze_and_redline_detection_coverage_gaps_in_doc to verify multi-pass idempotency..."
        )
        clear_doc_index_cache()
        pass2 = analyze_and_redline_detection_coverage_gaps_in_doc(
            EXISTING_CYCLE5_DOC_ID,
            run_live_siem_check=True,
            synthesize_missing_tdo_rules=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            skill_registry=skill_registry,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass2["status"] == "success"
        assert pass2["finding_count"] == 0, f"Expected 0 findings on Pass 2, got {pass2}"
        assert pass2["skipped_existing_suggestion_count"] == 7, (
            f"Expected 7 skipped suggestions on Pass 2, got {pass2}"
        )
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        print("[5/5] Cycle 17 (H8) live validation succeeded.")
        summary = {
            "status": "success",
            "cycle": 17,
            "horizon_id": "H8",
            "document_id": EXISTING_CYCLE5_DOC_ID,
            "document_title": DOC_TITLE,
            "new_docs_created": 0,
            "deleted_prior_comments": reset_info["deleted_prior_comments"],
            "utf16_length": read_res.get("char_count", len(read_res.get("text", ""))),
            "suggestion_count": inspected["suggestion_count"],
            "pre_accept_coverage": {
                "total_tdo_count": matrix["total_tdo_count"],
                "covered_tdo_count": matrix["covered_tdo_count"],
                "uncovered_tdo_count": matrix["uncovered_tdo_count"],
                "coverage_percentage": matrix["coverage_percentage"],
                "covered_tdo_ids": matrix["covered_tdo_ids"],
                "uncovered_tdo_ids": matrix["uncovered_tdo_ids"],
            },
            "pass1_finding_count": pass1["finding_count"],
            "pass1_defect_counts": defect_counts,
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "siem_tdo_results": {
                k: {
                    "rule_name": v["rule_name"],
                    "compiler_verified": v["compiler_verified"],
                    "retrohunt_event_count": v["retrohunt_event_count"],
                    "runbook_skill": v["runbook_skill"],
                    "runbook_skill_valid": v["runbook_skill_valid"],
                }
                for k, v in siem_tdo_results.items()
            },
            "post_accept_coverage": {
                "total_tdo_count": post_matrix["total_tdo_count"],
                "covered_tdo_count": post_matrix["covered_tdo_count"],
                "uncovered_tdo_count": post_matrix["uncovered_tdo_count"],
                "coverage_percentage": post_matrix["coverage_percentage"],
            },
            "pass2_finding_count": pass2["finding_count"],
            "pass2_skipped_existing_suggestion_count": pass2[
                "skipped_existing_suggestion_count"
            ],
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
