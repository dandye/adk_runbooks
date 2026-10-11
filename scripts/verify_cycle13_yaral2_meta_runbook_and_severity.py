#!/usr/bin/env python3
"""Cycle 13 (H19) Live Argolis Chronicle SIEM, SkillRegistry & Google Docs Validation.

Validates automated YARA-L 2.0 (`YL2`) `meta:` block Runbook Routing (`runbook_skill`)
and Severity-to-Risk-Score Consistency verification end-to-end against live Google
Docs API v1 (`docs.googleapis.com`), Google Drive API v3 (`www.googleapis.com/drive/v3`),
`SkillRegistry` (`SOC Runbooks`), and Argolis Chronicle SIEM (`dandye-0324-chronicle`):
1. Resets existing Google Doc `1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0` in place via
   Drive API v3 media upload (`PATCH /upload/drive/v3/files/{id}?uploadType=media`),
   allocating `0` new Google Docs.
2. Uploads a 4-rule incident postmortem containing:
   - Rule 1 (`gcp_sa_privilege_escalation_case_33278`): `meta:` has `severity = "LOW"` while
     `outcome:` defines `$risk_score = max(85)` (`meta_severity_risk_score_mismatch` -> `"HIGH"`)
     and omits `runbook_skill` (`missing_meta_runbook_skill` ->
     `runbook_skill = "compromised-user-account-response"`, folding cleanly onto the `severity`
     insertion anchor).
   - Rule 2 (`wins_d19_powershell_empire_case_33269`): `meta:` has non-canonical
     `severity = "SEV1"` (`invalid_meta_severity` -> `"CRITICAL"`, matching `$risk_score = max(95)`)
     and hallucinated `runbook_skill = "windows-powershell-playbook"`
     (`meta_runbook_skill_mismatch` -> `"malware-incident-response"`).
   - Rule 3 (`wins_d19_derpservice_persistence_case_33280`): `meta:` has `severity = "MEDIUM"`
     while `outcome:` defines `$risk_score = max(80)` (`meta_severity_risk_score_mismatch` ->
     `"HIGH"`) and wrong-domain `runbook_skill = "suspicious-login-triage"`
     (`meta_runbook_skill_mismatch` -> `"malware-incident-response"`).
   - Rule 4 (`wins_d19_cmd_valid_meta_control`): valid control rule (`severity = "MEDIUM"`
     with `$risk_score = max(55)`, `mitre_attack_technique = "T1059.003"`,
     `runbook_skill = "malware-incident-response"`), verifying `0` false positives.
3. Runs `verify_and_redline_yaral2_rules_in_doc(..., run_live_siem_check=True,
   verify_meta_mitre=True, synthesize_missing_meta=True, verify_meta_runbook=True,
   verify_meta_severity=True, synthesize_missing_runbook=True)` in Pass 1 and verifies all 5
   non-overlapping `meta:` repairs (`1` folded on Rule 1 + `2` on Rule 2 + `2` on Rule 3),
   `SkillRegistry` resolution for every `runbook_skill`, live Chronicle compiler verification
   (`validate_rule`), and historical UDM retrohunts (`search_udm`).
4. Runs `inspect_doc_suggestions` and verifies that all 4 rules in `accepted_text` compile
   in Chronicle SIEM, match expected UDM event counts, and reference valid `SkillRegistry`
   operational runbooks.
5. Re-runs `verify_and_redline_yaral2_rules_in_doc` in Pass 2 and verifies multi-pass
   idempotency (`yaral2_findings_count=0`, `skipped_existing_suggestion_count=5`).
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

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(MULTI_AGENT_DIR))

load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(REPO_ROOT / "external" / "mcp-security" / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    _iter_yaral2_rule_blocks,
    clear_doc_index_cache,
    extract_yaral2_meta_spec,
    inspect_doc_suggestions,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402
from skills.registry import SkillRegistry  # noqa: E402

REUSABLE_DOC_ID = "1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0"
DOC_TITLE = "Cycle13_H19_Live_YARAL2_Meta_Runbook_and_Severity_Validation"
START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"

POSTMORTEM_MARKDOWN = """# Incident Postmortem: Cycle 13 (H19) YARA-L 2.0 meta: Runbook Routing & Severity-to-Risk-Score Consistency Validation

## 1. Case 33278: GCP Service Account Privilege Escalation (Severity-to-Risk-Score Mismatch + Missing Runbook Skill Folded on Anchor)

rule gcp_sa_privilege_escalation_case_33278 {
  meta:
    author = "SecOps Agent"
    description = "Detects SetIamPolicy privilege escalation on GCP project from Case 33278"
    mitre_attack_technique = "T1098.003"
    mitre_attack_tactic = "Persistence / Privilege Escalation"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"
    severity = "LOW"
  events:
    $iam.metadata.log_type = "GCP_CLOUDAUDIT"
    $iam.principal.ip = "104.198.226.161"
    $iam.target.resource.name = "projects/base-production"
    $iam.principal.ip = $src_ip
  match:
    $src_ip over 15m
  outcome:
    $risk_score = max(85)
  condition:
    $iam
}

## 2. Case 33269: PowerShell Empire Stager on wins-d19 (Non-Canonical Severity Label + Hallucinated Runbook Skill)

rule wins_d19_powershell_empire_case_33269 {
  meta:
    author = "SecOps Agent"
    description = "Detects PowerShell Empire execution on wins-d19 from Case 33269"
    mitre_attack_technique = "T1059.001"
    mitre_attack_tactic = "Execution"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/001/"
    severity = "SEV1"
    runbook_skill = "windows-powershell-playbook"
  events:
    $ps.principal.hostname = "wins-d19"
    re.regex($ps.target.process.command_line, \\`.\\*powershell.\\*\\`) nocase
    $ps.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(95)
  condition:
    $ps
}

## 3. Case 33280: DERPService Windows Service Persistence on wins-d19 (Severity-to-Risk-Score Mismatch + Wrong-Domain Runbook Skill)

rule wins_d19_derpservice_persistence_case_33280 {
  meta:
    author = "SecOps Agent"
    description = "Detects DERPService service creation on wins-d19 from Case 33280"
    mitre_attack_technique = "T1543.003"
    mitre_attack_tactic = "Persistence / Privilege Escalation"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1543/003/"
    severity = "MEDIUM"
    runbook_skill = "suspicious-login-triage"
  events:
    $svc.principal.hostname = "wins-d19"
    re.regex($svc.target.process.command_line, \\`.\\*DERPService.\\*\\`) nocase
    $svc.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(80)
  condition:
    $svc
}

## 4. Valid Control: Calibrated Windows Command Shell Rule on wins-d19 (Zero False Positives)

rule wins_d19_cmd_valid_meta_control {
  meta:
    author = "SecOps Agent"
    description = "Valid control rule with consistent MEDIUM severity ($risk_score = 55) and malware-incident-response runbook"
    mitre_attack_technique = "T1059.003"
    mitre_attack_tactic = "Execution"
    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/003/"
    severity = "MEDIUM"
    runbook_skill = "malware-incident-response"
  events:
    $cmd.principal.hostname = "wins-d19"
    re.regex($cmd.target.process.command_line, \\`.\\*cmd\\\\.exe.\\*\\`) nocase
    $cmd.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(55)
  condition:
    $cmd
}
"""


def _reset_google_doc_in_place(
    doc_id: str,
    title: str,
    markdown_text: str,
    token: str,
    quota_project: str,
) -> dict[str, Any]:
    """Replaces an existing Google Doc's content in-place via Drive API v3 media upload
    and deletes any prior comments so 0 new Drive files are allocated.
    """
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
            content=markdown_text.encode("utf-8"),
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
    token_source = AdcTokenSource()
    token = token_source()
    skill_registry = SkillRegistry(str(REPO_ROOT / "skills"))

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
        reset_info = _reset_google_doc_in_place(
            REUSABLE_DOC_ID,
            DOC_TITLE,
            POSTMORTEM_MARKDOWN,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()

        # Pass 1: Run live YARA-L 2.0 meta: runbook routing, severity-to-risk-score, and MITRE verifier
        pass1 = verify_and_redline_yaral2_rules_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
            verify_meta_runbook=True,
            verify_meta_severity=True,
            synthesize_missing_runbook=True,
            skill_registry=skill_registry,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        assert pass1["yaral2_findings_count"] == 5, (
            f"Expected 5 meta findings in Pass 1, got {pass1['yaral2_findings_count']}: "
            f"{json.dumps(pass1.get('findings', []), indent=2)}"
        )
        assert pass1["comments"]["inserted_count"] == 5
        assert pass1["edits"]["applied_count"] == 5

        findings = pass1["findings"]
        rules_flagged = {f["rule_name"] for f in findings}
        assert "wins_d19_cmd_valid_meta_control" not in rules_flagged, (
            "Valid control rule wins_d19_cmd_valid_meta_control must have 0 false positives"
        )
        assert rules_flagged == {
            "gcp_sa_privilege_escalation_case_33278",
            "wins_d19_powershell_empire_case_33269",
            "wins_d19_derpservice_persistence_case_33280",
        }

        # Verify all 4 H19 defect types are covered (including folded types on Rule 1)
        all_detected_types: set[str] = set()
        for f in findings:
            all_detected_types.add(str(f["defect_type"]))
            for ft in f.get("folded_defect_types") or []:
                all_detected_types.add(str(ft))
        assert {
            "invalid_meta_severity",
            "meta_severity_risk_score_mismatch",
            "meta_runbook_skill_mismatch",
            "missing_meta_runbook_skill",
        }.issubset(all_detected_types), f"Missing H19 defect classes: {all_detected_types}"

        # Inspect suggestions and verify accepted_text rules against live Chronicle SIEM & SkillRegistry
        insp = inspect_doc_suggestions(
            REUSABLE_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert insp["status"] == "success"
        assert insp["suggestion_count"] == 5

        accepted_text = str(insp["accepted_text"])
        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 4

        accepted_rule_verifications: list[dict[str, Any]] = []
        for block in accepted_blocks:
            r_name = str(block["rule_name"])
            r_text = str(block["rule_text"])
            meta_spec = extract_yaral2_meta_spec(r_text)
            entries_by_key = meta_spec["entries_by_key"]
            sev_val = str(entries_by_key["severity"]["value"])
            rb_val = str(entries_by_key["runbook_skill"]["value"])
            skill_meta = skill_registry.get_skill(rb_val)
            assert skill_meta is not None, (
                f"Rule {r_name} runbook_skill '{rb_val}' not found in SkillRegistry"
            )
            siem_res = verify_yaral2_rule_with_siem(
                r_text,
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=False,
                verify_meta_mitre=True,
                synthesize_missing_meta=True,
                verify_meta_runbook=True,
                verify_meta_severity=True,
                synthesize_missing_runbook=True,
                skill_registry=skill_registry,
                start_time=START_TIME,
                end_time=END_TIME,
                siem_validate_fn=live_siem_validate_fn,
                siem_search_fn=live_siem_search_fn,
            )
            assert siem_res["compiler_verified"] is True, (
                f"Accepted rule {r_name} failed Chronicle compiler: {siem_res}"
            )
            assert siem_res["retrohunt_verified"] is True
            assert int(siem_res["retrohunt_event_count"]) > 0
            assert len(siem_res["findings"]) == 0, (
                f"Accepted rule {r_name} should have 0 remaining findings, got: {siem_res['findings']}"
            )
            accepted_rule_verifications.append(
                {
                    "rule_name": r_name,
                    "severity": sev_val,
                    "runbook_skill": rb_val,
                    "skill_category": skill_meta.category,
                    "compiler_verified": siem_res["compiler_verified"],
                    "retrohunt_udm_query": siem_res["retrohunt_udm_query"],
                    "retrohunt_event_count": siem_res["retrohunt_event_count"],
                    "outcome_values": siem_res.get("outcome_values", {}),
                }
            )

        # Pass 2: Verify multi-pass idempotency
        pass2 = verify_and_redline_yaral2_rules_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
            verify_meta_runbook=True,
            verify_meta_severity=True,
            synthesize_missing_runbook=True,
            skill_registry=skill_registry,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass2["status"] == "success"
        assert pass2["yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 5
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        summary = {
            "cycle": 13,
            "horizon_id": "H19",
            "document_id": REUSABLE_DOC_ID,
            "title": DOC_TITLE,
            "new_google_docs_allocated": 0,
            "reset_info": reset_info,
            "char_count": pass1["char_count"],
            "pass1_findings_count": pass1["yaral2_findings_count"],
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "pending_suggestion_count": insp["suggestion_count"],
            "pass1_findings": [
                {
                    "rule_name": f["rule_name"],
                    "defect_type": f["defect_type"],
                    "folded_defect_types": f.get(
                        "folded_defect_types", [f["defect_type"]]
                    ),
                    "meta_key": f.get("meta_key", ""),
                    "quote": f["quote"],
                    "replacement": f["replacement"],
                    "start_index": f["start_index"],
                    "end_index": f["end_index"],
                    "canonical_severity": f.get("canonical_severity"),
                    "risk_score": f.get("risk_score"),
                    "canonical_skill": f.get("canonical_skill"),
                    "skill_verified": f.get("skill_verified"),
                }
                for f in findings
            ],
            "accepted_rule_verifications": accepted_rule_verifications,
            "pass2_findings_count": pass2["yaral2_findings_count"],
            "pass2_skipped_existing_suggestion_count": pass2[
                "skipped_existing_suggestion_count"
            ],
        }
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
