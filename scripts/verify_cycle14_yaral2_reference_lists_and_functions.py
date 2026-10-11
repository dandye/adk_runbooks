#!/usr/bin/env python3
"""Cycle 14 (H18) Live Argolis Chronicle SIEM & Google Docs Validation.

Validates automated Chronicle SIEM YARA-L 2.0 (`YL2` — distinct from standard YARA
file/payload byte-pattern matching) Reference List (`%<list_name>`), `strings.coalesce()` /
`strings.concat()` / `strings.to_lower()`, `re.capture()`, and `IN (...)` Tuple Membership
verification and repair end-to-end against live Google Docs API v1 (`docs.googleapis.com`),
Google Drive API v3 (`www.googleapis.com/drive/v3`), and Argolis Chronicle SIEM
(`dandye-0324-chronicle`):
1. Resets existing Google Doc `1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0` in place via
   Drive API v3 media upload (`PATCH /upload/drive/v3/files/{id}?uploadType=media`),
   allocating `0` new Google Docs.
2. Uploads a 4-rule incident postmortem containing:
   - Rule 1 (`gcp_sa_in_tuple_and_coalesce_case_33278`):
     * `events:` uses SQL/SPL inline tuple `$e.ip in ("104.198.226.161", "34.135.255.85")`
       (`invalid_in_membership_syntax` ->
       `($e.principal.ip = "104.198.226.161" or $e.principal.ip = "34.135.255.85")`).
     * `outcome:` uses bare SQL `coalesce($e.user.userid, $e.ip, "unknown")`
       (`invalid_strings_function_syntax` ->
       `array_distinct(strings.coalesce($e.principal.user.userid, $e.principal.ip, "unknown"))`).
   - Rule 2 (`wins_d19_ref_list_and_re_capture_case_33269`):
     * `events:` uses unprefixed reference list `$e.principal.hostname in suspicious_windows_hosts`
       (`invalid_reference_list_syntax` -> `$e.principal.hostname in %suspicious_windows_hosts`).
     * `outcome:` uses non-canonical `regex_extract($e.process.command_line, /-(?:enc|encodedcommand|nop|e)\\b/)`
       (`invalid_re_capture_syntax` ->
       `array_distinct(re.capture($e.target.process.command_line, "(-(?:enc|encodedcommand|nop|e)\\\\b)"))`).
   - Rule 3 (`wins_d19_derpservice_lower_concat_case_33269`):
     * `events:` uses bare `lower($e.hostname) = "wins-d19"`
       (`invalid_strings_function_syntax` ->
       `strings.to_lower($e.principal.hostname) = "wins-d19"`) and
       `$e.principal.ip = %active_directory_tier0_hosts`
       (`invalid_reference_list_syntax` ->
       `$e.principal.ip in %active_directory_tier0_hosts`).
     * `outcome:` uses bare `concat($e.hostname, ":", $e.user.userid)`
       (`invalid_strings_function_syntax` ->
       `array_distinct(strings.concat($e.principal.hostname, ":", $e.principal.user.userid))`).
   - Rule 4 (`wins_d19_valid_h18_control`): valid control rule using canonical
     `($e.principal.hostname = "wins-d19" or $e.principal.hostname = "wins-d20")`,
     `$e.principal.hostname in %monitored_hosts`,
     `array_distinct(strings.coalesce($e.principal.user.userid, $e.principal.hostname, "unknown"))`,
     and `array_distinct(re.capture($e.target.process.command_line, "(cmd\\\\.exe)"))`,
     verifying `0` false positives.
3. Runs `verify_and_repair_yaral2_rules_in_doc(..., run_live_siem_check=True)` in Pass 1 and
   verifies all 7 non-overlapping repairs (`1` `invalid_in_membership_syntax`,
   `2` `invalid_reference_list_syntax`, `3` `invalid_strings_function_syntax`,
   `1` `invalid_re_capture_syntax`), live Chronicle compiler verification (`validate_rule`),
   historical UDM retrohunts (`search_udm`), and empirical `computed_string_outcomes`.
4. Runs `inspect_doc_suggestions` and verifies that all 4 rules in `accepted_text` compile in
   Chronicle SIEM, match expected UDM event counts, and compute non-empty string outcomes.
5. Re-runs `verify_and_repair_yaral2_rules_in_doc` in Pass 2 and verifies multi-pass
   idempotency (`yaral2_findings_count=0`, `skipped_existing_suggestion_count=7`).
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
    inspect_doc_suggestions,
    verify_and_repair_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

REUSABLE_DOC_ID = "1vVuPJnFuhPw8o8rNPgdtFDVjQBu8KPsoxvIa08CaNx0"
DOC_TITLE = "Cycle14_H18_Live_YARAL2_Reference_Lists_and_Functions_Validation"
START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"

POSTMORTEM_MARKDOWN = """# Incident Postmortem: Cycle 14 (H18) YARA-L 2.0 Reference List (%<list_name>), strings.coalesce() / re.capture() Function & IN-Tuple Membership Validation

## 1. Case 33278: GCP Service Account Privilege Escalation (SQL IN-Tuple Membership + Bare coalesce() in outcome:)

rule gcp_sa_in_tuple_and_coalesce_case_33278 {
  meta:
    author = "SecOps Autonomous Agent"
    description = "Detects SetIamPolicy privilege escalation from Case 33278"
    severity = "HIGH"
    runbook_skill = "compromised-user-account-response"
  events:
    $e.metadata.log_type = "GCP_CLOUDAUDIT"
    $e.ip in ("104.198.226.161", "34.135.255.85")
    $e.target.resource.name = "projects/base-production"
    $e.principal.ip = $src_ip
  match:
    $src_ip over 15m
  outcome:
    $risk_score = max(85)
    $actor_identity = coalesce($e.user.userid, $e.ip, "unknown")
  condition:
    $e
}

## 2. Case 33269: PowerShell Empire Stager on wins-d19 (Missing % Reference List Sigil + regex_extract() with Slash Literal)

rule wins_d19_ref_list_and_re_capture_case_33269 {
  meta:
    author = "SecOps Autonomous Agent"
    description = "Detects PowerShell Empire execution on wins-d19 from Case 33269"
    severity = "CRITICAL"
    runbook_skill = "malware-incident-response"
  events:
    $e.principal.hostname = "wins-d19"
    $e.principal.hostname in suspicious_windows_hosts
    re.regex($e.target.process.command_line, \\`.\\*powershell.\\*\\`) nocase
    $e.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(95)
    $ps_flag = regex_extract($e.process.command_line, /-(?:enc|encodedcommand|nop|e)\\b/)
  condition:
    $e
}

## 3. Case 33269: DERPService Windows Service Persistence on wins-d19 (Bare lower() + = %list_name + Bare concat() in outcome:)

rule wins_d19_derpservice_lower_concat_case_33269 {
  meta:
    author = "SecOps Autonomous Agent"
    description = "Detects DERPService service creation on wins-d19 from Case 33269"
    severity = "CRITICAL"
    runbook_skill = "malware-incident-response"
  events:
    lower($e.hostname) = "wins-d19"
    $e.principal.ip = %active_directory_tier0_hosts
    re.regex($e.target.process.command_line, \\`.\\*DERPService.\\*\\`) nocase
    $e.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(90)
    $actor_summary = concat($e.hostname, ":", $e.user.userid)
  condition:
    $e
}

## 4. Valid Control: Canonical Disjunction, %Reference List, strings.coalesce(), and re.capture() on wins-d19 (Zero False Positives)

rule wins_d19_valid_h18_control {
  meta:
    author = "SecOps Autonomous Agent"
    description = "Valid control rule with canonical disjunction, %monitored_hosts, strings.coalesce, and re.capture"
    severity = "MEDIUM"
    runbook_skill = "malware-incident-response"
  events:
    ($e.principal.hostname = "wins-d19" or $e.principal.hostname = "wins-d20")
    $e.principal.hostname in %monitored_hosts
    re.regex($e.target.process.command_line, \\`.\\*cmd\\\\.exe.\\*\\`) nocase
    $e.principal.hostname = $host
  match:
    $host over 15m
  outcome:
    $risk_score = max(55)
    $actor_user = array_distinct(strings.coalesce($e.principal.user.userid, $e.principal.hostname, "unknown"))
    $shell_bin = array_distinct(re.capture($e.target.process.command_line, \\`(cmd\\\\.exe)\\`))
  condition:
    $e
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

        # Pass 1: Run live YARA-L 2.0 Reference List, IN-tuple, strings.*, and re.capture() verifier
        pass1 = verify_and_repair_yaral2_rules_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        assert pass1["yaral2_findings_count"] == 7, (
            f"Expected 7 H18 findings in Pass 1, got {pass1['yaral2_findings_count']}: "
            f"{json.dumps(pass1.get('findings', []), indent=2)}"
        )
        assert pass1["yaral2_in_membership_repaired"] == 1
        assert pass1["yaral2_reference_lists_repaired"] == 2
        assert pass1["yaral2_strings_functions_repaired"] == 3
        assert pass1["yaral2_re_capture_repaired"] == 1
        assert pass1["comments"]["inserted_count"] == 7
        assert pass1["edits"]["applied_count"] == 7

        findings = pass1["findings"]
        rules_flagged = {f["rule_name"] for f in findings}
        assert "wins_d19_valid_h18_control" not in rules_flagged, (
            "Valid control rule wins_d19_valid_h18_control must have 0 false positives"
        )
        assert rules_flagged == {
            "gcp_sa_in_tuple_and_coalesce_case_33278",
            "wins_d19_ref_list_and_re_capture_case_33269",
            "wins_d19_derpservice_lower_concat_case_33269",
        }

        # Inspect suggestions and verify accepted_text rules against live Chronicle SIEM
        insp = inspect_doc_suggestions(
            REUSABLE_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert insp["status"] == "success"
        assert insp["suggestion_count"] == 7

        accepted_text = str(insp["accepted_text"])
        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 4

        accepted_rule_verifications: list[dict[str, Any]] = []
        for block in accepted_blocks:
            r_name = str(block["rule_name"])
            r_text = str(block["rule_text"])
            siem_res = verify_yaral2_rule_with_siem(
                r_text,
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=False,
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
            assert siem_res.get("computed_string_outcomes"), (
                f"Accepted rule {r_name} should have non-empty computed_string_outcomes: {siem_res}"
            )
            accepted_rule_verifications.append(
                {
                    "rule_name": r_name,
                    "compiler_verified": siem_res["compiler_verified"],
                    "compiler_output": siem_res["compiler_output"],
                    "reference_lists": siem_res.get("reference_lists", []),
                    "retrohunt_udm_query": siem_res["retrohunt_udm_query"],
                    "retrohunt_event_count": siem_res["retrohunt_event_count"],
                    "outcome_values": siem_res.get("outcome_values", {}),
                    "computed_string_outcomes": siem_res.get(
                        "computed_string_outcomes", {}
                    ),
                }
            )

        # Pass 2: Verify multi-pass idempotency on the red-lined Google Doc
        clear_doc_index_cache()
        pass2 = verify_and_repair_yaral2_rules_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate_fn,
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass2["status"] == "success"
        assert pass2["yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 7
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        summary = {
            "cycle": 14,
            "horizon": "H18",
            "document_id": REUSABLE_DOC_ID,
            "new_google_docs_created": 0,
            "reset_info": reset_info,
            "pass1_findings_count": pass1["yaral2_findings_count"],
            "pass1_in_membership_repaired": pass1["yaral2_in_membership_repaired"],
            "pass1_reference_lists_repaired": pass1["yaral2_reference_lists_repaired"],
            "pass1_strings_functions_repaired": pass1["yaral2_strings_functions_repaired"],
            "pass1_re_capture_repaired": pass1["yaral2_re_capture_repaired"],
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "pass1_findings": [
                {
                    "rule_name": f["rule_name"],
                    "defect_type": f["defect_type"],
                    "quote": f["quote"],
                    "replacement": f["replacement"],
                    "start_index": f["start_index"],
                    "end_index": f["end_index"],
                    "reference_lists": f.get("reference_lists", []),
                }
                for f in findings
            ],
            "accepted_rule_verifications": accepted_rule_verifications,
            "pass2_findings_count": pass2["yaral2_findings_count"],
            "pass2_skipped_existing_suggestion_count": pass2[
                "skipped_existing_suggestion_count"
            ],
            "pass2_comments_inserted": pass2["comments"]["inserted_count"],
            "pass2_edits_applied": pass2["edits"]["applied_count"],
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
