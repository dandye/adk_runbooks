#!/usr/bin/env python3
"""Cycle 16 (H5) Live Validation: Cross-Case Campaign Graph & Claim-to-Evidence Grounding Auditor.

Resets existing reusable Google Doc 1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE in place
(allocating 0 new Google Docs) with a 4-scenario Executive Threat Briefing containing:
1. Scenario 1 (contradicted_analyst_disposition_claim + missing_cross_case_campaign_correlation):
   Claims that SAML2 SP deletion and 2-step verification weakening by admin@mydomain.com from
   79.154.246.114 in SOAR Case 33287 was "a legitimate automated process" and omits sibling
   Cases 33281 and 33283.
2. Scenario 2 (missing_cross_case_campaign_correlation):
   Cites only Case 33269 on workstation wins-d19 (lisawalker), omitting sibling Cases 33280
   (DERPService persistence) and 33285 (Gamarue infection).
3. Scenario 3 (uncited_analytical_claim):
   Asserts that 294955789222-compute@developer.gserviceaccount.com from 104.198.226.161 executed
   SetIamPolicy granting roles/editor to hello@base-production.iam.gserviceaccount.com and deleted
   the prod-customers Cloud SQL instance without citing SOAR Case #33278, UDM actions, or MITRE IDs.
4. Scenario 4 (Well-Grounded Control Section):
   Contains complete multi-case correlation (Cases 33269, 33280, and 33285) and explicit
   [Evidence: SOAR Cases #33269, #33280, #33285 | ...] citation -> 0 false positives.

Executes Pass 1 against live Argolis Chronicle SIEM (dandye-0324-chronicle) and Google Docs API v1,
verifies inspect_doc_suggestions accepted_text yields 0 residual findings, and executes Pass 2
idempotency check.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "multi-agent"))

load_dotenv(ROOT / "multi-agent" / "manager" / ".env")
load_dotenv(ROOT / "external" / "mcp-security" / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    _extract_text_and_index_map,
    audit_and_redline_claim_evidence_and_campaign_in_doc,
    build_cross_case_campaign_graph,
    clear_doc_index_cache,
    find_claim_evidence_and_campaign_spans,
    inspect_doc_suggestions,
    list_doc_comments,
    resolve_docs_token,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

REUSABLE_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle16_H5_Cross_Case_Campaign_And_Claim_Evidence_Audit"

CYCLE16_MARKDOWN = """# Executive Threat Briefing: Multi-Case Intrusion & Campaign Synthesis

## Scenario 1: Google Workspace Super Admin Federation Tampering
Initial Tier-1 triage concluded that the SAML2 service provider deletion and 2-step verification changes by admin@mydomain.com from 79.154.246.114 in SOAR Case 33287 were a legitimate automated process.

## Scenario 2: Endpoint Intrusion on Workstation wins-d19
Endpoint containment was scoped exclusively to Case 33269 on workstation wins-d19 for user lisawalker after PowerShell activity was observed.

## Scenario 3: GCP Control-Plane Privilege Escalation & Database Destruction
The attacker used 294955789222-compute@developer.gserviceaccount.com from 104.198.226.161 to execute SetIamPolicy granting roles/editor to hello@base-production.iam.gserviceaccount.com and deleted the prod-customers Cloud SQL instance.

## Scenario 4: Well-Grounded Multi-Case Control Section
Correlated SOAR Cases 33269, 33280, and 33285 (Campaign CAMP-WINS-D19-ENDPOINT) confirm PowerShell Empire execution and DERPService persistence on host wins-d19 [Evidence: SOAR Cases #33269, #33280, #33285 | UDM: principal.hostname = "wins-d19" (powershell.exe / DERPService.exe) | MITRE: T1059.001, T1543.003].
"""


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

        def live_siem_search_fn(
            query: str,
            start_time: str = "2026-02-07T00:00:00Z",
            end_time: str = "2026-02-08T00:00:00Z",
            max_events: int = 25,
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
            f"[1/5] Resetting reusable Google Doc {REUSABLE_DOC_ID} in place (0 new Docs created)..."
        )
        clear_doc_index_cache()
        reset_meta = _reset_google_doc_in_place(
            REUSABLE_DOC_ID,
            DOC_TITLE,
            CYCLE16_MARKDOWN,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()
        print(f"      Reset complete: {reset_meta}")

        print(
            "[2/5] Running Pass 1: audit_and_redline_claim_evidence_and_campaign_in_doc(run_live_siem_check=True)..."
        )
        pass1 = audit_and_redline_claim_evidence_and_campaign_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        print(
            json.dumps(
                {
                    "status": pass1.get("status"),
                    "document_id": pass1.get("document_id"),
                    "title": pass1.get("title"),
                    "referenced_campaign_ids": pass1.get("campaign_graph", {}).get(
                        "referenced_campaign_ids"
                    ),
                    "finding_count": pass1.get("finding_count"),
                    "skipped_existing_suggestion_count": pass1.get(
                        "skipped_existing_suggestion_count"
                    ),
                    "comments_inserted": pass1.get("comments", {}).get("inserted_count"),
                    "edits_applied": pass1.get("edits", {}).get("applied_count"),
                    "siem_campaign_results": pass1.get("siem_campaign_results"),
                    "findings": pass1.get("findings"),
                },
                indent=2,
            )
        )

        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        assert (
            pass1["finding_count"] == 4
        ), f"Expected 4 findings, got {pass1['finding_count']}"
        assert pass1["comments"]["inserted_count"] == 4
        assert pass1["edits"]["applied_count"] == 4
        assert len(pass1["siem_campaign_results"]) == 3
        for sr in pass1["siem_campaign_results"]:
            assert sr["status"] == "success", f"SIEM campaign query failed: {sr}"
            assert (
                sr["events_matched"] > 0
            ), f"Expected >0 SIEM events for {sr['campaign_id']}"

        print(
            "[3/5] Inspecting pending suggestions and verifying 0 residual findings on accepted_text..."
        )
        inspected = inspect_doc_suggestions(
            REUSABLE_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert inspected["status"] == "success"
        assert inspected["suggestion_count"] == 4
        accepted_text = inspected["accepted_text"]
        synthetic_doc = {
            "body": {
                "content": [
                    {
                        "paragraph": {
                            "elements": [
                                {
                                    "startIndex": 1,
                                    "endIndex": len(accepted_text) + 1,
                                    "textRun": {"content": accepted_text},
                                }
                            ]
                        }
                    }
                ]
            }
        }
        acc_plain, acc_map = _extract_text_and_index_map(synthetic_doc)
        _, _, residual_findings = find_claim_evidence_and_campaign_spans(
            acc_plain, acc_map
        )
        print(
            f"      suggestion_count={inspected['suggestion_count']}, "
            f"residual_findings={len(residual_findings)}"
        )
        assert (
            len(residual_findings) == 0
        ), f"Expected 0 residual findings on accepted_text, got: {residual_findings}"

        acc_graph = build_cross_case_campaign_graph(acc_plain)
        for camp_id in (
            "CAMP-WINS-D19-ENDPOINT",
            "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER",
            "CAMP-GCP-CONTROL-PLANE-33278",
        ):
            missing = acc_graph["campaigns"][camp_id]["missing_sibling_cases_in_doc"]
            assert (
                missing == []
            ), f"Expected 0 missing sibling cases for {camp_id} in accepted_text, got {missing}"

        print("[4/5] Verifying anchored comments via list_doc_comments...")
        comments_list = list_doc_comments(
            REUSABLE_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert comments_list["status"] == "success"
        assert comments_list["unresolved_comment_count"] == 4

        print("[5/5] Running Pass 2 idempotency check...")
        clear_doc_index_cache()
        pass2 = audit_and_redline_claim_evidence_and_campaign_in_doc(
            REUSABLE_DOC_ID,
            run_live_siem_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        print(
            json.dumps(
                {
                    "status": pass2.get("status"),
                    "finding_count": pass2.get("finding_count"),
                    "skipped_existing_suggestion_count": pass2.get(
                        "skipped_existing_suggestion_count"
                    ),
                    "comments_inserted": pass2.get("comments", {}).get("inserted_count"),
                    "edits_applied": pass2.get("edits", {}).get("applied_count"),
                },
                indent=2,
            )
        )
        assert pass2["status"] == "success"
        assert pass2["finding_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 4
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        print("ALL CYCLE 16 (H5) LIVE VALIDATION ASSERTIONS PASSED.")
        return 0
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            if ts is not None:
                try:
                    loop.run_until_complete(ts.close())
                except Exception:
                    pass
        loop.close()


if __name__ == "__main__":
    raise SystemExit(main())
