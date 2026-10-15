#!/usr/bin/env python3
"""Cycle 15 (H13) Live Validation: Automated Leaked Credential Blast-Radius Triage,
Safe JWT Claim Extraction & Emergency Revocation Playbook Stager in Google Docs.

Reuses and resets the existing Cycle 5 Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. Pure-Python Base64URL safe JWT header/payload claim decoding (``sub``,
   ``email``, ``iss``, ``aud``, ``scope``, ``kid``) without exposing the
   cryptographic signature.
2. Live Chronicle SIEM (``dandye-0324-chronicle``) blast-radius hunting across
   ``GCP_CLOUDAUDIT`` (Case ``33278``, ``104.198.226.161``,
   ``294955789222-compute@developer.gserviceaccount.com``,
   ``hello@base-production.iam.gserviceaccount.com``, ``projects/base-production``)
   and ``WORKSPACE_ACTIVITY`` (Case ``33287``, ``79.154.246.114``,
   ``admin@mydomain.com``).
3. Non-destructive ``writeMode="SUGGEST"`` red-lining across all 6 credential
   and containment defect categories:
   - ``unredacted_leaked_credential``
   - ``destructive_service_account_delete``
   - ``local_only_gcloud_auth_revoke``
   - ``destructive_workspace_user_delete``
   - ``missing_credential_revocation_command``
   - ``destructive_aws_access_key_delete``
4. Multi-pass suggestion idempotency on Pass 2 (``skipped_existing_suggestion_count == 6``).
"""

from __future__ import annotations

import asyncio
import base64
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
    _load_doc_index_state,
    clear_doc_index_cache,
    decode_jwt_safe_claims,
    extract_leaked_credential_inventories,
    inspect_doc_suggestions,
    read_google_doc,
    resolve_docs_token,
    triage_and_redline_leaked_credentials_in_doc,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

EXISTING_CYCLE5_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle15_H13_Live_Leaked_Credential_Blast_Radius_and_Containment_Validation"


def _build_synthetic_jwt() -> str:
    """Builds a synthetic 3-part OIDC/OAuth JWT for Case 33278 validation."""
    header = {"alg": "RS256", "kid": "71f09a8b2c3d4e5f", "typ": "JWT"}
    payload = {
        "iss": "https://accounts.google.com",
        "sub": "294955789222-compute@developer.gserviceaccount.com",
        "email": "294955789222-compute@developer.gserviceaccount.com",
        "aud": "https://cloudresourcemanager.googleapis.com/",
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "exp": 1770508800,
    }
    h_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    p_b64 = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    sig = "SyntheticSignatureForValidationOnly9876543210abcdef"
    return f"{h_b64}.{p_b64}.{sig}"


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
    jwt_token = _build_synthetic_jwt()
    validation_doc_content = (
        "# Cycle 15 (H13) Live Validation: Leaked Credential Blast-Radius & Containment Stager\n\n"
        "## Scenario 1: Compromised GCP Compute Service Account OIDC JWT (Case 33278)\n"
        f"- Captured Authorization bearer token from source IP `104.198.226.161` targeting `projects/base-production`: `{jwt_token}`\n"
        "- Drafted destructive containment step: `gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com`\n"
        "- Drafted ineffective local workstation step: `gcloud auth revoke 294955789222-compute@developer.gserviceaccount.com`\n\n"
        "## Scenario 2: Compromised Google Workspace Super-Admin Session (Case 33287)\n"
        "- Redacted session token `<REDACTED_JWT:sha256=fedcba987654>` used by `admin@mydomain.com` from source IP `79.154.246.114`.\n"
        "- Drafted destructive containment step: `gam user admin@mydomain.com delete`\n\n"
        "## Scenario 3: Escalated GCP IAM Service Account Token Missing Revocation Playbook Step (Case 33278)\n"
        "- Stolen OAuth2 bearer token `<REDACTED_GCP_TOKEN:sha256=89abcdef0123>` for `hello@base-production.iam.gserviceaccount.com` observed from `104.198.226.161` on `projects/base-production`.\n\n"
        "## Scenario 4: Cross-Cloud AWS IAM Access Key Containment\n"
        "- Drafted destructive AWS CLI step: `aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name ci-deployer`\n"
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
        plain_text, index_map = _load_doc_index_state(EXISTING_CYCLE5_DOC_ID)
        assert plain_text is not None and index_map is not None

        claims = decode_jwt_safe_claims(jwt_token)
        assert claims["valid_jwt"] is True
        assert claims["kid"] == "71f09a8b2c3d4e5f"
        assert (
            claims["service_account_email"]
            == "294955789222-compute@developer.gserviceaccount.com"
        )

        inventories = extract_leaked_credential_inventories(plain_text, index_map)
        assert len(inventories) == 3, f"Expected 3 credentials, got {len(inventories)}"

        print(
            "[2/5] Running Pass 1 of triage_and_redline_leaked_credentials_in_doc with live Chronicle SIEM check..."
        )
        pass1 = triage_and_redline_leaked_credentials_in_doc(
            EXISTING_CYCLE5_DOC_ID,
            run_live_siem_check=True,
            redact_unredacted_credentials=True,
            synthesize_missing_revocation=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        assert pass1["credential_count"] == 3
        assert pass1["finding_count"] == 6
        assert pass1["comments"]["inserted_count"] == 6
        assert pass1["edits"]["applied_count"] == 6
        assert pass1["skipped_existing_suggestion_count"] == 0

        siem_results = pass1["siem_triage_results"]
        assert len(siem_results) == 3
        for sr in siem_results:
            assert sr["status"] == "success", f"SIEM triage failed: {sr}"
            assert sr["siem_verified"] is True
            assert sr["events_matched"] >= 1, f"Expected >=1 SIEM event, got {sr}"
            print(
                f"  -> SIEM Blast Radius ({sr['principal_email']} / {sr['source_ip']}): "
                f"events_matched={sr['events_matched']} actions={sr['observed_actions']}"
            )

        print("[3/5] Inspecting inline suggestions via inspect_doc_suggestions...")
        inspected = inspect_doc_suggestions(
            EXISTING_CYCLE5_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert inspected["status"] == "success"
        assert inspected["suggestion_count"] == 6
        accepted_text = inspected["accepted_text"]
        assert jwt_token not in accepted_text
        assert "<REDACTED_JWT:sha256=" in accepted_text
        assert (
            "gcloud iam service-accounts disable 294955789222-compute@developer.gserviceaccount.com"
            in accepted_text
        )
        assert "gam user admin@mydomain.com suspend" in accepted_text
        assert (
            "[Emergency Revocation: `gcloud iam service-accounts disable hello@base-production.iam.gserviceaccount.com`]"
            in accepted_text
        )
        assert (
            "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name ci-deployer"
            in accepted_text
        )

        print("[4/5] Running Pass 2 to verify multi-pass suggestion idempotency...")
        clear_doc_index_cache()
        pass2 = triage_and_redline_leaked_credentials_in_doc(
            EXISTING_CYCLE5_DOC_ID,
            run_live_siem_check=True,
            redact_unredacted_credentials=True,
            synthesize_missing_revocation=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            siem_search_fn=live_siem_search_fn,
            token_source=token_source,
            quota_project=quota_project,
        )
        assert pass2["status"] == "success"
        assert pass2["finding_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 6
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        summary = {
            "status": "success",
            "cycle": 15,
            "horizon_id": "H13",
            "document_id": EXISTING_CYCLE5_DOC_ID,
            "new_docs_created": 0,
            "reset_info": reset_info,
            "credential_count": pass1["credential_count"],
            "pass1_finding_count": pass1["finding_count"],
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "pass2_skipped_existing_suggestions": pass2[
                "skipped_existing_suggestion_count"
            ],
            "pass2_edits_applied": pass2["edits"]["applied_count"],
            "siem_triage_results": [
                {
                    "principal_email": r["principal_email"],
                    "source_ip": r["source_ip"],
                    "siem_query": r["siem_query"],
                    "events_matched": r["events_matched"],
                    "observed_actions": r["observed_actions"],
                    "target_resources": r["target_resources"],
                }
                for r in siem_results
            ],
        }
        print("[5/5] Cycle 15 (H13) Live Validation Summary:")
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
