#!/usr/bin/env python3
"""Cycle 4 (H4) Live Validation: Deterministic + Grounded MITRE ATT&CK & CVE/KEV
Span Verifier.

Validates against the live Argolis Google Workspace & SecOps environment
(``dandye-0324-chronicle``):
  1. Creates 1 Google Doc ``Cycle4_H4_Live_MITRE_ATTACK_and_CVE_Verifier_Validation``
     in ``SOC Reports`` containing realistic postmortem attribution lines and
     YARA-L 2.0 (``YL2``) ``meta:`` blocks across our Argolis SOAR cases
     (``33269``, ``33278``, ``33288``) and CISA KEV perimeter advisories with
     6 seeded taxonomy/attribution defects plus 2 valid control citations:
     - Seeded Defect 1 (Case ``33269`` PowerShell Empire stager): deprecated
       pre-subtechnique ATT&CK ID ``T1086`` -> ``T1059.001`` (Command and
       Scripting Interpreter: PowerShell).
     - Seeded Defect 2 (Case ``33269`` YARA-L 2.0 ``meta:`` block): sibling
       sub-technique mismatch ``T1059.003`` (Windows Command Shell) paired with
       ``powershell.exe -NoP -W Hidden`` -> ``T1059.001``.
     - Seeded Defect 3 (Case ``33288`` LSASS dump on ``win-f01``): sibling
       sub-technique mismatch ``T1003.002`` (Security Account Manager) paired
       with ``rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump`` ->
       ``T1003.001`` (OS Credential Dumping: LSASS Memory).
     - Seeded Defect 4 (Case ``33278`` GCP IAM compromise): sibling
       sub-technique mismatch ``T1078.001`` (Default Accounts) paired with GCP
       IAM service account ``base-service-account@base-production.iam.gserviceaccount.com``
       -> ``T1078.004`` (Valid Accounts: Cloud Accounts).
     - Seeded Defect 5 (Case ``33278`` YARA-L 2.0 ``meta:`` block): sibling
       sub-technique mismatch ``T1098.001`` (Additional Cloud Credentials)
       paired with ``SetIamPolicy`` granting ``roles/editor`` -> ``T1098.003``
       (Account Manipulation: Additional Cloud Roles).
     - Seeded Defect 6 (Edge VPN Perimeter Advisory): cross-vendor CISA KEV CVE
       swap ``CVE-2024-21887`` (Ivanti Connect Secure) attributed to Fortinet
       FortiOS SSL VPN out-of-bounds write -> ``CVE-2024-21762``.
     - Valid Control Citations (must NOT be flagged): ``T1218.011`` (System
       Binary Proxy Execution: Rundll32) and ``CVE-2024-3400`` (Palo Alto
       Networks PAN-OS GlobalProtect).
  2. Executes :func:`verify_and_redline_mitre_and_cve_in_doc` with
     ``run_web_grounding_check=True`` against the live Google Doc and confirms
     that all 6 defective spans receive anchored Google Docs comments with
     canonical ``attack.mitre.org``, ``nvd.nist.gov``, and ``cisa.gov`` URLs
     followed by 6 descending-index ``writeMode="SUGGEST"`` replacements, with
     zero false positives on the 2 valid control citations.
  3. Executes :func:`inspect_doc_suggestions` on the live Google Doc to verify
     all 6 ``suggest.*`` replacement pairs and unified diff between baseline and
     accepted projections.
  4. Re-runs :func:`verify_and_redline_mitre_and_cve_in_doc` a second time on
     the same document to confirm multi-pass idempotency
     (``skipped_existing_suggestion_count == 6``, ``edits.applied_count == 0``).
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
    verify_and_redline_mitre_and_cve_in_doc,
)
from manager.tools.drive_tools import reports_folder_id  # noqa: E402
from skills.drive_registry import DriveMcpClient  # noqa: E402

DOC_TITLE = "Cycle4_H4_Live_MITRE_ATTACK_and_CVE_Verifier_Validation"

VALIDATION_DOC_CONTENT = """# Cycle 4 (H4) Live Validation: Deterministic + Grounded MITRE ATT&CK & CVE/KEV Span Verifier

## 1. SOAR Case 33269: PowerShell Empire Stager on Endpoint (Execution)
- Observed Stager Attribution: Initial Empire stager execution mapped to deprecated technique ID T1086 (PowerShell Empire stager) during triage.
- YARA-L 2.0 (YL2) Detection Rule Meta Attribution:
  meta: mitre_attack_technique = "T1059.003" for powershell.exe -NoP -W Hidden encoded command execution on endpoint.

## 2. SOAR Case 33288: LSASS Memory Dump via Rundll32 on win-f01 (Credential Access & Defense Evasion)
- Credential Dumping Attribution: Attacker dumped LSASS process memory using rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump and attributed it to T1003.002 in the draft postmortem.
- Valid Proxy Execution Control Citation: System Binary Proxy Execution via rundll32.exe is canonically mapped to T1218.011 (https://attack.mitre.org/techniques/T1218/011/).

## 3. SOAR Case 33278: GCP Service Account Privilege Escalation (Initial Access & Persistence)
- Compromised Identity Attribution: Attacker authenticated as GCP IAM service account base-service-account@base-production.iam.gserviceaccount.com mapped to T1078.001 in initial notes.
- Privilege Escalation Attribution: Subsequent SetIamPolicy call granting roles/editor on projects/base-production was mapped to T1098.001 in the YARA-L 2.0 meta section.

## 4. Enterprise Edge VPN CISA KEV Advisories (Initial Access)
- Fortinet Perimeter Gateway: Unauthenticated out-of-bounds write on Fortinet FortiOS SSL VPN tracked under CVE-2024-21887 in the draft executive table.
- Valid Palo Alto Networks Control Citation: Command injection on Palo Alto Networks PAN-OS GlobalProtect gateway is canonically tracked under CVE-2024-3400 (https://nvd.nist.gov/vuln/detail/CVE-2024-3400).
"""


def _resolve_or_create_validation_doc() -> tuple[str, str]:
    """Reuses the Cycle 4 validation Google Doc if already created, or creates 1."""
    folder = reports_folder_id()
    if folder:
        client = DriveMcpClient()
        try:
            for item in client.iter_files(f"parentId = '{folder}'"):
                if str(item.get("title") or "").strip() == DOC_TITLE:
                    doc_id = str(item.get("id") or "").strip()
                    if doc_id:
                        return doc_id, f"https://docs.google.com/document/d/{doc_id}/edit"
        finally:
            client.close()

    created = create_google_doc(
        title=DOC_TITLE,
        content=VALIDATION_DOC_CONTENT,
    )
    assert created.get("status") == "success", f"create_google_doc failed: {created}"
    doc_id = str(created.get("document_id") or created.get("documentId") or "")
    view_url = created.get("viewUrl") or f"https://docs.google.com/document/d/{doc_id}/edit"
    return doc_id, view_url


def main() -> int:
    print(f"[1/4] Resolving/creating live Google Doc {DOC_TITLE!r} in SOC Reports...")
    doc_id, view_url = _resolve_or_create_validation_doc()
    print(f"      Google Doc ID: {doc_id}")
    print(f"      View URL:      {view_url}")

    print(
        f"[2/4] Running verify_and_redline_mitre_and_cve_in_doc({doc_id!r}, "
        "run_web_grounding_check=True)..."
    )
    redline_res = verify_and_redline_mitre_and_cve_in_doc(
        doc_id,
        run_web_grounding_check=True,
    )
    assert redline_res.get("status") == "success", f"Redline failed: {redline_res}"
    print(
        f"      mitre_cve_findings_count={redline_res['mitre_cve_findings_count']}, "
        f"comments_inserted={redline_res['comments']['inserted_count']}, "
        f"edits_applied={redline_res['edits']['applied_count']}"
    )
    for f in redline_res["findings"]:
        print(
            f"      - [{f['defect_type']}] {f['invalid_id']!r} -> {f['canonical_id']!r} "
            f"({f['canonical_name']}) @ UTF-16 {f['start_index']}..{f['end_index']}"
        )

    assert redline_res["mitre_cve_findings_count"] == 6
    assert redline_res["comments"]["inserted_count"] == 6
    assert redline_res["edits"]["applied_count"] == 6

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
    assert inspected["suggestion_count"] == 6

    print("[4/4] Re-running verify_and_redline_mitre_and_cve_in_doc to verify multi-pass idempotency...")
    second_pass = verify_and_redline_mitre_and_cve_in_doc(
        doc_id,
        run_web_grounding_check=False,
    )
    print(
        f"      Multi-pass idempotency: "
        f"skipped_existing_suggestion_count={second_pass['skipped_existing_suggestion_count']}, "
        f"mitre_cve_findings_count={second_pass['mitre_cve_findings_count']}, "
        f"comments_inserted={second_pass['comments']['inserted_count']}, "
        f"edits_applied={second_pass['edits']['applied_count']}"
    )
    assert second_pass["status"] == "success"
    assert second_pass["skipped_existing_suggestion_count"] == 6
    assert second_pass["mitre_cve_findings_count"] == 0
    assert second_pass["comments"]["inserted_count"] == 0
    assert second_pass["edits"]["applied_count"] == 0

    summary = {
        "status": redline_res["status"],
        "document_id": doc_id,
        "viewUrl": view_url,
        "char_count": redline_res["char_count"],
        "mitre_cve_findings_count": redline_res["mitre_cve_findings_count"],
        "findings": [
            {
                "defect_type": f["defect_type"],
                "invalid_id": f["invalid_id"],
                "canonical_id": f["canonical_id"],
                "canonical_name": f["canonical_name"],
                "tactic": f["tactic"],
                "reference_url": f["reference_url"],
                "start_index": f["start_index"],
                "end_index": f["end_index"],
            }
            for f in redline_res["findings"]
        ],
        "grounding_checks": redline_res["grounding_checks"],
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
            "mitre_cve_findings_count": second_pass["mitre_cve_findings_count"],
            "comments_inserted": second_pass["comments"]["inserted_count"],
            "edits_applied": second_pass["edits"]["applied_count"],
        },
        "new_google_docs_created": 1,
    }
    print("\n=== CYCLE 4 (H4) LIVE VALIDATION SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
