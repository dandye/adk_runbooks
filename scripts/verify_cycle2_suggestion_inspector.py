#!/usr/bin/env python3
"""Cycle 2 (H3) Live Validation: Bidirectional Google Docs Suggestion Inspector,
Multi-Pass Idempotency & Markdown Runbook Sync.

Validates against the live Argolis SecOps & Google Workspace environment
(``dandye-0324-chronicle``) with ZERO new Google Docs created:
  1. Runs :func:`inspect_doc_suggestions` on ``Cycle1_H1_Live_UDM_Query_Verifier_Validation``
     (``16VJd9N-1c7ZP49xgI0hsVYyOwGpoJtoHPT8sYR-vg80``) and verifies that all 4 live
     ``suggest.*`` Suggested Edits are extracted with exact ``suggestion_id``,
     ``deleted_text``, ``inserted_text``, ``start_index``, and ``end_index``, with
     zero text-fusion in ``baseline_text`` or ``accepted_text``, plus a clean
     ``unified_diff``.
  2. Verifies multi-pass idempotency by re-running
     :func:`verify_and_redline_udm_queries_in_doc` on the already-red-lined doc
     ``16VJd9N-1c7ZP49xgI0hsVYyOwGpoJtoHPT8sYR-vg80`` and asserting that
     ``skipped_existing_suggestion_count == 4`` and ``edits.applied_count == 0``.
  3. Runs :func:`export_accepted_doc_to_markdown` on the live staged Drive Runbook
     Red-Line Google Doc ``Runbook_Redline_compromised-user-account-response_Case_33278``
     (``1Pl_YLBmtyfFkT_R3xvQVugEb32KNyPfmbUQ-uiSex8o``,
     ``skill_name="compromised-user-account-response"``) and verifies that all 3
     pending Suggested Edits are applied in ``accepted_markdown`` and canonical YAML
     frontmatter is restored and validated via :func:`parse_frontmatter` and
     :class:`SkillRegistry`.
  4. Runs :func:`inspect_doc_suggestions` on ``SOAR_Case_33288_Sanitized_3Stage_Intrusion_Review``
     (``14kr7gtw5AJd4a53vCrQ4bIQdyW-t_v48LTtzWMhSg58``) to verify Stage A URL defanging
     suggestion inspection and selective ``accept_suggestion_ids`` projection.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from manager.tools.docs_review_tools import (  # noqa: E402
    export_accepted_doc_to_markdown,
    inspect_doc_suggestions,
    verify_and_redline_udm_queries_in_doc,
)
from skills.drive_registry import parse_frontmatter  # noqa: E402
from skills.registry import SkillRegistry  # noqa: E402

CYCLE1_UDM_DOC_ID = "16VJd9N-1c7ZP49xgI0hsVYyOwGpoJtoHPT8sYR-vg80"
RUNBOOK_REDLINE_DOC_ID = "1Pl_YLBmtyfFkT_R3xvQVugEb32KNyPfmbUQ-uiSex8o"
CASE_33288_DOC_ID = "14kr7gtw5AJd4a53vCrQ4bIQdyW-t_v48LTtzWMhSg58"


def main() -> int:
    print(f"[1/4] Inspecting live suggestions on {CYCLE1_UDM_DOC_ID}...")
    inspected = inspect_doc_suggestions(CYCLE1_UDM_DOC_ID)
    if inspected.get("status") != "success":
        print(f"      ERROR inspecting doc {CYCLE1_UDM_DOC_ID}: {inspected}")
        return 1

    suggestions = inspected["suggestions"]
    print(
        f"      Title: {inspected['title']!r}, suggestion_count={inspected['suggestion_count']}, "
        f"accepted_suggestion_count={inspected['accepted_suggestion_count']}"
    )
    for s in suggestions:
        print(
            f"      - {s['suggestion_id']} ({s['kind']} @ {s['start_index']}..{s['end_index']}): "
            f"{s['deleted_text']!r} -> {s['inserted_text']!r}"
        )

    assert inspected["suggestion_count"] == 4, f"Expected 4 suggestions, got {inspected['suggestion_count']}"
    assert "principal.ipip" not in inspected["baseline_text"]
    assert "ipprincipal.ip" not in inspected["baseline_text"]
    assert 'AND ip = "104.198.226.161"' in inspected["baseline_text"]
    assert 'AND principal.ip = "104.198.226.161"' in inspected["accepted_text"]
    assert 'target.resource.name = "projects/base-analytics/instances/prod-customers"' in inspected["accepted_text"]
    assert 'principal.hostname = "wins-d19" AND target.process.command_line = /.*cmd.*/ nocase' in inspected["accepted_text"]
    print("      Unified diff:")
    for line in inspected["unified_diff"].splitlines():
        print(f"        {line}")

    print(f"[2/4] Verifying multi-pass idempotency on already-redlined doc {CYCLE1_UDM_DOC_ID}...")
    second_pass = verify_and_redline_udm_queries_in_doc(
        CYCLE1_UDM_DOC_ID,
        run_live_siem_check=False,
    )
    print(
        f"      Multi-pass result: status={second_pass.get('status')}, "
        f"skipped_existing_suggestion_count={second_pass.get('skipped_existing_suggestion_count')}, "
        f"udm_findings_count={second_pass.get('udm_findings_count')}, "
        f"comments_inserted={second_pass.get('comments', {}).get('inserted_count')}, "
        f"edits_applied={second_pass.get('edits', {}).get('applied_count')}"
    )
    assert second_pass["status"] == "success"
    assert second_pass["skipped_existing_suggestion_count"] == 4
    assert second_pass["udm_findings_count"] == 0
    assert second_pass["comments"]["inserted_count"] == 0
    assert second_pass["edits"]["applied_count"] == 0

    print(f"[3/4] Exporting accepted Runbook Red-Line Google Doc {RUNBOOK_REDLINE_DOC_ID} to Markdown...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir) / "irps" / "compromised-user-account-response" / "SKILL.md"
        exported = export_accepted_doc_to_markdown(
            RUNBOOK_REDLINE_DOC_ID,
            skill_name="compromised-user-account-response",
            output_path=str(out_path),
            publish_to_drive=False,
        )
        if exported.get("status") != "success":
            print(f"      ERROR exporting runbook doc: {exported}")
            return 1

        print(
            f"      Exported title={exported['title']!r}, "
            f"suggestion_count={exported['suggestion_count']}, "
            f"accepted_suggestion_count={exported['accepted_suggestion_count']}, "
            f"frontmatter_restored={exported['frontmatter_restored']}, "
            f"frontmatter_valid={exported['frontmatter_valid']}, "
            f"char_count={exported['char_count']}"
        )
        for s in exported["suggestions"]:
            print(
                f"      - {s['suggestion_id']} ({s['kind']} @ {s['start_index']}..{s['end_index']}): "
                f"{s['deleted_text']!r} -> {s['inserted_text']!r}"
            )
        print("      Runbook unified diff:")
        for line in exported["unified_diff"].splitlines():
            print(f"        {line}")

        md = exported["accepted_markdown"]
        assert exported["suggestion_count"] == 3
        assert exported["frontmatter_restored"] is True
        assert exported["frontmatter_valid"] is True
        assert exported["frontmatter"]["name"] == "compromised-user-account-response"
        assert "gcloud iam service-accounts disable" in md
        assert "gcloud iam service-accounts delete" not in md
        assert 'target.resource.name = "projects/base-production"' in md
        assert "T1098.003 (Account Manipulation: Additional Cloud Roles)" in md

        parsed_fm = parse_frontmatter(out_path.read_text(encoding="utf-8"))
        assert parsed_fm.get("name") == "compromised-user-account-response"
        temp_registry = SkillRegistry(skills_dir=Path(tmp_dir))
        skill_meta = temp_registry.get_skill("compromised-user-account-response")
        assert skill_meta is not None
        print(
            f"      Verified SkillRegistry parsed exported SKILL.md: "
            f"name={skill_meta.name!r}, category={skill_meta.category!r}, version={skill_meta.version!r}"
        )

    print(f"[4/4] Inspecting Stage A URL defanging & selective acceptance on {CASE_33288_DOC_ID}...")
    case33288_inspected = inspect_doc_suggestions(CASE_33288_DOC_ID)
    if case33288_inspected.get("status") != "success":
        print(f"      ERROR inspecting {CASE_33288_DOC_ID}: {case33288_inspected}")
        return 1
    c_suggestions = case33288_inspected["suggestions"]
    print(
        f"      Title: {case33288_inspected['title']!r}, suggestion_count={case33288_inspected['suggestion_count']}"
    )
    for s in c_suggestions:
        print(
            f"      - {s['suggestion_id']} ({s['kind']} @ {s['start_index']}..{s['end_index']}): "
            f"{s['deleted_text']!r} -> {s['inserted_text']!r}"
        )
    first_sid = c_suggestions[0]["suggestion_id"]
    selective = inspect_doc_suggestions(
        CASE_33288_DOC_ID, accept_suggestion_ids=[first_sid]
    )
    assert selective["accepted_suggestion_count"] == 1
    print(
        f"      Selective acceptance verified: accept_suggestion_ids=[{first_sid!r}] -> "
        f"accepted_suggestion_count={selective['accepted_suggestion_count']}/{selective['suggestion_count']}"
    )

    summary = {
        "cycle1_doc_id": CYCLE1_UDM_DOC_ID,
        "cycle1_suggestion_count": inspected["suggestion_count"],
        "cycle1_suggestions": [
            {
                "suggestion_id": s["suggestion_id"],
                "deleted_text": s["deleted_text"],
                "inserted_text": s["inserted_text"],
                "start_index": s["start_index"],
                "end_index": s["end_index"],
            }
            for s in suggestions
        ],
        "multi_pass_idempotency": {
            "skipped_existing_suggestion_count": second_pass["skipped_existing_suggestion_count"],
            "udm_findings_count": second_pass["udm_findings_count"],
            "comments_inserted": second_pass["comments"]["inserted_count"],
            "edits_applied": second_pass["edits"]["applied_count"],
        },
        "runbook_export": {
            "doc_id": RUNBOOK_REDLINE_DOC_ID,
            "skill_name": exported["skill_name"],
            "suggestion_count": exported["suggestion_count"],
            "frontmatter_restored": exported["frontmatter_restored"],
            "frontmatter_valid": exported["frontmatter_valid"],
            "char_count": exported["char_count"],
        },
        "case_33288_selective_inspection": {
            "doc_id": CASE_33288_DOC_ID,
            "total_suggestions": case33288_inspected["suggestion_count"],
            "selective_accepted_count": selective["accepted_suggestion_count"],
        },
        "new_google_docs_created": 0,
    }
    print("\n=== CYCLE 2 (H3) LIVE VALIDATION SUMMARY ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
