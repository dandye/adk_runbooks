#!/usr/bin/env python3
"""Cycle 11 (H10 + H11) Live Validation Script.

Validates:
1. Lossless Google Docs Structural AST-to-Markdown Reconstructor (`reconstruct_markdown_from_doc_ast`),
   Unresolved Comment Governance Gate (`list_doc_comments` + `export_accepted_doc_to_markdown(..., require_resolved_comments=True)`),
   and `SkillRegistry` round-trip parsing on existing live Argolis Google Doc:
   - `1Pl_YLBmtyfFkT_R3xvQVugEb32KNyPfmbUQ-uiSex8o` (`Runbook_Redline_compromised-user-account-response_Case_33278`)
2. Italic-Stripped Regex Wildcard Recovery (`find_italic_corrupted_regex_spans`) and live Chronicle SIEM
   retrohunt restoration (`/.cmd./` -> `/.*cmd.*/` at UTF-16 `1139..1146`, `6` -> `12` events on `wins-d19`)
   plus multi-pass suggestion idempotency (`skipped_existing_suggestion_count=8`) on existing live Argolis Google Doc:
   - `1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc` (`Cycle3_H2_Live_YARAL2_Rule_Verifier_Validation`)

Allocates 0 new Google Docs in Google Drive.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "multi-agent")):
  if _p not in sys.path:
    sys.path.insert(0, _p)

from manager.tools.docs_review_tools import (  # noqa: E402
    _DOC_RAW_AST_CACHE,
    _iter_yaral2_rule_blocks,
    export_accepted_doc_to_markdown,
    find_italic_corrupted_regex_spans,
    inspect_doc_suggestions,
    list_doc_comments,
    read_google_doc,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)
import manager.tools.tools as tmod  # noqa: E402
from skills.drive_registry import parse_frontmatter  # noqa: E402

COMPROMISED_USER_DOC_ID = "1Pl_YLBmtyfFkT_R3xvQVugEb32KNyPfmbUQ-uiSex8o"
CYCLE3_YARAL2_DOC_ID = "1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc"


def main() -> int:
  loop = asyncio.new_event_loop()
  asyncio.set_event_loop(loop)

  print("=== Cycle 11 (H10 + H11) Live Validation ===")
  print("New Google Docs allocated: 0\n")

  # ---------------------------------------------------------------------------
  # Part 1: Unresolved Comment Governance Gate & Structural AST-to-Markdown
  #         on 1Pl_YLBmtyfFkT_R3xvQVugEb32KNyPfmbUQ-uiSex8o
  # ---------------------------------------------------------------------------
  print(
      f"[Part 1] Validating list_doc_comments, Governance Gate, and AST-to-Markdown on {COMPROMISED_USER_DOC_ID}..."
  )
  comments_res = list_doc_comments(COMPROMISED_USER_DOC_ID)
  assert comments_res["status"] == "success", f"list_doc_comments failed: {comments_res}"
  print(
      f"  list_doc_comments: total={comments_res['total_comment_count']}, "
      f"unresolved={comments_res['unresolved_comment_count']}, "
      f"resolved={comments_res['resolved_comment_count']}"
  )
  assert comments_res["total_comment_count"] >= 1, "Expected >=1 Drive comment on compromised-user doc"
  assert comments_res["unresolved_comment_count"] >= 1, "Expected >=1 unresolved comment on compromised-user doc"

  suggestions_res = inspect_doc_suggestions(COMPROMISED_USER_DOC_ID)
  assert suggestions_res["status"] == "success"
  print(
      f"  inspect_doc_suggestions: suggestion_count={suggestions_res['suggestion_count']}, "
      f"accepted_suggestion_count={suggestions_res['accepted_suggestion_count']}, "
      f"headings_reconstructed={suggestions_res['headings_reconstructed_count']}, "
      f"list_items_reconstructed={suggestions_res['list_items_reconstructed_count']}, "
      f"tables_reconstructed={suggestions_res['tables_reconstructed_count']}"
  )

  with tempfile.TemporaryDirectory() as tmpdir:
    blocked_out = Path(tmpdir) / "blocked_compromised_user.md"
    blocked_export = export_accepted_doc_to_markdown(
        COMPROMISED_USER_DOC_ID,
        output_path=str(blocked_out),
        reconstruct_markdown_structure=True,
        require_resolved_comments=True,
    )
    print(
        f"  Governance Gate (require_resolved_comments=True): status={blocked_export['status']}, "
        f"unresolved_comment_count={blocked_export['unresolved_comment_count']}"
    )
    assert blocked_export["status"] == "blocked_unresolved_comments"
    assert not blocked_out.exists(), "Blocked export must not write output_path"

    accepted_out = Path(tmpdir) / "accepted_compromised_user.md"
    accepted_export = export_accepted_doc_to_markdown(
        COMPROMISED_USER_DOC_ID,
        output_path=str(accepted_out),
        reconstruct_markdown_structure=True,
        require_resolved_comments=False,
    )
    assert accepted_export["status"] == "success", f"Export failed: {accepted_export}"
    assert accepted_out.exists()
    print(
        f"  Structural Export (require_resolved_comments=False): status={accepted_export['status']}, "
        f"skill_name={accepted_export['skill_name']!r}, "
        f"frontmatter_restored={accepted_export['frontmatter_restored']}, "
        f"headings={accepted_export['headings_reconstructed_count']}, "
        f"list_items={accepted_export['list_items_reconstructed_count']}, "
        f"tables={accepted_export['tables_reconstructed_count']}, "
        f"italic_regex_wildcards_recovered={accepted_export['italic_regex_wildcards_recovered_count']}"
    )
    assert accepted_export["headings_reconstructed_count"] >= 5
    assert accepted_export["list_items_reconstructed_count"] >= 5
    assert accepted_export["frontmatter_valid"] is True

    fm = parse_frontmatter(accepted_export["accepted_markdown"])
    assert fm.get("name") == "compromised-user-account-response", f"Unexpected frontmatter: {fm}"
    assert (
        "# Compromised User Account Incident Response Plan (IRP) / Runbook"
        in accepted_export["accepted_markdown"]
    )
    assert "## Objective" in accepted_export["accepted_markdown"]
    assert "### " in accepted_export["accepted_markdown"]

  # ---------------------------------------------------------------------------
  # Part 2: Italic-Stripped Regex Wildcard Recovery & Live SIEM Retrohunt
  #         on 1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc
  # ---------------------------------------------------------------------------
  print(
      f"\n[Part 2] Validating Italic-Stripped Regex Wildcard Recovery & Live SIEM on {CYCLE3_YARAL2_DOC_ID}..."
  )
  siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
  try:
    siem_tools = {
        t.name: t
        for t in loop.run_until_complete(siem_toolset.get_tools(readonly_context=None))
    }
    print(
        f"  Discovered {len(siem_tools)} SIEM tools "
        f"(validate_rule={'validate_rule' in siem_tools}, search_udm={'search_udm' in siem_tools})"
    )

    def live_siem_validate(rule_text: str) -> Any:
      return loop.run_until_complete(
          siem_tools["validate_rule"].run_async(
              args={"rule_text": rule_text},
              tool_context=None,
          )
      )

    def live_siem_search(
        query: str,
        start_time: str = "2026-02-07T00:00:00Z",
        end_time: str = "2026-02-08T00:00:00Z",
        max_events: int = 15,
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

    doc_info = read_google_doc(CYCLE3_YARAL2_DOC_ID)
    assert doc_info["status"] == "success"
    raw_doc = _DOC_RAW_AST_CACHE[CYCLE3_YARAL2_DOC_ID]

    italic_comments, italic_edits, italic_findings = find_italic_corrupted_regex_spans(
        raw_doc,
    )
    print(f"  find_italic_corrupted_regex_spans count: {len(italic_findings)}")
    assert len(italic_findings) >= 1, "Expected /.cmd./ italic-corrupted regex span"
    f0 = italic_findings[0]
    print(
        f"  Span 0: start_index={f0['start_index']}, end_index={f0['end_index']}, "
        f"quote={f0['quote']!r}, replacement={f0['replacement']!r}, "
        f"italic_subspans={f0['italic_subspans']}"
    )
    assert f0["quote"] == "/.cmd./"
    assert f0["replacement"] == "/.*cmd.*/"
    assert f0["end_index"] - f0["start_index"] == 7
    assert f0["start_index"] in (1035, 1139, 1148)

    # Extract baseline Rule 2 (wins_d19_lolbin_execution_case_33280) and compare
    # live SIEM retrohunt BEFORE vs AFTER italic wildcard recovery
    rule_blocks = _iter_yaral2_rule_blocks(doc_info["content"])
    rule2_block = next(
        b for b in rule_blocks if b["rule_name"] == "wins_d19_lolbin_execution_case_33280"
    )
    corrupted_siem = verify_yaral2_rule_with_siem(
        rule2_block["rule_text"],
        run_retrohunt_check=True,
        siem_validate_fn=live_siem_validate,
        siem_search_fn=live_siem_search,
        doc=None,
    )
    restored_siem = verify_yaral2_rule_with_siem(
        rule2_block["rule_text"],
        run_retrohunt_check=True,
        siem_validate_fn=live_siem_validate,
        siem_search_fn=live_siem_search,
        doc=raw_doc,
    )
    print(
        f"  Rule 2 WITHOUT italic wildcard recovery: "
        f"query={corrupted_siem['retrohunt_udm_query']!r}, "
        f"compiler_verified={corrupted_siem['compiler_verified']}, "
        f"retrohunt_event_count={corrupted_siem['retrohunt_event_count']}"
    )
    print(
        f"  Rule 2 WITH italic wildcard recovery (doc=raw_doc): "
        f"query={restored_siem['retrohunt_udm_query']!r}, "
        f"compiler_verified={restored_siem['compiler_verified']}, "
        f"retrohunt_event_count={restored_siem['retrohunt_event_count']}"
    )
    assert corrupted_siem["retrohunt_event_count"] == 6, (
        f"Expected 6 events with corrupted /.cmd./ (got {corrupted_siem['retrohunt_event_count']})"
    )
    assert restored_siem["compiler_verified"] is True
    assert "/.*cmd.*/" in restored_siem["retrohunt_udm_query"]
    assert restored_siem["retrohunt_event_count"] == 12, (
        f"Expected 12 events after restoring /.*cmd.*/ (got {restored_siem['retrohunt_event_count']})"
    )

    # Verify the staged suggestion on 1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc
    # and multi-pass idempotency
    c3_inspected = inspect_doc_suggestions(CYCLE3_YARAL2_DOC_ID)
    assert c3_inspected["status"] == "success"
    wildcard_suggs = [
        s
        for s in c3_inspected["suggestions"]
        if s.get("deleted_text") == "/.cmd./" and s.get("inserted_text") == "/.*cmd.*/"
    ]
    print(
        f"  inspect_doc_suggestions on {CYCLE3_YARAL2_DOC_ID}: "
        f"suggestion_count={c3_inspected['suggestion_count']}, "
        f"wildcard_suggestion={wildcard_suggs}"
    )
    assert c3_inspected["suggestion_count"] == 8
    assert len(wildcard_suggs) == 1

    print("  Running multi-pass idempotency check of verify_and_redline_yaral2_rules_in_doc...")
    pass2 = verify_and_redline_yaral2_rules_in_doc(
        CYCLE3_YARAL2_DOC_ID,
        run_live_siem_check=True,
        siem_validate_fn=live_siem_validate,
        siem_search_fn=live_siem_search,
    )
    assert pass2["status"] == "success"
    print(
        f"  Idempotency result: yaral2_findings_count={pass2['yaral2_findings_count']}, "
        f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
    )
    assert pass2["yaral2_findings_count"] == 0
    assert pass2["skipped_existing_suggestion_count"] == 8

    # Verify accepted Markdown export on 1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc
    cycle3_export = export_accepted_doc_to_markdown(
        CYCLE3_YARAL2_DOC_ID,
        reconstruct_markdown_structure=True,
        require_resolved_comments=False,
    )
    assert cycle3_export["status"] == "success"
    print(
        f"  Accepted export on {CYCLE3_YARAL2_DOC_ID}: "
        f"headings={cycle3_export['headings_reconstructed_count']}, "
        f"tables={cycle3_export['tables_reconstructed_count']}, "
        f"contains /.*cmd.*/={'/.*cmd.*/' in cycle3_export['accepted_markdown']}"
    )
    assert cycle3_export["headings_reconstructed_count"] >= 3
    assert "/.*cmd.*/" in cycle3_export["accepted_markdown"]
  finally:
    for ts in (siem_toolset, soar_toolset, gti_toolset):
      if ts is not None:
        try:
          loop.run_until_complete(ts.close())
        except Exception:
          pass

  summary = {
      "status": "PASS",
      "new_google_docs_allocated": 0,
      "compromised_user_doc": {
          "document_id": COMPROMISED_USER_DOC_ID,
          "total_comment_count": comments_res["total_comment_count"],
          "unresolved_comment_count": comments_res["unresolved_comment_count"],
          "governance_gate_status": blocked_export["status"],
          "skill_name": accepted_export["skill_name"],
          "frontmatter_restored": accepted_export["frontmatter_restored"],
          "headings_reconstructed_count": accepted_export["headings_reconstructed_count"],
          "list_items_reconstructed_count": accepted_export["list_items_reconstructed_count"],
          "tables_reconstructed_count": accepted_export["tables_reconstructed_count"],
      },
      "cycle3_yaral2_doc": {
          "document_id": CYCLE3_YARAL2_DOC_ID,
          "italic_corrupted_span": {
              "start_index": f0["start_index"],
              "end_index": f0["end_index"],
              "quote": f0["quote"],
              "replacement": f0["replacement"],
              "italic_subspans": f0["italic_subspans"],
          },
          "corrupted_retrohunt_udm_query": corrupted_siem["retrohunt_udm_query"],
          "corrupted_retrohunt_event_count": corrupted_siem["retrohunt_event_count"],
          "restored_retrohunt_udm_query": restored_siem["retrohunt_udm_query"],
          "restored_retrohunt_event_count": restored_siem["retrohunt_event_count"],
          "siem_compiler_verified": restored_siem["compiler_verified"],
          "total_suggestions_on_doc": c3_inspected["suggestion_count"],
          "wildcard_suggestion_id": wildcard_suggs[0]["suggestion_id"],
          "idempotency_findings_staged": pass2["yaral2_findings_count"],
          "idempotency_skipped_existing": pass2["skipped_existing_suggestion_count"],
          "accepted_markdown_headings_reconstructed": cycle3_export["headings_reconstructed_count"],
          "accepted_markdown_has_restored_wildcard": "/.*cmd.*/" in cycle3_export["accepted_markdown"],
      },
  }
  print("\n=== SUMMARY JSON ===")
  print(json.dumps(summary, indent=2))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
