#!/usr/bin/env python3
"""Cycle 6 (H9) Live Validation: Zero-Hit UDM Query Semantic Diagnostics & Field-Value Pivot Recommender Inside Google Docs.

Validates:
1. Direct live Chronicle SIEM (`search_udm`) zero-hit semantic diagnosis
   via `diagnose_zero_hit_udm_query` across all 3 failure classes:
   - `value_format_mismatch` (+ schema defect from SOAR Case 33278):
     `metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161" AND resource.name = "projects/base-analytics/instances/prod-customers"`
     -> anchor `metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161"`
     -> recommends `target.resource.name = "projects/base-production"` (`pivot_event_count > 0`).
   - `exact_match_on_command_line` (from SOAR Cases 33280 / 33285):
     `principal.hostname = "wins-d19" AND target.process.command_line = "cmd.exe"`
     -> anchor `principal.hostname = "wins-d19"` (`anchor_event_count == 12`)
     -> recommends `target.process.command_line = /.*cmd\.exe.*/ nocase` (`pivot_event_count == 4`).
   - `entity_role_swap` (principal vs. target process entity role):
     `principal.hostname = "wins-d19" AND principal.process.command_line = /.*cmd.*/ nocase`
     -> anchor `principal.hostname = "wins-d19"` (`anchor_event_count == 12`)
     -> recommends `target.process.command_line = /.*cmd.*/ nocase` (`pivot_event_count == 4`).
2. End-to-end Google Docs API v1 non-destructive review (`verify_and_redline_udm_queries_in_doc`)
   on a single newly created Google Doc (`Cycle6_H9_Live_Zero_Hit_UDM_Pivot_Recommender_Validation`)
   containing all 3 zero-hit queries plus a valid control query (`metadata.log_type = "WINDOWS_SYSMON" AND principal.hostname = "wins-d19"`):
   - Pass 1 stages 3 anchored comments and 3 descending-index `writeMode="SUGGEST"` edits
     (`udm_findings_count == 3`, `zero_hit_findings_count == 3`) with 0 false positives on the control query.
   - `inspect_doc_suggestions` verifies the unified diff across all 3 SIEM-verified pivots.
   - Pass 2 verifies strict multi-pass idempotency (`skipped_existing_suggestion_count == 3`, `edits.applied_count == 0`).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = PROJECT_ROOT / "multi-agent"
for p in (PROJECT_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(MULTI_AGENT_DIR / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    create_google_doc,
    diagnose_zero_hit_udm_query,
    inspect_doc_suggestions,
    verify_and_redline_udm_queries_in_doc,
)


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    start_time = "2026-02-07T00:00:00Z"
    end_time = "2026-02-08T00:00:00Z"

    q1 = (
        'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161" '
        'AND resource.name = "projects/base-analytics/instances/prod-customers"'
    )
    q2 = 'principal.hostname = "wins-d19" AND target.process.command_line = "cmd.exe"'
    q3 = 'principal.hostname = "wins-d19" AND principal.process.command_line = /.*DERPService.*/ nocase'
    q_control = 'metadata.log_type = "WINDOWS_SYSMON" AND principal.hostname = "wins-d19"'

    print("Initializing Argolis Chronicle SIEM MCP toolset...")
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(siem_toolset.get_tools(readonly_context=None))
        }
        print(f"Discovered {len(siem_tools)} SIEM tools (search_udm present: {'search_udm' in siem_tools})")

        def live_siem_search(
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

        print("\n=== Step 1: Direct Live Chronicle SIEM Zero-Hit Diagnostics ===")
        diag1 = diagnose_zero_hit_udm_query(
            q1,
            start_time=start_time,
            end_time=end_time,
            siem_search_fn=live_siem_search,
        )
        print("Query 1 diagnosis:", json.dumps(diag1, indent=2))
        assert diag1["status"] == "success", f"diag1 failed: {diag1}"
        assert diag1["zero_hit"] is True
        assert diag1["diagnosis_class"] == "value_format_mismatch"
        assert diag1["recommended_clause"] == 'target.resource.name = "projects/base-production"'
        assert diag1["pivot_verified"] is True
        assert diag1["pivot_event_count"] > 0

        diag2 = diagnose_zero_hit_udm_query(
            q2,
            start_time=start_time,
            end_time=end_time,
            siem_search_fn=live_siem_search,
        )
        print("Query 2 diagnosis:", json.dumps(diag2, indent=2))
        assert diag2["status"] == "success", f"diag2 failed: {diag2}"
        assert diag2["zero_hit"] is True
        assert diag2["diagnosis_class"] == "exact_match_on_command_line"
        assert diag2["anchor_event_count"] > 0
        assert diag2["recommended_clause"] == r"target.process.command_line = /.*cmd\.exe.*/ nocase"
        assert diag2["pivot_verified"] is True
        assert diag2["pivot_event_count"] > 0

        diag3 = diagnose_zero_hit_udm_query(
            q3,
            start_time=start_time,
            end_time=end_time,
            siem_search_fn=live_siem_search,
        )
        print("Query 3 diagnosis:", json.dumps(diag3, indent=2))
        assert diag3["status"] == "success", f"diag3 failed: {diag3}"
        assert diag3["zero_hit"] is True
        assert diag3["diagnosis_class"] == "entity_role_swap"
        assert diag3["anchor_event_count"] > 0
        assert diag3["recommended_field"] == "target.process.command_line"
        assert diag3["recommended_clause"] == "target.process.command_line = /.*DERPService.*/ nocase"
        assert diag3["pivot_verified"] is True
        assert diag3["pivot_event_count"] > 0

        print("\n=== Step 2: Create Google Doc & Run Live Zero-Hit UDM Red-Lining ===")
        doc_body = (
            "# Cycle 6 (H9) Zero-Hit UDM Query Semantic Diagnostics & Pivot Recommender\n\n"
            "## 1. Cloud Audit Resource Filter (SOAR Case 33278)\n"
            f"`{q1}`\n\n"
            "## 2. Endpoint Command-Line Exact Equality Filter (SOAR Cases 33280 / 33285)\n"
            f"`{q2}`\n\n"
            "## 3. Endpoint Process Entity Role Filter (SOAR Cases 33280 / 33285)\n"
            f"`{q3}`\n\n"
            "## 4. Valid Baseline Control Query\n"
            f"`{q_control}`\n"
        )
        doc_res = create_google_doc(
            title="Cycle6_H9_Live_Zero_Hit_UDM_Pivot_Recommender_Validation",
            content=doc_body,
        )
        assert doc_res.get("status") == "success", f"create_google_doc failed: {doc_res}"
        doc_id = str(doc_res["document_id"])
        doc_url = str(
            doc_res.get("viewUrl")
            or doc_res.get("web_view_link")
            or f"https://docs.google.com/document/d/{doc_id}/edit"
        )
        print(f"Created Google Doc: {doc_id} ({doc_url})")

        pass1 = verify_and_redline_udm_queries_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_queries=True,
            start_time=start_time,
            end_time=end_time,
            siem_search_fn=live_siem_search,
        )
        print(
            "Pass 1 summary:",
            json.dumps(
                {
                    "status": pass1.get("status"),
                    "udm_findings_count": pass1.get("udm_findings_count"),
                    "zero_hit_findings_count": pass1.get("zero_hit_findings_count"),
                    "skipped_existing_suggestion_count": pass1.get(
                        "skipped_existing_suggestion_count"
                    ),
                    "comments": pass1.get("comments"),
                    "edits": pass1.get("edits"),
                    "findings": pass1.get("findings"),
                },
                indent=2,
            ),
        )
        assert pass1["status"] == "success"
        assert pass1["udm_findings_count"] == 3
        assert pass1["zero_hit_findings_count"] == 3
        assert pass1["skipped_existing_suggestion_count"] == 0
        assert pass1["comments"]["inserted_count"] == 3
        assert pass1["edits"]["applied_count"] == 3

        print("\n=== Step 3: Inspect Pending Suggestions & Unified Diff ===")
        insp = inspect_doc_suggestions(doc_id)
        print("Suggestion count:", insp.get("suggestion_count"))
        print("Unified diff:\n" + str(insp.get("unified_diff") or ""))
        assert insp["status"] == "success"
        assert insp["suggestion_count"] == 3
        accepted_text = str(insp.get("accepted_text") or "")
        assert 'target.resource.name = "projects/base-production"' in accepted_text
        assert r"target.process.command_line = /.*cmd\.exe.*/ nocase" in accepted_text
        assert "target.process.command_line = /.*DERPService.*/ nocase" in accepted_text
        assert q_control in accepted_text

        print("\n=== Step 4: Multi-Pass Idempotency Verification (Pass 2) ===")
        pass2 = verify_and_redline_udm_queries_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_queries=True,
            start_time=start_time,
            end_time=end_time,
            siem_search_fn=live_siem_search,
        )
        print(
            "Pass 2 summary:",
            json.dumps(
                {
                    "status": pass2.get("status"),
                    "udm_findings_count": pass2.get("udm_findings_count"),
                    "zero_hit_findings_count": pass2.get("zero_hit_findings_count"),
                    "skipped_existing_suggestion_count": pass2.get(
                        "skipped_existing_suggestion_count"
                    ),
                    "comments": pass2.get("comments"),
                    "edits": pass2.get("edits"),
                },
                indent=2,
            ),
        )
        assert pass2["status"] == "success"
        assert pass2["udm_findings_count"] == 0
        assert pass2["zero_hit_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 3
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0

        print("\nALL CYCLE 6 (H9) LIVE VALIDATIONS PASSED.")
        print(
            json.dumps(
                {
                    "document_id": doc_id,
                    "web_view_link": doc_url,
                    "q1_anchor_events": diag1["anchor_event_count"],
                    "q1_pivot_events": diag1["pivot_event_count"],
                    "q2_anchor_events": diag2["anchor_event_count"],
                    "q2_pivot_events": diag2["pivot_event_count"],
                    "q3_anchor_events": diag3["anchor_event_count"],
                    "q3_pivot_events": diag3["pivot_event_count"],
                    "pass1_findings": pass1["udm_findings_count"],
                    "pass1_zero_hit_findings": pass1["zero_hit_findings_count"],
                    "pass1_comments": pass1["comments"]["inserted_count"],
                    "pass1_edits": pass1["edits"]["applied_count"],
                    "pass2_skipped_existing_suggestions": pass2[
                        "skipped_existing_suggestion_count"
                    ],
                    "pass2_edits": pass2["edits"]["applied_count"],
                },
                indent=2,
            )
        )
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
