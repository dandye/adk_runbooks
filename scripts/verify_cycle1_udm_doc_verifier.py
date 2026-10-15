#!/usr/bin/env python3
"""Cycle 1 (H1) Live Validation: Chronicle UDM Query Syntax & Schema Verifier Inside Docs.

Validates against the live Argolis SecOps tenant (``dandye-0324-chronicle``):
  1. Resolves canonical Chronicle UDM documentation URL via Developer Knowledge
     Remote MCP (``https://developerknowledge.googleapis.com/mcp``).
  2. Connects to live Chronicle SIEM via ``init_shared_mcp_tools()`` (``search_udm``)
     and verifies :func:`verify_udm_query_with_siem` on defective UDM queries from
     SOAR Case ``33278`` (``ip = "104.198.226.161"``, ``resource.name = ...``) and
     Cases ``33280``/``33285`` (``hostname = "wins-d19"``).
  3. Inspects existing Smoke Test Google Doc ``1DV3E98OQSNuSuV_dClYJ21PF7xnSHLq6vioDthXEx3M``
     with :func:`find_udm_field_spans` to confirm deterministic UTF-16 span extraction.
  4. Creates 1 focused validation Google Doc
     ``Cycle1_H1_Live_UDM_Query_Verifier_Validation`` in ``SOC Reports`` and runs
     :func:`verify_and_redline_udm_queries_in_doc` with ``run_live_siem_check=True``
     to anchor live SIEM-verified comments and ``writeMode="SUGGEST"`` edits.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    _load_doc_index_state,
    create_google_doc,
    find_udm_field_spans,
    read_google_doc,
    verify_and_redline_udm_queries_in_doc,
    verify_udm_query_with_siem,
)
from scripts.experiment_argolis_soar_cases import (  # noqa: E402
    resolve_grounding_citations,
)

EXISTING_SMOKE_DOC_ID = "1DV3E98OQSNuSuV_dClYJ21PF7xnSHLq6vioDthXEx3M"

VALIDATION_DOC_CONTENT = """# Cycle 1 (H1) Live Validation: Chronicle UDM Query Syntax & Schema Verifier

## 1. SOAR Case 33278 GCP Cloud Audit Hunting Queries
Run the following Chronicle UDM query to pivot on all GCP Cloud Audit activity from the attacker IP:
`metadata.log_type = "GCP_CLOUDAUDIT" AND ip = "104.198.226.161"`

Run the following Chronicle UDM query to inspect the deleted Cloud SQL instance resource:
`metadata.log_type = "GCP_CLOUDAUDIT" AND resource.name = "projects/base-analytics/instances/prod-customers"`

## 2. SOAR Cases 33280 & 33285 Endpoint Process Hunting Query
Run the following Chronicle UDM query to inspect suspicious process launches on host wins-d19:
`hostname = "wins-d19" AND process.command_line = /.*cmd.*/ nocase`
"""


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print("[1/4] Resolving canonical UDM documentation via Developer Knowledge MCP...")
    citations = loop.run_until_complete(resolve_grounding_citations())
    udm_url = citations["udm_field_list_url"]
    print(f"      Resolved UDM Field List URL: {udm_url}")

    print("[2/4] Initializing Argolis Chronicle SIEM MCP toolset...")
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(siem_toolset.get_tools(readonly_context=None))
        }
        print(f"      Discovered {len(siem_tools)} SIEM tools (search_udm present: {'search_udm' in siem_tools})")

        def live_siem_search(
            query: str,
            start_time: str = "2026-02-07T00:00:00Z",
            end_time: str = "2026-02-08T00:00:00Z",
            max_events: int = 10,
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

        q1 = 'metadata.log_type = "GCP_CLOUDAUDIT" AND ip = "104.198.226.161"'
        res1 = verify_udm_query_with_siem(
            q1,
            start_time="2026-02-07T19:00:00Z",
            end_time="2026-02-07T19:35:00Z",
            max_events=10,
            siem_search_fn=live_siem_search,
        )
        print(
            f"      Query 1 dry-run: status={res1['status']}, siem_verified={res1['siem_verified']}, "
            f"repaired={res1['repaired_query']!r}, event_count={res1['event_count']}"
        )

        q2 = 'metadata.log_type = "GCP_CLOUDAUDIT" AND resource.name = "projects/base-analytics/instances/prod-customers"'
        res2 = verify_udm_query_with_siem(
            q2,
            start_time="2026-02-07T19:00:00Z",
            end_time="2026-02-07T19:35:00Z",
            max_events=10,
            siem_search_fn=live_siem_search,
        )
        print(
            f"      Query 2 dry-run: status={res2['status']}, siem_verified={res2['siem_verified']}, "
            f"repaired={res2['repaired_query']!r}, event_count={res2['event_count']}"
        )

        print(f"[3/4] Inspecting existing Google Doc {EXISTING_SMOKE_DOC_ID}...")
        smoke_read = read_google_doc(EXISTING_SMOKE_DOC_ID)
        if smoke_read.get("status") == "success":
            plain_text, index_map = _load_doc_index_state(EXISTING_SMOKE_DOC_ID)
            _, _, smoke_findings = find_udm_field_spans(
                plain_text or "", index_map or [], udm_doc_url=udm_url
            )
            print(
                f"      Existing Smoke Doc ({smoke_read.get('char_count')} chars) "
                f"UDM findings: {json.dumps(smoke_findings)}"
            )

        print("[4/4] Creating Cycle1_H1_Live_UDM_Query_Verifier_Validation Google Doc and red-lining...")
        created = create_google_doc(
            title="Cycle1_H1_Live_UDM_Query_Verifier_Validation",
            content=VALIDATION_DOC_CONTENT,
        )
        if created.get("status") != "success":
            print(f"      ERROR creating validation Google Doc: {created}")
            return 1

        doc_id = created["document_id"]
        view_url = created.get("viewUrl")
        print(f"      Created Google Doc: {doc_id} ({view_url})")

        redline_res = verify_and_redline_udm_queries_in_doc(
            doc_id,
            run_live_siem_check=True,
            start_time="2026-02-07T00:00:00Z",
            end_time="2026-02-08T00:00:00Z",
            max_events=15,
            udm_doc_url=udm_url,
            siem_search_fn=live_siem_search,
        )
        summary = {
            "status": redline_res.get("status"),
            "document_id": doc_id,
            "viewUrl": view_url,
            "char_count": redline_res.get("char_count"),
            "udm_findings_count": redline_res.get("udm_findings_count"),
            "findings": redline_res.get("findings"),
            "siem_checks": [
                {
                    "original_query": c.get("original_query"),
                    "repaired_query": c.get("repaired_query"),
                    "siem_verified": c.get("siem_verified"),
                    "event_count": c.get("event_count"),
                }
                for c in redline_res.get("siem_checks", [])
            ],
            "comments": redline_res.get("comments"),
            "edits": redline_res.get("edits"),
        }
        print("      Red-line result summary:")
        print(json.dumps(summary, indent=2))
        return 0 if redline_res.get("status") == "success" else 1
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            try:
                loop.run_until_complete(ts.close())
            except Exception:
                pass
        loop.close()


if __name__ == "__main__":
    raise SystemExit(main())
