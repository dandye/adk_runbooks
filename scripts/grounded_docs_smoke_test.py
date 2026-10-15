#!/usr/bin/env python3
"""Smoke test for Developer Knowledge Remote MCP and Google Docs API v1 review tools.

Exercises a realistic SecOps Incident Postmortem & Runbook Red-Line workflow:
  1. ``https://developerknowledge.googleapis.com/mcp`` via ADK ``McpToolset``:
     - Startup discovery ``get_tools(readonly_context=None)``
     - Queries ``search_documents`` for GCP IAM service account containment
       (``disable`` vs ``delete``) and Chronicle UDM process field syntax
       (``target.process.command_line``).
  2. ``web_search_verifier`` wrapped in ``AgentTool`` (verifies schema declaration).
  3. Live Google Docs API v1 non-destructive review workflow
     (``--create-review-doc`` or ``--document-id <DOC_ID>``):
     - ``create_google_doc`` (in ``DRIVE_REPORTS_FOLDER_ID``)
     - ``read_google_doc`` (builds 1-based UTF-16 character index map)
     - ``insert_doc_comments`` (anchors 3 grounded SOC review comments BEFORE edits)
     - ``propose_doc_suggested_edits`` (4 back-to-front ``writeMode="SUGGEST"``
       edits fixing MITRE ATT&CK sub-technique ID, defanging a live C2 URL,
       correcting a hallucinated Chronicle UDM field path, and replacing
       destructive service account deletion with reversible disablement)

Usage (inside the direnv-activated worktree):

  python scripts/grounded_docs_smoke_test.py
  python scripts/grounded_docs_smoke_test.py --create-review-doc
  python scripts/grounded_docs_smoke_test.py --document-id <GOOGLE_DOC_ID>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

# Ensure project root and multi-agent are on sys.path
_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from manager.tools.docs_review_tools import (  # noqa: E402
    create_google_doc,
    insert_doc_comments,
    propose_doc_suggested_edits,
    read_google_doc,
)
from manager.tools.grounding_tools import (  # noqa: E402
    developer_knowledge_api_key,
    developer_knowledge_mcp_url,
    developer_knowledge_quota_project,
    init_developer_knowledge_toolset,
    init_web_search_agent_tool,
)


SAMPLE_REVIEW_DOC_CONTENT = """# INC-2026-1011 Postmortem & Runbook Red-Line: Compromised GCP Service Account

## 1. Threat Telemetry & MITRE ATT&CK Mapping
- Initial Execution: Encoded PowerShell cradle (`powershell.exe -nop -w hidden -enc ...`) classified under MITRE ATT&CK technique `T1059.003 (Windows Command Shell)`.
- Outbound C2 Callback: Beacon observed fetching second-stage payload from `https://login-micros0ft-update.com/stage2.ps1`.

## 2. Google SecOps (Chronicle) UDM Hunting Query
Run the following UDM search to identify other hosts executing the encoded cradle:
`metadata.event_type = "PROCESS_LAUNCH" AND process.command_line = /.*-enc.*/ nocase`

## 3. Immediate GCP IAM Containment Runbook Step
To cut off attacker access immediately during triage, run:
`gcloud iam service-accounts delete sa-prod-etl@dandye-0324-chronicle.iam.gserviceaccount.com`
"""


def _extract_first_doc_url(res: dict, prefix_filter: str = "") -> str | None:
    """Extracts a canonical https:// URL from a Developer Knowledge search_documents response."""
    for block in res.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            try:
                parsed = json.loads(block.get("text", "{}"))
                results = parsed.get("results", [])
                for item in results:
                    if not isinstance(item, dict):
                        continue
                    if item.get("url"):
                        return str(item["url"])
                    parent = str(item.get("parent", ""))
                    if parent.startswith("documents/"):
                        candidate = "https://" + parent[len("documents/"):]
                        if not prefix_filter or prefix_filter in candidate:
                            return candidate
            except json.JSONDecodeError:
                pass
    return None


async def probe_developer_knowledge_mcp(custom_query: str | None = None) -> dict[str, str]:
    """Connects to Developer Knowledge MCP, lists tools, and verifies IAM + UDM docs."""
    url = developer_knowledge_mcp_url()
    project = developer_knowledge_quota_project()
    has_key = bool(developer_knowledge_api_key())
    print(f"[devknowledge] URL:           {url}")
    print(f"[devknowledge] Quota project: {project or '<unset>'}")
    print(f"[devknowledge] Auth mode:     {'X-Goog-Api-Key' if has_key else 'ADC Bearer + X-Goog-User-Project'}")

    citations = {
        "iam_url": "https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable",
        "udm_url": "https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list",
    }

    toolset = init_developer_knowledge_toolset()
    try:
        tools = await toolset.get_tools(readonly_context=None)
        names = [t.name for t in tools]
        print(f"[devknowledge] Discovered {len(names)} tools (readonly_context=None): {names}")

        by_name = {t.name: t for t in tools}
        if "search_documents" in by_name:
            iam_query = custom_query or "gcloud iam service-accounts disable delete service account"
            print(f"[devknowledge] 1. Querying IAM containment docs: {iam_query!r}...")
            iam_res = await by_name["search_documents"].run_async(
                args={"query": iam_query}, tool_context=None
            )
            found_iam = _extract_first_doc_url(iam_res, "iam/docs")
            if found_iam:
                citations["iam_url"] = found_iam
            print(f"[devknowledge]    Resolved IAM citation: {citations['iam_url']}")

            udm_query = "udm-field-list target.process.command_line"
            print(f"[devknowledge] 2. Querying Chronicle UDM schema docs: {udm_query!r}...")
            udm_res = await by_name["search_documents"].run_async(
                args={"query": udm_query}, tool_context=None
            )
            found_udm = _extract_first_doc_url(udm_res, "udm-field-list")
            if found_udm:
                citations["udm_url"] = found_udm
            print(f"[devknowledge]    Resolved UDM citation: {citations['udm_url']}")
    finally:
        await toolset.close()
    return citations


def probe_web_search_agent_tool() -> None:
    """Verifies AgentTool(web_search_verifier) declaration."""
    agent_tool = init_web_search_agent_tool()
    decl = agent_tool._get_declaration()
    print(f"[web_search]   AgentTool name: {decl.name} (child tools: {[str(t) for t in agent_tool.agent.tools]})")


def probe_google_docs_review(
    document_id: str | None, create_new: bool, citations: dict[str, str]
) -> int:
    """Exercises create_google_doc -> read_google_doc -> insert_doc_comments -> propose_doc_suggested_edits."""
    target_doc_id = document_id
    if create_new and not target_doc_id:
        print("[docs] Creating INC-2026-1011 Postmortem & Runbook Google Doc in DRIVE_REPORTS_FOLDER_ID...")
        created = create_google_doc(
            title="INC_2026_1011_Postmortem_and_Runbook_Redline",
            content=SAMPLE_REVIEW_DOC_CONTENT,
        )
        if created.get("status") != "success":
            print(f"[docs] create_google_doc failed: {created}")
            return 1
        target_doc_id = created["document_id"]
        print(f"[docs] Created Google Doc: {target_doc_id} ({created.get('viewUrl')})")

    if not target_doc_id:
        print("[docs] Skipping live Docs API v1 mutation (pass --create-review-doc or --document-id <ID>).")
        return 0

    print(f"[docs] 1. Reading document {target_doc_id}...")
    read_res = read_google_doc(target_doc_id)
    if read_res.get("status") != "success":
        print(f"[docs] read_google_doc failed: {read_res}")
        return 1
    print(f"[docs]    Mapped {read_res['char_count']} UTF-16 character positions")

    print("[docs] 2. Inserting 4 grounded SOC review comments (BEFORE edits)...")
    comment_res = insert_doc_comments(
        target_doc_id,
        [
            {
                "quote": "T1059.003 (Windows Command Shell)",
                "comment": (
                    "MITRE ATT&CK mismatch: powershell.exe -enc payloads map to "
                    "T1059.001 (PowerShell), not T1059.003 (cmd.exe) "
                    "(https://attack.mitre.org/techniques/T1059/001/)."
                ),
            },
            {
                "quote": "https://login-micros0ft-update.com/stage2.ps1",
                "comment": (
                    "Live C2 URL auto-linkifies in Google Docs and creates a click hazard "
                    "for bridge reviewers. Defang indicator to hxxps:// and [.] before sharing."
                ),
            },
            {
                "quote": "process.command_line",
                "comment": (
                    "Invalid Chronicle UDM field path: UDM requires an entity prefix such as "
                    f"target.process.command_line or principal.process.command_line ({citations['udm_url']})."
                ),
            },
            {
                "quote": "gcloud iam service-accounts delete",
                "comment": (
                    "High blast-radius containment warning: deleting a production service account "
                    "destroys its unique resource ID and breaks Workload Identity bindings. "
                    f"Use reversible 'gcloud iam service-accounts disable' during triage ({citations['iam_url']})."
                ),
            },
        ],
    )
    print(f"[docs]    insert_doc_comments result: {comment_res}")

    print("[docs] 3. Proposing 4 non-destructive Suggested Edits (back-to-front writeMode=SUGGEST)...")
    edit_res = propose_doc_suggested_edits(
        target_doc_id,
        [
            {
                "quote": "T1059.003 (Windows Command Shell)",
                "replacement": "T1059.001 (PowerShell)",
            },
            {
                "quote": "https://login-micros0ft-update.com/stage2.ps1",
                "replacement": "hxxps://login-micros0ft-update[.]com/stage2.ps1",
            },
            {
                "quote": "process.command_line",
                "replacement": "target.process.command_line",
            },
            {
                "quote": "gcloud iam service-accounts delete",
                "replacement": "gcloud iam service-accounts disable",
            },
        ],
    )
    print(f"[docs]    propose_doc_suggested_edits result: {edit_res}")
    return 0 if edit_res.get("status") == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--query",
        default=None,
        help="Optional custom query to send to Developer Knowledge MCP search_documents.",
    )
    parser.add_argument(
        "--create-review-doc",
        action="store_true",
        help="Create an INC-2026-1011 Postmortem & Runbook Google Doc in DRIVE_REPORTS_FOLDER_ID and apply grounded comments + suggested edits.",
    )
    parser.add_argument(
        "--document-id",
        default=None,
        help="Existing Google Doc ID to read and annotate.",
    )
    args = parser.parse_args()

    probe_web_search_agent_tool()
    try:
        citations = asyncio.run(probe_developer_knowledge_mcp(args.query))
    except Exception as err:
        print(f"[devknowledge] Error probing Developer Knowledge MCP: {err}")
        citations = {
            "iam_url": "https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable",
            "udm_url": "https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list",
        }

    return probe_google_docs_review(args.document_id, args.create_review_doc, citations)


if __name__ == "__main__":
    sys.exit(main())
