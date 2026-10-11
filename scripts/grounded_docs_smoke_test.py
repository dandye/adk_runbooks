#!/usr/bin/env python3
"""Smoke test for Developer Knowledge Remote MCP and Google Docs API v1 review tools.

Exercises, end to end:
  1. ``https://developerknowledge.googleapis.com/mcp`` via ADK ``McpToolset``:
     - Startup discovery ``get_tools(readonly_context=None)``
     - ``search_documents`` and ``get_documents`` / ``answer_query``
  2. ``web_search_verifier`` wrapped in ``AgentTool`` (verifies schema declaration).
  3. Optional live Google Docs API v1 non-destructive review workflow
     (``--create-review-doc`` or ``--document-id <DOC_ID>``):
     - ``create_google_doc`` (in ``DRIVE_REPORTS_FOLDER_ID``)
     - ``read_google_doc`` (builds 1-based UTF-16 character index map)
     - ``insert_doc_comments`` (anchors native comments before any text edits)
     - ``propose_doc_suggested_edits`` (back-to-front ``writeMode="SUGGEST"``)

Usage (inside the direnv-activated worktree):

  python scripts/grounded_docs_smoke_test.py
  python scripts/grounded_docs_smoke_test.py --query "Vertex AI IAM predefined roles"
  python scripts/grounded_docs_smoke_test.py --create-review-doc
  python scripts/grounded_docs_smoke_test.py --document-id <GOOGLE_DOC_ID>
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
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


SAMPLE_REVIEW_DOC_CONTENT = """# Suspicious Login & Vertex AI Remediation Runbook (Draft)

## Step 1: Service Account Permissions
Grant the service account `roles/owner` on the Google Cloud project so the
agent can invoke Vertex AI models.

## Step 2: Model Configuration
Configure the triage sub-agent to use `gemini-1.5-pro` for log analysis.
"""


async def probe_developer_knowledge_mcp(query: str) -> str:
    """Connects to Developer Knowledge MCP, lists tools, and runs a search query."""
    url = developer_knowledge_mcp_url()
    project = developer_knowledge_quota_project()
    has_key = bool(developer_knowledge_api_key())
    print(f"[devknowledge] URL:           {url}")
    print(f"[devknowledge] Quota project: {project or '<unset>'}")
    print(f"[devknowledge] Auth mode:     {'X-Goog-Api-Key' if has_key else 'ADC Bearer + X-Goog-User-Project'}")

    toolset = init_developer_knowledge_toolset()
    citation_url = "https://cloud.google.com/iam/docs/understanding-roles"
    try:
        tools = await toolset.get_tools(readonly_context=None)
        names = [t.name for t in tools]
        print(f"[devknowledge] Discovered {len(names)} tools (readonly_context=None): {names}")

        by_name = {t.name: t for t in tools}
        if "search_documents" in by_name:
            print(f"[devknowledge] Calling search_documents(query={query!r})...")
            res = await by_name["search_documents"].run_async(
                args={"query": query}, tool_context=None
            )
            print(f"[devknowledge] search_documents isError={res.get('isError', False)}")
            payload_str = json.dumps(res, indent=2)[:800]
            print(f"[devknowledge] Response preview:\n{payload_str}")
            for block in res.get("content", []):
                if isinstance(block, dict) and block.get("type") == "text":
                    try:
                        parsed = json.loads(block.get("text", "{}"))
                        results = parsed.get("results", [])
                        if results and isinstance(results[0], dict):
                            first = results[0]
                            if first.get("url"):
                                citation_url = str(first["url"])
                                break
                            parent = str(first.get("parent", ""))
                            if parent.startswith("documents/"):
                                citation_url = "https://" + parent[len("documents/"):]
                                break
                    except json.JSONDecodeError:
                        pass
    finally:
        await toolset.close()
    return citation_url


def probe_web_search_agent_tool() -> None:
    """Verifies AgentTool(web_search_verifier) declaration."""
    agent_tool = init_web_search_agent_tool()
    decl = agent_tool._get_declaration()
    print(f"[web_search]   AgentTool name: {decl.name} (child tools: {[str(t) for t in agent_tool.agent.tools]})")


def probe_google_docs_review(document_id: str | None, create_new: bool, citation_url: str) -> int:
    """Exercises create_google_doc -> read_google_doc -> insert_doc_comments -> propose_doc_suggested_edits."""
    target_doc_id = document_id
    if create_new and not target_doc_id:
        print("[docs] Creating test Google Doc in DRIVE_REPORTS_FOLDER_ID...")
        created = create_google_doc(
            title="Grounded_Runbook_Review_Smoke_Test",
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
    print(f"[docs]    Title: {read_res['title']!r} ({read_res['char_count']} chars)")

    print("[docs] 2. Inserting anchored comments (BEFORE edits)...")
    comment_res = insert_doc_comments(
        target_doc_id,
        [
            {
                "quote": "roles/owner",
                "comment": (
                    "Avoid primitive roles/owner; grant least-privilege "
                    f"roles/aiplatform.user instead ({citation_url})."
                ),
            }
        ],
    )
    print(f"[docs]    insert_doc_comments result: {comment_res}")

    print("[docs] 3. Proposing non-destructive Suggested Edits (writeMode=SUGGEST)...")
    edit_res = propose_doc_suggested_edits(
        target_doc_id,
        [
            {"quote": "roles/owner", "replacement": "roles/aiplatform.user"},
            {"quote": "gemini-1.5-pro", "replacement": "gemini-2.5-pro"},
        ],
    )
    print(f"[docs]    propose_doc_suggested_edits result: {edit_res}")
    return 0 if edit_res.get("status") == "success" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--query",
        default="Vertex AI IAM predefined roles roles/aiplatform.user",
        help="Query to send to Developer Knowledge MCP search_documents.",
    )
    parser.add_argument(
        "--create-review-doc",
        action="store_true",
        help="Create a test Google Doc in DRIVE_REPORTS_FOLDER_ID and apply comments + suggested edits.",
    )
    parser.add_argument(
        "--document-id",
        default=None,
        help="Existing Google Doc ID to read and annotate.",
    )
    args = parser.parse_args()

    probe_web_search_agent_tool()
    try:
        citation_url = asyncio.run(probe_developer_knowledge_mcp(args.query))
    except Exception as err:
        print(f"[devknowledge] Error probing Developer Knowledge MCP: {err}")
        citation_url = "https://cloud.google.com/iam/docs/understanding-roles"

    return probe_google_docs_review(args.document_id, args.create_review_doc, citation_url)


if __name__ == "__main__":
    sys.exit(main())
