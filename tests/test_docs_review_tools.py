"""Unit tests for ``manager.tools.docs_review_tools``: Google Docs API v1
non-destructive review primitives (UTF-16 index mapping, dual-identity token
resolution, ``insert_doc_comments``, and back-to-front descending-index
``propose_doc_suggested_edits`` with ``writeMode="SUGGEST"``)."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from manager.tools.docs_review_tools import (
     clear_doc_index_cache,
    _extract_text_and_index_map,
    _find_quote_indices,
    create_google_doc,
    insert_doc_comments,
    propose_doc_suggested_edits,
    read_google_doc,
    resolve_docs_token,
)
from skills.drive_registry import DriveMcpClient, StaticTokenSource
from tests.fake_drive_mcp import GOOGLE_DOC_MIME_TYPE, FakeDriveMcpServer


def make_fake_doc_payload() -> dict[str, Any]:
    """Builds a realistic Google Docs API v1 ``documents.get`` response with
    both body paragraphs and a table cell."""
    # Paragraph 1 (startIndex 1): "Use roles/owner for Vertex AI.\n" (31 chars -> indices 1..31)
    # Table cell paragraph (startIndex 35): "gemini-1.5-pro is current.\n" (27 chars -> indices 35..61)
    # Paragraph 2 (startIndex 65): "Run gcloud alpha chronicle list.\n" (33 chars -> indices 65..97)
    p1_text = "Use roles/owner for Vertex AI.\n"
    cell_text = "gemini-1.5-pro is current.\n"
    p2_text = "Run gcloud alpha chronicle list.\n"
    return {
        "documentId": "doc-123",
        "title": "SOC Runbook Draft",
        "tabs": [
            {
                "documentTab": {
                    "body": {
                        "content": [
                            {
                                "paragraph": {
                                    "elements": [
                                        {
                                            "startIndex": 1,
                                            "endIndex": 1 + len(p1_text),
                                            "textRun": {"content": p1_text},
                                        }
                                    ]
                                }
                            },
                            {
                                "table": {
                                    "tableRows": [
                                        {
                                            "tableCells": [
                                                {
                                                    "content": [
                                                        {
                                                            "paragraph": {
                                                                "elements": [
                                                                    {
                                                                        "startIndex": 35,
                                                                        "endIndex": 35 + len(cell_text),
                                                                        "textRun": {"content": cell_text},
                                                                    }
                                                                ]
                                                            }
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            },
                            {
                                "paragraph": {
                                    "elements": [
                                        {
                                            "startIndex": 65,
                                            "endIndex": 65 + len(p2_text),
                                            "textRun": {"content": p2_text},
                                        }
                                    ]
                                }
                            },
                        ]
                    }
                }
            }
        ],
    }


@pytest.fixture(autouse=True)
def _reset_doc_cache():
    clear_doc_index_cache()
    yield
    clear_doc_index_cache()


# ---------------------------------------------------------------------------
# 1. UTF-16 Index Extraction & Quote Resolution
# ---------------------------------------------------------------------------


def test_extract_text_and_index_map_handles_paragraphs_and_tables():
    doc = make_fake_doc_payload()
    plain_text, index_map = _extract_text_and_index_map(doc)

    assert "Use roles/owner for Vertex AI." in plain_text
    assert "gemini-1.5-pro is current." in plain_text
    assert "Run gcloud alpha chronicle list." in plain_text
    assert len(plain_text) == len(index_map)

    # First quote inside Paragraph 1 (starts at index 1 + 4 = 5)
    span1 = _find_quote_indices(plain_text, index_map, "roles/owner")
    assert span1 == (5, 16)

    # Second quote inside the Table Cell (starts at index 35)
    span2 = _find_quote_indices(plain_text, index_map, "gemini-1.5-pro")
    assert span2 == (35, 49)

    # Third quote inside Paragraph 2 (starts at index 65 + 4 = 69)
    span3 = _find_quote_indices(plain_text, index_map, "gcloud alpha chronicle list")
    assert span3 == (69, 96)


def test_extract_text_and_index_map_handles_utf16_surrogate_pairs():
    """Characters outside the Basic Multilingual Plane occupy 2 UTF-16 code units
    in the Google Docs API index space."""
    # U+1D400 (MATHEMATICAL BOLD CAPITAL A) is 4 bytes in UTF-8, 2 code units in UTF-16.
    text = "A\U0001d400B\n"
    doc = {
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 6,
                                "textRun": {"content": text},
                            }
                        ]
                    }
                }
            ]
        }
    }
    plain_text, index_map = _extract_text_and_index_map(doc)
    assert plain_text == text
    # 'A' -> 1, U+1D400 -> 2 (takes 2 UTF-16 units: 2 and 3), 'B' -> 4, '\n' -> 5
    assert index_map == [1, 2, 4, 5]
    assert _find_quote_indices(plain_text, index_map, "B") == (4, 5)


# ---------------------------------------------------------------------------
# 2. Dual-Identity Token Resolution
# ---------------------------------------------------------------------------


def test_resolve_docs_token_prefers_session_user_access_token_over_adc():
    ctx = SimpleNamespace(state={"user_access_token": "oauth-user-token-777"})
    token = resolve_docs_token(
        tool_context=ctx,
        token_source=StaticTokenSource("adc-fallback-token"),
    )
    assert token == "oauth-user-token-777"


def test_resolve_docs_token_falls_back_to_adc_when_no_user_token():
    ctx = SimpleNamespace(state={})
    token = resolve_docs_token(
        tool_context=ctx,
        token_source=StaticTokenSource("adc-fallback-token"),
    )
    assert token == "adc-fallback-token"


# ---------------------------------------------------------------------------
# 3. End-to-End Flow: read_google_doc -> insert_doc_comments -> propose_doc_suggested_edits
# ---------------------------------------------------------------------------


def test_read_insert_comments_and_propose_suggested_edits_ordering_and_payload():
    doc_payload = make_fake_doc_payload()
    recorded_requests: list[tuple[str, str, dict[str, Any], dict[str, str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        if request.method == "GET":
            recorded_requests.append((request.method, str(request.url), {}, headers))
            return httpx.Response(200, json=doc_payload)
        body = json.loads(request.content.decode("utf-8"))
        recorded_requests.append((request.method, str(request.url), body, headers))
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(200, json={"replies": [{} for _ in body.get("requests", [])]})

    transport = httpx.MockTransport(handler)
    ctx = SimpleNamespace(state={"user_access_token": "user-oauth-tok"})

    # Step 1: read_google_doc populates doc_plain_text and doc_index_map
    read_res = read_google_doc(
        "doc-123",
        tool_context=ctx,
        quota_project="dandye-0324-chronicle",
        transport=transport,
    )
    assert read_res["status"] == "success"
    assert read_res["title"] == "SOC Runbook Draft"
    assert "roles/owner" in read_res["content"]
    assert "doc_plain_text" in ctx.state
    assert "doc_index_map" in ctx.state

    # Step 2: insert_doc_comments anchors native comments BEFORE any text edits
    comments_input = json.dumps(
        [
            {
                "quote": "roles/owner",
                "comment": "Grant least-privilege roles/aiplatform.user instead of roles/owner (https://docs.cloud.google.com/iam/docs/understanding-roles).",
            },
            {
                "quote": "gcloud alpha chronicle list",
                "comment": "Verify exact Chronicle CLI flags via Developer Knowledge MCP.",
            },
        ]
    )
    comment_res = insert_doc_comments(
        "doc-123",
        comments_input,
        tool_context=ctx,
        quota_project="dandye-0324-chronicle",
        transport=transport,
    )
    assert comment_res["status"] == "success"
    assert comment_res["inserted_count"] == 2
    assert comment_res["comment_ids"] == ["c-0", "c-1"]

    _, comment_url, comment_body, comment_headers = recorded_requests[1]
    assert comment_url == "https://docs.googleapis.com/v1/documents/doc-123:batchUpdate"
    assert comment_headers["authorization"] == "Bearer user-oauth-tok"
    assert comment_headers["x-goog-user-project"] == "dandye-0324-chronicle"
    assert comment_body["requests"] == [
        {
            "insertComment": {
                "content": "Grant least-privilege roles/aiplatform.user instead of roles/owner (https://docs.cloud.google.com/iam/docs/understanding-roles).",
                "range": {"startIndex": 5, "endIndex": 16},
            }
        },
        {
            "insertComment": {
                "content": "Verify exact Chronicle CLI flags via Developer Knowledge MCP.",
                "range": {"startIndex": 69, "endIndex": 96},
            }
        },
    ]

    # Step 3: propose_doc_suggested_edits sorts ranges DESCENDING by startIndex
    # and attaches writeControl: {"writeMode": "SUGGEST"}
    edits_input = json.dumps(
        [
            # Deliberately supply in ascending document order (startIndex 5, then 35, then 69)
            {"quote": "roles/owner", "replacement": "roles/aiplatform.user"},
            {"quote": "gemini-1.5-pro", "replacement": "gemini-2.5-pro"},
            {"quote": "gcloud alpha chronicle list", "replacement": "gcloud chronicle instances describe"},
        ]
    )
    edit_res = propose_doc_suggested_edits(
        "doc-123",
        edits_input,
        tool_context=ctx,
        quota_project="dandye-0324-chronicle",
        transport=transport,
    )
    assert edit_res["status"] == "success"
    assert edit_res["applied_count"] == 3

    _, edit_url, edit_body, _ = recorded_requests[2]
    assert edit_url == "https://docs.googleapis.com/v1/documents/doc-123:batchUpdate"
    assert edit_body["writeControl"] == {"writeMode": "SUGGEST"}

    # Verify requests are ordered back-to-front: startIndex 69 first, then 35, then 5!
    reqs = edit_body["requests"]
    assert len(reqs) == 6
    assert reqs[0] == {"deleteContentRange": {"range": {"startIndex": 69, "endIndex": 96}}}
    assert reqs[1] == {
        "insertText": {"location": {"index": 69}, "text": "gcloud chronicle instances describe"}
    }
    assert reqs[2] == {"deleteContentRange": {"range": {"startIndex": 35, "endIndex": 49}}}
    assert reqs[3] == {"insertText": {"location": {"index": 35}, "text": "gemini-2.5-pro"}}
    assert reqs[4] == {"deleteContentRange": {"range": {"startIndex": 5, "endIndex": 16}}}
    assert reqs[5] == {"insertText": {"location": {"index": 5}, "text": "roles/aiplatform.user"}}


def test_propose_doc_suggested_edits_rejects_overlapping_ranges():
    doc_payload = make_fake_doc_payload()
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=doc_payload))
    ctx = SimpleNamespace(state={"user_access_token": "tok"})

    read_google_doc("doc-123", tool_context=ctx, transport=transport)

    # "Use roles/owner" (1..16) overlaps with "roles/owner for Vertex AI" (5..30)
    overlapping_edits = json.dumps(
        [
            {"quote": "Use roles/owner", "replacement": "Grant roles/aiplatform.user"},
            {"quote": "roles/owner for Vertex AI", "replacement": "roles/aiplatform.user for Vertex"},
        ]
    )
    res = propose_doc_suggested_edits(
        "doc-123", overlapping_edits, tool_context=ctx, transport=transport
    )
    assert res["status"] == "error"
    assert "Overlapping edit ranges" in res["message"]


def test_works_without_tool_context_via_in_process_doc_cache():
    """Direct Python callers or ADK wrappers that do not pass ``tool_context``
    still share the index map harvested by ``read_google_doc``."""
    doc_payload = make_fake_doc_payload()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc_payload)
        return httpx.Response(200, json={"replies": [{"insertComment": {"commentId": "c-standalone"}}]})

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("standalone-adc-token")

    read_res = read_google_doc(
        "doc-123", tool_context=None, token_source=token_source, transport=transport
    )
    assert read_res["status"] == "success"

    comment_res = insert_doc_comments(
        "doc-123",
        [{"quote": "roles/owner", "comment": "Use least privilege."}],
        tool_context=None,
        token_source=token_source,
        transport=transport,
    )
    assert comment_res["status"] == "success"
    assert comment_res["inserted_count"] == 1


def test_create_google_doc_creates_converted_google_doc_in_drive(
    fake_drive: FakeDriveMcpServer,
):
    reports_folder = fake_drive.store.add_folder("SOC Reports")
    client = DriveMcpClient(
        url=fake_drive.url,
        token_source=StaticTokenSource("drive-tok"),
        quota_project="dandye-0324-chronicle",
    )
    with patch.dict(os.environ, {"DRIVE_REPORTS_FOLDER_ID": reports_folder}, clear=False):
        created = create_google_doc(
            title="Suspicious Login Runbook Review",
            content="# Suspicious Login Triage\n\nUse roles/owner for Vertex AI.\n",
            client=client,
        )
    assert created["status"] == "success"
    assert created["mimeType"] == GOOGLE_DOC_MIME_TYPE
    assert created["parentId"] == reports_folder
    # Verify disableConversionToGoogleType was False so Drive converted text -> Google Doc
    create_calls = fake_drive.store.calls_for("create_file")
    assert len(create_calls) == 1
    assert create_calls[0]["disableConversionToGoogleType"] is False


def test_adk_function_tool_declarations_for_docs_review_tools():
    """Verifies that the LLM-facing wrapper functions in ``manager.tools.tools``
    generate valid ADK ``FunctionDeclaration`` schemas without leaking internal
    test-only parameters (``transport``, ``token_source``, ``client``) or
    ``tool_context``."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module

    for fn_name in (
        "create_google_doc",
        "read_google_doc",
        "insert_doc_comments",
        "propose_doc_suggested_edits",
        "review_google_doc_with_stage_a",
        "stage_runbook_update_as_google_doc",
        "post_reviewed_doc_to_soar_case",
        "verify_and_redline_udm_queries_in_doc",
        "inspect_doc_suggestions",
        "export_accepted_doc_to_markdown",
    ):
        fn = getattr(tools_module, fn_name)
        ft = FunctionTool(fn)
        decl = ft._get_declaration()
        assert decl is not None
        assert decl.name == fn_name
        schema = decl.parameters_json_schema or {}
        props = schema.get("properties", {})
        assert "tool_context" not in props
        assert "transport" not in props
        assert "token_source" not in props
        assert "client" not in props
        assert "siem_search_fn" not in props
        assert "skill_content_override" not in props


def test_sanitize_telemetry_text_redacts_encoded_blobs_and_memdump_args():
    from manager.tools.docs_review_tools import sanitize_telemetry_text

    raw_cmd = "powershell.exe -NoP -W Hidden -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk"
    sanitized = sanitize_telemetry_text(raw_cmd)
    assert "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk" not in sanitized
    assert "<REDACTED_B64:len=32,sha256=" in sanitized

    raw_dump = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\out.dmp full"
    sanitized_dump = sanitize_telemetry_text(raw_dump)
    assert "624 C:\\temp\\out.dmp" not in sanitized_dump
    assert "MiniDump <REDACTED_DUMP_ARGS:sha256=" in sanitized_dump

    sha256_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    with_hash = f"file_sha256={sha256_hex}"
    assert sanitize_telemetry_text(with_hash) == with_hash


def test_find_deterministic_indicator_spans_and_span_based_edits():
    from manager.tools.docs_review_tools import (
        _extract_text_and_index_map,
        defang_url,
        find_deterministic_indicator_spans,
    )

    assert defang_url("https://c2.badactor-example.com/auth") == "hxxps://c2[.]badactor-example[.]com/auth"

    p1 = "Callback to https://c2.badactor-example.com/auth observed.\n"
    p2 = "Reference: https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable\n"
    doc = {
        "documentId": "doc-123",
        "title": "Indicator Review Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(p1),
                                "textRun": {"content": p1},
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1 + len(p1),
                                "endIndex": 1 + len(p1) + len(p2),
                                "textRun": {"content": p2},
                            }
                        ]
                    }
                },
            ]
        },
    }
    plain_text, index_map = _extract_text_and_index_map(doc)
    comments, edits = find_deterministic_indicator_spans(plain_text, index_map)
    assert len(comments) == 1
    assert len(edits) == 1
    assert edits[0]["replacement"] == "hxxps://c2[.]badactor-example[.]com/auth"
    assert isinstance(edits[0]["start_index"], int)
    assert isinstance(edits[0]["end_index"], int)

    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc)
        body = json.loads(request.content.decode("utf-8"))
        batch_calls.append(body)
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={"replies": [{"insertComment": {"commentId": "c-span-0"}}]},
            )
        return httpx.Response(200, json={"replies": [{} for _ in body.get("requests", [])]})

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")
    ctx = SimpleNamespace(state={})
    read_google_doc("doc-123", tool_context=ctx, token_source=token_source, transport=transport)

    comment_res = insert_doc_comments(
        "doc-123",
        comments,
        tool_context=ctx,
        token_source=token_source,
        transport=transport,
    )
    assert comment_res["status"] == "success"
    assert comment_res["inserted_count"] == 1

    edit_res = propose_doc_suggested_edits(
        "doc-123",
        edits,
        tool_context=ctx,
        token_source=token_source,
        transport=transport,
    )
    assert edit_res["status"] == "success"
    assert edit_res["applied_count"] == 1
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}


def test_review_google_doc_with_stage_a_combines_span_and_semantic_reviews():
    from manager.tools.docs_review_tools import review_google_doc_with_stage_a

    p1 = "Callback to https://c2.badactor-example.com/stage2.ps1 observed.\n"
    p2 = "Containment: gcloud iam service-accounts delete compromised-sa@proj.iam.gserviceaccount.com\n"
    doc = {
        "documentId": "doc-stage-ab",
        "title": "Combined Review Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(p1),
                                "textRun": {"content": p1},
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1 + len(p1),
                                "endIndex": 1 + len(p1) + len(p2),
                                "textRun": {"content": p2},
                            }
                        ]
                    }
                },
            ]
        },
    }
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc)
        body = json.loads(request.content.decode("utf-8"))
        batch_calls.append(body)
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200, json={"replies": [{} for _ in body.get("requests", [])]}
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    res = review_google_doc_with_stage_a(
        "doc-stage-ab",
        semantic_comments=[
            {
                "quote": "gcloud iam service-accounts delete",
                "comment": "Use reversible disable instead of delete (https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable).",
            }
        ],
        semantic_edits=[
            {
                "quote": "gcloud iam service-accounts delete",
                "replacement": "gcloud iam service-accounts disable",
            }
        ],
        token_source=token_source,
        transport=transport,
    )
    assert res["status"] == "success"
    assert res["stage_a_url_count"] == 1
    assert res["comments"]["inserted_count"] == 2
    assert res["edits"]["applied_count"] == 2
    assert len(batch_calls) == 2
    assert "insertComment" in batch_calls[0]["requests"][0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    # Verify back-to-front ordering: paragraph 2 edit (higher startIndex) comes before paragraph 1 URL edit
    first_del_start = batch_calls[1]["requests"][0]["deleteContentRange"]["range"]["startIndex"]
    second_del_start = batch_calls[1]["requests"][2]["deleteContentRange"]["range"]["startIndex"]
    assert first_del_start > second_del_start


def test_stage_runbook_update_as_google_doc_creates_and_redlines_runbook_draft(
    fake_drive: FakeDriveMcpServer,
):
    from manager.tools.docs_review_tools import stage_runbook_update_as_google_doc

    reports_folder = fake_drive.store.add_folder("SOC Reports")
    client = DriveMcpClient(
        url=fake_drive.url,
        token_source=StaticTokenSource("drive-tok"),
        quota_project="dandye-0324-chronicle",
    )

    runbook_md = (
        "# Compromised User Account Response\n\n"
        "## Containment\n"
        "- Execute `gcloud iam service-accounts delete` on affected service accounts.\n"
    )
    appended_lessons = (
        "## Lessons Learned from SOAR Case 33278\n"
        "- Attacker callback URL: https://c2.badactor-example.com/beacon\n"
        "- Query UDM field: `resource.name = \"projects/base-analytics/instances/prod-customers\"`\n"
    )
    combined_text = runbook_md.rstrip() + "\n\n" + appended_lessons.strip() + "\n"
    doc_payload = {
        "documentId": "doc-runbook-1",
        "title": "Runbook_Redline_compromised-user-account-response_Case_33278",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(combined_text),
                                "textRun": {"content": combined_text},
                            }
                        ]
                    }
                }
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc_payload)
        body = json.loads(request.content.decode("utf-8"))
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-rb-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200, json={"replies": [{} for _ in body.get("requests", [])]}
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    with patch.dict(os.environ, {"DRIVE_REPORTS_FOLDER_ID": reports_folder}, clear=False):
        res = stage_runbook_update_as_google_doc(
            skill_name="compromised-user-account-response",
            case_id="33278",
            semantic_comments=[
                {
                    "quote": "gcloud iam service-accounts delete",
                    "comment": "Case 33278 Lesson Learned: Use reversible disable instead of delete (https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable).",
                },
                {
                    "quote": "resource.name",
                    "comment": "Case 33278 Lesson Learned: Prefix UDM field with target.resource.name (https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list).",
                },
            ],
            semantic_edits=[
                {
                    "quote": "gcloud iam service-accounts delete",
                    "replacement": "gcloud iam service-accounts disable",
                },
                {
                    "quote": "resource.name",
                    "replacement": "target.resource.name",
                },
            ],
            lessons_learned_markdown=appended_lessons,
            skill_content_override=runbook_md,
            client=client,
            token_source=token_source,
            transport=transport,
        )

    assert res["status"] == "success"
    assert res["skill_name"] == "compromised-user-account-response"
    assert res["case_id"] == "33278"
    assert res["stage_a_url_count"] == 1
    assert res["comments"]["inserted_count"] == 3
    assert res["edits"]["applied_count"] == 3


def test_post_reviewed_doc_to_soar_case_sanitizes_and_posts_comment():
    from manager.tools.docs_review_tools import post_reviewed_doc_to_soar_case

    recorded_soar_calls: list[tuple[str, str]] = []

    def fake_soar_post(case_id: str, comment: str) -> dict[str, Any]:
        recorded_soar_calls.append((case_id, comment))
        return {"id": 99901, "comment": comment, "case_id": case_id}

    res = post_reviewed_doc_to_soar_case(
        case_id="33288",
        doc_title="SOAR_Case_33288_Sanitized_3Stage_Intrusion_Review",
        doc_url="https://docs.google.com/document/d/doc-33288/edit",
        skill_name="phishing-response",
        redline_summary=[
            "Defanged live phishing URL via Stage A span-based addressing",
            "Corrected LSASS MiniDump 624 C:\\temp\\lsass.dmp full technique to T1003.001",
            "Sanitized stager -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
        ],
        runbook_doc_url="https://docs.google.com/document/d/rb-33288/edit",
        soar_comment_fn=fake_soar_post,
    )
    assert res["status"] == "success"
    assert len(recorded_soar_calls) == 1
    posted_case_id, posted_comment = recorded_soar_calls[0]
    assert posted_case_id == "33288"
    assert "https://docs.google.com/document/d/doc-33288/edit" in posted_comment
    assert "https://docs.google.com/document/d/rb-33288/edit" in posted_comment
    # Verify raw base64 and raw MiniDump args were sanitized before hitting SOAR
    assert "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk" not in posted_comment
    assert "<REDACTED_B64:len=32,sha256=" in posted_comment
    assert "<REDACTED_DUMP_ARGS:sha256=" in posted_comment


def test_grounded_soar_review_workflow_executes_end_to_end():
    from manager.tools.workflow_tools import run_grounded_soar_review_workflow

    out = run_grounded_soar_review_workflow(
        case_id="33278",
        skill_name="compromised-user-account-response",
        raw_telemetry_summary="powershell.exe -NoP -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
    )
    assert "33278" in out
    assert "compromised-user-account-response" in out
    assert "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk" not in out
    assert "<REDACTED_B64:len=32,sha256=" in out


# ---------------------------------------------------------------------------
# Cycle 1 (H1): Live Chronicle UDM Query Syntax & Schema Verifier Inside Docs
# ---------------------------------------------------------------------------


def test_find_udm_field_spans_detects_unprefixed_and_hallucinated_udm_fields():
    from manager.tools.docs_review_tools import (
        _extract_text_and_index_map,
        _find_quote_indices,
        find_udm_field_spans,
    )

    p1 = (
        'Valid query: `metadata.event_type = "PROCESS_LAUNCH" AND '
        'target.process.command_line = "powershell.exe" AND principal.ip = "10.0.0.1"`\n'
    )
    p2 = (
        'Broken query 1: `metadata.event_type = "PROCESS_LAUNCH" AND '
        'process.command_line = /.*-enc.*/ nocase AND principal.process.cmd_line != "cmd.exe"`\n'
    )
    p3 = (
        'Broken query 2: `metadata.log_type = "GCP_CLOUDAUDIT" AND '
        'resource.name = "projects/base-production" AND ip = "104.198.226.161"`\n'
    )
    doc = {
        "documentId": "doc-udm-spans",
        "title": "UDM Span Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(p1),
                                "textRun": {"content": p1},
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1 + len(p1),
                                "endIndex": 1 + len(p1) + len(p2),
                                "textRun": {"content": p2},
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1 + len(p1) + len(p2),
                                "endIndex": 1 + len(p1) + len(p2) + len(p3),
                                "textRun": {"content": p3},
                            }
                        ]
                    }
                },
            ]
        },
    }
    plain_text, index_map = _extract_text_and_index_map(doc)
    comments, edits, findings = find_udm_field_spans(plain_text, index_map)

    assert len(findings) == 4
    assert len(comments) == 4
    assert len(edits) == 4

    by_invalid = {f["invalid_field"]: f for f in findings}
    assert set(by_invalid.keys()) == {
        "process.command_line",
        "principal.process.cmd_line",
        "resource.name",
        "ip",
    }
    assert by_invalid["process.command_line"]["canonical_field"] == "target.process.command_line"
    assert (
        by_invalid["principal.process.cmd_line"]["canonical_field"]
        == "principal.process.command_line"
    )
    assert by_invalid["resource.name"]["canonical_field"] == "target.resource.name"
    assert by_invalid["ip"]["canonical_field"] == "principal.ip"

    # Verify exact 1-based UTF-16 span coordinates match _find_quote_indices for each defect
    for field_name in ("resource.name", "principal.process.cmd_line"):
        expected_span = _find_quote_indices(plain_text, index_map, field_name)
        assert (
            by_invalid[field_name]["start_index"],
            by_invalid[field_name]["end_index"],
        ) == expected_span


def test_verify_udm_query_with_siem_repairs_and_executes_dry_run():
    from manager.tools.docs_review_tools import verify_udm_query_with_siem

    captured_calls: list[dict[str, Any]] = []

    def fake_siem_search(
        query: str,
        start_time: str = "",
        end_time: str = "",
        max_events: int = 5,
    ) -> dict[str, Any]:
        captured_calls.append(
            {
                "query": query,
                "start_time": start_time,
                "end_time": end_time,
                "max_events": max_events,
            }
        )
        return {
            "events": [
                {"udm": {"metadata": {"eventType": "USER_RESOURCE_ACCESS"}}},
                {"udm": {"metadata": {"eventType": "USER_RESOURCE_UPDATE_CONTENT"}}},
            ]
        }

    broken_query = (
        'metadata.log_type = "GCP_CLOUDAUDIT" AND '
        'resource.name = "projects/base-production" AND ip = "104.198.226.161"'
    )
    res = verify_udm_query_with_siem(
        broken_query,
        start_time="2026-02-07T19:00:00Z",
        end_time="2026-02-07T19:35:00Z",
        max_events=10,
        siem_search_fn=fake_siem_search,
    )

    assert res["status"] == "success"
    assert res["siem_verified"] is True
    assert res["event_count"] == 2
    assert (
        res["repaired_query"]
        == 'metadata.log_type = "GCP_CLOUDAUDIT" AND '
        'target.resource.name = "projects/base-production" AND principal.ip = "104.198.226.161"'
    )
    assert len(res["replacements"]) == 2
    assert len(captured_calls) == 1
    assert captured_calls[0]["query"] == res["repaired_query"]
    assert captured_calls[0]["max_events"] == 10


def test_verify_and_redline_udm_queries_in_doc_anchors_comments_and_suggest_edits():
    from manager.tools.docs_review_tools import verify_and_redline_udm_queries_in_doc

    p1 = (
        "## Hunting Query\n"
        '`metadata.log_type = "GCP_CLOUDAUDIT" AND resource.name = "projects/base-production" '
        'AND ip = "104.198.226.161"`\n'
    )
    doc = {
        "documentId": "doc-udm-live",
        "title": "UDM Verifier Redline Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(p1),
                                "textRun": {"content": p1},
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc)
        body = json.loads(request.content.decode("utf-8"))
        batch_calls.append(body)
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-udm-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200, json={"replies": [{} for _ in body.get("requests", [])]}
        )

    def fake_siem_search(query: str, **_kwargs: Any) -> dict[str, Any]:
        return {"events": [{"id": f"ev-{i}"} for i in range(5)]}

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    res = verify_and_redline_udm_queries_in_doc(
        "doc-udm-live",
        run_live_siem_check=True,
        siem_search_fn=fake_siem_search,
        token_source=token_source,
        transport=transport,
    )

    assert res["status"] == "success"
    assert res["udm_findings_count"] == 2
    assert len(res["siem_checks"]) == 1
    assert res["siem_checks"][0]["siem_verified"] is True
    assert res["siem_checks"][0]["event_count"] == 5
    assert res["comments"]["inserted_count"] == 2
    assert res["edits"]["applied_count"] == 2

    # Verify ordering: insertComment batchUpdate first, writeMode="SUGGEST" batchUpdate second
    assert len(batch_calls) == 2
    comment_reqs = batch_calls[0]["requests"]
    assert len(comment_reqs) == 2
    assert "udm-field-list" in comment_reqs[0]["insertComment"]["content"]
    assert "events_matched=5" in comment_reqs[0]["insertComment"]["content"]

    edit_batch = batch_calls[1]
    assert edit_batch["writeControl"] == {"writeMode": "SUGGEST"}
    # Descending startIndex order: 'ip' (later in line) deleted/inserted before 'resource.name' (earlier)
    first_del = edit_batch["requests"][0]["deleteContentRange"]["range"]["startIndex"]
    second_del = edit_batch["requests"][2]["deleteContentRange"]["range"]["startIndex"]
    assert first_del > second_del


def test_review_google_doc_with_stage_a_deduplicates_udm_and_semantic_spans():
    from manager.tools.docs_review_tools import review_google_doc_with_stage_a

    p1 = (
        'Run query: `metadata.event_type = "PROCESS_LAUNCH" AND '
        'process.command_line = /.*-enc.*/ AND file.sha256 = "abcd"`\n'
    )
    doc = {
        "documentId": "doc-dedup-udm",
        "title": "Dedup UDM Stage A/B Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(p1),
                                "textRun": {"content": p1},
                            }
                        ]
                    }
                }
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc)
        body = json.loads(request.content.decode("utf-8"))
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-dedup-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200, json={"replies": [{} for _ in body.get("requests", [])]}
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    # Caller explicitly supplies a semantic comment/edit for 'process.command_line',
    # while leaving 'file.sha256' to be caught automatically by Stage A UDM detection.
    res = review_google_doc_with_stage_a(
        "doc-dedup-udm",
        semantic_comments=[
            {
                "quote": "process.command_line",
                "comment": "Custom caller comment for process.command_line.",
            }
        ],
        semantic_edits=[
            {
                "quote": "process.command_line",
                "replacement": "target.process.command_line",
            }
        ],
        token_source=token_source,
        transport=transport,
    )

    assert res["status"] == "success"
    assert res["stage_a_udm_count"] == 2
    # 1 deduplicated Stage A UDM edit (file.sha256) + 1 Stage B semantic edit (process.command_line) = 2
    assert res["comments"]["inserted_count"] == 2
    assert res["edits"]["applied_count"] == 2


# ---------------------------------------------------------------------------
# Cycle 2 (H3): Bidirectional Google Docs Suggestion Inspector, Multi-Pass
# Idempotency & Markdown Runbook Sync
# ---------------------------------------------------------------------------


def _make_inline_suggestions_doc_payload() -> dict[str, Any]:
    """Builds a realistic Google Docs API v1 ``SUGGESTIONS_INLINE`` payload.

    Mirrors the exact wire structure returned by Docs API v1 after
    ``writeMode="SUGGEST"`` edits:
    - Paragraph 1 has a replacement (`suggest.rep1`: `ip` -> `principal.ip`).
    - Paragraph 2 is untouched after the shift (`resource.name = "projects/base-production"\n`).
    """
    pre = 'Query: `metadata.log_type = "GCP_CLOUDAUDIT" AND '  # len 49 -> 1..50
    ins = "principal.ip"  # len 12 -> 50..62
    dele = "ip"  # len 2 -> 62..64
    post = ' = "104.198.226.161"`\n'  # len 22 -> 64..86
    p2 = 'Next: `resource.name = "projects/base-production"`\n'  # len 51 -> 86..137
    return {
        "documentId": "doc-inline-sugg",
        "title": "Inline Suggestion Projection Test",
        "tabs": [
            {
                "documentTab": {
                    "body": {
                        "content": [
                            {
                                "paragraph": {
                                    "elements": [
                                        {
                                            "startIndex": 1,
                                            "endIndex": 50,
                                            "textRun": {"content": pre},
                                        },
                                        {
                                            "startIndex": 50,
                                            "endIndex": 62,
                                            "textRun": {
                                                "content": ins,
                                                "suggestedInsertionIds": ["suggest.rep1"],
                                            },
                                        },
                                        {
                                            "startIndex": 62,
                                            "endIndex": 64,
                                            "textRun": {
                                                "content": dele,
                                                "suggestedDeletionIds": ["suggest.rep1"],
                                            },
                                        },
                                        {
                                            "startIndex": 64,
                                            "endIndex": 86,
                                            "textRun": {"content": post},
                                        },
                                    ]
                                }
                            },
                            {
                                "paragraph": {
                                    "elements": [
                                        {
                                            "startIndex": 86,
                                            "endIndex": 137,
                                            "textRun": {"content": p2},
                                        }
                                    ]
                                }
                            },
                        ]
                    }
                }
            }
        ],
    }


def test_extract_text_and_index_map_handles_inline_suggestions_without_text_fusion():
    from manager.tools.docs_review_tools import (
        _extract_text_and_index_map,
        _find_quote_indices,
        extract_doc_projections,
    )

    doc = _make_inline_suggestions_doc_payload()

    baseline_text, baseline_map = _extract_text_and_index_map(doc, view_mode="baseline")
    accepted_text, accepted_map = _extract_text_and_index_map(doc, view_mode="accepted")
    inline_text, _ = _extract_text_and_index_map(doc, view_mode="inline")

    # Baseline excludes suggestedInsertionIds so 'principal.ip' and 'ip' never fuse
    assert "principal.ipip" not in baseline_text
    assert "ipprincipal.ip" not in baseline_text
    assert 'AND ip = "104.198.226.161"' in baseline_text
    assert "principal.ip" not in baseline_text

    # Accepted excludes suggestedDeletionIds and includes suggestedInsertionIds
    assert 'AND principal.ip = "104.198.226.161"' in accepted_text
    assert "principal.ipip" not in accepted_text
    assert len(accepted_text) == len(accepted_map)

    # Inline preserves the raw concatenation
    assert "principal.ipip" in inline_text

    # Subsequent untouched paragraph still maps to its exact post-suggestion UTF-16 indices (93..106)
    res_span = _find_quote_indices(baseline_text, baseline_map, "resource.name")
    assert res_span == (93, 106)

    projections = extract_doc_projections(doc)
    assert len(projections["suggestions"]) == 1
    s0 = projections["suggestions"][0]
    assert s0["suggestion_id"] == "suggest.rep1"
    assert s0["kind"] == "replace"
    assert s0["deleted_text"] == "ip"
    assert s0["inserted_text"] == "principal.ip"
    assert s0["start_index"] == 50
    assert s0["end_index"] == 64
    assert projections["pending_suggestion_spans"] == [(50, 64)]


def test_inspect_doc_suggestions_returns_structured_pairs_and_unified_diff():
    from manager.tools.docs_review_tools import inspect_doc_suggestions

    doc = {
        "documentId": "doc-inspect-1",
        "title": "Runbook Redline Diff Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 15,
                                "textRun": {"content": "Containment: `"},
                            },
                            {
                                "startIndex": 15,
                                "endIndex": 50,
                                "textRun": {
                                    "content": "gcloud iam service-accounts disable",
                                    "suggestedInsertionIds": ["suggest.sa_fix"],
                                },
                            },
                            {
                                "startIndex": 50,
                                "endIndex": 84,
                                "textRun": {
                                    "content": "gcloud iam service-accounts delete",
                                    "suggestedDeletionIds": ["suggest.sa_fix"],
                                },
                            },
                            {
                                "startIndex": 84,
                                "endIndex": 86,
                                "textRun": {"content": "`\n"},
                            },
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 86,
                                "endIndex": 108,
                                "textRun": {
                                    "content": "Note: verify scope.\n",
                                    "suggestedInsertionIds": ["suggest.pure_ins"],
                                },
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 108,
                                "endIndex": 126,
                                "textRun": {
                                    "content": "Deprecated step.\n",
                                    "suggestedDeletionIds": ["suggest.pure_del"],
                                },
                            }
                        ]
                    }
                },
            ]
        },
    }

    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=doc))
    token_source = StaticTokenSource("adc-token")

    res_all = inspect_doc_suggestions(
        "doc-inspect-1",
        token_source=token_source,
        transport=transport,
    )
    assert res_all["status"] == "success"
    assert res_all["suggestion_count"] == 3
    assert res_all["accepted_suggestion_count"] == 3
    by_id = {s["suggestion_id"]: s for s in res_all["suggestions"]}
    assert by_id["suggest.sa_fix"]["kind"] == "replace"
    assert by_id["suggest.pure_ins"]["kind"] == "insert"
    assert by_id["suggest.pure_del"]["kind"] == "delete"
    assert "-Containment: `gcloud iam service-accounts delete`" in res_all["unified_diff"]
    assert "+Containment: `gcloud iam service-accounts disable`" in res_all["unified_diff"]
    assert "Deprecated step." not in res_all["accepted_text"]
    assert "Note: verify scope." in res_all["accepted_text"]

    # Selective acceptance: accept only suggest.sa_fix, reject pure_ins and pure_del
    res_partial = inspect_doc_suggestions(
        "doc-inspect-1",
        accept_suggestion_ids=["suggest.sa_fix"],
        token_source=token_source,
        transport=transport,
    )
    assert res_partial["accepted_suggestion_count"] == 1
    assert "gcloud iam service-accounts disable" in res_partial["accepted_text"]
    assert "Note: verify scope." not in res_partial["accepted_text"]
    assert "Deprecated step." in res_partial["accepted_text"]


def test_multi_pass_review_skips_spans_with_existing_pending_suggestions():
    from manager.tools.docs_review_tools import (
        review_google_doc_with_stage_a,
        verify_and_redline_udm_queries_in_doc,
    )

    # Doc has 1 already-suggested UDM fix ('ip' -> 'principal.ip' at 50..64)
    # and 1 untouched UDM defect ('resource.name' at 93..106)
    doc = _make_inline_suggestions_doc_payload()
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=doc)
        body = json.loads(request.content.decode("utf-8"))
        batch_calls.append(body)
        if "insertComment" in json.dumps(body):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-mp-{i}"}}
                        for i in range(len(body.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200, json={"replies": [{} for _ in body.get("requests", [])]}
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    # Pass 1 on partially-redlined doc: skips 'ip' (already has suggest.rep1) and only redlines 'resource.name'
    res = verify_and_redline_udm_queries_in_doc(
        "doc-inline-sugg",
        run_live_siem_check=False,
        token_source=token_source,
        transport=transport,
    )
    assert res["status"] == "success"
    assert res["skipped_existing_suggestion_count"] == 1
    assert res["udm_findings_count"] == 1
    assert res["findings"][0]["invalid_field"] == "resource.name"
    assert res["edits"]["applied_count"] == 1

    # Now test a fully red-lined doc where all defects already have pending suggestions:
    fully_redlined_doc = {
        "documentId": "doc-fully-redlined",
        "title": "Fully Redlined Doc",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 50,
                                "textRun": {
                                    "content": 'Query: `metadata.log_type = "GCP_CLOUDAUDIT" AND '
                                },
                            },
                            {
                                "startIndex": 50,
                                "endIndex": 62,
                                "textRun": {
                                    "content": "principal.ip",
                                    "suggestedInsertionIds": ["suggest.rep1"],
                                },
                            },
                            {
                                "startIndex": 62,
                                "endIndex": 64,
                                "textRun": {
                                    "content": "ip",
                                    "suggestedDeletionIds": ["suggest.rep1"],
                                },
                            },
                            {
                                "startIndex": 64,
                                "endIndex": 86,
                                "textRun": {"content": ' = "104.198.226.161"`\n'},
                            },
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    transport_full = httpx.MockTransport(
        lambda req: httpx.Response(200, json=fully_redlined_doc)
    )

    res_idempotent = verify_and_redline_udm_queries_in_doc(
        "doc-fully-redlined",
        run_live_siem_check=False,
        token_source=token_source,
        transport=transport_full,
    )
    assert res_idempotent["status"] == "success"
    assert res_idempotent["skipped_existing_suggestion_count"] == 1
    assert res_idempotent["udm_findings_count"] == 0
    assert res_idempotent["comments"]["inserted_count"] == 0
    assert res_idempotent["edits"]["applied_count"] == 0

    res_stage_a_idempotent = review_google_doc_with_stage_a(
        "doc-fully-redlined",
        semantic_comments=[{"quote": "ip", "comment": "Duplicate comment"}],
        semantic_edits=[{"quote": "ip", "replacement": "principal.ip"}],
        token_source=token_source,
        transport=transport_full,
    )
    assert res_stage_a_idempotent["status"] == "success"
    assert res_stage_a_idempotent["skipped_existing_suggestion_count"] == 1
    assert res_stage_a_idempotent["comments"]["inserted_count"] == 0
    assert res_stage_a_idempotent["edits"]["applied_count"] == 0


def test_export_accepted_doc_to_markdown_restores_frontmatter_and_applies_edits(
    tmp_path,
    fake_drive: FakeDriveMcpServer,
):
    from manager.tools.docs_review_tools import export_accepted_doc_to_markdown
    from skills.drive_registry import parse_frontmatter
    from skills.registry import SkillRegistry

    reports_folder = fake_drive.store.add_folder("SOC Reports")
    drive_client = DriveMcpClient(
        url=fake_drive.url,
        token_source=StaticTokenSource("drive-tok"),
        quota_project="dandye-0324-chronicle",
    )

    source_skill_md = (
        "---\n"
        "name: compromised-user-account-response\n"
        "description: Use when executing containment for compromised user credentials.\n"
        "category: irps\n"
        "version: 1.0.0\n"
        "---\n\n"
        "# Compromised User Account IRP\n"
    )

    # Simulate a converted Google Doc where YAML frontmatter '---' was collapsed into a single line
    # and 3 Suggested Edits are pending:
    collapsed_fm = (
        "name: compromised-user-account-response description: Use when executing "
        "containment for compromised user credentials. category: irps version: 1.0.0\n"
    )
    doc = {
        "documentId": "doc-export-rb",
        "title": "Runbook_Redline_compromised-user-account-response_Case_33278",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {"startIndex": 1, "endIndex": 2, "textRun": {"content": "\n"}}
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 2,
                                "endIndex": 2 + len(collapsed_fm),
                                "textRun": {"content": collapsed_fm},
                            }
                        ]
                    }
                },
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 200,
                                "endIndex": 235,
                                "textRun": {
                                    "content": "# Compromised User Account IRP\n\nRun "
                                },
                            },
                            {
                                "startIndex": 235,
                                "endIndex": 270,
                                "textRun": {
                                    "content": "gcloud iam service-accounts disable",
                                    "suggestedInsertionIds": ["suggest.1"],
                                },
                            },
                            {
                                "startIndex": 270,
                                "endIndex": 304,
                                "textRun": {
                                    "content": "gcloud iam service-accounts delete",
                                    "suggestedDeletionIds": ["suggest.1"],
                                },
                            },
                            {
                                "startIndex": 304,
                                "endIndex": 318,
                                "textRun": {"content": " and query `"},
                            },
                            {
                                "startIndex": 318,
                                "endIndex": 338,
                                "textRun": {
                                    "content": "target.resource.name",
                                    "suggestedInsertionIds": ["suggest.2"],
                                },
                            },
                            {
                                "startIndex": 338,
                                "endIndex": 351,
                                "textRun": {
                                    "content": "resource.name",
                                    "suggestedDeletionIds": ["suggest.2"],
                                },
                            },
                            {
                                "startIndex": 351,
                                "endIndex": 370,
                                "textRun": {"content": '` for beacon URL '},
                            },
                            {
                                "startIndex": 370,
                                "endIndex": 413,
                                "textRun": {
                                    "content": "hxxps://c2[.]badactor-example[.]com/beacon",
                                    "suggestedInsertionIds": ["suggest.3"],
                                },
                            },
                            {
                                "startIndex": 413,
                                "endIndex": 452,
                                "textRun": {
                                    "content": "https://c2.badactor-example.com/beacon",
                                    "suggestedDeletionIds": ["suggest.3"],
                                },
                            },
                            {
                                "startIndex": 452,
                                "endIndex": 454,
                                "textRun": {"content": ".\n"},
                            },
                        ]
                    }
                },
            ]
        },
    }

    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=doc))
    token_source = StaticTokenSource("adc-token")
    out_file = tmp_path / "exported_runbook" / "SKILL.md"

    with patch.dict(os.environ, {"DRIVE_REPORTS_FOLDER_ID": reports_folder}, clear=False):
        res = export_accepted_doc_to_markdown(
            "doc-export-rb",
            skill_name="compromised-user-account-response",
            output_path=str(out_file),
            publish_to_drive=True,
            skill_content_override=source_skill_md,
            client=drive_client,
            token_source=token_source,
            transport=transport,
        )

    assert res["status"] == "success"
    assert res["suggestion_count"] == 3
    assert res["accepted_suggestion_count"] == 3
    assert res["frontmatter_restored"] is True
    assert res["frontmatter_valid"] is True
    assert res["frontmatter"]["name"] == "compromised-user-account-response"

    exported_md = res["accepted_markdown"]
    assert exported_md.startswith("---\nname: compromised-user-account-response\n")
    assert "gcloud iam service-accounts disable" in exported_md
    assert "gcloud iam service-accounts delete" not in exported_md
    assert "target.resource.name" in exported_md
    assert "hxxps://c2[.]badactor-example[.]com/beacon" in exported_md
    assert "https://c2.badactor-example.com/beacon" not in exported_md

    # Verify written file on disk parses cleanly through SkillRegistry
    assert out_file.exists()
    parsed_fm = parse_frontmatter(out_file.read_text(encoding="utf-8"))
    assert parsed_fm["name"] == "compromised-user-account-response"
    temp_reg = SkillRegistry(skills_dir=tmp_path)
    meta = temp_reg.get_skill("compromised-user-account-response")
    assert meta is not None
    assert meta.category == "irps"
    assert res["drive"] is not None
    assert res["drive"]["parentId"] == reports_folder




