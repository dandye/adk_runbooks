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


