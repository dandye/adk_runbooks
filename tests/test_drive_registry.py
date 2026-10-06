"""Tests for the Drive-backed skill registry and its MCP client.

Most tests talk to the in-process fake Drive MCP server (see
``tests/fake_drive_mcp.py``) over real HTTP so the stateless JSON-RPC path,
pagination, base64 decoding and SSE parsing are all exercised end to end.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from skills.drive_registry import (
    AdcTokenSource,
    DriveMcpClient,
    DriveMcpError,
    DriveRegistryConfigError,
    DriveSkillMetadata,
    DriveSkillRegistry,
    StaticTokenSource,
    build_runbook_query,
    parse_frontmatter,
    parse_jsonrpc_response,
    skill_name_from_title,
    unwrap_tool_result,
)
from skills.registry import SkillRegistry
from tests.fake_drive_mcp import (
    GOOGLE_DOC_MIME_TYPE,
    PERMISSION_DENIED_MESSAGE,
    FakeDriveMcpServer,
    FakeDriveStore,
)

TRIAGE_RUNBOOK = (
    "---\n"
    "name: triage-alerts\n"
    "description: Assessing incoming security alerts.\n"
    "category: triage\n"
    "version: 2.1.0\n"
    "---\n\n"
    "# Alert Triage Instructions\n\n"
    "```yaral\n"
    "rule example { meta: author = \"soc\" }\n"
    "```\n"
    "1. Inspect alert.\n"
)

PHISHING_RUNBOOK = "# Phishing Response\n\nContain the mailbox first.\n"


class FakeClock:
    """Deterministic monotonic clock for TTL tests."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_client(server: FakeDriveMcpServer, quota_project: str = "test-project") -> DriveMcpClient:
    return DriveMcpClient(
        url=server.url,
        token_source=StaticTokenSource("test-token"),
        quota_project=quota_project,
    )


def make_registry(
    server: FakeDriveMcpServer,
    folder_id: str,
    *,
    ttl: float = 60.0,
    clock: FakeClock | None = None,
) -> DriveSkillRegistry:
    return DriveSkillRegistry(
        folder_id=folder_id,
        client=make_client(server),
        cache_ttl_seconds=ttl,
        clock=clock or FakeClock(),
    )


def seed_runbooks(store: FakeDriveStore) -> tuple[str, str, str]:
    folder = store.add_folder("SOC Runbooks")
    triage = store.add_markdown("triage-alerts.md", TRIAGE_RUNBOOK, folder)
    phishing = store.add_markdown("Phishing Response.md", PHISHING_RUNBOOK, folder)
    return folder, triage, phishing


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def test_build_runbook_query_uses_drive_mcp_grammar():
    query = build_runbook_query("abc123")
    assert query == "parentId = 'abc123' and mimeType = 'text/markdown'"
    assert "in parents" not in query
    with pytest.raises(DriveRegistryConfigError):
        build_runbook_query("")


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("triage-alerts.md", "triage-alerts"),
        ("Phishing Response.md", "phishing-response"),
        ("Deep_Dive  Investigation.MD", "deep-dive-investigation"),
        ("weird!!name", "weirdname"),
    ],
)
def test_skill_name_from_title(title: str, expected: str):
    assert skill_name_from_title(title) == expected


def test_parse_frontmatter_handles_missing_and_invalid_yaml():
    assert parse_frontmatter(TRIAGE_RUNBOOK)["name"] == "triage-alerts"
    assert parse_frontmatter(PHISHING_RUNBOOK) == {}
    assert parse_frontmatter("---\nname: [unterminated\n---\nbody") == {}
    assert parse_frontmatter("---\n- just\n- a list\n---\nbody") == {}


def _response(content_type: str, body: str) -> httpx.Response:
    request = httpx.Request("POST", "https://example.invalid/mcp")
    return httpx.Response(
        200, headers={"content-type": content_type}, content=body.encode("utf-8"), request=request
    )


def test_parse_jsonrpc_response_json_object_and_batch():
    message = {"jsonrpc": "2.0", "id": 1, "result": {"content": []}}
    assert parse_jsonrpc_response(_response("application/json", json.dumps(message))) == message
    batch = [{"jsonrpc": "2.0", "method": "notifications/progress"}, message]
    assert parse_jsonrpc_response(_response("application/json", json.dumps(batch))) == message
    with pytest.raises(DriveMcpError):
        parse_jsonrpc_response(_response("application/json", "<html>nope</html>"))


def test_parse_jsonrpc_response_sse_picks_last_result_event():
    message = {"jsonrpc": "2.0", "id": 7, "result": {"content": [], "structuredContent": {"ok": 1}}}
    body = (
        "event: message\n"
        'data: {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}\n\n'
        "event: message\n"
        f"data: {json.dumps(message)}\n\n"
        ": keep-alive\n\n"
    )
    assert parse_jsonrpc_response(_response("text/event-stream; charset=utf-8", body)) == message
    with pytest.raises(DriveMcpError):
        parse_jsonrpc_response(_response("text/event-stream", ": only a comment\n\n"))


def test_unwrap_tool_result_prefers_structured_content_and_raises_on_error():
    structured = {"files": [{"id": "1"}]}
    result = {"content": [{"type": "text", "text": "ignored"}], "structuredContent": structured}
    assert unwrap_tool_result(result) is structured
    assert unwrap_tool_result({"content": [{"type": "text", "text": '{"a": 1}'}]}) == {"a": 1}
    assert unwrap_tool_result({"content": [{"type": "text", "text": "plain text"}]}) == "plain text"
    assert unwrap_tool_result({"content": []}) == {}
    with pytest.raises(DriveMcpError, match="does not have permission"):
        unwrap_tool_result(
            {"isError": True, "content": [{"type": "text", "text": PERMISSION_DENIED_MESSAGE}]}
        )


def test_adc_token_source_refuses_missing_isolated_adc(tmp_path: Path):
    env = {"CLOUDSDK_CONFIG": str(tmp_path)}
    with patch.dict(os.environ, env, clear=False):
        os.environ.pop("GOOGLE_APPLICATION_CREDENTIALS", None)
        with pytest.raises(DriveRegistryConfigError, match="--enable-gdrive-access"):
            AdcTokenSource()()


# --------------------------------------------------------------------------
# Client against the fake server
# --------------------------------------------------------------------------


def test_client_sends_bearer_and_quota_project_headers(fake_drive: FakeDriveMcpServer):
    folder, _, _ = seed_runbooks(fake_drive.store)
    client = make_client(fake_drive, quota_project="dandye-0324-chronicle")
    page = client.search_files(build_runbook_query(folder))
    assert {f["title"] for f in page["files"]} == {"triage-alerts.md", "Phishing Response.md"}
    headers = fake_drive.store.last_headers
    assert headers["authorization"] == "Bearer test-token"
    assert headers["x-goog-user-project"] == "dandye-0324-chronicle"
    assert "text/event-stream" in headers["accept"]
    assert fake_drive.store.calls_for("search_files")[0]["excludeContentSnippets"] is True


def test_client_download_text_decodes_base64_exactly(fake_drive: FakeDriveMcpServer):
    _, triage, _ = seed_runbooks(fake_drive.store)
    client = make_client(fake_drive)
    assert client.download_text(triage) == TRIAGE_RUNBOOK
    # read_file_content is the verbalized variant: fences are gone.
    verbalized = client.read_file_content(triage)
    assert "Alert Triage Instructions" in verbalized
    assert "```" not in verbalized
    meta = client.get_file_metadata(triage)
    assert meta["title"] == "triage-alerts.md"
    assert meta["mimeType"] == "text/markdown"


def test_client_create_markdown_file_disables_doc_conversion(fake_drive: FakeDriveMcpServer):
    folder = fake_drive.store.add_folder("SOC Reports")
    client = make_client(fake_drive)
    created = client.create_markdown_file(
        title="incident-report.md", text="# Report\n\nAll clear.\n", parent_id=folder
    )
    assert created["mimeType"] == "text/markdown"
    assert created["parentId"] == folder
    assert created["viewUrl"].startswith("https://drive.google.com/")
    call = fake_drive.store.calls_for("create_file")[0]
    assert call["disableConversionToGoogleType"] is True
    assert call["contentMimeType"] == "text/markdown"
    assert client.download_text(created["id"]) == "# Report\n\nAll clear.\n"


def test_fake_server_converts_text_to_google_doc_without_flag(fake_drive: FakeDriveMcpServer):
    """Guards the fake itself: omitting the flag must be observable."""
    folder = fake_drive.store.add_folder("SOC Reports")
    client = make_client(fake_drive)
    created = client.call_tool(
        "create_file",
        {"title": "x.md", "contentMimeType": "text/markdown", "textContent": "x", "parentId": folder},
    )
    assert created["mimeType"] == GOOGLE_DOC_MIME_TYPE


def test_client_rejects_drive_v3_parent_grammar(fake_drive: FakeDriveMcpServer):
    folder, _, _ = seed_runbooks(fake_drive.store)
    client = make_client(fake_drive)
    with pytest.raises(DriveMcpError, match="Invalid query clause"):
        client.search_files(f"'{folder}' in parents")


def test_client_surfaces_permission_denied(fake_drive: FakeDriveMcpServer):
    fake_drive.store.deny_message = PERMISSION_DENIED_MESSAGE
    client = make_client(fake_drive)
    with pytest.raises(DriveMcpError, match=PERMISSION_DENIED_MESSAGE):
        client.search_files("mimeType = 'text/markdown'")


def test_client_handles_sse_responses(fake_drive_sse: FakeDriveMcpServer):
    _, triage, _ = seed_runbooks(fake_drive_sse.store)
    client = make_client(fake_drive_sse)
    assert client.download_text(triage) == TRIAGE_RUNBOOK
    page = client.search_files("mimeType = 'text/markdown'")
    assert len(page["files"]) == 2


def test_client_reports_http_errors(fake_drive: FakeDriveMcpServer):
    client = DriveMcpClient(
        url=fake_drive.url.replace("/mcp", "/definitely-not-mcp"),
        token_source=StaticTokenSource("t"),
        quota_project="p",
    )
    with pytest.raises(DriveMcpError, match="HTTP 404"):
        client.call_tool("search_files", {"query": "mimeType = 'text/markdown'"})


# --------------------------------------------------------------------------
# Registry against the fake server
# --------------------------------------------------------------------------


def test_registry_requires_folder_id(fake_drive: FakeDriveMcpServer):
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("DRIVE_RUNBOOKS_FOLDER_ID", None)
        with pytest.raises(DriveRegistryConfigError, match="DRIVE_RUNBOOKS_FOLDER_ID"):
            DriveSkillRegistry(client=make_client(fake_drive))


def test_registry_scans_folder_and_keeps_skill_registry_contract(fake_drive: FakeDriveMcpServer):
    folder, triage_id, phishing_id = seed_runbooks(fake_drive.store)
    # Noise that must not be indexed: a Google Doc in the folder and Markdown elsewhere.
    fake_drive.store.add_markdown("notes.md", "nope", folder, mime_type=GOOGLE_DOC_MIME_TYPE)
    other_folder = fake_drive.store.add_folder("Elsewhere")
    fake_drive.store.add_markdown("stray.md", "nope", other_folder)

    registry = make_registry(fake_drive, folder)
    assert isinstance(registry, SkillRegistry)

    triage = registry.get_skill("triage-alerts")
    assert isinstance(triage, DriveSkillMetadata)
    assert triage.file_id == triage_id
    assert triage.category == "triage"
    assert triage.version == "2.1.0"
    assert triage.description == "Assessing incoming security alerts."
    assert triage.view_url.endswith(f"/{triage_id}/view")
    # Hyphen/underscore aliases behave like the local registry.
    assert registry.get_skill("triage_alerts") is triage

    phishing = registry.get_skill("phishing-response")
    assert isinstance(phishing, DriveSkillMetadata)
    assert phishing.file_id == phishing_id
    assert phishing.category == "drive"
    assert phishing.description == "Runbook Phishing Response.md"

    assert registry.get_skill("stray") is None
    assert registry.get_skill("notes") is None

    # Exact bytes round-trip, including frontmatter and fenced code.
    assert registry.get_skill_content("triage_alerts") == TRIAGE_RUNBOOK
    assert registry.get_skill_content("phishing-response") == PHISHING_RUNBOOK
    assert registry.get_skill_content("missing").startswith("Error: Skill 'missing' not found")

    catalog = registry.get_skill_catalog()
    assert "triage-alerts" in catalog and "phishing-response" in catalog
    assert [s.name for s in registry.list_skills_by_category("triage")] == ["triage-alerts"]


def test_registry_paginates_through_large_folders(fake_drive: FakeDriveMcpServer):
    folder = fake_drive.store.add_folder("SOC Runbooks")
    for index in range(7):
        fake_drive.store.add_markdown(f"runbook-{index}.md", f"# Runbook {index}\n", folder)
    client = DriveMcpClient(
        url=fake_drive.url, token_source=StaticTokenSource("t"), quota_project="p"
    )
    registry = DriveSkillRegistry(folder_id=folder, client=client, cache_ttl_seconds=60)
    names = {m.name for m in registry.skills.values()}
    assert names == {f"runbook-{i}" for i in range(7)}

    # Re-scan with a tiny page size to prove nextPageToken is followed.
    fake_drive.store.calls.clear()
    files = list(client.iter_files(build_runbook_query(folder), page_size=3))
    assert len(files) == 7
    search_calls = fake_drive.store.calls_for("search_files")
    assert [c["pageToken"] for c in search_calls] == [None, "3", "6"]


def test_registry_ttl_refresh_redownloads_only_changed_files(fake_drive: FakeDriveMcpServer):
    folder, triage_id, _ = seed_runbooks(fake_drive.store)
    clock = FakeClock()
    registry = make_registry(fake_drive, folder, ttl=30, clock=clock)
    assert len(fake_drive.store.calls_for("download_file_content")) == 2

    # Within the TTL nothing is re-listed.
    clock.advance(10)
    assert registry.get_skill_content("triage-alerts") == TRIAGE_RUNBOOK
    assert len(fake_drive.store.calls_for("search_files")) == 1

    # An analyst edits the runbook in Drive; after the TTL it is picked up and
    # the untouched runbook is not downloaded again.
    updated = TRIAGE_RUNBOOK.replace("1. Inspect alert.", "1. Inspect alert carefully.")
    fake_drive.store.update_markdown(
        triage_id, updated, modified_time="2026-02-02T00:00:00.000Z"
    )
    clock.advance(31)
    assert registry.get_skill_content("triage-alerts") == updated
    assert len(fake_drive.store.calls_for("search_files")) == 2
    downloads = fake_drive.store.calls_for("download_file_content")
    assert [c["fileId"] for c in downloads].count(triage_id) == 2
    assert len(downloads) == 3

    # A newly added runbook appears after the next TTL window.
    fake_drive.store.add_markdown("new-runbook.md", "# New\n", folder)
    clock.advance(31)
    assert registry.get_skill("new-runbook") is not None
    assert registry.get_skill_content("new_runbook") == "# New\n"


def test_registry_serves_cached_catalog_when_refresh_fails(fake_drive: FakeDriveMcpServer):
    folder, _, _ = seed_runbooks(fake_drive.store)
    clock = FakeClock()
    registry = make_registry(fake_drive, folder, ttl=5, clock=clock)

    fake_drive.store.deny_message = PERMISSION_DENIED_MESSAGE
    clock.advance(60)
    # No exception: the last good catalog keeps serving the investigation.
    assert registry.get_skill_content("triage-alerts") == TRIAGE_RUNBOOK
    assert "phishing-response" in registry.get_skill_catalog()


def test_registry_construction_fails_loudly_without_access(fake_drive: FakeDriveMcpServer):
    folder, _, _ = seed_runbooks(fake_drive.store)
    fake_drive.store.deny_message = PERMISSION_DENIED_MESSAGE
    with pytest.raises(DriveMcpError, match=PERMISSION_DENIED_MESSAGE):
        make_registry(fake_drive, folder)


def test_registry_skips_undownloadable_files(fake_drive: FakeDriveMcpServer):
    folder, triage_id, _ = seed_runbooks(fake_drive.store)
    store = fake_drive.store
    original_download = store.download

    def flaky_download(file_id: str, export_mime_type):
        if file_id == triage_id:
            from mcp.server.fastmcp.exceptions import ToolError  # pylint: disable=import-outside-toplevel

            store._record("download_file_content", {"fileId": file_id})  # pylint: disable=protected-access
            raise ToolError("backend hiccup")
        return original_download(file_id, export_mime_type)

    with patch.object(store, "download", side_effect=flaky_download):
        registry = make_registry(fake_drive, folder)
    assert registry.get_skill("triage-alerts") is None
    assert registry.get_skill("phishing-response") is not None


def test_registry_reads_configuration_from_environment(fake_drive: FakeDriveMcpServer):
    folder, _, _ = seed_runbooks(fake_drive.store)
    env = {
        "DRIVE_RUNBOOKS_FOLDER_ID": folder,
        "DRIVE_RUNBOOKS_CACHE_TTL_SECONDS": "120",
        "DRIVE_MCP_URL": fake_drive.url,
        "DRIVE_MCP_QUOTA_PROJECT": "env-project",
    }
    with patch.dict(os.environ, env, clear=False):
        client = DriveMcpClient(token_source=StaticTokenSource("env-token"))
        registry = DriveSkillRegistry(client=client)
    assert registry.folder_id == folder
    assert registry.cache_ttl_seconds == 120.0
    assert client.url == fake_drive.url
    assert client.quota_project == "env-project"
    assert fake_drive.store.last_headers["x-goog-user-project"] == "env-project"
    assert registry.get_skill("triage-alerts") is not None
    assert base64.b64decode(
        fake_drive.store.download(registry.get_skill("triage-alerts").file_id, None)["content"]
    ).decode() == TRIAGE_RUNBOOK
