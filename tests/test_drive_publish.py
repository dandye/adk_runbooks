"""Tests for the Drive wiring in ``manager.tools``: runbook source selection,
the ADK Drive ``McpToolset`` and report publishing."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from manager.tools import drive_tools
from manager.tools import tools as tools_module
from manager.tools.drive_tools import (
    DRIVE_TOOL_FILTER,
    BearerTokenAuth,
    build_skill_registry,
    drive_toolset_configured,
    init_drive_toolset,
    make_drive_httpx_client_factory,
    publish_report_to_drive,
)
from skills.drive_registry import (
    DriveMcpClient,
    DriveRegistryConfigError,
    DriveSkillRegistry,
    StaticTokenSource,
)
from skills.registry import SkillRegistry
from tests.fake_drive_mcp import PERMISSION_DENIED_MESSAGE, FakeDriveMcpServer

RUNBOOK = (
    "---\n"
    "name: triage-alerts\n"
    "description: Assessing incoming security alerts.\n"
    "category: triage\n"
    "---\n\n"
    "# Alert Triage Instructions\n"
)

REPORT_BODY = "# Incident Report\n\n## Summary\n\nContained.\n"


def make_client(server: FakeDriveMcpServer) -> DriveMcpClient:
    return DriveMcpClient(
        url=server.url, token_source=StaticTokenSource("test-token"), quota_project="test-project"
    )


@pytest.fixture
def drive_env(fake_drive: FakeDriveMcpServer):
    """Environment that points the Drive integration at the fake server.

    ``AdcTokenSource`` is swapped for a static token so nothing touches gcloud.
    """
    runbooks = fake_drive.store.add_folder("SOC Runbooks")
    reports = fake_drive.store.add_folder("SOC Reports")
    fake_drive.store.add_markdown("triage-alerts.md", RUNBOOK, runbooks)
    env = {
        "DRIVE_MCP_URL": fake_drive.url,
        "DRIVE_MCP_QUOTA_PROJECT": "env-project",
        "DRIVE_RUNBOOKS_FOLDER_ID": runbooks,
        "DRIVE_REPORTS_FOLDER_ID": reports,
        "DRIVE_MCP_TOOLSET": "1",
    }
    drive_tools.reset_drive_client()
    with patch.dict(os.environ, env, clear=False), patch(
        "skills.drive_registry.AdcTokenSource", lambda: StaticTokenSource("env-token")
    ):
        yield {"runbooks": runbooks, "reports": reports}
    drive_tools.reset_drive_client()


@pytest.fixture
def no_drive_env():
    with patch.dict(os.environ, {}, clear=False):
        for key in (
            "DRIVE_RUNBOOKS_FOLDER_ID",
            "DRIVE_REPORTS_FOLDER_ID",
            "RUNBOOK_SOURCE",
            "DRIVE_MCP_TOOLSET",
        ):
            os.environ.pop(key, None)
        yield


# --------------------------------------------------------------------------
# httpx auth plumbing
# --------------------------------------------------------------------------


def test_bearer_token_auth_stamps_a_fresh_token_per_request():
    tokens = iter(["tok-1", "tok-2"])
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200, json={})

    with httpx.Client(
        transport=httpx.MockTransport(handler), auth=BearerTokenAuth(lambda: next(tokens))
    ) as client:
        client.get("https://example.invalid/")
        client.get("https://example.invalid/")
    assert seen == ["Bearer tok-1", "Bearer tok-2"]


def test_httpx_client_factory_matches_mcp_sdk_contract():
    factory = make_drive_httpx_client_factory(StaticTokenSource("t"))
    client = factory(headers={"X-Goog-User-Project": "p"}, timeout=httpx.Timeout(5), auth=None)
    try:
        assert isinstance(client, httpx.AsyncClient)
        assert isinstance(client.auth, BearerTokenAuth)
        assert client.headers["X-Goog-User-Project"] == "p"
    finally:
        asyncio.run(client.aclose())

    explicit = httpx.BasicAuth("u", "p")
    client = factory(auth=explicit)
    try:
        assert client.auth is explicit
    finally:
        asyncio.run(client.aclose())


# --------------------------------------------------------------------------
# Runbook source selection
# --------------------------------------------------------------------------


def test_build_skill_registry_local_source(no_drive_env):
    registry = build_skill_registry("local")
    assert type(registry) is SkillRegistry
    assert registry.get_skill("triage-alerts") is not None


def test_build_skill_registry_defaults_to_drive_and_falls_back_when_unconfigured(
    no_drive_env, caplog: pytest.LogCaptureFixture
):
    assert drive_tools.runbook_source() == "drive"
    with caplog.at_level(logging.WARNING, logger="manager.tools.drive_tools"):
        registry = build_skill_registry()
    assert type(registry) is SkillRegistry
    assert "DRIVE_RUNBOOKS_FOLDER_ID" in caplog.text
    assert "falling back to the local skills/ tree" in caplog.text


def test_build_skill_registry_uses_drive_when_configured(drive_env):
    registry = build_skill_registry("drive")
    assert isinstance(registry, DriveSkillRegistry)
    assert registry.folder_id == drive_env["runbooks"]
    assert registry.get_skill_content("triage_alerts") == RUNBOOK
    assert registry.client.quota_project == "env-project"


def test_build_skill_registry_falls_back_when_drive_denies_access(
    drive_env, fake_drive: FakeDriveMcpServer, caplog: pytest.LogCaptureFixture
):
    fake_drive.store.deny_message = PERMISSION_DENIED_MESSAGE
    with caplog.at_level(logging.WARNING, logger="manager.tools.drive_tools"):
        registry = build_skill_registry("drive")
    assert type(registry) is SkillRegistry
    assert PERMISSION_DENIED_MESSAGE in caplog.text


def test_build_skill_registry_unknown_source_uses_local(caplog: pytest.LogCaptureFixture):
    with caplog.at_level(logging.WARNING, logger="manager.tools.drive_tools"):
        registry = build_skill_registry("sharepoint")
    assert type(registry) is SkillRegistry
    assert "Unknown RUNBOOK_SOURCE" in caplog.text


def test_build_skill_registry_accepts_injected_factories():
    sentinel_local = object()
    sentinel_drive = object()
    assert (
        build_skill_registry("local", local_registry_factory=lambda: sentinel_local)
        is sentinel_local
    )

    class FakeDrive:
        folder_id = "f"
        skills: dict = {}

    drive = FakeDrive()
    assert build_skill_registry("drive", drive_registry_factory=lambda: drive) is drive
    del sentinel_drive


def test_global_registry_is_a_skill_registry():
    # Import-time construction must never crash, whatever the environment.
    assert isinstance(tools_module.global_skill_registry, SkillRegistry)
    assert tools_module.load_skill("definitely-missing-skill").startswith("Error")


# --------------------------------------------------------------------------
# Drive toolset
# --------------------------------------------------------------------------


def test_drive_toolset_configured_matrix(no_drive_env):
    assert drive_toolset_configured() is False
    with patch.dict(os.environ, {"DRIVE_REPORTS_FOLDER_ID": "x"}):
        assert drive_toolset_configured() is True
        with patch.dict(os.environ, {"DRIVE_MCP_TOOLSET": "0"}):
            assert drive_toolset_configured() is False
    with patch.dict(os.environ, {"DRIVE_RUNBOOKS_FOLDER_ID": "y"}):
        assert drive_toolset_configured() is True


def test_init_drive_toolset_lists_and_calls_tools_through_adk(
    drive_env, fake_drive: FakeDriveMcpServer
):
    toolset = init_drive_toolset(token_source=StaticTokenSource("adk-token"))
    assert toolset.tool_name_prefix == "drive"
    params = toolset._connection_params  # pylint: disable=protected-access
    assert params.url == fake_drive.url
    assert params.headers == {"X-Goog-User-Project": "env-project"}
    assert "Authorization" not in params.headers

    async def exercise():
        try:
            tools = await toolset.get_tools()
            names = {tool.name.removeprefix("drive_") for tool in tools}
            assert names == set(DRIVE_TOOL_FILTER)
            headers = fake_drive.store.last_headers
            assert headers["authorization"] == "Bearer adk-token"
            assert headers["x-goog-user-project"] == "env-project"

            create = next(t for t in tools if t.name.endswith("create_file"))
            result = await create.run_async(
                args={
                    "title": "adk-report.md",
                    "contentMimeType": "text/markdown",
                    "textContent": REPORT_BODY,
                    "parentId": drive_env["reports"],
                    "disableConversionToGoogleType": True,
                },
                tool_context=None,
            )
            assert result.get("isError") is False
            assert result["structuredContent"]["mimeType"] == "text/markdown"
        finally:
            await toolset.close()

    asyncio.run(exercise())
    created = [f for f in fake_drive.store.files.values() if f.title == "adk-report.md"]
    assert len(created) == 1
    assert created[0].data.decode("utf-8") == REPORT_BODY


def test_init_drive_mcp_tools_only_when_configured(no_drive_env, drive_env):
    toolset = tools_module.init_drive_mcp_tools()
    assert toolset is not None
    assert toolset.tool_name_prefix == "drive"
    with patch.dict(os.environ, {"DRIVE_MCP_TOOLSET": "0"}):
        assert tools_module.init_drive_mcp_tools() is None


# --------------------------------------------------------------------------
# Report publishing
# --------------------------------------------------------------------------


def test_publish_report_requires_folder(no_drive_env):
    with pytest.raises(DriveRegistryConfigError, match="DRIVE_REPORTS_FOLDER_ID"):
        publish_report_to_drive("r.md", "# r", client=DriveMcpClient(token_source=lambda: "t"))


def test_publish_report_to_drive_creates_markdown(drive_env, fake_drive: FakeDriveMcpServer):
    client = make_client(fake_drive)
    result = publish_report_to_drive("weekly.md", REPORT_BODY, client=client)
    assert set(result) == {"id", "title", "viewUrl", "parentId"}
    assert result["parentId"] == drive_env["reports"]
    assert result["title"] == "weekly.md"
    assert fake_drive.store.files[result["id"]].mime_type == "text/markdown"
    assert fake_drive.store.calls_for("create_file")[0]["disableConversionToGoogleType"] is True


def test_write_report_dual_writes_locally_and_to_drive(
    drive_env, fake_drive: FakeDriveMcpServer, tmp_path: Path
):
    with patch.dict(os.environ, {"REPORTS_DIR": str(tmp_path)}), patch.object(
        drive_tools, "_shared_client", make_client(fake_drive)
    ):
        result = tools_module.write_report("incident_report", REPORT_BODY)

    local_path = Path(result["local_path"])
    assert local_path.parent == tmp_path
    assert re.fullmatch(r"incident_report_\d{8}_\d{6}\.md", local_path.name)
    assert local_path.read_text(encoding="utf-8") == REPORT_BODY

    assert result["drive_error"] is None
    drive = result["drive"]
    assert drive["title"] == local_path.name
    assert drive["parentId"] == drive_env["reports"]
    assert drive["viewUrl"].startswith("https://drive.google.com/")
    stored = fake_drive.store.files[drive["id"]]
    assert stored.data.decode("utf-8") == REPORT_BODY
    assert stored.mime_type == "text/markdown"


def test_write_report_keeps_local_copy_when_drive_denies(
    drive_env, fake_drive: FakeDriveMcpServer, tmp_path: Path
):
    fake_drive.store.deny_message = PERMISSION_DENIED_MESSAGE
    with patch.dict(os.environ, {"REPORTS_DIR": str(tmp_path)}), patch.object(
        drive_tools, "_shared_client", make_client(fake_drive)
    ):
        result = tools_module.write_report("incident_report_20260101_120000.md", REPORT_BODY)
    assert Path(result["local_path"]).name == "incident_report_20260101_120000.md"
    assert Path(result["local_path"]).read_text(encoding="utf-8") == REPORT_BODY
    assert result["drive"] is None
    assert PERMISSION_DENIED_MESSAGE in result["drive_error"]


def test_write_report_without_drive_configured(no_drive_env, tmp_path: Path):
    with patch.dict(os.environ, {"REPORTS_DIR": str(tmp_path)}):
        result = tools_module.write_report("plain_report", "# plain\n")
    assert Path(result["local_path"]).read_text(encoding="utf-8") == "# plain\n"
    assert result["drive"] is None
    assert result["drive_error"] is None
