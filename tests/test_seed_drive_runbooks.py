"""Tests for scripts/seed_drive_runbooks.py against a mocked Drive REST API."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "seed_drive_runbooks.py"

spec = importlib.util.spec_from_file_location("seed_drive_runbooks", SCRIPT_PATH)
seed = importlib.util.module_from_spec(spec)
sys.modules["seed_drive_runbooks"] = seed
spec.loader.exec_module(seed)  # type: ignore[union-attr]

TRIAGE = (
    "---\nname: triage-alerts\ndescription: Triage.\ncategory: triage\n---\n# Triage\n"
)
HUNT = "---\nname: hunt_beacons\ndescription: Hunt.\ncategory: hunting\n---\n# Hunt\n"


def make_skills_dir(tmp_path: Path) -> Path:
    skills = tmp_path / "skills"
    (skills / "triage" / "triage-alerts").mkdir(parents=True)
    (skills / "triage" / "triage-alerts" / "SKILL.md").write_text(TRIAGE, encoding="utf-8")
    (skills / "hunting" / "hunt_beacons").mkdir(parents=True)
    (skills / "hunting" / "hunt_beacons" / "SKILL.md").write_text(HUNT, encoding="utf-8")
    return skills


class FakeDriveRest:
    """Just enough of Drive REST v3 for the seed script: list, create, upload, patch."""

    def __init__(self) -> None:
        self.files: dict[str, dict[str, Any]] = {}
        self.requests: list[httpx.Request] = []
        self._counter = 0

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _new_id(self) -> str:
        self._counter += 1
        return f"rest-{self._counter:03d}"

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Authorization"] == "Bearer rest-token"
        assert request.headers["X-Goog-User-Project"] == "quota-project"
        url = urlparse(str(request.url))
        params = {k: v[0] for k, v in parse_qs(url.query).items()}

        if request.method == "GET" and url.path == "/drive/v3/files":
            return httpx.Response(200, json={"files": self._query(params["q"])})
        if request.method == "POST" and url.path == "/drive/v3/files":
            body = json.loads(request.content)
            return httpx.Response(200, json=self._store(body, b""))
        if request.method == "POST" and url.path == "/upload/drive/v3/files":
            assert params["uploadType"] == "multipart"
            metadata, media = self._split_multipart(request)
            return httpx.Response(200, json=self._store(metadata, media))
        if request.method == "PATCH" and url.path.startswith("/upload/drive/v3/files/"):
            file_id = url.path.rsplit("/", 1)[1]
            record = self.files[file_id]
            record["md5Checksum"] = hashlib.md5(request.content).hexdigest()
            record["_content"] = request.content
            return httpx.Response(200, json=self._public(record))
        return httpx.Response(404, json={"error": {"message": f"unexpected {request.method} {url.path}"}})

    def _store(self, metadata: dict[str, Any], media: bytes) -> dict[str, Any]:
        file_id = self._new_id()
        record = {
            "id": file_id,
            "name": metadata["name"],
            "mimeType": metadata.get("mimeType", "application/octet-stream"),
            "parents": metadata.get("parents", ["root"]),
            "md5Checksum": hashlib.md5(media).hexdigest(),
            "modifiedTime": "2026-01-01T00:00:00.000Z",
            "webViewLink": f"https://drive.google.com/open?id={file_id}",
            "_content": media,
        }
        self.files[file_id] = record
        return self._public(record)

    @staticmethod
    def _public(record: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in record.items() if not k.startswith("_") and k != "parents"}

    def _query(self, q: str) -> list[dict[str, Any]]:
        results = []
        for record in self.files.values():
            if "mimeType = 'application/vnd.google-apps.folder'" in q and record["mimeType"] != seed.FOLDER_MIME_TYPE:
                continue
            name_match = [part for part in q.split(" and ") if part.startswith("name = ")]
            if name_match and record["name"] != name_match[0].split("'", 2)[1]:
                continue
            parent_parts = [part for part in q.split(" and ") if part.endswith(" in parents")]
            if parent_parts and parent_parts[0].split("'")[1] not in record["parents"]:
                continue
            results.append(self._public(record))
        return results

    @staticmethod
    def _split_multipart(request: httpx.Request) -> tuple[dict[str, Any], bytes]:
        content_type = request.headers["Content-Type"]
        assert content_type.startswith("multipart/related; boundary=")
        boundary = content_type.split("boundary=", 1)[1].encode()
        parts = [p for p in request.content.split(b"--" + boundary) if p.strip() not in (b"", b"--")]
        assert len(parts) == 2, parts
        meta_headers, meta_body = parts[0].split(b"\r\n\r\n", 1)
        media_headers, media_body = parts[1].split(b"\r\n\r\n", 1)
        assert b"application/json" in meta_headers
        assert b"text/markdown" in media_headers
        # Only the CRLF that precedes the closing boundary belongs to the framing.
        if media_body.endswith(b"\r\n"):
            media_body = media_body[:-2]
        return json.loads(meta_body.strip()), media_body


@pytest.fixture
def rest() -> FakeDriveRest:
    return FakeDriveRest()


@pytest.fixture
def client(rest: FakeDriveRest) -> seed.DriveRestClient:
    drive_client = seed.DriveRestClient(
        token_source=lambda: "rest-token", quota_project="quota-project", transport=rest.transport()
    )
    yield drive_client
    drive_client.close()


def test_collect_runbooks_dedupes_aliases_and_filters(tmp_path: Path):
    skills = make_skills_dir(tmp_path)
    runbooks = seed.collect_runbooks(skills)
    assert [r.drive_name for r in runbooks] == ["hunt_beacons.md", "triage-alerts.md"]
    assert runbooks[1].text == TRIAGE
    assert runbooks[1].md5 == hashlib.md5(TRIAGE.encode()).hexdigest()
    assert [r.name for r in seed.collect_runbooks(skills, categories={"triage"})] == ["triage-alerts"]
    assert len(seed.collect_runbooks(skills, limit=1)) == 1


def test_find_or_create_folder_is_idempotent(client: seed.DriveRestClient, rest: FakeDriveRest):
    folder, created = client.find_or_create_folder("SOC Runbooks")
    assert created is True
    assert folder["mimeType"] == seed.FOLDER_MIME_TYPE
    again, created_again = client.find_or_create_folder("SOC Runbooks")
    assert created_again is False
    assert again["id"] == folder["id"]
    create_calls = [r for r in rest.requests if r.method == "POST"]
    assert len(create_calls) == 1
    assert json.loads(create_calls[0].content)["parents"] == ["root"]


def test_upload_markdown_sends_multipart_text_markdown(client: seed.DriveRestClient, rest: FakeDriveRest):
    folder, _ = client.find_or_create_folder("SOC Runbooks")
    created = client.upload_markdown(name="triage-alerts.md", text=TRIAGE, parent_id=folder["id"])
    record = rest.files[created["id"]]
    assert record["mimeType"] == "text/markdown"
    assert record["parents"] == [folder["id"]]
    assert record["_content"].decode("utf-8") == TRIAGE
    assert client.list_children(folder["id"])["triage-alerts.md"]["id"] == created["id"]


def test_sync_runbooks_creates_skips_and_updates(tmp_path: Path, client: seed.DriveRestClient, rest: FakeDriveRest):
    runbooks = seed.collect_runbooks(make_skills_dir(tmp_path))
    folder, _ = client.find_or_create_folder("SOC Runbooks")
    logs: list[str] = []

    dry = seed.sync_runbooks(client, runbooks, folder["id"], update=False, dry_run=True, log=logs.append)
    assert (dry.created, dry.updated, dry.unchanged, dry.skipped) == (2, 0, 0, 0)
    assert not [r for r in rest.requests if r.url.path.startswith("/upload/")]

    first = seed.sync_runbooks(client, runbooks, folder["id"], update=False, dry_run=False, log=logs.append)
    assert (first.created, first.unchanged) == (2, 0)

    second = seed.sync_runbooks(client, runbooks, folder["id"], update=False, dry_run=False, log=logs.append)
    assert (second.created, second.updated, second.unchanged, second.skipped) == (0, 0, 2, 0)

    # Drift in Drive: skipped without --update, replaced with it.
    triage_id = next(i for i, f in rest.files.items() if f["name"] == "triage-alerts.md")
    rest.files[triage_id]["md5Checksum"] = "deadbeef"
    third = seed.sync_runbooks(client, runbooks, folder["id"], update=False, dry_run=False, log=logs.append)
    assert (third.unchanged, third.skipped) == (1, 1)
    fourth = seed.sync_runbooks(client, runbooks, folder["id"], update=True, dry_run=False, log=logs.append)
    assert (fourth.updated, fourth.unchanged) == (1, 1)
    assert rest.files[triage_id]["_content"].decode("utf-8") == TRIAGE
    assert any(r.method == "PATCH" for r in rest.requests)
    assert any("pass --update" in line for line in logs)


def test_rest_errors_are_wrapped():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "Drive API has not been used"}})

    drive_client = seed.DriveRestClient(
        token_source=lambda: "rest-token", quota_project="", transport=httpx.MockTransport(handler)
    )
    try:
        with pytest.raises(seed.DriveRestError, match="HTTP 403"):
            drive_client.find_folder("SOC Runbooks")
    finally:
        drive_client.close()


def test_write_env_file_replaces_and_appends(tmp_path: Path):
    env_path = tmp_path / ".env"
    env_path.write_text("FOO=1\nexport DRIVE_RUNBOOKS_FOLDER_ID=old\n", encoding="utf-8")
    seed.write_env_file(env_path, {"DRIVE_RUNBOOKS_FOLDER_ID": "new", "DRIVE_REPORTS_FOLDER_ID": "rep"})
    assert env_path.read_text(encoding="utf-8") == (
        "FOO=1\nDRIVE_RUNBOOKS_FOLDER_ID=new\nDRIVE_REPORTS_FOLDER_ID=rep\n"
    )
    missing = tmp_path / "fresh.env"
    seed.write_env_file(missing, {"DRIVE_REPORTS_FOLDER_ID": "x"})
    assert missing.read_text(encoding="utf-8") == "DRIVE_REPORTS_FOLDER_ID=x\n"
