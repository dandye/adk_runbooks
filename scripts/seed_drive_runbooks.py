#!/usr/bin/env python3
"""Seed Google Drive with the SOC runbooks and create the reports folder.

Creates (or reuses) two folders in the authenticated user's My Drive and
uploads every local ``skills/**/SKILL.md`` runbook into the runbooks folder as
a native ``text/markdown`` file named ``<skill-name>.md``. The Drive MCP server
and :class:`skills.drive_registry.DriveSkillRegistry` then serve those files to
the agents.

This script talks to the Drive REST API v3 directly (``drive.googleapis.com``),
not to the Drive MCP server, so it works even while the GCP project is still
waiting to be allowlisted for Drive MCP ``tools/call``. It reuses the same
isolated Application Default Credentials as the rest of the worktree.

Usage (inside the direnv-activated worktree)::

    python scripts/seed_drive_runbooks.py --dry-run
    python scripts/seed_drive_runbooks.py
    python scripts/seed_drive_runbooks.py --category triage --category irps
    python scripts/seed_drive_runbooks.py --update            # overwrite drifted files
    python scripts/seed_drive_runbooks.py --write-env         # record folder ids in .env

The folder layout is flat on purpose: the Drive registry lists direct children
of ``DRIVE_RUNBOOKS_FOLDER_ID`` only (``parentId = '<id>'``), and each runbook
already carries its ``category`` in YAML frontmatter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from skills.drive_registry import (  # noqa: E402  pylint: disable=wrong-import-position
    MARKDOWN_MIME_TYPE,
    AdcTokenSource,
    DriveRegistryConfigError,
    TokenSource,
)
from skills.registry import SkillMetadata, SkillRegistry  # noqa: E402  pylint: disable=wrong-import-position

DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"
DRIVE_UPLOAD_BASE = "https://www.googleapis.com/upload/drive/v3"
FOLDER_MIME_TYPE = "application/vnd.google-apps.folder"
FILE_FIELDS = "id,name,mimeType,modifiedTime,md5Checksum,webViewLink"
DEFAULT_RUNBOOKS_FOLDER = "SOC Runbooks"
DEFAULT_REPORTS_FOLDER = "SOC Reports"
ENV_KEYS = ("DRIVE_RUNBOOKS_FOLDER_ID", "DRIVE_REPORTS_FOLDER_ID")


class DriveRestError(RuntimeError):
    """Raised when the Drive REST API returns an error."""


def _escape_query_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class DriveRestClient:
    """Tiny Drive REST API v3 client (files.list / create / update)."""

    def __init__(
        self,
        *,
        token_source: TokenSource,
        quota_project: str = "",
        transport: httpx.BaseTransport | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._token_source = token_source
        self._quota_project = quota_project
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        self._http.close()

    def _headers(self, **extra: str) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._token_source()}"}
        if self._quota_project:
            headers["X-Goog-User-Project"] = self._quota_project
        headers.update(extra)
        return headers

    def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._http.request(method, url, **kwargs)
        except httpx.HTTPError as err:
            raise DriveRestError(f"{method} {url} failed: {err}") from err
        if response.status_code >= 400:
            raise DriveRestError(
                f"{method} {url} -> HTTP {response.status_code}: {response.text[:400]}"
            )
        if not response.content:
            return {}
        return response.json()

    def list_files(self, query: str, *, fields: str = FILE_FIELDS) -> Iterator[dict[str, Any]]:
        """Yields every file matching a Drive API v3 ``q`` expression."""
        page_token: str | None = None
        while True:
            params = {
                "q": query,
                "fields": f"nextPageToken,files({fields})",
                "pageSize": 200,
                "spaces": "drive",
            }
            if page_token:
                params["pageToken"] = page_token
            page = self._request("GET", f"{DRIVE_API_BASE}/files", params=params, headers=self._headers())
            yield from page.get("files", [])
            page_token = page.get("nextPageToken")
            if not page_token:
                return

    def find_folder(self, name: str, parent_id: str = "root") -> dict[str, Any] | None:
        # Drive API v3 grammar: note the "'<id>' in parents" form here differs from
        # the Drive MCP server's "parentId = '<id>'".
        query = (
            f"name = '{_escape_query_value(name)}' and mimeType = '{FOLDER_MIME_TYPE}' "
            f"and trashed = false and '{parent_id}' in parents"
        )
        for folder in self.list_files(query):
            return folder
        return None

    def create_folder(self, name: str, parent_id: str = "root") -> dict[str, Any]:
        body = {"name": name, "mimeType": FOLDER_MIME_TYPE, "parents": [parent_id]}
        return self._request(
            "POST",
            f"{DRIVE_API_BASE}/files",
            params={"fields": FILE_FIELDS},
            headers=self._headers(**{"Content-Type": "application/json; charset=UTF-8"}),
            content=json.dumps(body).encode("utf-8"),
        )

    def find_or_create_folder(self, name: str, parent_id: str = "root") -> tuple[dict[str, Any], bool]:
        existing = self.find_folder(name, parent_id)
        if existing is not None:
            return existing, False
        return self.create_folder(name, parent_id), True

    def list_children(self, folder_id: str) -> dict[str, dict[str, Any]]:
        """Returns the non-trashed children of a folder keyed by name."""
        query = f"'{folder_id}' in parents and trashed = false"
        return {item["name"]: item for item in self.list_files(query)}

    def upload_markdown(self, *, name: str, text: str, parent_id: str) -> dict[str, Any]:
        """Creates ``name`` as a native text/markdown file (multipart upload)."""
        metadata = {"name": name, "parents": [parent_id], "mimeType": MARKDOWN_MIME_TYPE}
        boundary = f"soc-runbooks-{uuid.uuid4().hex}"
        body = b"".join(
            [
                f"--{boundary}\r\n".encode(),
                b"Content-Type: application/json; charset=UTF-8\r\n\r\n",
                json.dumps(metadata).encode("utf-8"),
                f"\r\n--{boundary}\r\n".encode(),
                f"Content-Type: {MARKDOWN_MIME_TYPE}; charset=UTF-8\r\n\r\n".encode(),
                text.encode("utf-8"),
                f"\r\n--{boundary}--\r\n".encode(),
            ]
        )
        return self._request(
            "POST",
            f"{DRIVE_UPLOAD_BASE}/files",
            params={"uploadType": "multipart", "fields": FILE_FIELDS},
            headers=self._headers(**{"Content-Type": f"multipart/related; boundary={boundary}"}),
            content=body,
        )

    def update_markdown(self, *, file_id: str, text: str) -> dict[str, Any]:
        """Replaces the content of an existing file, keeping its metadata."""
        return self._request(
            "PATCH",
            f"{DRIVE_UPLOAD_BASE}/files/{file_id}",
            params={"uploadType": "media", "fields": FILE_FIELDS},
            headers=self._headers(**{"Content-Type": f"{MARKDOWN_MIME_TYPE}; charset=UTF-8"}),
            content=text.encode("utf-8"),
        )


@dataclass(frozen=True)
class Runbook:
    """A local runbook ready for upload."""

    name: str
    category: str
    path: Path
    text: str

    @property
    def drive_name(self) -> str:
        return f"{self.name}.md"

    @property
    def md5(self) -> str:
        return hashlib.md5(self.text.encode("utf-8")).hexdigest()  # Drive's md5Checksum


def collect_runbooks(
    skills_dir: Path | None = None,
    *,
    categories: set[str] | None = None,
    limit: int | None = None,
) -> list[Runbook]:
    """Loads the unique local skills, optionally filtered by category."""
    registry = SkillRegistry(skills_dir) if skills_dir else SkillRegistry()
    seen: set[int] = set()
    runbooks: list[Runbook] = []
    for meta in registry.skills.values():
        if id(meta) in seen:
            continue
        seen.add(id(meta))
        if categories and meta.category not in categories:
            continue
        runbooks.append(_to_runbook(meta))
    runbooks.sort(key=lambda r: (r.category, r.name))
    if limit is not None:
        runbooks = runbooks[:limit]
    return runbooks


def _to_runbook(meta: SkillMetadata) -> Runbook:
    return Runbook(
        name=meta.name,
        category=meta.category,
        path=meta.path,
        text=meta.path.read_text(encoding="utf-8"),
    )


@dataclass
class SyncStats:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped: int = 0


def sync_runbooks(
    client: DriveRestClient,
    runbooks: list[Runbook],
    folder_id: str,
    *,
    update: bool,
    dry_run: bool,
    log=print,
) -> SyncStats:
    """Uploads runbooks into ``folder_id``; existing files are left alone unless ``update``."""
    existing = client.list_children(folder_id)
    stats = SyncStats()
    for runbook in runbooks:
        remote = existing.get(runbook.drive_name)
        if remote is None:
            log(f"  create   {runbook.drive_name}  [{runbook.category}]")
            if not dry_run:
                client.upload_markdown(name=runbook.drive_name, text=runbook.text, parent_id=folder_id)
            stats.created += 1
        elif remote.get("md5Checksum") == runbook.md5:
            stats.unchanged += 1
        elif update:
            log(f"  update   {runbook.drive_name}  [{runbook.category}]")
            if not dry_run:
                client.update_markdown(file_id=remote["id"], text=runbook.text)
            stats.updated += 1
        else:
            log(f"  skip     {runbook.drive_name}  (differs in Drive; pass --update to overwrite)")
            stats.skipped += 1
    return stats


def write_env_file(env_path: Path, values: dict[str, str]) -> None:
    """Sets ``KEY=value`` lines in ``env_path`` (created if missing, keys replaced in place)."""
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    remaining = dict(values)
    for index, line in enumerate(lines):
        match = re.match(r"^(?:export\s+)?([A-Z0-9_]+)=", line)
        if match and match.group(1) in remaining:
            lines[index] = f"{match.group(1)}={remaining.pop(match.group(1))}"
    for key, value in remaining.items():
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runbooks-folder-name", default=DEFAULT_RUNBOOKS_FOLDER)
    parser.add_argument("--reports-folder-name", default=DEFAULT_REPORTS_FOLDER)
    parser.add_argument("--parent-folder-id", default="root", help="Where to create the folders (default: My Drive root).")
    parser.add_argument("--category", action="append", default=[], help="Only upload runbooks in this category (repeatable).")
    parser.add_argument("--limit", type=int, default=None, help="Upload at most N runbooks (smoke tests).")
    parser.add_argument("--update", action="store_true", help="Overwrite Drive files whose content differs from local.")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing to Drive.")
    parser.add_argument("--write-env", action="store_true", help="Record the folder ids in the worktree .env file.")
    parser.add_argument("--env-file", default=str(PROJECT_ROOT / ".env"))
    parser.add_argument(
        "--quota-project",
        default=os.environ.get("DRIVE_MCP_QUOTA_PROJECT") or os.environ.get("GCP_PROJECT_ID") or "",
        help="Project sent as X-Goog-User-Project (default: $DRIVE_MCP_QUOTA_PROJECT / $GCP_PROJECT_ID).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        token_source = AdcTokenSource()
        token_source()  # Fail fast with the reauth hint before touching Drive.
    except DriveRegistryConfigError as err:
        print(f"[auth] {err}", file=sys.stderr)
        return 2

    client = DriveRestClient(token_source=token_source, quota_project=args.quota_project)
    try:
        runbooks = collect_runbooks(categories=set(args.category) or None, limit=args.limit)
        print(f"[local] {len(runbooks)} runbooks selected from {PROJECT_ROOT / 'skills'}")

        if args.dry_run:
            runbooks_folder = client.find_folder(args.runbooks_folder_name, args.parent_folder_id)
            reports_folder = client.find_folder(args.reports_folder_name, args.parent_folder_id)
            for label, folder, name in (
                ("runbooks", runbooks_folder, args.runbooks_folder_name),
                ("reports", reports_folder, args.reports_folder_name),
            ):
                state = f"exists id={folder['id']}" if folder else "would create"
                print(f"[drive] {label} folder '{name}': {state}")
            if runbooks_folder is None:
                for runbook in runbooks:
                    print(f"  create   {runbook.drive_name}  [{runbook.category}]")
                print(f"[dry-run] {len(runbooks)} files would be created")
                return 0
            stats = sync_runbooks(client, runbooks, runbooks_folder["id"], update=args.update, dry_run=True)
            print(f"[dry-run] create={stats.created} update={stats.updated} unchanged={stats.unchanged} skip={stats.skipped}")
            return 0

        runbooks_folder, created = client.find_or_create_folder(args.runbooks_folder_name, args.parent_folder_id)
        print(f"[drive] runbooks folder '{args.runbooks_folder_name}': {'created' if created else 'exists'} id={runbooks_folder['id']}")
        reports_folder, created = client.find_or_create_folder(args.reports_folder_name, args.parent_folder_id)
        print(f"[drive] reports folder '{args.reports_folder_name}': {'created' if created else 'exists'} id={reports_folder['id']}")

        stats = sync_runbooks(client, runbooks, runbooks_folder["id"], update=args.update, dry_run=False)
        print(f"[drive] create={stats.created} update={stats.updated} unchanged={stats.unchanged} skip={stats.skipped}")

        values = {
            "DRIVE_RUNBOOKS_FOLDER_ID": runbooks_folder["id"],
            "DRIVE_REPORTS_FOLDER_ID": reports_folder["id"],
        }
        print()
        print("Add to the worktree .env (loaded by direnv):")
        for key, value in values.items():
            print(f"  {key}={value}")
        if args.write_env:
            env_path = Path(args.env_file)
            write_env_file(env_path, values)
            print(f"[env] wrote {', '.join(values)} to {env_path}; run `direnv reload`.")
        if runbooks_folder.get("webViewLink"):
            print(f"[drive] open: {runbooks_folder['webViewLink']}")
        return 0
    except DriveRestError as err:
        print(f"[drive] {err}", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
