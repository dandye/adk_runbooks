#!/usr/bin/env python3
"""Smoke test for the Google Drive remote MCP server (Streamable HTTP).

Verifies, end to end, that the isolated Argolis Application Default
Credentials in this worktree can drive ``https://drivemcp.googleapis.com/mcp/v1``:

  1. Resolves an OAuth 2.0 access token from ADC and prints its granted scopes
     (the Drive MCP server needs a Drive scope on the token).
  2. Initializes an MCP session and lists the public toolset.
  3. Runs ``search_files`` for ``text/markdown`` files (optionally scoped to a
     folder) so we can see how Markdown runbooks surface through the server.
  4. Optionally reads one file through both ``read_file_content`` (verbalized
     GenAI text) and ``download_file_content`` (exact base64 bytes).
  5. Optionally creates a throwaway ``.md`` file with
     ``disableConversionToGoogleType=true`` and confirms the stored MIME type
     stays ``text/markdown`` instead of becoming a Google Doc.

Usage (inside the direnv-activated worktree):

  python scripts/drive_mcp_smoke_test.py
  python scripts/drive_mcp_smoke_test.py --folder-id "$DRIVE_RUNBOOKS_FOLDER_ID"
  python scripts/drive_mcp_smoke_test.py --read-file-id <FILE_ID>
  python scripts/drive_mcp_smoke_test.py --folder-id <FOLDER_ID> --create-test-file
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import datetime as dt
import json
import os
import sys
import textwrap
from typing import Any

import google.auth
from google.auth.transport.requests import Request
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

DEFAULT_DRIVE_MCP_URL = "https://drivemcp.googleapis.com/mcp/v1"
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
DRIVE_SCOPE_PREFIX = "https://www.googleapis.com/auth/drive"
PUBLIC_TOOLS = (
    "copy_file",
    "create_file",
    "download_file_content",
    "get_file_metadata",
    "get_file_permissions",
    "list_recent_files",
    "read_file_content",
    "search_files",
)
REAUTH_HINT = textwrap.dedent(
    """\
    Authenticate inside this direnv-activated worktree so the isolated ADC
    refresh token exists and carries https://www.googleapis.com/auth/drive:

      ACCOUNT="admin@dandye.altostrat.com"
      gcloud auth login "$ACCOUNT" --enable-gdrive-access --update-adc
    """
)


def local_adc_path() -> str:
  """Returns the ADC file google-auth will use, honoring the direnv isolation."""
  explicit = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
  if explicit:
    return explicit
  config_dir = os.environ.get("CLOUDSDK_CONFIG") or os.path.expanduser("~/.config/gcloud")
  return os.path.join(config_dir, "application_default_credentials.json")


def resolve_access_token() -> str:
  """Returns a fresh OAuth 2.0 access token from Application Default Credentials."""
  adc_path = local_adc_path()
  if not os.path.exists(adc_path):
    # Without this guard google-auth silently falls back to the Cloudtop VM's
    # metadata-server service account, which is the wrong identity entirely.
    raise google.auth.exceptions.DefaultCredentialsError(
        f"no ADC file at {adc_path} (CLOUDSDK_CONFIG={os.environ.get('CLOUDSDK_CONFIG', '<unset>')})"
    )
  print(f"[auth] ADC file: {adc_path}")
  credentials, _ = google.auth.default()
  credentials.refresh(Request())
  if not credentials.token:
    raise RuntimeError("ADC refresh succeeded but produced an empty token.")
  return credentials.token


def describe_token(token: str) -> list[str]:
  """Prints the identity and scopes bound to ``token`` and returns the scopes."""
  response = httpx.get(TOKENINFO_URL, params={"access_token": token}, timeout=15)
  if response.status_code != 200:
    print(f"[warn] tokeninfo returned HTTP {response.status_code}: {response.text[:200]}")
    return []
  info = response.json()
  scopes = sorted(info.get("scope", "").split())
  print(f"[auth] email:   {info.get('email', '<unknown>')}")
  print(f"[auth] expires: {info.get('expires_in', '?')}s")
  print("[auth] scopes:")
  for scope in scopes:
    print(f"         - {scope}")
  if not any(scope.startswith(DRIVE_SCOPE_PREFIX) for scope in scopes):
    print()
    print(REAUTH_HINT)
  return scopes


def build_headers(token: str, quota_project: str) -> dict[str, str]:
  """Builds the headers the Drive MCP server expects on every request."""
  headers = {"Authorization": f"Bearer {token}"}
  if quota_project:
    # The gcloud OAuth client is owned by Google, so the project that has
    # drive.googleapis.com and drivemcp.googleapis.com enabled must be named
    # explicitly as the quota / consumer project.
    headers["X-Goog-User-Project"] = quota_project
  return headers


def unwrap_tool_result(result: Any) -> Any:
  """Returns structured content when present, else the concatenated text parts."""
  structured = getattr(result, "structuredContent", None)
  if structured:
    return structured
  texts: list[str] = []
  for part in getattr(result, "content", []) or []:
    text = getattr(part, "text", None)
    if text:
      texts.append(text)
  joined = "\n".join(texts)
  try:
    return json.loads(joined)
  except (json.JSONDecodeError, TypeError):
    return joined


def build_search_query(folder_id: str, mime_type: str, extra: str) -> str:
  """Composes a Drive MCP ``search_files`` query string.

  Note the Drive MCP grammar differs from Drive API v3: folders are matched with
  ``parentId = '<id>'`` rather than ``'<id>' in parents``.
  """
  clauses: list[str] = []
  if mime_type:
    clauses.append(f"mimeType = '{mime_type}'")
  if folder_id:
    clauses.append(f"parentId = '{folder_id}'")
  if extra:
    clauses.append(f"({extra})")
  return " and ".join(clauses) if clauses else "owner = 'me'"


async def run_smoke_test(args: argparse.Namespace) -> int:
  """Runs the smoke test and returns a process exit code."""
  token = resolve_access_token()
  describe_token(token)
  headers = build_headers(token, args.quota_project)

  print()
  print(f"[mcp] connecting to {args.url} (quota project: {args.quota_project or '<none>'})")
  async with streamablehttp_client(args.url, headers=headers, timeout=60) as (
      read_stream,
      write_stream,
      _,
  ):
    async with ClientSession(read_stream, write_stream) as session:
      init = await session.initialize()
      server = init.serverInfo
      print(f"[mcp] server: {server.name} {server.version} (protocol {init.protocolVersion})")

      listed = await session.list_tools()
      names = sorted(tool.name for tool in listed.tools)
      print(f"[mcp] {len(names)} tools:")
      for tool in sorted(listed.tools, key=lambda t: t.name):
        first_line = (tool.description or "").strip().splitlines()[:1]
        print(f"         - {tool.name}: {first_line[0][:90] if first_line else ''}")
      missing = sorted(set(PUBLIC_TOOLS) - set(names))
      if missing:
        print(f"[warn] expected public tools missing from tools/list: {missing}")

      query = build_search_query(args.folder_id, args.mime_type, args.extra_query)
      print()
      print(f"[search_files] query: {query}")
      search = await session.call_tool(
          "search_files",
          {"query": query, "pageSize": args.page_size},
      )
      payload = unwrap_tool_result(search)
      files = payload.get("files", []) if isinstance(payload, dict) else []
      if not files:
        print("[search_files] no files matched (empty folder, or the token lacks Drive scope).")
        if not isinstance(payload, dict):
          print(f"[search_files] raw response: {str(payload)[:500]}")
      for item in files:
        print(
            f"         - {item.get('title')}  id={item.get('id')}  "
            f"mimeType={item.get('mimeType')}  modified={item.get('modifiedTime')}"
        )

      if args.read_file_id:
        await read_both_ways(session, args.read_file_id, args.preview_chars)

      if args.create_test_file:
        if not args.folder_id:
          print("[create_file] --create-test-file requires --folder-id; skipping.")
        else:
          await create_markdown_probe(session, args.folder_id)
  return 0


async def read_both_ways(session: ClientSession, file_id: str, preview_chars: int) -> None:
  """Reads one file via read_file_content and download_file_content and compares."""
  print()
  print(f"[read_file_content] fileId={file_id}")
  verbalized = unwrap_tool_result(
      await session.call_tool("read_file_content", {"fileId": file_id})
  )
  # read_file_content returns {fileContent, textFormattingNotSupported,
  # contentAnchoredComments, unanchoredComments}.
  verbalized_text = (
      str(verbalized.get("fileContent") or json.dumps(verbalized))
      if isinstance(verbalized, dict)
      else str(verbalized)
  )
  print(textwrap.indent(verbalized_text[:preview_chars], "    | "))

  print()
  print(f"[download_file_content] fileId={file_id}")
  downloaded = unwrap_tool_result(
      await session.call_tool("download_file_content", {"fileId": file_id})
  )
  # download_file_content returns {id, title, mimeType, content} with the
  # bytes base64-encoded under "content".
  raw_bytes: bytes | None = None
  if isinstance(downloaded, dict):
    encoded = downloaded.get("content")
    if isinstance(encoded, str):
      try:
        raw_bytes = base64.b64decode(encoded, validate=True)
      except (ValueError, binascii.Error):
        raw_bytes = encoded.encode("utf-8")
  if raw_bytes is None:
    print(f"    (unexpected response shape) {str(downloaded)[:300]}")
    return
  raw_text = raw_bytes.decode("utf-8", errors="replace")
  print(textwrap.indent(raw_text[:preview_chars], "    | "))
  print(
      f"[compare] verbalized={len(verbalized_text)} chars, raw={len(raw_bytes)} bytes, "
      f"byte-identical={verbalized_text == raw_text}"
  )


async def create_markdown_probe(session: ClientSession, folder_id: str) -> None:
  """Creates a tiny Markdown file and verifies it was stored as text/markdown."""
  stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
  title = f"drive-mcp-probe-{stamp}.md"
  body = textwrap.dedent(
      f"""\
      ---
      id: drive-mcp-probe
      created: {stamp}
      source: adk_runbooks/scripts/drive_mcp_smoke_test.py
      ---
      # Drive MCP probe

      This file was created through `create_file` with
      `disableConversionToGoogleType: true` to confirm the server keeps native
      Markdown instead of converting it into a Google Doc.
      """
  )
  print()
  print(f"[create_file] title={title} parentId={folder_id}")
  created = unwrap_tool_result(
      await session.call_tool(
          "create_file",
          {
              "title": title,
              "contentMimeType": "text/markdown",
              "textContent": body,
              "parentId": folder_id,
              "disableConversionToGoogleType": True,
          },
      )
  )
  print(f"    response: {json.dumps(created, indent=2)[:600]}")
  file_id = created.get("id") if isinstance(created, dict) else None
  if not file_id and isinstance(created, dict):
    file_id = (created.get("file") or {}).get("id")
  if not file_id:
    print("[create_file] could not find the new file id in the response.")
    return
  metadata = unwrap_tool_result(
      await session.call_tool("get_file_metadata", {"fileId": file_id})
  )
  mime_type = metadata.get("mimeType") if isinstance(metadata, dict) else None
  verdict = "OK" if mime_type == "text/markdown" else "UNEXPECTED"
  print(f"[get_file_metadata] id={file_id} mimeType={mime_type} -> {verdict}")


def parse_args(argv: list[str]) -> argparse.Namespace:
  """Parses command line flags."""
  parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument("--url", default=os.environ.get("DRIVE_MCP_URL", DEFAULT_DRIVE_MCP_URL))
  parser.add_argument(
      "--quota-project",
      default=os.environ.get("DRIVE_MCP_QUOTA_PROJECT") or os.environ.get("GCP_PROJECT_ID", ""),
      help="Project with drive.googleapis.com and drivemcp.googleapis.com enabled.",
  )
  parser.add_argument("--folder-id", default=os.environ.get("DRIVE_RUNBOOKS_FOLDER_ID", ""))
  parser.add_argument("--mime-type", default="text/markdown")
  parser.add_argument("--extra-query", default="", help="Additional Drive MCP query clause.")
  parser.add_argument("--page-size", type=int, default=10)
  parser.add_argument("--read-file-id", default="", help="Read this file via both read tools.")
  parser.add_argument("--preview-chars", type=int, default=400)
  parser.add_argument(
      "--create-test-file",
      action="store_true",
      help="Create a throwaway .md in --folder-id and verify it stays text/markdown.",
  )
  return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
  args = parse_args(sys.argv[1:] if argv is None else argv)
  try:
    return asyncio.run(run_smoke_test(args))
  except google.auth.exceptions.DefaultCredentialsError as err:
    print(f"[error] no Application Default Credentials: {err}")
    print(REAUTH_HINT)
    return 2
  except google.auth.exceptions.RefreshError as err:
    print(f"[error] ADC refresh failed (Argolis reauth likely required): {err}")
    print(REAUTH_HINT)
    return 2
  except httpx.HTTPStatusError as err:
    print(f"[error] HTTP {err.response.status_code} from {err.request.url}: {err.response.text[:500]}")
    return 1
  except Exception as err:  # pylint: disable=broad-exception-caught
    print(f"[error] {type(err).__name__}: {err}")
    return 1


if __name__ == "__main__":
  sys.exit(main())
