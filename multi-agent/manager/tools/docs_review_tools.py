"""Google Docs API v1 non-destructive review tools for SOC runbooks and reports.

Implements the collaborative human-in-the-loop document review primitives from
Irani (2026) (*Building an AI Document Reviewer with Google ADK, Gemini and the
New Google Docs Comments & Suggested Edits API*):

1. **Dual-Identity Token Resolution** (:func:`resolve_docs_token`) -- Prefers an
   end-user OAuth 2.0 access token in ``tool_context.state["user_access_token"]``
   so comments and suggested edits carry the human reviewer's Workspace identity,
   and falls back cleanly to the worktree's Application Default Credentials
   (:class:`skills.drive_registry.AdcTokenSource`) for CLI and headless runs.

2. **UTF-16 Character-Index Mapping** (:func:`_extract_text_and_index_map`) --
   Walks ``tabs[0].documentTab.body.content`` across both paragraphs and nested
   table cells to map every character in the plain-text projection to its exact
   1-based UTF-16 code-unit index in the Google Docs structural tree.

3. **Two-Step Non-Destructive Review Invariant**:
   - :func:`insert_doc_comments` executes **first**, anchoring native Google Docs
     comments (``insertComment``) with rationale and authoritative citation URLs
     to the original pre-edit index spans.
   - :func:`propose_doc_suggested_edits` executes **second**, validating that no
     replacement spans overlap, sorting spans **descending by ``startIndex``**
     (back-to-front) so earlier edits do not shift subsequent UTF-16 offsets,
     and submitting ``deleteContentRange`` + ``insertText`` under
     ``"writeControl": {"writeMode": "SUGGEST"}``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

# Ensure project root is in sys.path for skills imports
_project_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from skills.drive_registry import (  # noqa: E402
    AdcTokenSource,
    DriveMcpClient,
    DriveMcpError,
    DriveRegistryConfigError,
    TokenSource,
)
from .drive_tools import (  # noqa: E402
    drive_quota_project,
    get_drive_client,
    reports_folder_id,
    runbooks_folder_id,
)

logger = logging.getLogger(__name__)

DOCS_API_BASE_URL = "https://docs.googleapis.com/v1/documents"
GOOGLE_DOC_MIME_TYPE = "application/vnd.google-apps.document"
MARKDOWN_MIME_TYPE = "text/markdown"
DEFAULT_DOCS_TIMEOUT_SECONDS = 30.0

DEFAULT_TRUSTED_DOC_DOMAINS: tuple[str, ...] = (
    "docs.cloud.google.com",
    "cloud.google.com",
    "console.cloud.google.com",
    "attack.mitre.org",
    "ltstrtn.backstory.chronicle.security",
    "backstory.chronicle.security",
    "chronicle.security",
    "googleapis.com",
    "googleusercontent.com",
    "docs.google.com",
    "drive.google.com",
    "github.com",
)

_ENC_FLAG_RE = re.compile(
    r"(-(?:e|en|enc|encodedcommand)\s+)([A-Za-z0-9+/=]{8,})",
    re.IGNORECASE,
)
_STANDALONE_B64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{64,}={0,2})(?![A-Za-z0-9+/=_-])"
)
_MEMDUMP_ARGS_RE = re.compile(
    r"(?i)(\bMiniDump)\s+([^\r\n\"'`]+)"
)
_LIVE_URL_RE = re.compile(
    r"https?://[^\s)\]`\"'>]+"
)

_cache_lock = threading.Lock()
_DOC_INDEX_CACHE: dict[str, tuple[str, list[int]]] = {}


def clear_doc_index_cache() -> None:
    """Clears the in-process fallback index cache (used by tests)."""
    with _cache_lock:
        _DOC_INDEX_CACHE.clear()


def _short_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def sanitize_telemetry_text(text: str) -> str:
    """Redacts raw Base64 stagers and sensitive memory-dump arguments at the tool boundary.

    Replaces verbatim encoded payloads and credential-dump argument sequences with
    deterministic forensic tokens (length + 12-char SHA-256 fingerprint) so LLMs
    can reason over and edit incident reports without echoing weaponized strings
    that trigger model output safety classifiers.
    """
    if not text:
        return text

    def _replace_enc_flag(match: re.Match[str]) -> str:
        prefix, blob = match.group(1), match.group(2)
        return f"{prefix}<REDACTED_B64:len={len(blob)},sha256={_short_sha256(blob)}>"

    def _replace_standalone_b64(match: re.Match[str]) -> str:
        blob = match.group(1)
        return f"<REDACTED_B64:len={len(blob)},sha256={_short_sha256(blob)}>"

    def _replace_memdump(match: re.Match[str]) -> str:
        verb, args_str = match.group(1), match.group(2).strip()
        if args_str.startswith("<REDACTED_"):
            return match.group(0)
        return f"{verb} <REDACTED_DUMP_ARGS:sha256={_short_sha256(args_str)}>"

    sanitized = _ENC_FLAG_RE.sub(_replace_enc_flag, text)
    sanitized = _STANDALONE_B64_RE.sub(_replace_standalone_b64, sanitized)
    sanitized = _MEMDUMP_ARGS_RE.sub(_replace_memdump, sanitized)
    return sanitized


def defang_url(url: str) -> str:
    """Defangs an HTTP(S) URL by replacing scheme and dots in the hostname."""
    cleaned = url.rstrip(".,;:")
    if cleaned.startswith("https://"):
        scheme_replaced = "hxxps://" + cleaned[len("https://") :]
    elif cleaned.startswith("http://"):
        scheme_replaced = "hxxp://" + cleaned[len("http://") :]
    else:
        return url
    scheme_sep = scheme_replaced.find("://") + 3
    slash_pos = scheme_replaced.find("/", scheme_sep)
    if slash_pos == -1:
        host = scheme_replaced[scheme_sep:]
        rest = ""
    else:
        host = scheme_replaced[scheme_sep:slash_pos]
        rest = scheme_replaced[slash_pos:]
    defanged_host = host.replace(".", "[.]")
    return scheme_replaced[:scheme_sep] + defanged_host + rest


def _utf16_code_unit_len(ch: str) -> int:
    """Returns the number of 16-bit UTF-16 code units occupied by a character."""
    return len(ch.encode("utf-16-le")) // 2


def _extract_text_and_index_map(doc: dict[str, Any]) -> tuple[str, list[int]]:
    """Extracts plain text and a 1-based UTF-16 index map from a Docs API payload.

    Recurses into ``tabs[0].documentTab.body.content`` (or top-level ``body.content``)
    across both ``paragraph`` elements and ``table.tableRows[].tableCells[]``.
    """
    tabs = doc.get("tabs", [])
    if tabs:
        body = tabs[0].get("documentTab", {}).get("body", {})
    else:
        body = doc.get("body", {})

    chars: list[str] = []
    index_map: list[int] = []

    def _walk_elements(elements: list[dict[str, Any]]) -> None:
        for element in elements:
            if "paragraph" in element:
                for pe in element["paragraph"].get("elements", []):
                    text_run = pe.get("textRun")
                    if not text_run:
                        continue
                    content = text_run.get("content", "")
                    start_idx = pe.get("startIndex", 0)
                    utf16_offset = 0
                    for ch in content:
                        chars.append(ch)
                        index_map.append(start_idx + utf16_offset)
                        utf16_offset += _utf16_code_unit_len(ch)
            elif "table" in element:
                for row in element["table"].get("tableRows", []):
                    for cell in row.get("tableCells", []):
                        _walk_elements(cell.get("content", []))

    _walk_elements(body.get("content", []))
    return "".join(chars), index_map


def _find_quote_indices(
    plain_text: str, index_map: list[int], quote: str
) -> tuple[int, int] | None:
    """Finds ``quote`` in ``plain_text`` and returns its ``(startIndex, endIndex)``
    in the Google Docs UTF-16 coordinate space."""
    if not quote or not plain_text or not index_map:
        return None

    pos = plain_text.find(quote)
    matched_len = len(quote)

    if pos == -1:
        # Whitespace-normalized fallback for quotes spanning line wraps
        norm_quote = " ".join(quote.split())
        if not norm_quote:
            return None
        norm_chars: list[str] = []
        norm_to_orig: list[int] = []
        prev_ws = False
        for i, ch in enumerate(plain_text):
            if ch in (" ", "\t", "\n", "\r"):
                if not prev_ws and norm_chars:
                    norm_chars.append(" ")
                    norm_to_orig.append(i)
                prev_ws = True
            else:
                norm_chars.append(ch)
                norm_to_orig.append(i)
                prev_ws = False
        norm_text = "".join(norm_chars)
        norm_pos = norm_text.find(norm_quote)
        if norm_pos == -1:
            return None
        orig_start = norm_to_orig[norm_pos]
        orig_end = norm_to_orig[norm_pos + len(norm_quote) - 1]
        start_idx = index_map[orig_start]
        end_idx = index_map[orig_end] + _utf16_code_unit_len(plain_text[orig_end])
        return (start_idx, end_idx)

    end_char_pos = pos + matched_len - 1
    start_idx = index_map[pos]
    end_idx = index_map[end_char_pos] + _utf16_code_unit_len(plain_text[end_char_pos])
    return (start_idx, end_idx)


def resolve_docs_token(
    tool_context: Any = None,
    *,
    token_source: TokenSource | None = None,
) -> str:
    """Resolves the OAuth 2.0 bearer token for Google Docs API v1 calls.

    Follows the Dual-Identity pattern:
    1. If ``tool_context.state["user_access_token"]`` is present, uses the
       logged-in end user's OAuth token so comments and suggested edits carry
       their personal Workspace identity.
    2. Otherwise falls back to ``token_source`` or the worktree's
       :class:`skills.drive_registry.AdcTokenSource`.
    """
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict):
            user_token = str(state.get("user_access_token") or "").strip()
            if user_token:
                return user_token
    source = token_source or AdcTokenSource()
    return source()


def _build_docs_headers(
    token: str,
    *,
    quota_project: str | None = None,
) -> dict[str, str]:
    project = quota_project if quota_project is not None else drive_quota_project()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if project:
        headers["X-Goog-User-Project"] = project
    return headers


def _store_doc_index_state(
    document_id: str,
    plain_text: str,
    index_map: list[int],
    tool_context: Any = None,
) -> None:
    with _cache_lock:
        _DOC_INDEX_CACHE[document_id] = (plain_text, index_map)
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict):
            state["doc_plain_text"] = plain_text
            state["doc_index_map"] = index_map
            state["doc_id"] = document_id


def _load_doc_index_state(
    document_id: str,
    tool_context: Any = None,
) -> tuple[str | None, list[int] | None]:
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict):
            plain_text = state.get("doc_plain_text")
            index_map = state.get("doc_index_map")
            if plain_text is not None and index_map is not None:
                return plain_text, index_map
    with _cache_lock:
        cached = _DOC_INDEX_CACHE.get(document_id)
        if cached is not None:
            return cached
    return None, None


def create_google_doc(
    title: str,
    content: str,
    folder_id: str | None = None,
    *,
    client: DriveMcpClient | None = None,
) -> dict[str, Any]:
    """Creates a native Google Doc (``application/vnd.google-apps.document``) in Drive.

    Unlike :func:`publish_report_to_drive` (which passes
    ``disableConversionToGoogleType=True`` to store raw ``text/markdown``), this
    tool leaves ``disableConversionToGoogleType=False`` so Google Drive converts
    the Markdown/text into a collaborative Google Doc that supports anchored
    comments and Suggested Edits via the Google Docs API v1.

    Args:
        title: Document title in Google Drive.
        content: Initial Markdown or plain-text content.
        folder_id: Optional target Drive folder ID; defaults to
            ``DRIVE_REPORTS_FOLDER_ID`` or ``DRIVE_RUNBOOKS_FOLDER_ID``.
        client: Optional injected :class:`DriveMcpClient` for tests.

    Returns:
        dict with ``status``, ``document_id``, ``title``, ``viewUrl``,
        ``parentId``, and ``mimeType``.
    """
    destination = (
        (folder_id or "").strip()
        or reports_folder_id()
        or runbooks_folder_id()
    )
    if not destination:
        return {
            "status": "error",
            "message": (
                "No target Drive folder ID provided and neither DRIVE_REPORTS_FOLDER_ID "
                "nor DRIVE_RUNBOOKS_FOLDER_ID is set."
            ),
        }
    try:
        drive = client or get_drive_client()
        created = drive.call_tool(
            "create_file",
            {
                "title": title,
                "contentMimeType": MARKDOWN_MIME_TYPE,
                "textContent": content,
                "parentId": destination,
                "disableConversionToGoogleType": False,
            },
        )
        if not isinstance(created, dict):
            created = {}
        doc_id = created.get("id", "")
        return {
            "status": "success",
            "document_id": doc_id,
            "title": created.get("title", title),
            "viewUrl": created.get(
                "viewUrl", f"https://docs.google.com/document/d/{doc_id}/edit"
            ),
            "parentId": created.get("parentId", destination),
            "mimeType": created.get("mimeType", GOOGLE_DOC_MIME_TYPE),
        }
    except (DriveMcpError, DriveRegistryConfigError) as err:
        return {"status": "error", "message": f"Failed to create Google Doc via Drive MCP: {err}"}


def read_google_doc(
    document_id: str,
    tool_context: Any = None,
    *,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Reads a Google Doc via Docs API v1 and caches its 1-based UTF-16 index map.

    Always call ``read_google_doc`` before calling ``insert_doc_comments`` or
    ``propose_doc_suggested_edits``.

    Args:
        document_id: The Google Docs ``documentId``.
        tool_context: Optional ADK ``ToolContext`` holding session state.

    Returns:
        dict containing ``status``, ``document_id``, ``title``, ``content``,
        and ``char_count``.
    """
    try:
        token = resolve_docs_token(tool_context, token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError) as err:
        return {"status": "error", "message": str(err)}

    url = f"{DOCS_API_BASE_URL}/{document_id}"
    headers = _build_docs_headers(token, quota_project=quota_project)
    try:
        with httpx.Client(
            timeout=DEFAULT_DOCS_TIMEOUT_SECONDS, transport=transport
        ) as http:
            resp = http.get(url, params={"includeTabsContent": "true"}, headers=headers)
    except httpx.HTTPError as err:
        return {"status": "error", "message": f"HTTP transport error reading doc: {err}"}

    if resp.status_code != 200:
        return {
            "status": "error",
            "message": f"Google Docs API returned HTTP {resp.status_code}: {resp.text[:300]}",
        }

    doc = resp.json()
    title = doc.get("title", "Untitled")
    plain_text, index_map = _extract_text_and_index_map(doc)
    _store_doc_index_state(document_id, plain_text, index_map, tool_context=tool_context)

    return {
        "status": "success",
        "document_id": document_id,
        "title": title,
        "content": plain_text,
        "char_count": len(plain_text),
    }


def insert_doc_comments(
    document_id: str,
    comments: str | list[dict[str, str]],
    tool_context: Any = None,
    *,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Anchors native review comments to exact text spans in a Google Doc.

    IMPORTANT ORDERING INVARIANT: Always call ``insert_doc_comments`` BEFORE
    ``propose_doc_suggested_edits`` because both resolve quotes against the
    pre-edit ``doc_index_map`` captured by ``read_google_doc``.

    Args:
        document_id: The Google Docs ``documentId``.
        comments: JSON string or list of ``{"quote": "<exact substring>",
            "comment": "<review note + citation URL>"}`` objects.
        tool_context: Optional ADK ``ToolContext``.

    Returns:
        dict with ``status``, ``inserted_count``, ``comment_ids``, and ``skipped``.
    """
    try:
        token = resolve_docs_token(tool_context, token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError) as err:
        return {"status": "error", "message": str(err)}

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Document index map not found. Call read_google_doc first.",
        }

    if isinstance(comments, str):
        try:
            comment_list = json.loads(comments)
        except json.JSONDecodeError as err:
            return {"status": "error", "message": f"Invalid comments JSON: {err}"}
    else:
        comment_list = comments

    if not isinstance(comment_list, list) or not comment_list:
        return {"status": "error", "message": "No comments provided."}

    requests_list: list[dict[str, Any]] = []
    skipped: list[str] = []

    for item in comment_list:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote") or "")
        text = str(item.get("comment") or "").strip()
        raw_start = item.get("start_index")
        raw_end = item.get("end_index")
        if not text:
            skipped.append(quote or "<empty comment>")
            continue
        if isinstance(raw_start, int) and isinstance(raw_end, int) and 1 <= raw_start < raw_end:
            start_idx, end_idx = raw_start, raw_end
        elif quote:
            span = _find_quote_indices(plain_text, index_map, quote)
            if span is None:
                skipped.append(quote[:80])
                continue
            start_idx, end_idx = span
        else:
            skipped.append("<empty quote>")
            continue
        requests_list.append(
            {
                "insertComment": {
                    "content": text,
                    "range": {
                        "startIndex": start_idx,
                        "endIndex": end_idx,
                    },
                }
            }
        )

    if not requests_list:
        return {
            "status": "error",
            "message": f"Could not match any quoted text in document. Skipped: {skipped}",
        }

    url = f"{DOCS_API_BASE_URL}/{document_id}:batchUpdate"
    headers = _build_docs_headers(token, quota_project=quota_project)
    try:
        with httpx.Client(
            timeout=DEFAULT_DOCS_TIMEOUT_SECONDS, transport=transport
        ) as http:
            resp = http.post(url, headers=headers, json={"requests": requests_list})
    except httpx.HTTPError as err:
        return {"status": "error", "message": f"HTTP transport error inserting comments: {err}"}

    if resp.status_code != 200:
        return {
            "status": "error",
            "message": f"Google Docs batchUpdate failed ({resp.status_code}): {resp.text[:300]}",
        }

    data = resp.json()
    comment_ids = [
        cid
        for reply in data.get("replies", [])
        if isinstance(reply, dict)
        and "insertComment" in reply
        and (cid := reply.get("insertComment", {}).get("commentId"))
    ]
    result: dict[str, Any] = {
        "status": "success",
        "inserted_count": len(requests_list),
        "comment_ids": comment_ids,
    }
    if skipped:
        result["skipped"] = skipped
    return result


def propose_doc_suggested_edits(
    document_id: str,
    edits: str | list[dict[str, Any]],
    tool_context: Any = None,
    *,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Proposes non-destructive Suggested Edits (``writeMode="SUGGEST"``) in a Google Doc.

    Validates that no edit spans overlap and sorts all replacements in
    **descending order of ``startIndex``** (back-to-front) so earlier edits in
    the ``batchUpdate`` payload do not shift UTF-16 character offsets for
    subsequent edits earlier in the document.

    Each edit item may specify either:
    - ``{"quote": "<exact substring to replace>", "replacement": "<proposed text>"}``
    - ``{"start_index": <int>, "end_index": <int>, "replacement": "<proposed text>"}``
      (1-based UTF-16 indices from ``read_google_doc``, avoiding any need to echo
      suspicious command strings in LLM tool call arguments).

    Args:
        document_id: The Google Docs ``documentId``.
        edits: JSON string or list of edit objects.
        tool_context: Optional ADK ``ToolContext``.

    Returns:
        dict with ``status``, ``applied_count``, and ``skipped``.
    """
    try:
        token = resolve_docs_token(tool_context, token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError) as err:
        return {"status": "error", "message": str(err)}

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Document index map not found. Call read_google_doc first.",
        }

    if isinstance(edits, str):
        try:
            edit_list = json.loads(edits)
        except json.JSONDecodeError as err:
            return {"status": "error", "message": f"Invalid edits JSON: {err}"}
    else:
        edit_list = edits

    if not isinstance(edit_list, list) or not edit_list:
        return {"status": "error", "message": "No edits provided."}

    resolved: list[tuple[int, int, str, str]] = []
    skipped: list[str] = []

    for item in edit_list:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote") or "")
        replacement = item.get("replacement")
        raw_start = item.get("start_index")
        raw_end = item.get("end_index")
        if replacement is None:
            skipped.append(quote or "<missing replacement>")
            continue
        if isinstance(raw_start, int) and isinstance(raw_end, int) and 1 <= raw_start < raw_end:
            start_idx, end_idx = raw_start, raw_end
            label = quote or f"span[{start_idx}:{end_idx}]"
        elif quote:
            span = _find_quote_indices(plain_text, index_map, quote)
            if span is None:
                skipped.append(quote[:80])
                continue
            start_idx, end_idx = span
            label = quote
        else:
            skipped.append("<empty quote>")
            continue
        resolved.append((start_idx, end_idx, str(replacement), label))

    if not resolved:
        return {
            "status": "error",
            "message": f"Could not match any quoted text in document. Skipped: {skipped}",
        }

    # Sort descending by startIndex (back-to-front) so edits near the end of the
    # document execute first and never shift character indices of earlier spans.
    resolved.sort(key=lambda item: item[0], reverse=True)

    # Reject overlapping ranges (in descending order: prev_start < curr_end means overlap).
    for i in range(1, len(resolved)):
        prev_start, _prev_end, _, prev_quote = resolved[i - 1]
        _curr_start, curr_end, _, curr_quote = resolved[i]
        if prev_start < curr_end:
            return {
                "status": "error",
                "message": (
                    f"Overlapping edit ranges detected between {curr_quote[:40]!r} "
                    f"and {prev_quote[:40]!r}. Provide non-overlapping quotes."
                ),
            }

    requests_list: list[dict[str, Any]] = []
    for start_idx, end_idx, replacement, _quote in resolved:
        requests_list.append(
            {
                "deleteContentRange": {
                    "range": {
                        "startIndex": start_idx,
                        "endIndex": end_idx,
                    }
                }
            }
        )
        if replacement:
            requests_list.append(
                {
                    "insertText": {
                        "location": {"index": start_idx},
                        "text": replacement,
                    }
                }
            )

    payload = {
        "writeControl": {"writeMode": "SUGGEST"},
        "requests": requests_list,
    }

    url = f"{DOCS_API_BASE_URL}/{document_id}:batchUpdate"
    headers = _build_docs_headers(token, quota_project=quota_project)
    try:
        with httpx.Client(
            timeout=DEFAULT_DOCS_TIMEOUT_SECONDS, transport=transport
        ) as http:
            resp = http.post(url, headers=headers, json=payload)
    except httpx.HTTPError as err:
        return {
            "status": "error",
            "message": f"HTTP transport error proposing suggested edits: {err}",
        }

    if resp.status_code != 200:
        return {
            "status": "error",
            "message": f"Google Docs batchUpdate failed ({resp.status_code}): {resp.text[:300]}",
        }

    result: dict[str, Any] = {
        "status": "success",
        "applied_count": len(resolved),
    }
    if skipped:
        result["skipped"] = skipped
    return result


def _is_trusted_domain(url: str, trusted_domains: tuple[str, ...]) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    return any(host == dom or host.endswith("." + dom) for dom in trusted_domains)


def find_deterministic_indicator_spans(
    plain_text: str,
    index_map: list[int],
    *,
    trusted_domains: tuple[str, ...] = DEFAULT_TRUSTED_DOC_DOMAINS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans document text for live untrusted URLs and raw encoded blobs without an LLM.

    Returns ``(comments, edits)`` using 1-based UTF-16 ``start_index`` and
    ``end_index`` coordinates so ``insert_doc_comments`` and
    ``propose_doc_suggested_edits`` can stage red-lines directly via the Docs API.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits

    for match in _LIVE_URL_RE.finditer(plain_text):
        raw_url = match.group(0).rstrip(".,;:")
        if _is_trusted_domain(raw_url, trusted_domains):
            continue
        char_start = match.start()
        char_end = char_start + len(raw_url) - 1
        start_idx = index_map[char_start]
        end_idx = index_map[char_end] + _utf16_code_unit_len(plain_text[char_end])
        defanged = defang_url(raw_url)
        if defanged == raw_url:
            continue
        comments.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "comment": (
                    "Deterministic Indicator Safety Check: Live external URL auto-linkifies "
                    "in Google Docs and creates a click hazard for incident responders. "
                    "Defang indicator scheme and hostname before distributing the report."
                ),
            }
        )
        edits.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "replacement": defanged,
            }
        )

    return comments, edits

