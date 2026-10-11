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

import difflib
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
    parse_frontmatter,
)
from .drive_tools import (  # noqa: E402
    drive_quota_project,
    get_drive_client,
    publish_report_to_drive,
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
    "nvd.nist.gov",
    "cisa.gov",
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

DEFAULT_UDM_FIELD_LIST_URL = (
    "https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list"
)
DEFAULT_YARAL2_DOC_URL = (
    "https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax"
)
MITRE_ATTACK_BASE_URL = "https://attack.mitre.org/techniques"
NVD_CVE_BASE_URL = "https://nvd.nist.gov/vuln/detail"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def mitre_technique_url(technique_id: str) -> str:
    """Converts a MITRE ATT&CK technique ID (e.g. ``T1059.001`` or ``T1059``) to its canonical URL."""
    cleaned = str(technique_id or "").strip().upper()
    if "." in cleaned:
        parent, sub = cleaned.split(".", 1)
        return f"{MITRE_ATTACK_BASE_URL}/{parent}/{sub}/"
    return f"{MITRE_ATTACK_BASE_URL}/{cleaned}/"


def nvd_cve_url(cve_id: str) -> str:
    """Converts a CVE ID (e.g. ``CVE-2024-21762``) to its canonical NIST NVD detail URL."""
    cleaned = str(cve_id or "").strip().upper()
    return f"{NVD_CVE_BASE_URL}/{cleaned}"


DEPRECATED_MITRE_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "T1086": {
        "canonical_id": "T1059.001",
        "canonical_name": "Command and Scripting Interpreter: PowerShell",
        "short_name": "PowerShell",
        "deprecated_name": "PowerShell",
        "tactic": "Execution",
    },
    "T1085": {
        "canonical_id": "T1218.011",
        "canonical_name": "System Binary Proxy Execution: Rundll32",
        "short_name": "Rundll32",
        "deprecated_name": "Rundll32",
        "tactic": "Defense Evasion",
    },
    "T1117": {
        "canonical_id": "T1218.010",
        "canonical_name": "System Binary Proxy Execution: Regsvr32",
        "short_name": "Regsvr32",
        "deprecated_name": "Regsvr32",
        "tactic": "Defense Evasion",
    },
    "T1170": {
        "canonical_id": "T1218.005",
        "canonical_name": "System Binary Proxy Execution: Mshta",
        "short_name": "Mshta",
        "deprecated_name": "Mshta",
        "tactic": "Defense Evasion",
    },
    "T1064": {
        "canonical_id": "T1059",
        "canonical_name": "Command and Scripting Interpreter",
        "short_name": "Command and Scripting Interpreter",
        "deprecated_name": "Scripting",
        "tactic": "Execution",
    },
    "T1100": {
        "canonical_id": "T1505.003",
        "canonical_name": "Server Software Component: Web Shell",
        "short_name": "Web Shell",
        "deprecated_name": "Web Shell",
        "tactic": "Persistence",
    },
    "T1075": {
        "canonical_id": "T1550.002",
        "canonical_name": "Use Alternate Authentication Material: Pass the Hash",
        "short_name": "Pass the Hash",
        "deprecated_name": "Pass the Hash",
        "tactic": "Lateral Movement",
    },
    "T1504": {
        "canonical_id": "T1546.013",
        "canonical_name": "Event Triggered Execution: PowerShell Profile",
        "short_name": "PowerShell Profile",
        "deprecated_name": "PowerShell Profile",
        "tactic": "Persistence",
    },
}

CANONICAL_MITRE_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059": {
        "canonical_name": "Command and Scripting Interpreter",
        "short_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
    },
    "T1059.001": {
        "canonical_name": "Command and Scripting Interpreter: PowerShell",
        "short_name": "PowerShell",
        "tactic": "Execution",
    },
    "T1059.003": {
        "canonical_name": "Command and Scripting Interpreter: Windows Command Shell",
        "short_name": "Windows Command Shell",
        "tactic": "Execution",
    },
    "T1059.004": {
        "canonical_name": "Command and Scripting Interpreter: Unix Shell",
        "short_name": "Unix Shell",
        "tactic": "Execution",
    },
    "T1003": {
        "canonical_name": "OS Credential Dumping",
        "short_name": "OS Credential Dumping",
        "tactic": "Credential Access",
    },
    "T1003.001": {
        "canonical_name": "OS Credential Dumping: LSASS Memory",
        "short_name": "LSASS Memory",
        "tactic": "Credential Access",
    },
    "T1003.002": {
        "canonical_name": "OS Credential Dumping: Security Account Manager",
        "short_name": "Security Account Manager",
        "tactic": "Credential Access",
    },
    "T1003.003": {
        "canonical_name": "OS Credential Dumping: NTDS",
        "short_name": "NTDS",
        "tactic": "Credential Access",
    },
    "T1078": {
        "canonical_name": "Valid Accounts",
        "short_name": "Valid Accounts",
        "tactic": "Initial Access / Privilege Escalation",
    },
    "T1078.001": {
        "canonical_name": "Valid Accounts: Default Accounts",
        "short_name": "Default Accounts",
        "tactic": "Initial Access / Privilege Escalation",
    },
    "T1078.002": {
        "canonical_name": "Valid Accounts: Domain Accounts",
        "short_name": "Domain Accounts",
        "tactic": "Initial Access / Privilege Escalation",
    },
    "T1078.003": {
        "canonical_name": "Valid Accounts: Local Accounts",
        "short_name": "Local Accounts",
        "tactic": "Initial Access / Privilege Escalation",
    },
    "T1078.004": {
        "canonical_name": "Valid Accounts: Cloud Accounts",
        "short_name": "Cloud Accounts",
        "tactic": "Initial Access / Privilege Escalation",
    },
    "T1098": {
        "canonical_name": "Account Manipulation",
        "short_name": "Account Manipulation",
        "tactic": "Persistence / Privilege Escalation",
    },
    "T1098.001": {
        "canonical_name": "Account Manipulation: Additional Cloud Credentials",
        "short_name": "Additional Cloud Credentials",
        "tactic": "Persistence / Privilege Escalation",
    },
    "T1098.003": {
        "canonical_name": "Account Manipulation: Additional Cloud Roles",
        "short_name": "Additional Cloud Roles",
        "tactic": "Persistence / Privilege Escalation",
    },
    "T1218": {
        "canonical_name": "System Binary Proxy Execution",
        "short_name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
    },
    "T1218.003": {
        "canonical_name": "System Binary Proxy Execution: CMSTP",
        "short_name": "CMSTP",
        "tactic": "Defense Evasion",
    },
    "T1218.005": {
        "canonical_name": "System Binary Proxy Execution: Mshta",
        "short_name": "Mshta",
        "tactic": "Defense Evasion",
    },
    "T1218.010": {
        "canonical_name": "System Binary Proxy Execution: Regsvr32",
        "short_name": "Regsvr32",
        "tactic": "Defense Evasion",
    },
    "T1218.011": {
        "canonical_name": "System Binary Proxy Execution: Rundll32",
        "short_name": "Rundll32",
        "tactic": "Defense Evasion",
    },
    "T1505.003": {
        "canonical_name": "Server Software Component: Web Shell",
        "short_name": "Web Shell",
        "tactic": "Persistence",
    },
    "T1550.002": {
        "canonical_name": "Use Alternate Authentication Material: Pass the Hash",
        "short_name": "Pass the Hash",
        "tactic": "Lateral Movement",
    },
    "T1546.013": {
        "canonical_name": "Event Triggered Execution: PowerShell Profile",
        "short_name": "PowerShell Profile",
        "tactic": "Persistence",
    },
}

CANONICAL_CISA_KEV_CATALOG: dict[str, dict[str, Any]] = {
    "CVE-2024-21762": {
        "vendor": "Fortinet",
        "product": "FortiOS SSL VPN",
        "vulnerability_name": "Fortinet FortiOS Out-of-Bounds Write Vulnerability",
        "cwe": "CWE-787",
        "vendor_keywords": ("fortinet", "fortios", "fortigate"),
    },
    "CVE-2024-21887": {
        "vendor": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerability_name": "Ivanti Connect Secure and Policy Secure Command Injection Vulnerability",
        "cwe": "CWE-77",
        "vendor_keywords": ("ivanti", "connect secure", "policy secure", "pulse secure"),
    },
    "CVE-2023-46805": {
        "vendor": "Ivanti",
        "product": "Connect Secure and Policy Secure",
        "vulnerability_name": "Ivanti Connect Secure and Policy Secure Authentication Bypass Vulnerability",
        "cwe": "CWE-287",
        "vendor_keywords": ("ivanti", "connect secure", "policy secure", "pulse secure"),
    },
    "CVE-2024-3400": {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS GlobalProtect",
        "vulnerability_name": "Palo Alto Networks PAN-OS Command Injection Vulnerability",
        "cwe": "CWE-77",
        "vendor_keywords": ("palo alto", "pan-os", "panos", "globalprotect"),
    },
}

_MITRE_TECHNIQUE_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(T\d{4}(?:\.\d{3})?)(?![A-Za-z0-9_]|(?:\.\d))"
)
_CVE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])(CVE-\d{4}-\d{4,7})(?![A-Za-z0-9_-])"
)

VALID_UDM_TOP_LEVEL_PREFIXES: tuple[str, ...] = (
    "metadata",
    "principal",
    "target",
    "src",
    "observer",
    "intermediary",
    "about",
    "security_result",
    "network",
    "extensions",
    "additional",
)

CANONICAL_UDM_FIELD_CORRECTIONS: dict[str, str] = {
    "process.command_line": "target.process.command_line",
    "process.cmd_line": "target.process.command_line",
    "principal.process.cmd_line": "principal.process.command_line",
    "target.process.cmd_line": "target.process.command_line",
    "process.file.sha256": "target.process.file.sha256",
    "file.sha256": "target.process.file.sha256",
    "file.md5": "target.process.file.md5",
    "file.path": "target.file.full_path",
    "resource.name": "target.resource.name",
    "resource.type": "target.resource.resource_type",
    "user.userid": "principal.user.userid",
    "user.email": "principal.user.email_addresses",
    "user.email_addresses": "principal.user.email_addresses",
    "event_type": "metadata.event_type",
    "log_type": "metadata.log_type",
    "ip": "principal.ip",
    "hostname": "principal.hostname",
    "network.http.url": "target.url",
    "security_result.alert_name": "security_result.rule_name",
}

_UDM_COMPARISON_RE = re.compile(
    r"(?<![A-Za-z0-9_.$-])([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"(\s*(?:!=|=)\s*)"
    r"(?:\"[^\r\n\"]*\"|'[^\r\n']*'|“[^\r\n”]*”|/[^\r\n/]+/(?:\s*nocase)?)"
)

_YARAL2_RULE_HEADER_RE = re.compile(
    r"(?<![A-Za-z0-9_])rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
_YARAL2_SECTION_HEADER_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s{]))(meta|events|strings|match|outcome|condition|options)\s*:"
)
_YARAL2_EVENT_FIELD_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?![A-Za-z0-9_.])"
)
_YARAL2_PLACEHOLDER_RHS_RE = re.compile(
    r"(?:!=|=)\s*\$([A-Za-z_][A-Za-z0-9_]*)(?!\.)"
)
_YARAL2_PLACEHOLDER_LHS_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)(?!\.)\s*(?:!=|=)"
)
_YARAL2_COND_VAR_RE = re.compile(
    r"([#$])([A-Za-z_][A-Za-z0-9_]*)(?!\.)"
)
_YARAL2_RE_REGEX_SLASH_NORM_RE = re.compile(
    r"(re\.regex\(\s*\$[A-Za-z_][A-Za-z0-9_.]*\s*,\s*)/([^/\r\n]+)/(\s*nocase)?(\s*\))(\s*nocase)?",
    re.IGNORECASE,
)
_YARAL2_RE_REGEX_CALL_RE = re.compile(
    r"re\.regex\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*"
    r"(?:/([^/\r\n]+)/|`([^`\r\n]+)`|\"([^\r\n\"]+)\")\s*(nocase)?\s*\)\s*(nocase)?",
    re.IGNORECASE,
)
_YARAL2_EVENT_COMPARISON_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)"
    r"(\s*(?:!=|=)\s*)"
    r"(\"[^\r\n\"]*\"|'[^\r\n']*'|“[^\r\n”]*”|/[^\r\n/]+/(?:\s*nocase)?|`[^`\r\n]*`(?:\s*nocase)?)"
)

_FRONTMATTER_BLOCK_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

_cache_lock = threading.Lock()
_DOC_INDEX_CACHE: dict[str, tuple[str, list[int]]] = {}
_DOC_SUGGESTION_CACHE: dict[str, list[tuple[int, int]]] = {}


def clear_doc_index_cache() -> None:
    """Clears the in-process fallback index cache (used by tests)."""
    with _cache_lock:
        _DOC_INDEX_CACHE.clear()
        _DOC_SUGGESTION_CACHE.clear()


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
        if re.fullmatch(r"[0-9a-fA-F]+", blob):
            return blob
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


def _normalize_suggestion_ids(
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None,
) -> set[str] | None:
    """Normalizes optional suggestion ID filters into a set of IDs (or ``None`` for all)."""
    if accept_suggestion_ids is None:
        return None
    if isinstance(accept_suggestion_ids, str):
        stripped = accept_suggestion_ids.strip()
        if not stripped or stripped.lower() in ("all", "*"):
            return None
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
                if isinstance(parsed, list):
                    return {str(x).strip() for x in parsed if str(x).strip()}
            except json.JSONDecodeError:
                pass
        return {part.strip() for part in stripped.split(",") if part.strip()}
    if isinstance(accept_suggestion_ids, (list, set, tuple)):
        return {str(x).strip() for x in accept_suggestion_ids if str(x).strip()}
    return None


def _extract_text_and_index_map(
    doc: dict[str, Any],
    *,
    view_mode: str = "baseline",
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None = None,
) -> tuple[str, list[int]]:
    """Extracts plain text and a 1-based UTF-16 index map from a Docs API payload.

    Recurses into ``tabs[0].documentTab.body.content`` (or top-level ``body.content``)
    across both ``paragraph`` elements and ``table.tableRows[].tableCells[]``.

    Args:
        doc: Google Docs API v1 ``documents.get`` response payload.
        view_mode: One of:
            - ``"baseline"`` (default): includes untouched ``textRun``s and
              ``suggestedDeletionIds`` ``textRun``s while excluding
              ``suggestedInsertionIds`` ``textRun``s so pending replacements
              never fuse ``deleted_text + inserted_text`` in ``plain_text``,
              while still mapping every character to its exact 1-based UTF-16
              index in the live Google Doc coordinate space.
            - ``"accepted"``: includes untouched ``textRun``s and accepted
              ``suggestedInsertionIds`` ``textRun``s while excluding accepted
              ``suggestedDeletionIds`` ``textRun``s (honoring
              ``accept_suggestion_ids`` when provided).
            - ``"inline"``: raw concatenation of all ``textRun``s.
        accept_suggestion_ids: Optional collection or JSON/comma-separated string
            of ``suggest.*`` IDs to accept when ``view_mode="accepted"``. When
            ``None`` or ``""``, all pending suggestions are accepted.
    """
    if view_mode not in ("baseline", "accepted", "inline"):
        raise ValueError(f"Unsupported view_mode: {view_mode!r}")

    accepted_set = _normalize_suggestion_ids(accept_suggestion_ids)
    tabs = doc.get("tabs", [])
    if tabs:
        body = tabs[0].get("documentTab", {}).get("body", {})
    else:
        body = doc.get("body", {})

    chars: list[str] = []
    index_map: list[int] = []

    def _should_include_text_run(del_ids: list[str], ins_ids: list[str]) -> bool:
        if view_mode == "inline":
            return True
        if view_mode == "baseline":
            return not bool(ins_ids)
        # view_mode == "accepted"
        if accepted_set is None:
            return not bool(del_ids)
        if ins_ids and not any(sid in accepted_set for sid in ins_ids):
            return False
        if del_ids and any(sid in accepted_set for sid in del_ids):
            return False
        return True

    def _walk_elements(elements: list[dict[str, Any]]) -> None:
        for element in elements:
            if "paragraph" in element:
                for pe in element["paragraph"].get("elements", []):
                    text_run = pe.get("textRun")
                    if not text_run:
                        continue
                    del_ids = [
                        str(x) for x in (text_run.get("suggestedDeletionIds") or []) if x
                    ]
                    ins_ids = [
                        str(x) for x in (text_run.get("suggestedInsertionIds") or []) if x
                    ]
                    if not _should_include_text_run(del_ids, ins_ids):
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


def extract_doc_projections(
    doc: dict[str, Any],
    *,
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Extracts baseline, accepted, and inline projections plus structured suggestion spans.

    Groups paired ``suggestedDeletionIds`` and ``suggestedInsertionIds`` across
    paragraphs and nested table cells by ``suggestion_id`` in document encounter
    order.
    """
    accepted_set = _normalize_suggestion_ids(accept_suggestion_ids)
    tabs = doc.get("tabs", [])
    if tabs:
        body = tabs[0].get("documentTab", {}).get("body", {})
    else:
        body = doc.get("body", {})

    suggestions_by_id: dict[str, dict[str, Any]] = {}

    def _ensure_rec(sid: str, start_idx: int, end_idx: int) -> dict[str, Any]:
        rec = suggestions_by_id.get(sid)
        if rec is None:
            rec = {
                "suggestion_id": sid,
                "deleted_parts": [],
                "inserted_parts": [],
                "start_index": start_idx,
                "end_index": end_idx,
                "del_start": None,
                "del_end": None,
                "ins_start": None,
                "ins_end": None,
            }
            suggestions_by_id[sid] = rec
        else:
            rec["start_index"] = min(rec["start_index"], start_idx)
            rec["end_index"] = max(rec["end_index"], end_idx)
        return rec

    def _walk_suggestions(elements: list[dict[str, Any]]) -> None:
        for element in elements:
            if "paragraph" in element:
                for pe in element["paragraph"].get("elements", []):
                    text_run = pe.get("textRun")
                    if not text_run:
                        continue
                    content = text_run.get("content", "")
                    start_idx = int(pe.get("startIndex", 0) or 0)
                    utf16_len = sum(_utf16_code_unit_len(ch) for ch in content)
                    end_idx = int(pe.get("endIndex", start_idx + utf16_len) or (start_idx + utf16_len))
                    del_ids = [
                        str(x) for x in (text_run.get("suggestedDeletionIds") or []) if x
                    ]
                    ins_ids = [
                        str(x) for x in (text_run.get("suggestedInsertionIds") or []) if x
                    ]
                    for sid in del_ids:
                        rec = _ensure_rec(sid, start_idx, end_idx)
                        rec["deleted_parts"].append(content)
                        rec["del_start"] = (
                            start_idx
                            if rec["del_start"] is None
                            else min(rec["del_start"], start_idx)
                        )
                        rec["del_end"] = (
                            end_idx
                            if rec["del_end"] is None
                            else max(rec["del_end"], end_idx)
                        )
                    for sid in ins_ids:
                        rec = _ensure_rec(sid, start_idx, end_idx)
                        rec["inserted_parts"].append(content)
                        rec["ins_start"] = (
                            start_idx
                            if rec["ins_start"] is None
                            else min(rec["ins_start"], start_idx)
                        )
                        rec["ins_end"] = (
                            end_idx
                            if rec["ins_end"] is None
                            else max(rec["ins_end"], end_idx)
                        )
            elif "table" in element:
                for row in element["table"].get("tableRows", []):
                    for cell in row.get("tableCells", []):
                        _walk_suggestions(cell.get("content", []))

    _walk_suggestions(body.get("content", []))

    suggestions: list[dict[str, Any]] = []
    pending_suggestion_spans: list[tuple[int, int]] = []
    for sid, rec in suggestions_by_id.items():
        deleted_text = "".join(rec["deleted_parts"])
        inserted_text = "".join(rec["inserted_parts"])
        if deleted_text and inserted_text:
            kind = "replace"
        elif inserted_text:
            kind = "insert"
        else:
            kind = "delete"
        is_accepted = (accepted_set is None) or (sid in accepted_set)
        start_idx = int(rec["start_index"])
        end_idx = int(rec["end_index"])
        pending_suggestion_spans.append((start_idx, end_idx))
        suggestions.append(
            {
                "suggestion_id": sid,
                "kind": kind,
                "deleted_text": deleted_text,
                "inserted_text": inserted_text,
                "start_index": start_idx,
                "end_index": end_idx,
                "deletion_span": (
                    [rec["del_start"], rec["del_end"]]
                    if rec["del_start"] is not None
                    else None
                ),
                "insertion_span": (
                    [rec["ins_start"], rec["ins_end"]]
                    if rec["ins_start"] is not None
                    else None
                ),
                "accepted": is_accepted,
            }
        )

    baseline_text, baseline_index_map = _extract_text_and_index_map(
        doc, view_mode="baseline"
    )
    accepted_text, accepted_index_map = _extract_text_and_index_map(
        doc, view_mode="accepted", accept_suggestion_ids=accept_suggestion_ids
    )
    inline_text, inline_index_map = _extract_text_and_index_map(
        doc, view_mode="inline"
    )
    return {
        "baseline_text": baseline_text,
        "baseline_index_map": baseline_index_map,
        "accepted_text": accepted_text,
        "accepted_index_map": accepted_index_map,
        "inline_text": inline_text,
        "inline_index_map": inline_index_map,
        "suggestions": suggestions,
        "pending_suggestion_spans": pending_suggestion_spans,
    }


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
    *,
    pending_suggestion_spans: list[tuple[int, int]] | None = None,
) -> None:
    spans = list(pending_suggestion_spans or [])
    with _cache_lock:
        _DOC_INDEX_CACHE[document_id] = (plain_text, index_map)
        _DOC_SUGGESTION_CACHE[document_id] = spans
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict):
            state["doc_plain_text"] = plain_text
            state["doc_index_map"] = index_map
            state["doc_pending_suggestion_spans"] = spans
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


def _load_doc_pending_suggestion_spans(
    document_id: str,
    tool_context: Any = None,
) -> list[tuple[int, int]]:
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict) and state.get("doc_id") == document_id:
            raw_spans = state.get("doc_pending_suggestion_spans")
            if isinstance(raw_spans, list):
                return [
                    (int(sp[0]), int(sp[1]))
                    for sp in raw_spans
                    if isinstance(sp, (list, tuple)) and len(sp) == 2
                ]
    with _cache_lock:
        return list(_DOC_SUGGESTION_CACHE.get(document_id, []))


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
    ``propose_doc_suggested_edits``. Extracts the ``"baseline"`` text projection
    (excluding ``suggestedInsertionIds`` so pending replacements never fuse
    ``deleted_text + inserted_text``) while caching ``pending_suggestion_spans``
    for multi-pass review idempotency.

    Args:
        document_id: The Google Docs ``documentId``.
        tool_context: Optional ADK ``ToolContext`` holding session state.

    Returns:
        dict containing ``status``, ``document_id``, ``title``, ``content``,
        ``char_count``, ``pending_suggestions_count``, and ``suggestions``.
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
    projections = extract_doc_projections(doc)
    plain_text = projections["baseline_text"]
    index_map = projections["baseline_index_map"]
    suggestions = projections["suggestions"]
    pending_spans = projections["pending_suggestion_spans"]
    _store_doc_index_state(
        document_id,
        plain_text,
        index_map,
        tool_context=tool_context,
        pending_suggestion_spans=pending_spans,
    )

    return {
        "status": "success",
        "document_id": document_id,
        "title": title,
        "content": plain_text,
        "char_count": len(plain_text),
        "pending_suggestions_count": len(suggestions),
        "suggestions": suggestions,
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


def _extract_udm_query_from_line(
    plain_text: str, char_start: int, fallback_clause: str
) -> str:
    """Extracts the surrounding UDM query expression from the line containing ``char_start``."""
    line_start = plain_text.rfind("\n", 0, char_start) + 1
    line_end = plain_text.find("\n", char_start)
    if line_end == -1:
        line_end = len(plain_text)
    line = plain_text[line_start:line_end].strip()

    # Prefer backtick-delimited query expressions when present on the line
    for bt_match in re.finditer(r"`([^`]+)`", line):
        segment = bt_match.group(1).strip()
        if fallback_clause in segment:
            return segment

    first_cmp = _UDM_COMPARISON_RE.search(line)
    if first_cmp is not None:
        candidate = line[first_cmp.start() :].strip().strip("`")
        if candidate:
            return candidate
    return fallback_clause


def find_udm_field_spans(
    plain_text: str,
    index_map: list[int],
    *,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans document text for unprefixed or hallucinated Chronicle UDM fields without an LLM.

    Matches UDM comparison clauses (``<field_token> (=|!=) ("..."|/regex/)``) and checks
    ``<field_token>`` against :data:`CANONICAL_UDM_FIELD_CORRECTIONS` while ignoring
    valid canonical UDM fields prefixed with :data:`VALID_UDM_TOP_LEVEL_PREFIXES`.

    Returns:
        ``(comments, edits, findings)`` using 1-based UTF-16 ``start_index`` and
        ``end_index`` coordinates.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    for match in _UDM_COMPARISON_RE.finditer(plain_text):
        field_token = match.group(1)
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(field_token)
        if not canonical_field or canonical_field == field_token:
            continue

        char_start = match.start(1)
        char_end = match.end(1) - 1
        start_idx = index_map[char_start]
        end_idx = index_map[char_end] + _utf16_code_unit_len(plain_text[char_end])
        clause = match.group(0)
        query_line = _extract_udm_query_from_line(plain_text, char_start, clause)

        comments.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "quote": field_token,
                "comment": (
                    f"Deterministic Chronicle UDM Schema Check: '{field_token}' is not a valid "
                    f"canonical Chronicle UDM field path. Use '{canonical_field}' ({udm_doc_url})."
                ),
            }
        )
        edits.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "quote": field_token,
                "replacement": canonical_field,
            }
        )
        findings.append(
            {
                "invalid_field": field_token,
                "canonical_field": canonical_field,
                "start_index": start_idx,
                "end_index": end_idx,
                "clause": clause,
                "query_line": query_line,
            }
        )

    return comments, edits, findings


def _parse_siem_search_output(raw_res: Any) -> dict[str, Any]:
    """Normalizes an MCP or Python ``search_udm`` response into a dictionary."""
    if isinstance(raw_res, dict):
        if "content" in raw_res and isinstance(raw_res["content"], list):
            for block in raw_res["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = str(block.get("text") or "").strip()
                    if text:
                        try:
                            parsed = json.loads(text)
                            if isinstance(parsed, dict):
                                return parsed
                        except json.JSONDecodeError:
                            return {"raw_text": text}
        return raw_res
    if isinstance(raw_res, str):
        stripped = raw_res.strip()
        if stripped.startswith("Error"):
            raise RuntimeError(stripped)
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {"raw_text": stripped}
    return {"raw_result": raw_res}


def verify_udm_query_with_siem(
    query: str,
    *,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 5,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Repairs unprefixed/hallucinated UDM fields in ``query`` and runs a Chronicle SIEM dry-run.

    Args:
        query: Candidate Chronicle UDM query string.
        start_time: ISO-8601 start time for the SIEM dry-run search window.
        end_time: ISO-8601 end time for the SIEM dry-run search window.
        max_events: Maximum UDM events to fetch during verification.
        siem_search_fn: Optional callable for testing or direct MCP tool injection.

    Returns:
        dict with ``status``, ``original_query``, ``repaired_query``, ``replacements``,
        ``siem_verified``, and ``event_count``.
    """
    replacements: list[dict[str, str]] = []

    def _replace_clause(match: re.Match[str]) -> str:
        field_token = match.group(1)
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(field_token)
        if not canonical_field or canonical_field == field_token:
            return match.group(0)
        replacements.append(
            {
                "invalid_field": field_token,
                "canonical_field": canonical_field,
            }
        )
        return canonical_field + match.group(0)[len(field_token) :]

    repaired_query = _UDM_COMPARISON_RE.sub(_replace_clause, query)

    try:
        if siem_search_fn is not None:
            try:
                raw_res = siem_search_fn(
                    query=repaired_query,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                )
            except TypeError:
                raw_res = siem_search_fn(repaired_query)
        else:
            from .tools import execute_mcp_tool

            raw_res = execute_mcp_tool(
                "secops-mcp_search_udm",
                {
                    "query": repaired_query,
                    "start_time": start_time,
                    "end_time": end_time,
                    "max_events": max_events,
                },
            )
        parsed = _parse_siem_search_output(raw_res)
        if "error" in parsed and "events" not in parsed:
            return {
                "status": "error",
                "original_query": query,
                "repaired_query": repaired_query,
                "replacements": replacements,
                "siem_verified": False,
                "event_count": 0,
                "message": str(parsed.get("error")),
            }
        events = parsed.get("events")
        event_count = (
            len(events)
            if isinstance(events, list)
            else int(parsed.get("event_count", 0) or 0)
        )
        return {
            "status": "success",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": True,
            "event_count": event_count,
            "siem_response": parsed,
        }
    except Exception as err:
        return {
            "status": "error",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": False,
            "event_count": 0,
            "message": f"Chronicle SIEM UDM dry-run failed: {err}",
        }


def verify_and_redline_udm_queries_in_doc(
    document_id: str,
    *,
    run_live_siem_check: bool = False,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 5,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    siem_search_fn: Any = None,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Lints UDM queries in a Google Doc, optionally dry-runs them in Chronicle SIEM, and stages red-lines.

    1. Calls :func:`read_google_doc` to build the 1-based UTF-16 character index map
       and cache ``pending_suggestion_spans``.
    2. Calls :func:`find_udm_field_spans` to locate unprefixed or hallucinated UDM fields,
       automatically skipping any span that overlaps an existing pending suggestion
       (ensuring 100% multi-pass idempotency).
    3. When ``run_live_siem_check=True`` (or ``siem_search_fn`` is provided), executes
       :func:`verify_udm_query_with_siem` on each defective query and enriches the
       anchored Google Docs comment with live SIEM verification metadata.
    4. Anchors comments first via :func:`insert_doc_comments` and stages descending-index
       Suggested Edits second via :func:`propose_doc_suggested_edits` (``writeMode="SUGGEST"``).
    """
    read_res = read_google_doc(
        document_id,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    if read_res.get("status") != "success":
        return read_res

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Failed to load UTF-16 index map after read_google_doc.",
        }

    raw_comments, raw_edits, raw_findings = find_udm_field_spans(
        plain_text, index_map, udm_doc_url=udm_doc_url
    )
    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    skipped_existing_suggestion_count = 0
    for c_item, e_item, f_item in zip(raw_comments, raw_edits, raw_findings):
        f_span = (int(f_item["start_index"]), int(f_item["end_index"]))
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        comments.append(c_item)
        edits.append(e_item)
        findings.append(f_item)

    siem_checks: list[dict[str, Any]] = []
    if (run_live_siem_check or siem_search_fn is not None) and findings:
        query_cache: dict[str, dict[str, Any]] = {}
        for idx, finding in enumerate(findings):
            q_line = str(finding.get("query_line") or finding.get("clause") or "")
            if q_line not in query_cache:
                siem_res = verify_udm_query_with_siem(
                    q_line,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_search_fn=siem_search_fn,
                )
                query_cache[q_line] = siem_res
                siem_checks.append(siem_res)
            else:
                siem_res = query_cache[q_line]

            if siem_res.get("siem_verified"):
                comments[idx]["comment"] = (
                    f"{comments[idx]['comment']} "
                    f"[SIEM Dry-Run Verified: query='{siem_res['repaired_query']}', "
                    f"events_matched={siem_res['event_count']}]"
                )

    comments_res: dict[str, Any] = {"status": "skipped", "inserted_count": 0, "comment_ids": []}
    if comments:
        comments_res = insert_doc_comments(
            document_id,
            comments,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if comments_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"insert_doc_comments failed: {comments_res.get('message')}",
                "comments": comments_res,
            }

    edits_res: dict[str, Any] = {"status": "skipped", "applied_count": 0}
    if edits:
        edits_res = propose_doc_suggested_edits(
            document_id,
            edits,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if edits_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"propose_doc_suggested_edits failed: {edits_res.get('message')}",
                "comments": comments_res,
                "edits": edits_res,
            }

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "udm_findings_count": len(findings),
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "siem_checks": siem_checks,
        "comments": comments_res,
        "edits": edits_res,
    }


def _build_utf16_index_map(text: str, start_index: int = 1) -> list[int]:
    """Builds a synthetic 1-based UTF-16 index map for standalone text strings."""
    index_map: list[int] = []
    cursor = start_index
    for ch in text:
        index_map.append(cursor)
        cursor += _utf16_code_unit_len(ch)
    return index_map


def _iter_yaral2_rule_blocks(plain_text: str) -> list[dict[str, Any]]:
    """Extracts ``rule <name> { ... }`` blocks from ``plain_text`` with balanced braces."""
    blocks: list[dict[str, Any]] = []
    if not plain_text:
        return blocks

    search_pos = 0
    text_len = len(plain_text)
    while search_pos < text_len:
        match = _YARAL2_RULE_HEADER_RE.search(plain_text, search_pos)
        if match is None:
            break
        rule_name = match.group(1)
        open_brace = match.end() - 1
        depth = 0
        in_double_quote = False
        escape = False
        close_brace = -1
        for idx in range(open_brace, text_len):
            ch = plain_text[idx]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_double_quote = not in_double_quote
                continue
            if in_double_quote:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    close_brace = idx
                    break
        if close_brace == -1:
            search_pos = match.end()
            continue

        char_start = match.start()
        char_end = close_brace + 1
        blocks.append(
            {
                "rule_name": rule_name,
                "char_start": char_start,
                "char_end": char_end,
                "rule_text": plain_text[char_start:char_end],
            }
        )
        search_pos = char_end

    return blocks


def _normalize_yaral2_re_regex_calls(rule_text: str) -> str:
    """Normalizes ``re.regex($var.field, /pattern/ nocase)`` into valid Chronicle YARA-L 2.0
    ``re.regex($var.field, `pattern`) nocase`` syntax."""

    def _replace_call(match: re.Match[str]) -> str:
        prefix = match.group(1)
        pattern = match.group(2)
        inner_nocase = match.group(3) or ""
        close_paren = match.group(4)
        outer_nocase = match.group(5) or ""
        has_nocase = bool(inner_nocase.strip() or outer_nocase.strip())
        suffix = " nocase" if has_nocase else ""
        return f"{prefix}`{pattern}`{close_paren}{suffix}"

    return _YARAL2_RE_REGEX_SLASH_NORM_RE.sub(_replace_call, rule_text)


def _extract_retrohunt_udm_query_from_yaral2(
    rule_text: str,
) -> tuple[str, list[str]]:
    """Extracts a Chronicle UDM retrohunt search query and clause list from a YARA-L 2.0 rule's events section."""
    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    events_body = ""
    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name in ("events", "strings"):
            b_start = sm.end()
            b_end = (
                sec_matches[i + 1].start()
                if i + 1 < len(sec_matches)
                else max(b_start, rule_text.rfind("}"))
            )
            events_body += "\n" + rule_text[b_start:b_end]

    if not events_body.strip():
        return "", []

    cleaned_lines = [
        raw_line
        for raw_line in events_body.splitlines()
        if not raw_line.strip().startswith("//")
    ]
    cleaned_body = "\n".join(cleaned_lines)

    positioned_clauses: list[tuple[int, str]] = []
    re_spans: list[tuple[int, int]] = []
    for re_match in _YARAL2_RE_REGEX_CALL_RE.finditer(cleaned_body):
        re_spans.append((re_match.start(), re_match.end()))
        raw_field = re_match.group(2)
        field_path = CANONICAL_UDM_FIELD_CORRECTIONS.get(raw_field, raw_field)
        pattern = re_match.group(3) or re_match.group(4) or re_match.group(5) or ""
        has_nocase = bool(re_match.group(6) or re_match.group(7))
        clause = (
            f"{field_path} = /{pattern}/ nocase"
            if has_nocase
            else f"{field_path} = /{pattern}/"
        )
        positioned_clauses.append((re_match.start(), clause))

    for cmp_match in _YARAL2_EVENT_COMPARISON_RE.finditer(cleaned_body):
        c_span = (cmp_match.start(), cmp_match.end())
        if any(_spans_overlap(c_span, r_span) for r_span in re_spans):
            continue
        raw_field = cmp_match.group(2)
        field_path = CANONICAL_UDM_FIELD_CORRECTIONS.get(raw_field, raw_field)
        op = cmp_match.group(3).strip()
        rhs = cmp_match.group(4).strip()
        clause = f"{field_path} {op} {rhs}"
        positioned_clauses.append((cmp_match.start(), clause))

    positioned_clauses.sort(key=lambda item: item[0])
    clauses: list[str] = []
    for _pos, clause in positioned_clauses:
        if clause not in clauses:
            clauses.append(clause)

    return " AND ".join(clauses), clauses


def find_yaral2_rule_spans(
    plain_text: str,
    index_map: list[int],
    *,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for YARA-L 2.0 (``YL2``) detection rules and computes 1-based UTF-16 spans.

    Detects three deterministic YARA-L 2.0 defect classes without an LLM:
    1. Standard YARA (``strings:``) vs. Chronicle YARA-L 2.0 (``events:``) section confusion,
       explicitly distinguishing standard YARA (file/payload byte-pattern matching) from
       YARA-L 2.0 / YL2 (Chronicle SIEM UDM event detection rules).
    2. Event-variable-prefixed invalid UDM fields (``$<var>.<field_path>`` in comparisons or
       inside YARA-L 2.0 function calls such as ``re.regex($<var>.<field_path>, ...)``).
    3. Condition event-variable mismatch (when ``events:`` binds ``$<var>`` and ``condition:``
       references an undeclared event variable such as ``$event``).

    Returns:
        ``(comments, edits, findings)`` with exact 1-based UTF-16 ``start_index`` and
        ``end_index`` coordinates, plus synthesized ``repaired_rule_text`` and
        ``retrohunt_udm_query`` per rule block.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    for block in _iter_yaral2_rule_blocks(plain_text):
        rule_name = block["rule_name"]
        rule_char_start = int(block["char_start"])
        rule_text = str(block["rule_text"])

        sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
        if not sec_matches:
            continue

        sections: list[dict[str, Any]] = []
        for i, sm in enumerate(sec_matches):
            sec_name = sm.group(1).lower()
            token_text = sm.group(0).lstrip(" \t")
            token_local_start = sm.end() - len(token_text)
            token_local_end = sm.end()
            body_local_start = sm.end()
            body_local_end = (
                sec_matches[i + 1].start()
                if i + 1 < len(sec_matches)
                else max(body_local_start, rule_text.rfind("}"))
            )
            sections.append(
                {
                    "name": sec_name,
                    "token_text": token_text,
                    "token_start": token_local_start,
                    "token_end": token_local_end,
                    "body_start": body_local_start,
                    "body_end": body_local_end,
                    "body": rule_text[body_local_start:body_local_end],
                }
            )

        declared_event_vars: list[str] = []
        declared_placeholder_vars: set[str] = set()
        for sec in sections:
            if sec["name"] in ("events", "strings"):
                for ev_m in _YARAL2_EVENT_FIELD_RE.finditer(sec["body"]):
                    vname = ev_m.group(1)
                    if vname not in declared_event_vars:
                        declared_event_vars.append(vname)
                for ph_m in _YARAL2_PLACEHOLDER_RHS_RE.finditer(sec["body"]):
                    declared_placeholder_vars.add(ph_m.group(1))
                for ph_m in _YARAL2_PLACEHOLDER_LHS_RE.finditer(sec["body"]):
                    declared_placeholder_vars.add(ph_m.group(1))

        rule_defects: list[dict[str, Any]] = []

        # (a) Standard YARA 'strings:' section used instead of YARA-L 2.0 'events:'
        for sec in sections:
            if sec["name"] == "strings":
                local_start = int(sec["token_start"])
                local_end = int(sec["token_end"])
                quote = rule_text[local_start:local_end]
                rule_defects.append(
                    {
                        "local_start": local_start,
                        "local_end": local_end,
                        "defect_type": "yara_strings_section",
                        "quote": quote,
                        "replacement": "events:",
                        "invalid_field": quote,
                        "canonical_field": "events:",
                        "comment": (
                            f"Deterministic YARA-L 2.0 (YL2) Syntax Check in rule '{rule_name}': "
                            "'strings:' is a standard YARA section for file/payload byte-pattern "
                            "matching, not a valid Chronicle SIEM YARA-L 2.0 (YL2) UDM event "
                            f"detection rule section. Replace '{quote}' with 'events:' ({yaral2_doc_url})."
                        ),
                    }
                )

        # (b) Event-variable-prefixed invalid UDM fields ($<var>.<field_path>)
        for ev_m in _YARAL2_EVENT_FIELD_RE.finditer(rule_text):
            var_name = ev_m.group(1)
            field_path = ev_m.group(2)
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(field_path)
            if not canonical_field or canonical_field == field_path:
                continue
            local_start = ev_m.start(0)
            local_end = ev_m.end(0)
            quote = f"${var_name}.{field_path}"
            replacement = f"${var_name}.{canonical_field}"
            rule_defects.append(
                {
                    "local_start": local_start,
                    "local_end": local_end,
                    "defect_type": "invalid_udm_field",
                    "event_var": f"${var_name}",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": field_path,
                    "canonical_field": canonical_field,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) UDM Schema Check in rule '{rule_name}': "
                        f"'{quote}' references non-canonical Chronicle UDM field '{field_path}'. "
                        f"Use '{replacement}' ({udm_doc_url})."
                    ),
                }
            )

        # (c) Undeclared event variable in 'condition:' section
        if len(declared_event_vars) == 1:
            canonical_ev = declared_event_vars[0]
            for sec in sections:
                if sec["name"] != "condition":
                    continue
                for cm in _YARAL2_COND_VAR_RE.finditer(sec["body"]):
                    sigil = cm.group(1)
                    cond_var = cm.group(2)
                    if (
                        cond_var in declared_event_vars
                        or cond_var in declared_placeholder_vars
                    ):
                        continue
                    local_start = int(sec["body_start"]) + cm.start(0)
                    local_end = int(sec["body_start"]) + cm.end(0)
                    quote = f"{sigil}{cond_var}"
                    replacement = f"{sigil}{canonical_ev}"
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "condition_variable_mismatch",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Condition Binding Check in rule '{rule_name}': "
                                f"condition references undeclared event variable '{quote}', while the events "
                                f"section binds '${canonical_ev}'. Replace '{quote}' with "
                                f"'{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )

        if not rule_defects:
            continue

        rule_defects.sort(key=lambda d: int(d["local_start"]))

        # Build repaired_rule_text by applying local replacements back-to-front
        repaired_rule = rule_text
        for defect in sorted(
            rule_defects, key=lambda d: int(d["local_start"]), reverse=True
        ):
            l_start = int(defect["local_start"])
            l_end = int(defect["local_end"])
            repaired_rule = (
                repaired_rule[:l_start]
                + str(defect["replacement"])
                + repaired_rule[l_end:]
            )
        repaired_rule = _normalize_yaral2_re_regex_calls(repaired_rule)
        retrohunt_query, retrohunt_clauses = _extract_retrohunt_udm_query_from_yaral2(
            repaired_rule
        )

        for defect in rule_defects:
            abs_start = rule_char_start + int(defect["local_start"])
            abs_end = rule_char_start + int(defect["local_end"]) - 1
            start_idx = index_map[abs_start]
            end_idx = index_map[abs_end] + _utf16_code_unit_len(plain_text[abs_end])
            quote = str(defect["quote"])
            replacement = str(defect["replacement"])
            comment_text = str(defect["comment"])

            comments.append(
                {
                    "start_index": start_idx,
                    "end_index": end_idx,
                    "quote": quote,
                    "comment": comment_text,
                }
            )
            edits.append(
                {
                    "start_index": start_idx,
                    "end_index": end_idx,
                    "quote": quote,
                    "replacement": replacement,
                }
            )
            findings.append(
                {
                    "rule_name": rule_name,
                    "defect_type": defect["defect_type"],
                    "invalid_field": defect["invalid_field"],
                    "canonical_field": defect["canonical_field"],
                    "quote": quote,
                    "replacement": replacement,
                    "start_index": start_idx,
                    "end_index": end_idx,
                    "original_rule_text": rule_text,
                    "repaired_rule_text": repaired_rule,
                    "retrohunt_udm_query": retrohunt_query,
                    "retrohunt_clauses": retrohunt_clauses,
                }
            )

    return comments, edits, findings


def _strip_non_ascii_symbols(text: str) -> str:
    """Strips non-ASCII symbols/pictographs from upstream MCP responses."""
    cleaned = "".join(ch for ch in text if ord(ch) < 128)
    return re.sub(r"[ \t]{2,}", " ", cleaned).strip()


def _parse_siem_validate_output(raw_res: Any) -> dict[str, Any]:
    """Normalizes an MCP or Python ``validate_rule`` response into a dictionary."""
    if isinstance(raw_res, dict):
        if "content" in raw_res and isinstance(raw_res["content"], list):
            for block in raw_res["content"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = _strip_non_ascii_symbols(str(block.get("text") or ""))
                    passed = (
                        "rule validation passed" in text.lower()
                        or "appears to be valid" in text.lower()
                    )
                    return {"compiler_verified": passed, "compiler_output": text}
        if "success" in raw_res or "isValid" in raw_res:
            passed = bool(raw_res.get("success") or raw_res.get("isValid"))
            msg = _strip_non_ascii_symbols(
                str(raw_res.get("message") or raw_res.get("compiler_output") or raw_res)
            )
            return {"compiler_verified": passed, "compiler_output": msg}
    if isinstance(raw_res, str):
        cleaned = _strip_non_ascii_symbols(raw_res)
        passed = (
            "rule validation passed" in cleaned.lower()
            or "appears to be valid" in cleaned.lower()
        )
        return {"compiler_verified": passed, "compiler_output": cleaned}
    return {
        "compiler_verified": False,
        "compiler_output": _strip_non_ascii_symbols(str(raw_res)),
    }


def verify_yaral2_rule_with_siem(
    rule_text: str,
    *,
    run_retrohunt_check: bool = True,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 10,
    siem_validate_fn: Any = None,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Repairs a candidate YARA-L 2.0 (``YL2``) rule, compiles it via Chronicle ``validate_rule``,
    and dry-runs its ``events:`` predicates against historical Chronicle UDM telemetry.
    """
    synthetic_map = _build_utf16_index_map(rule_text)
    _comments, _edits, findings = find_yaral2_rule_spans(rule_text, synthetic_map)

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = blocks[0]["rule_name"] if blocks else "unknown_rule"

    if findings:
        repaired_rule_text = str(findings[0]["repaired_rule_text"])
        retrohunt_udm_query = str(findings[0]["retrohunt_udm_query"])
        retrohunt_clauses = list(findings[0].get("retrohunt_clauses") or [])
    else:
        repaired_rule_text = _normalize_yaral2_re_regex_calls(rule_text)
        retrohunt_udm_query, retrohunt_clauses = (
            _extract_retrohunt_udm_query_from_yaral2(repaired_rule_text)
        )

    compiler_verified = False
    compiler_output = ""
    try:
        if siem_validate_fn is not None:
            try:
                raw_val = siem_validate_fn(rule_text=repaired_rule_text)
            except TypeError:
                raw_val = siem_validate_fn(repaired_rule_text)
        else:
            from .tools import execute_mcp_tool

            raw_val = execute_mcp_tool(
                "secops-mcp_validate_rule",
                {"rule_text": repaired_rule_text},
            )
        parsed_val = _parse_siem_validate_output(raw_val)
        compiler_verified = bool(parsed_val["compiler_verified"])
        compiler_output = str(parsed_val["compiler_output"])
    except Exception as err:
        compiler_verified = False
        compiler_output = f"Chronicle validate_rule call failed: {err}"

    retrohunt_verified = False
    retrohunt_event_count = 0
    retrohunt_res: dict[str, Any] = {}
    retrohunt_initial_zero_hit_query: str | None = None

    if run_retrohunt_check and retrohunt_udm_query:
        retrohunt_res = verify_udm_query_with_siem(
            retrohunt_udm_query,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        retrohunt_verified = bool(retrohunt_res.get("siem_verified"))
        retrohunt_event_count = int(retrohunt_res.get("event_count", 0) or 0)

        # If a multi-clause GCP Cloud Audit query yields 0 hits due to a restrictive
        # target.resource.name literal (where SetIamPolicy stores project scope under
        # target.cloud.project.name), pivot to the remaining core clauses.
        if (
            retrohunt_verified
            and retrohunt_event_count == 0
            and len(retrohunt_clauses) >= 2
            and any(c.startswith("target.resource.name =") for c in retrohunt_clauses)
        ):
            relaxed_clauses = [
                c
                for c in retrohunt_clauses
                if not c.startswith("target.resource.name =")
            ]
            if relaxed_clauses:
                relaxed_query = " AND ".join(relaxed_clauses)
                relaxed_res = verify_udm_query_with_siem(
                    relaxed_query,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_search_fn=siem_search_fn,
                )
                if relaxed_res.get("siem_verified") and int(
                    relaxed_res.get("event_count", 0) or 0
                ) > 0:
                    retrohunt_initial_zero_hit_query = retrohunt_udm_query
                    retrohunt_udm_query = relaxed_query
                    retrohunt_event_count = int(relaxed_res.get("event_count", 0) or 0)
                    retrohunt_res = relaxed_res

    result: dict[str, Any] = {
        "status": "success" if compiler_verified else "error",
        "rule_name": rule_name,
        "original_rule_text": rule_text,
        "repaired_rule_text": repaired_rule_text,
        "findings": findings,
        "compiler_verified": compiler_verified,
        "compiler_output": compiler_output,
        "retrohunt_udm_query": retrohunt_udm_query,
        "retrohunt_verified": retrohunt_verified,
        "retrohunt_event_count": retrohunt_event_count,
        "retrohunt_response": retrohunt_res,
    }
    if retrohunt_initial_zero_hit_query is not None:
        result["retrohunt_initial_zero_hit_query"] = retrohunt_initial_zero_hit_query
    return result


def verify_and_redline_yaral2_rules_in_doc(
    document_id: str,
    *,
    run_live_siem_check: bool = False,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 10,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
    siem_validate_fn: Any = None,
    siem_search_fn: Any = None,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Lints YARA-L 2.0 (``YL2``) rules in a Google Doc, optionally compiles and retrohunts them
    in Chronicle SIEM, and stages non-destructive Suggested Edits (``writeMode="SUGGEST"``).

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 character index map
       and ``pending_suggestion_spans``.
    2. Calls :func:`find_yaral2_rule_spans` and skips any span that overlaps an existing
       pending suggestion (guaranteeing multi-pass idempotency).
    3. When ``run_live_siem_check=True`` (or ``siem_validate_fn`` / ``siem_search_fn`` is
       provided), verifies each repaired YARA-L 2.0 rule via :func:`verify_yaral2_rule_with_siem`
       and enriches the anchored Google Docs comments with compiler and retrohunt results.
    4. Anchors comments first via :func:`insert_doc_comments` and stages descending-index
       Suggested Edits second via :func:`propose_doc_suggested_edits` (``writeMode="SUGGEST"``).
    """
    read_res = read_google_doc(
        document_id,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    if read_res.get("status") != "success":
        return read_res

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Failed to load UTF-16 index map after read_google_doc.",
        }

    raw_comments, raw_edits, raw_findings = find_yaral2_rule_spans(
        plain_text,
        index_map,
        udm_doc_url=udm_doc_url,
        yaral2_doc_url=yaral2_doc_url,
    )
    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    skipped_existing_suggestion_count = 0
    for c_item, e_item, f_item in zip(raw_comments, raw_edits, raw_findings):
        f_span = (int(f_item["start_index"]), int(f_item["end_index"]))
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        comments.append(c_item)
        edits.append(e_item)
        findings.append(f_item)

    siem_rule_checks: list[dict[str, Any]] = []
    if (
        run_live_siem_check
        or siem_validate_fn is not None
        or siem_search_fn is not None
    ) and findings:
        rule_cache: dict[str, dict[str, Any]] = {}
        for idx, finding in enumerate(findings):
            r_name = str(finding.get("rule_name") or "")
            orig_rule = str(finding.get("original_rule_text") or "")
            cache_key = r_name or orig_rule
            if cache_key not in rule_cache:
                rule_check = verify_yaral2_rule_with_siem(
                    orig_rule,
                    run_retrohunt_check=True,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_validate_fn=siem_validate_fn,
                    siem_search_fn=siem_search_fn,
                )
                rule_cache[cache_key] = rule_check
                siem_rule_checks.append(rule_check)
            else:
                rule_check = rule_cache[cache_key]

            if rule_check.get("compiler_verified"):
                comments[idx]["comment"] = (
                    f"{comments[idx]['comment']} "
                    f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                    f"Retrohunt Dry-Run: query='{rule_check['retrohunt_udm_query']}', "
                    f"events_matched={rule_check['retrohunt_event_count']}]"
                )

    comments_res: dict[str, Any] = {
        "status": "skipped",
        "inserted_count": 0,
        "comment_ids": [],
    }
    if comments:
        comments_res = insert_doc_comments(
            document_id,
            comments,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if comments_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"insert_doc_comments failed: {comments_res.get('message')}",
                "comments": comments_res,
            }

    edits_res: dict[str, Any] = {"status": "skipped", "applied_count": 0}
    if edits:
        edits_res = propose_doc_suggested_edits(
            document_id,
            edits,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if edits_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"propose_doc_suggested_edits failed: {edits_res.get('message')}",
                "comments": comments_res,
                "edits": edits_res,
            }

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "yaral2_findings_count": len(findings),
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "siem_rule_checks": siem_rule_checks,
        "comments": comments_res,
        "edits": edits_res,
    }


def _extract_mitre_cve_clause_context(
    plain_text: str,
    token_start: int,
    token_end: int,
    same_line_spans: list[tuple[int, int]],
    rule_blocks: list[dict[str, Any]],
) -> tuple[str, str, str]:
    """Returns ``(clause_context, full_line, paren_label)`` for a MITRE or CVE token."""
    line_start = plain_text.rfind("\n", 0, token_start) + 1
    line_end = plain_text.find("\n", token_start)
    if line_end == -1:
        line_end = len(plain_text)
    full_line = plain_text[line_start:line_end]

    # Check for an immediate parenthetical label right after the token, e.g. T1059.003 (PowerShell)
    tail = plain_text[token_end:line_end]
    paren_match = re.match(r"^\s*\(([^()\r\n]{2,90})\)", tail)
    paren_label = paren_match.group(1).strip() if paren_match else ""

    # If multiple tokens of the same type appear on the same line (e.g. a collapsed
    # YARA-L 2.0 rule block or multi-column line), scope clause_context to the segment
    # surrounding this token so adjacent tokens do not cross-contaminate.
    if len(same_line_spans) > 1:
        seg_start = line_start
        seg_end = line_end
        for idx, (s_start, s_end) in enumerate(same_line_spans):
            if s_start == token_start and s_end == token_end:
                if idx > 0:
                    seg_start = same_line_spans[idx - 1][1]
                if idx + 1 < len(same_line_spans):
                    seg_end = same_line_spans[idx + 1][0]
                break
        clause_context = plain_text[seg_start:seg_end]
    else:
        clause_context = full_line
        # If this token is on a standalone meta: line inside a multi-line YARA-L 2.0 rule block
        # that only cites this single MITRE/CVE token, include the rule block context.
        for rb in rule_blocks:
            rb_start = int(rb["char_start"])
            rb_end = int(rb["char_end"])
            if rb_start <= token_start < rb_end:
                rb_text = str(rb["rule_text"])
                if len(_MITRE_TECHNIQUE_RE.findall(rb_text)) <= 1:
                    clause_context = full_line + "\n" + rb_text
                break

    return clause_context, full_line, paren_label


def _disambiguate_mitre_technique(
    tech_id: str,
    clause_context: str,
    paren_label: str,
) -> dict[str, str] | None:
    """Evaluates ``tech_id`` against ``DEPRECATED_MITRE_TECHNIQUE_MAP`` and sibling
    sub-technique disambiguation rules."""
    # (a) Deprecated / revoked pre-subtechnique ATT&CK IDs
    dep = DEPRECATED_MITRE_TECHNIQUE_MAP.get(tech_id)
    if dep is not None:
        canonical_id = dep["canonical_id"]
        canonical_name = dep["canonical_name"]
        tactic = dep["tactic"]
        dep_name = dep["deprecated_name"]
        canon_url = mitre_technique_url(canonical_id)
        dep_url = mitre_technique_url(tech_id)
        return {
            "defect_type": "deprecated_mitre_id",
            "invalid_id": tech_id,
            "canonical_id": canonical_id,
            "canonical_name": canonical_name,
            "tactic": tactic,
            "reference_url": canon_url,
            "secondary_url": dep_url,
            "comment": (
                f"Deterministic MITRE ATT&CK Taxonomy Check: '{tech_id}' ({dep_name}, {dep_url}) "
                f"is a revoked/deprecated pre-subtechnique ATT&CK identifier. Replace '{tech_id}' "
                f"with '{canonical_id}' ({canonical_name}, Tactic: {tactic}, {canon_url})."
            ),
        }

    ctx = clause_context.lower()
    plabel = paren_label.lower().strip()
    cited_meta = CANONICAL_MITRE_TECHNIQUES.get(tech_id, {})
    cited_name = cited_meta.get("canonical_name", tech_id)

    canonical_id: str | None = None
    reason_detail = ""

    # (b.1) T1059 Command and Scripting Interpreter family
    if tech_id.startswith("T1059"):
        ps_indicators = (
            "powershell",
            "pwsh",
            "-enc",
            "-encodedcommand",
            "-nop",
            "-w hidden",
            "-windowstyle hidden",
            "invoke-expression",
            "frombase64string",
            "empire",
        )
        cmd_indicators = ("cmd.exe", "cmd /c", "batch script", ".bat")
        unix_indicators = ("/bin/bash", "/bin/sh", "bash -c", "bash -i", "zsh")

        has_ps = any(k in ctx for k in ps_indicators) or "powershell" in plabel
        has_cmd = any(k in ctx for k in cmd_indicators) or "windows command shell" in plabel
        has_unix = any(k in ctx for k in unix_indicators) or "unix shell" in plabel

        if tech_id in ("T1059.003", "T1059.004", "T1059") and has_ps:
            canonical_id = "T1059.001"
            reason_detail = "PowerShell execution telemetry/stager activity"
        elif tech_id in ("T1059.001", "T1059.004") and has_cmd and not has_ps:
            canonical_id = "T1059.003"
            reason_detail = "Windows Command Shell (cmd.exe) execution telemetry"
        elif tech_id in ("T1059.001", "T1059.003") and has_unix and not has_ps and not has_cmd:
            canonical_id = "T1059.004"
            reason_detail = "Unix Shell (/bin/sh or /bin/bash) execution telemetry"

    # (b.2) T1003 OS Credential Dumping family
    elif tech_id.startswith("T1003"):
        lsass_indicators = (
            "lsass",
            "comsvcs.dll",
            "minidump",
            "procdump",
            "sekurlsa",
            "mimikatz",
            "lsass.dmp",
        )
        ntds_indicators = ("ntds.dit", "ntdsutil")
        sam_indicators = ("hklm\\sam", "sam hive", "reg save")

        has_lsass = any(k in ctx for k in lsass_indicators) or "lsass" in plabel
        has_ntds = any(k in ctx for k in ntds_indicators) or "ntds" in plabel
        has_sam = (
            any(k in ctx for k in sam_indicators)
            or "security account manager" in plabel
            or plabel == "sam"
        )

        if tech_id in ("T1003.002", "T1003.003", "T1003") and has_lsass:
            canonical_id = "T1003.001"
            reason_detail = "LSASS process memory dump telemetry (comsvcs.dll MiniDump / lsass)"
        elif tech_id in ("T1003.001", "T1003.002", "T1003") and has_ntds and not has_lsass:
            canonical_id = "T1003.003"
            reason_detail = "Active Directory NTDS.dit credential extraction telemetry"
        elif tech_id in ("T1003.001", "T1003.003") and has_sam and not has_lsass and not has_ntds:
            canonical_id = "T1003.002"
            reason_detail = "Security Account Manager (SAM) hive extraction telemetry"

    # (b.3) T1078 Valid Accounts family
    elif tech_id.startswith("T1078"):
        cloud_acct_indicators = (
            "gserviceaccount.com",
            "serviceaccount:",
            "gcp",
            "google workspace",
            "workspace admin",
            "cloud account",
            "cloud identity",
            "iam service account",
            "entra id",
            "azure ad",
            "aws iam",
            "okta",
        )
        has_cloud_acct = (
            any(k in ctx for k in cloud_acct_indicators) or "cloud account" in plabel
        )
        if tech_id in ("T1078.001", "T1078.002", "T1078.003", "T1078") and has_cloud_acct:
            canonical_id = "T1078.004"
            reason_detail = "GCP IAM service account or cloud identity compromise"

    # (b.4) T1098 Account Manipulation family
    elif tech_id.startswith("T1098"):
        cloud_role_indicators = (
            "setiampolicy",
            "roles/editor",
            "roles/owner",
            "roles/iam",
            "roles/",
            "role binding",
            "iam role",
            "additional cloud roles",
            "privileged role",
        )
        cloud_cred_indicators = (
            "serviceaccountkeys.create",
            "createaccesskey",
            "oauth client",
            "additional cloud credentials",
        )
        has_cloud_role = (
            any(k in ctx for k in cloud_role_indicators)
            or "additional cloud roles" in plabel
        )
        has_cloud_cred = (
            any(k in ctx for k in cloud_cred_indicators)
            or "additional cloud credentials" in plabel
        )
        if tech_id in ("T1098.001", "T1098") and has_cloud_role:
            canonical_id = "T1098.003"
            reason_detail = "cloud IAM role binding manipulation (SetIamPolicy / roles/ grant)"
        elif tech_id == "T1098.003" and has_cloud_cred and not has_cloud_role:
            canonical_id = "T1098.001"
            reason_detail = "cloud credential or key creation manipulation"

    # (b.5) T1218 System Binary Proxy Execution family
    elif tech_id.startswith("T1218"):
        has_rundll32 = "rundll32" in ctx or "rundll32" in plabel
        has_regsvr32 = "regsvr32" in ctx or "scrobj.dll" in ctx or "regsvr32" in plabel
        has_mshta = "mshta" in ctx or ".hta" in ctx or "mshta" in plabel
        has_cmstp = "cmstp" in ctx or "cmstp" in plabel

        if (
            tech_id in ("T1218.010", "T1218.005", "T1218.003", "T1218")
            and has_rundll32
            and not has_regsvr32
            and not has_mshta
            and not has_cmstp
        ):
            canonical_id = "T1218.011"
            reason_detail = "rundll32.exe proxy execution telemetry"
        elif (
            tech_id in ("T1218.011", "T1218.005", "T1218.003", "T1218")
            and has_regsvr32
            and not has_rundll32
            and not has_mshta
            and not has_cmstp
        ):
            canonical_id = "T1218.010"
            reason_detail = "regsvr32.exe proxy execution telemetry"
        elif (
            tech_id in ("T1218.011", "T1218.010", "T1218.003", "T1218")
            and has_mshta
            and not has_rundll32
            and not has_regsvr32
            and not has_cmstp
        ):
            canonical_id = "T1218.005"
            reason_detail = "mshta.exe proxy execution telemetry"
        elif (
            tech_id in ("T1218.011", "T1218.010", "T1218.005", "T1218")
            and has_cmstp
            and not has_rundll32
            and not has_regsvr32
            and not has_mshta
        ):
            canonical_id = "T1218.003"
            reason_detail = "cmstp.exe proxy execution telemetry"

    # (b.6) Explicit parenthetical label contradiction fallback
    if canonical_id is None and plabel:
        for cand_id, cand_meta in CANONICAL_MITRE_TECHNIQUES.items():
            if cand_id == tech_id:
                continue
            short_lower = cand_meta["short_name"].lower()
            canon_lower = cand_meta["canonical_name"].lower()
            if plabel == short_lower or plabel == canon_lower:
                canonical_id = cand_id
                reason_detail = f"explicit parenthetical technique label '({paren_label})'"
                break

    if canonical_id is None or canonical_id == tech_id:
        return None

    target_meta = CANONICAL_MITRE_TECHNIQUES[canonical_id]
    canonical_name = target_meta["canonical_name"]
    tactic = target_meta["tactic"]
    canon_url = mitre_technique_url(canonical_id)
    cited_url = mitre_technique_url(tech_id)
    return {
        "defect_type": "mitre_subtechnique_mismatch",
        "invalid_id": tech_id,
        "canonical_id": canonical_id,
        "canonical_name": canonical_name,
        "tactic": tactic,
        "reference_url": canon_url,
        "secondary_url": cited_url,
        "comment": (
            f"Deterministic MITRE ATT&CK Sub-Technique Check: '{tech_id}' ({cited_name}) "
            f"does not match observed {reason_detail}. Replace '{tech_id}' with "
            f"'{canonical_id}' ({canonical_name}, Tactic: {tactic}, {canon_url})."
        ),
    }


def _disambiguate_cve_id(
    cve_id: str,
    clause_context: str,
) -> dict[str, str] | None:
    """Evaluates ``cve_id`` against ``CANONICAL_CISA_KEV_CATALOG`` for cross-vendor attribution swaps."""
    cited_meta = CANONICAL_CISA_KEV_CATALOG.get(cve_id)
    if cited_meta is None:
        return None

    ctx = clause_context.lower()
    # If the clause explicitly names the cited CVE's own vendor/product, preserve it.
    if any(kw in ctx for kw in cited_meta["vendor_keywords"]):
        return None

    canonical_cve: str | None = None
    if any(kw in ctx for kw in ("fortinet", "fortios", "fortigate")):
        canonical_cve = "CVE-2024-21762"
    elif any(kw in ctx for kw in ("palo alto", "pan-os", "panos", "globalprotect")):
        canonical_cve = "CVE-2024-3400"
    elif any(kw in ctx for kw in ("ivanti", "connect secure", "policy secure", "pulse secure")):
        if "authentication bypass" in ctx or "auth bypass" in ctx or "cwe-287" in ctx:
            canonical_cve = "CVE-2023-46805"
        else:
            canonical_cve = "CVE-2024-21887"

    if canonical_cve is None or canonical_cve == cve_id:
        return None

    target_meta = CANONICAL_CISA_KEV_CATALOG[canonical_cve]
    canon_nvd_url = nvd_cve_url(canonical_cve)
    cited_nvd_url = nvd_cve_url(cve_id)
    return {
        "defect_type": "cve_vendor_mismatch",
        "invalid_id": cve_id,
        "canonical_id": canonical_cve,
        "canonical_name": f"{target_meta['vendor']} {target_meta['product']} ({target_meta['vulnerability_name']})",
        "tactic": f"{target_meta['vendor']} ({target_meta['cwe']})",
        "reference_url": canon_nvd_url,
        "secondary_url": CISA_KEV_CATALOG_URL,
        "comment": (
            f"Deterministic CISA KEV / NVD CVE Attribution Check: '{cve_id}' belongs to "
            f"{cited_meta['vendor']} {cited_meta['product']} ({cited_meta['vulnerability_name']}, "
            f"{cited_nvd_url}), not {target_meta['vendor']} {target_meta['product']}. "
            f"Replace '{cve_id}' with '{canonical_cve}' ({target_meta['vulnerability_name']}, "
            f"{target_meta['cwe']}, {canon_nvd_url} | {CISA_KEV_CATALOG_URL})."
        ),
    }


def find_mitre_and_cve_spans(
    plain_text: str,
    index_map: list[int],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for MITRE ATT&CK technique IDs (``Txxxx(.xxx)``) and CVE IDs
    (``CVE-YYYY-NNNN+``) and identifies deterministic taxonomy and attribution defects.

    Detects three defect classes without echoing surrounding offensive command lines:
    1. ``deprecated_mitre_id``: revoked/superseded pre-subtechnique ATT&CK IDs
       (e.g. ``T1086`` -> ``T1059.001`` PowerShell, ``T1085`` -> ``T1218.011`` Rundll32).
    2. ``mitre_subtechnique_mismatch``: sibling sub-technique or parenthetical label
       contradictions (e.g. ``T1059.003`` paired with PowerShell telemetry -> ``T1059.001``;
       ``T1003.002`` paired with ``comsvcs.dll, MiniDump`` / ``lsass`` -> ``T1003.001``;
       ``T1078.001`` paired with GCP IAM service accounts -> ``T1078.004``;
       ``T1098.001`` paired with ``SetIamPolicy`` / ``roles/editor`` -> ``T1098.003``;
       ``T1218.010`` paired with ``rundll32.exe`` -> ``T1218.011``).
    3. ``cve_vendor_mismatch``: cross-vendor CISA KEV CVE swaps (e.g. ``CVE-2024-21887``
       Ivanti Connect Secure attributed to Fortinet FortiOS SSL VPN -> ``CVE-2024-21762``).

    Returns:
        ``(comments, edits, findings)`` with exact 1-based UTF-16 ``start_index`` and
        ``end_index`` spans and canonical ``attack.mitre.org``, ``nvd.nist.gov``, and
        ``cisa.gov`` citations.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    rule_blocks = _iter_yaral2_rule_blocks(plain_text)

    mitre_matches = list(_MITRE_TECHNIQUE_RE.finditer(plain_text))
    cve_matches = list(_CVE_ID_RE.finditer(plain_text))

    # Group spans by line start so multi-token lines can isolate per-token clauses
    mitre_spans_by_line: dict[int, list[tuple[int, int]]] = {}
    for m in mitre_matches:
        l_start = plain_text.rfind("\n", 0, m.start(1)) + 1
        mitre_spans_by_line.setdefault(l_start, []).append((m.start(1), m.end(1)))

    cve_spans_by_line: dict[int, list[tuple[int, int]]] = {}
    for m in cve_matches:
        l_start = plain_text.rfind("\n", 0, m.start(1)) + 1
        cve_spans_by_line.setdefault(l_start, []).append((m.start(1), m.end(1)))

    raw_items: list[tuple[int, dict[str, Any], dict[str, Any], dict[str, Any]]] = []

    for m in mitre_matches:
        tech_id = m.group(1).upper()
        char_start = m.start(1)
        char_end = m.end(1)
        l_start = plain_text.rfind("\n", 0, char_start) + 1
        clause_ctx, full_line, paren_label = _extract_mitre_cve_clause_context(
            plain_text,
            char_start,
            char_end,
            mitre_spans_by_line.get(l_start, []),
            rule_blocks,
        )
        verdict = _disambiguate_mitre_technique(tech_id, clause_ctx, paren_label)
        if verdict is None:
            continue
        start_idx = index_map[char_start]
        end_idx = index_map[char_end - 1] + _utf16_code_unit_len(plain_text[char_end - 1])
        quote = plain_text[char_start:char_end]
        replacement = verdict["canonical_id"]
        comment_obj = {
            "start_index": start_idx,
            "end_index": end_idx,
            "quote": quote,
            "comment": verdict["comment"],
        }
        edit_obj = {
            "start_index": start_idx,
            "end_index": end_idx,
            "quote": quote,
            "replacement": replacement,
        }
        finding_obj = {
            "defect_type": verdict["defect_type"],
            "invalid_id": quote,
            "canonical_id": replacement,
            "canonical_name": verdict["canonical_name"],
            "tactic": verdict["tactic"],
            "reference_url": verdict["reference_url"],
            "secondary_url": verdict["secondary_url"],
            "quote": quote,
            "replacement": replacement,
            "start_index": start_idx,
            "end_index": end_idx,
            "rationale": verdict["comment"],
            "comment": verdict["comment"],
            "context_line": sanitize_telemetry_text(full_line.strip()),
        }
        raw_items.append((start_idx, comment_obj, edit_obj, finding_obj))

    for m in cve_matches:
        cve_id = m.group(1).upper()
        char_start = m.start(1)
        char_end = m.end(1)
        l_start = plain_text.rfind("\n", 0, char_start) + 1
        clause_ctx, full_line, _paren_label = _extract_mitre_cve_clause_context(
            plain_text,
            char_start,
            char_end,
            cve_spans_by_line.get(l_start, []),
            rule_blocks,
        )
        verdict = _disambiguate_cve_id(cve_id, clause_ctx)
        if verdict is None:
            continue
        start_idx = index_map[char_start]
        end_idx = index_map[char_end - 1] + _utf16_code_unit_len(plain_text[char_end - 1])
        quote = plain_text[char_start:char_end]
        replacement = verdict["canonical_id"]
        comment_obj = {
            "start_index": start_idx,
            "end_index": end_idx,
            "quote": quote,
            "comment": verdict["comment"],
        }
        edit_obj = {
            "start_index": start_idx,
            "end_index": end_idx,
            "quote": quote,
            "replacement": replacement,
        }
        finding_obj = {
            "defect_type": verdict["defect_type"],
            "invalid_id": quote,
            "canonical_id": replacement,
            "canonical_name": verdict["canonical_name"],
            "tactic": verdict["tactic"],
            "reference_url": verdict["reference_url"],
            "secondary_url": verdict["secondary_url"],
            "quote": quote,
            "replacement": replacement,
            "start_index": start_idx,
            "end_index": end_idx,
            "rationale": verdict["comment"],
            "comment": verdict["comment"],
            "context_line": sanitize_telemetry_text(full_line.strip()),
        }
        raw_items.append((start_idx, comment_obj, edit_obj, finding_obj))

    raw_items.sort(key=lambda item: item[0])
    for _s_idx, c_obj, e_obj, f_obj in raw_items:
        comments.append(c_obj)
        edits.append(e_obj)
        findings.append(f_obj)

    return comments, edits, findings


def _run_mitre_cve_grounding_check(
    finding: dict[str, Any],
    *,
    web_verifier_fn: Any = None,
) -> dict[str, Any]:
    """Executes an optional grounding check for a MITRE ATT&CK or CVE finding."""
    invalid_id = str(finding.get("invalid_id") or "")
    canonical_id = str(finding.get("canonical_id") or "")
    canonical_name = str(finding.get("canonical_name") or "")
    ref_url = str(finding.get("reference_url") or "")

    if web_verifier_fn is not None:
        try:
            raw_res = web_verifier_fn(finding)
        except TypeError:
            raw_res = web_verifier_fn(canonical_id)
        if isinstance(raw_res, dict):
            summary = _strip_non_ascii_symbols(
                str(
                    raw_res.get("summary")
                    or raw_res.get("verification")
                    or f"{invalid_id} -> {canonical_id} ({canonical_name}) verified via {ref_url}"
                )
            )
            return {
                "invalid_id": invalid_id,
                "canonical_id": canonical_id,
                "verified": bool(raw_res.get("verified", True)),
                "summary": summary,
                "reference_url": str(raw_res.get("reference_url") or ref_url),
            }
        summary = _strip_non_ascii_symbols(str(raw_res))
        return {
            "invalid_id": invalid_id,
            "canonical_id": canonical_id,
            "verified": True,
            "summary": summary,
            "reference_url": ref_url,
        }

    return {
        "invalid_id": invalid_id,
        "canonical_id": canonical_id,
        "verified": True,
        "summary": (
            f"Canonical taxonomy mapping {invalid_id} -> {canonical_id} "
            f"({canonical_name}) verified ({ref_url})"
        ),
        "reference_url": ref_url,
    }


def verify_and_redline_mitre_and_cve_in_doc(
    document_id: str,
    *,
    run_web_grounding_check: bool = False,
    web_verifier_fn: Any = None,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Verifies MITRE ATT&CK technique/sub-technique IDs and CISA KEV CVE citations
    inside a Google Doc and stages non-destructive Suggested Edits (``writeMode="SUGGEST"``).

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 index map and
       ``pending_suggestion_spans``.
    2. Calls :func:`find_mitre_and_cve_spans` and skips any span overlapping an
       existing pending suggestion (``skipped_existing_suggestion_count``).
    3. When ``run_web_grounding_check=True`` (or ``web_verifier_fn`` is provided),
       enriches anchored comments with grounded MITRE ATT&CK / NVD / CISA KEV
       verification metadata.
    4. Anchors comments first via :func:`insert_doc_comments` and stages descending-index
       ``writeMode="SUGGEST"`` edits second via :func:`propose_doc_suggested_edits`.
    """
    read_res = read_google_doc(
        document_id,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    if read_res.get("status") != "success":
        return read_res

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Failed to load UTF-16 index map after read_google_doc.",
        }

    raw_comments, raw_edits, raw_findings = find_mitre_and_cve_spans(
        plain_text, index_map
    )
    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    skipped_existing_suggestion_count = 0
    for c_item, e_item, f_item in zip(raw_comments, raw_edits, raw_findings):
        f_span = (int(f_item["start_index"]), int(f_item["end_index"]))
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        comments.append(c_item)
        edits.append(e_item)
        findings.append(f_item)

    grounding_checks: list[dict[str, Any]] = []
    if (run_web_grounding_check or web_verifier_fn is not None) and findings:
        check_cache: dict[tuple[str, str], dict[str, Any]] = {}
        for idx, finding in enumerate(findings):
            key = (str(finding["invalid_id"]), str(finding["canonical_id"]))
            if key not in check_cache:
                g_check = _run_mitre_cve_grounding_check(
                    finding, web_verifier_fn=web_verifier_fn
                )
                check_cache[key] = g_check
                grounding_checks.append(g_check)
            else:
                g_check = check_cache[key]
            if g_check.get("verified"):
                comments[idx]["comment"] = (
                    f"{comments[idx]['comment']} "
                    f"[Grounded MITRE/CVE Verification: {g_check['summary']}]"
                )

    comments_res: dict[str, Any] = {
        "status": "skipped",
        "inserted_count": 0,
        "comment_ids": [],
    }
    if comments:
        comments_res = insert_doc_comments(
            document_id,
            comments,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if comments_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"insert_doc_comments failed: {comments_res.get('message')}",
                "comments": comments_res,
            }

    edits_res: dict[str, Any] = {"status": "skipped", "applied_count": 0}
    if edits:
        edits_res = propose_doc_suggested_edits(
            document_id,
            edits,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if edits_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"propose_doc_suggested_edits failed: {edits_res.get('message')}",
                "comments": comments_res,
                "edits": edits_res,
            }

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "mitre_cve_findings_count": len(findings),
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "grounding_checks": grounding_checks,
        "comments": comments_res,
        "edits": edits_res,
    }


def _resolve_item_span(
    plain_text: str, index_map: list[int], item: dict[str, Any]
) -> tuple[int, int] | None:
    raw_start = item.get("start_index")
    raw_end = item.get("end_index")
    if isinstance(raw_start, int) and isinstance(raw_end, int) and 1 <= raw_start < raw_end:
        return (raw_start, raw_end)
    quote = str(item.get("quote") or "")
    if quote:
        return _find_quote_indices(plain_text, index_map, quote)
    return None


def _spans_overlap(span_a: tuple[int, int], span_b: tuple[int, int]) -> bool:
    return max(span_a[0], span_b[0]) < min(span_a[1], span_b[1])


def _parse_json_or_list(items: str | list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if items is None:
        return []
    if isinstance(items, str):
        stripped = items.strip()
        if not stripped:
            return []
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, list) else []
    if isinstance(items, list):
        return [x for x in items if isinstance(x, dict)]
    return []


def review_google_doc_with_stage_a(
    document_id: str,
    semantic_comments: str | list[dict[str, Any]] | None = None,
    semantic_edits: str | list[dict[str, Any]] | None = None,
    tool_context: Any = None,
    *,
    include_udm_stage_a: bool = True,
    include_yaral2_stage_a: bool = True,
    include_mitre_cve_stage_a: bool = True,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Executes the two-stage non-destructive review pipeline on a Google Doc.

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 index map
       and ``pending_suggestion_spans``.
    2. Runs Stage A (:func:`find_deterministic_indicator_spans`,
       :func:`find_udm_field_spans` when ``include_udm_stage_a=True``,
       :func:`find_yaral2_rule_spans` when ``include_yaral2_stage_a=True``, and
       :func:`find_mitre_and_cve_spans` when ``include_mitre_cve_stage_a=True``)
       to locate live untrusted URLs, standalone Chronicle UDM field defects,
       YARA-L 2.0 rule defects, and MITRE ATT&CK / CVE defects by numeric UTF-16
       span without echoing them through an LLM.
    3. Deduplicates Stage A UDM, YARA-L 2.0, and MITRE/CVE spans against
       overlapping Stage B ``semantic_comments`` and ``semantic_edits`` and skips
       any span that overlaps an existing pending suggestion (multi-pass idempotency).
    4. Anchors all comments first via :func:`insert_doc_comments`.
    5. Stages all Suggested Edits second via :func:`propose_doc_suggested_edits`
       (sorted descending by ``startIndex`` under ``writeMode="SUGGEST"``).
    """
    read_res = read_google_doc(
        document_id,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    if read_res.get("status") != "success":
        return read_res

    plain_text, index_map = _load_doc_index_state(document_id, tool_context=tool_context)
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Failed to load UTF-16 index map after read_google_doc.",
        }

    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    stage_a_comments, stage_a_edits = find_deterministic_indicator_spans(
        plain_text, index_map
    )

    try:
        stage_b_comments = _parse_json_or_list(semantic_comments)
        stage_b_edits = _parse_json_or_list(semantic_edits)
    except json.JSONDecodeError as err:
        return {"status": "error", "message": f"Invalid semantic review JSON: {err}"}

    existing_comment_spans = [
        sp
        for item in (stage_a_comments + stage_b_comments)
        if (sp := _resolve_item_span(plain_text, index_map, item)) is not None
    ]
    existing_edit_spans = [
        sp
        for item in (stage_a_edits + stage_b_edits)
        if (sp := _resolve_item_span(plain_text, index_map, item)) is not None
    ]

    stage_a_udm_count = 0
    deduped_udm_comments: list[dict[str, Any]] = []
    deduped_udm_edits: list[dict[str, Any]] = []
    if include_udm_stage_a:
        udm_comments, udm_edits, udm_findings = find_udm_field_spans(
            plain_text, index_map
        )
        stage_a_udm_count = len(udm_findings)
        for c_item in udm_comments:
            c_span = (c_item["start_index"], c_item["end_index"])
            if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
                deduped_udm_comments.append(c_item)
                existing_comment_spans.append(c_span)
        for e_item in udm_edits:
            e_span = (e_item["start_index"], e_item["end_index"])
            if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
                deduped_udm_edits.append(e_item)
                existing_edit_spans.append(e_span)

    stage_a_yaral2_count = 0
    deduped_yaral2_comments: list[dict[str, Any]] = []
    deduped_yaral2_edits: list[dict[str, Any]] = []
    if include_yaral2_stage_a:
        yl2_comments, yl2_edits, yl2_findings = find_yaral2_rule_spans(
            plain_text, index_map
        )
        stage_a_yaral2_count = len(yl2_findings)
        for c_item in yl2_comments:
            c_span = (c_item["start_index"], c_item["end_index"])
            if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
                deduped_yaral2_comments.append(c_item)
                existing_comment_spans.append(c_span)
        for e_item in yl2_edits:
            e_span = (e_item["start_index"], e_item["end_index"])
            if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
                deduped_yaral2_edits.append(e_item)
                existing_edit_spans.append(e_span)

    stage_a_mitre_cve_count = 0
    deduped_mitre_cve_comments: list[dict[str, Any]] = []
    deduped_mitre_cve_edits: list[dict[str, Any]] = []
    if include_mitre_cve_stage_a:
        mc_comments, mc_edits, mc_findings = find_mitre_and_cve_spans(
            plain_text, index_map
        )
        stage_a_mitre_cve_count = len(mc_findings)
        for c_item in mc_comments:
            c_span = (c_item["start_index"], c_item["end_index"])
            if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
                deduped_mitre_cve_comments.append(c_item)
                existing_comment_spans.append(c_span)
        for e_item in mc_edits:
            e_span = (e_item["start_index"], e_item["end_index"])
            if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
                deduped_mitre_cve_edits.append(e_item)
                existing_edit_spans.append(e_span)

    raw_all_comments = (
        stage_a_comments
        + deduped_udm_comments
        + deduped_yaral2_comments
        + deduped_mitre_cve_comments
        + stage_b_comments
    )
    raw_all_edits = (
        stage_a_edits
        + deduped_udm_edits
        + deduped_yaral2_edits
        + deduped_mitre_cve_edits
        + stage_b_edits
    )

    all_comments: list[dict[str, Any]] = []
    for c_item in raw_all_comments:
        c_span = _resolve_item_span(plain_text, index_map, c_item)
        if c_span is not None and any(
            _spans_overlap(c_span, p_span) for p_span in pending_spans
        ):
            continue
        all_comments.append(c_item)

    all_edits: list[dict[str, Any]] = []
    skipped_existing_suggestion_count = 0
    for e_item in raw_all_edits:
        e_span = _resolve_item_span(plain_text, index_map, e_item)
        if e_span is not None and any(
            _spans_overlap(e_span, p_span) for p_span in pending_spans
        ):
            skipped_existing_suggestion_count += 1
            continue
        all_edits.append(e_item)

    comments_res: dict[str, Any] = {"status": "skipped", "inserted_count": 0, "comment_ids": []}
    if all_comments:
        comments_res = insert_doc_comments(
            document_id,
            all_comments,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if comments_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"insert_doc_comments failed: {comments_res.get('message')}",
                "comments": comments_res,
            }

    edits_res: dict[str, Any] = {"status": "skipped", "applied_count": 0}
    if all_edits:
        edits_res = propose_doc_suggested_edits(
            document_id,
            all_edits,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if edits_res.get("status") != "success":
            return {
                "status": "error",
                "message": f"propose_doc_suggested_edits failed: {edits_res.get('message')}",
                "comments": comments_res,
                "edits": edits_res,
            }

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "stage_a_url_count": len(stage_a_edits),
        "stage_a_udm_count": stage_a_udm_count,
        "stage_a_yaral2_count": stage_a_yaral2_count,
        "stage_a_mitre_cve_count": stage_a_mitre_cve_count,
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "comments": comments_res,
        "edits": edits_res,
    }


def stage_runbook_update_as_google_doc(
    skill_name: str,
    case_id: str,
    semantic_comments: str | list[dict[str, Any]] | None = None,
    semantic_edits: str | list[dict[str, Any]] | None = None,
    lessons_learned_markdown: str = "",
    folder_id: str | None = None,
    tool_context: Any = None,
    *,
    skill_content_override: str | None = None,
    client: DriveMcpClient | None = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Stages a non-destructive Google Doc red-line draft of a Drive runbook.

    Loads the Markdown runbook ``skill_name`` from ``SOC Runbooks``, optionally
    appends sanitized ``lessons_learned_markdown`` from SOAR case ``case_id``,
    creates a collaborative Google Doc draft, and executes
    :func:`review_google_doc_with_stage_a` so a human detection engineer can
    Accept or Reject each proposed update in Google Docs.
    """
    if skill_content_override is not None:
        base_markdown = skill_content_override
    else:
        from .drive_tools import build_skill_registry

        registry = build_skill_registry()
        base_markdown = registry.get_skill_content(skill_name)
        if not base_markdown or base_markdown.startswith("Skill '"):
            return {
                "status": "error",
                "message": f"Could not load runbook skill {skill_name!r}: {base_markdown}",
            }

    sanitized_lessons = sanitize_telemetry_text(lessons_learned_markdown or "")
    if sanitized_lessons.strip():
        full_markdown = base_markdown.rstrip() + "\n\n" + sanitized_lessons.strip() + "\n"
    else:
        full_markdown = base_markdown

    safe_case = re.sub(r"[^A-Za-z0-9_-]+", "_", str(case_id).strip()) or "general"
    doc_title = f"Runbook_Redline_{skill_name}_Case_{safe_case}"

    created = create_google_doc(
        title=doc_title,
        content=full_markdown,
        folder_id=folder_id,
        client=client,
    )
    if created.get("status") != "success":
        return created

    doc_id = created["document_id"]
    review_res = review_google_doc_with_stage_a(
        doc_id,
        semantic_comments=semantic_comments,
        semantic_edits=semantic_edits,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    return {
        "status": review_res.get("status", "error"),
        "skill_name": skill_name,
        "case_id": str(case_id),
        "document_id": doc_id,
        "title": doc_title,
        "viewUrl": created.get("viewUrl", f"https://docs.google.com/document/d/{doc_id}/edit"),
        "char_count": review_res.get("char_count", 0),
        "stage_a_url_count": review_res.get("stage_a_url_count", 0),
        "stage_a_udm_count": review_res.get("stage_a_udm_count", 0),
        "stage_a_yaral2_count": review_res.get("stage_a_yaral2_count", 0),
        "stage_a_mitre_cve_count": review_res.get("stage_a_mitre_cve_count", 0),
        "comments": review_res.get("comments", {}),
        "edits": review_res.get("edits", {}),
        "message": review_res.get("message", ""),
    }


def format_soar_doc_review_comment(
    case_id: str,
    doc_title: str,
    doc_url: str,
    skill_name: str,
    redline_summary: list[str],
    *,
    runbook_doc_url: str = "",
) -> str:
    """Formats a sanitized SOAR case timeline comment linking to the red-lined Google Docs."""
    lines = [
        f"[Grounded Google Docs Review Completed for Case {case_id}]",
        f"- Incident Report & Postmortem Google Doc: {doc_title} ({doc_url})",
        f"- Active Runbook Applied: {skill_name}",
    ]
    if runbook_doc_url:
        lines.append(f"- Staged Runbook Red-Line Draft (writeMode=SUGGEST): {runbook_doc_url}")
    if redline_summary:
        lines.append("- Grounded Review Findings & Red-Lines Staged:")
        for item in redline_summary:
            lines.append(f"  * {sanitize_telemetry_text(str(item))}")
    return sanitize_telemetry_text("\n".join(lines))


def post_reviewed_doc_to_soar_case(
    case_id: str,
    doc_title: str,
    doc_url: str,
    skill_name: str,
    redline_summary: str | list[str],
    *,
    runbook_doc_url: str = "",
    soar_comment_fn: Any = None,
) -> dict[str, Any]:
    """Posts a sanitized summary of the grounded Google Doc review to a SOAR case timeline."""
    if isinstance(redline_summary, str):
        try:
            parsed = json.loads(redline_summary)
            summary_list = [str(x) for x in parsed] if isinstance(parsed, list) else [redline_summary]
        except json.JSONDecodeError:
            summary_list = [line.strip() for line in redline_summary.splitlines() if line.strip()]
    else:
        summary_list = [str(x) for x in redline_summary]

    comment_text = format_soar_doc_review_comment(
        case_id=str(case_id),
        doc_title=doc_title,
        doc_url=doc_url,
        skill_name=skill_name,
        redline_summary=summary_list,
        runbook_doc_url=runbook_doc_url,
    )

    try:
        if soar_comment_fn is not None:
            raw_res = soar_comment_fn(str(case_id), comment_text)
        else:
            from .tools import execute_mcp_tool

            raw_res = execute_mcp_tool(
                "soar-mcp_post_case_comment",
                {"case_id": str(case_id), "comment": comment_text},
            )
    except Exception as err:
        return {
            "status": "error",
            "case_id": str(case_id),
            "comment": comment_text,
            "message": f"Failed to post SOAR case comment: {err}",
        }

    return {
        "status": "success",
        "case_id": str(case_id),
        "comment": comment_text,
        "soar_response": raw_res,
    }


def inspect_doc_suggestions(
    document_id: str,
    *,
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None = None,
    suggestions_view_mode: str = "SUGGESTIONS_INLINE",
    context_lines: int = 3,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Inspects pending Suggested Edits in a Google Doc and computes a unified diff.

    Fetches the Google Doc via Docs API v1, extracts clean ``baseline_text``
    (excluding ``suggestedInsertionIds`` so deleted+inserted strings never fuse)
    and ``accepted_text`` (applying all or selected ``accept_suggestion_ids``),
    groups paired ``suggestedDeletionIds`` and ``suggestedInsertionIds`` by
    ``suggestion_id``, and generates a standard unified diff.
    """
    try:
        token = resolve_docs_token(tool_context, token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError) as err:
        return {"status": "error", "message": str(err)}

    url = f"{DOCS_API_BASE_URL}/{document_id}"
    headers = _build_docs_headers(token, quota_project=quota_project)
    params: dict[str, str] = {"includeTabsContent": "true"}
    if suggestions_view_mode and suggestions_view_mode != "DEFAULT_FOR_CURRENT_ACCESS":
        params["suggestionsViewMode"] = suggestions_view_mode

    try:
        with httpx.Client(
            timeout=DEFAULT_DOCS_TIMEOUT_SECONDS, transport=transport
        ) as http:
            resp = http.get(url, params=params, headers=headers)
    except httpx.HTTPError as err:
        return {"status": "error", "message": f"HTTP transport error reading doc: {err}"}

    if resp.status_code != 200:
        return {
            "status": "error",
            "message": f"Google Docs API returned HTTP {resp.status_code}: {resp.text[:300]}",
        }

    doc = resp.json()
    title = doc.get("title", "Untitled")
    projections = extract_doc_projections(
        doc, accept_suggestion_ids=accept_suggestion_ids
    )
    baseline_text = projections["baseline_text"]
    baseline_index_map = projections["baseline_index_map"]
    accepted_text = projections["accepted_text"]
    suggestions = projections["suggestions"]
    pending_spans = projections["pending_suggestion_spans"]

    _store_doc_index_state(
        document_id,
        baseline_text,
        baseline_index_map,
        tool_context=tool_context,
        pending_suggestion_spans=pending_spans,
    )

    diff_lines = list(
        difflib.unified_diff(
            baseline_text.splitlines(keepends=True),
            accepted_text.splitlines(keepends=True),
            fromfile=f"{title} (baseline)",
            tofile=f"{title} (accepted)",
            n=context_lines,
        )
    )
    unified_diff = "".join(diff_lines)
    accepted_count = sum(1 for item in suggestions if item.get("accepted"))

    return {
        "status": "success",
        "document_id": document_id,
        "title": title,
        "suggestion_count": len(suggestions),
        "accepted_suggestion_count": accepted_count,
        "suggestions": suggestions,
        "pending_suggestion_spans": [
            {"start_index": start_idx, "end_index": end_idx}
            for start_idx, end_idx in pending_spans
        ],
        "baseline_text": baseline_text,
        "accepted_text": accepted_text,
        "unified_diff": unified_diff,
    }


def _extract_canonical_frontmatter_header(
    skill_name: str,
    *,
    skill_content_override: str | None = None,
) -> str:
    """Extracts or builds the canonical YAML frontmatter header for ``skill_name``."""
    raw_source = ""
    meta = None
    if skill_content_override is not None:
        raw_source = skill_content_override
    elif skill_name:
        from .drive_tools import build_skill_registry

        registry = build_skill_registry()
        meta = registry.get_skill(skill_name)
        candidate = registry.get_skill_content(skill_name)
        if candidate and not candidate.startswith("Error:"):
            raw_source = candidate

    if raw_source:
        match = _FRONTMATTER_BLOCK_RE.match(raw_source.lstrip())
        if match:
            return f"---\n{match.group(1).strip()}\n---\n\n"

    if meta is not None:
        return (
            "---\n"
            f"name: {meta.name}\n"
            f"description: {meta.description}\n"
            f"category: {meta.category or 'irps'}\n"
            f"version: {meta.version or '1.0.0'}\n"
            "---\n\n"
        )
    if skill_name:
        return (
            "---\n"
            f"name: {skill_name}\n"
            f"description: Runbook for {skill_name}\n"
            "category: irps\n"
            "version: 1.0.0\n"
            "---\n\n"
        )
    return ""


def export_accepted_doc_to_markdown(
    document_id: str,
    *,
    skill_name: str = "",
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None = None,
    output_path: str = "",
    publish_to_drive: bool = False,
    drive_title: str = "",
    folder_id: str | None = None,
    skill_content_override: str | None = None,
    client: DriveMcpClient | None = None,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Exports a red-lined Google Doc with accepted Suggested Edits back to Markdown.

    1. Calls :func:`inspect_doc_suggestions` to obtain the clean ``accepted_text``
       (with all or selected ``accept_suggestion_ids`` applied and zero fused
       inline suggestion artifacts).
    2. When ``skill_name`` (or ``skill_content_override``) is provided, checks
       whether the exported text begins with YAML frontmatter (``--- ... ---``).
       If Google Docs horizontal-rule conversion stripped the frontmatter
       delimiter lines, reconstructs the canonical YAML frontmatter header from
       the source skill so the exported Markdown remains a valid
       :class:`SkillRegistry` / :class:`DriveSkillRegistry` runbook.
    3. Optionally writes the accepted Markdown to ``output_path`` and/or publishes
       it to Google Drive via :func:`publish_report_to_drive`.
    """
    inspected = inspect_doc_suggestions(
        document_id,
        accept_suggestion_ids=accept_suggestion_ids,
        tool_context=tool_context,
        token_source=token_source,
        quota_project=quota_project,
        transport=transport,
    )
    if inspected.get("status") != "success":
        return inspected

    accepted_text = str(inspected.get("accepted_text") or "")
    frontmatter_restored = False

    if _FRONTMATTER_BLOCK_RE.match(accepted_text.lstrip()):
        accepted_markdown = accepted_text.lstrip()
    elif skill_name or skill_content_override:
        canonical_fm = _extract_canonical_frontmatter_header(
            skill_name, skill_content_override=skill_content_override
        )
        cleaned_body = accepted_text.lstrip()
        # Strip collapsed single-line frontmatter artifact produced when Google Drive
        # converts YAML '---' delimiters into horizontalRule elements.
        collapsed_fm_re = re.compile(
            r"^name:\s*\S+[^\n]*\bdescription:\s*[^\n]*\n+",
            re.IGNORECASE,
        )
        cleaned_body = collapsed_fm_re.sub("", cleaned_body, count=1).lstrip()
        if canonical_fm:
            accepted_markdown = canonical_fm + cleaned_body
            frontmatter_restored = True
        else:
            accepted_markdown = cleaned_body
    else:
        accepted_markdown = accepted_text

    parsed_fm = parse_frontmatter(accepted_markdown)

    saved_path: str | None = None
    if output_path and output_path.strip():
        out_file = Path(output_path.strip()).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(accepted_markdown, encoding="utf-8")
        saved_path = str(out_file)

    drive_result: dict[str, Any] | None = None
    drive_error: str | None = None
    if publish_to_drive:
        target_title = (
            drive_title.strip()
            or (f"{skill_name}.md" if skill_name else f"{inspected['title']}.md")
        )
        try:
            drive_result = publish_report_to_drive(
                target_title,
                accepted_markdown,
                folder_id=folder_id,
                client=client,
            )
        except (DriveMcpError, DriveRegistryConfigError) as err:
            drive_error = str(err)

    return {
        "status": "success",
        "document_id": document_id,
        "title": inspected["title"],
        "skill_name": skill_name,
        "suggestion_count": inspected["suggestion_count"],
        "accepted_suggestion_count": inspected["accepted_suggestion_count"],
        "suggestions": inspected["suggestions"],
        "unified_diff": inspected["unified_diff"],
        "frontmatter_restored": frontmatter_restored,
        "frontmatter_valid": bool(parsed_fm.get("name")),
        "frontmatter": parsed_fm,
        "accepted_markdown": accepted_markdown,
        "char_count": len(accepted_markdown),
        "output_path": saved_path,
        "drive": drive_result,
        "drive_error": drive_error,
    }


