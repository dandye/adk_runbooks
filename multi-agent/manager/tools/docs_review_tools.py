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

import base64
import difflib
import hashlib
import ipaddress
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
DRIVE_FILES_API_BASE_URL = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DOC_MIME_TYPE = "application/vnd.google-apps.document"
MARKDOWN_MIME_TYPE = "text/markdown"
DEFAULT_DOCS_TIMEOUT_SECONDS = 30.0

DEFAULT_GCP_SA_DISABLE_DOC_URL = (
    "https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable"
)
DEFAULT_GCP_SA_KEYS_DELETE_DOC_URL = (
    "https://docs.cloud.google.com/iam/docs/keys-create-delete"
)
DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL = (
    "https://support.google.com/a/answer/33312"
)
DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
)

DEFAULT_TRUSTED_DOC_DOMAINS: tuple[str, ...] = (
    "docs.cloud.google.com",
    "cloud.google.com",
    "console.cloud.google.com",
    "support.google.com",
    "docs.aws.amazon.com",
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
    "T1543": {
        "canonical_name": "Create or Modify System Process",
        "short_name": "Create or Modify System Process",
        "tactic": "Persistence / Privilege Escalation",
    },
    "T1543.003": {
        "canonical_name": "Create or Modify System Process: Windows Service",
        "short_name": "Windows Service",
        "tactic": "Persistence / Privilege Escalation",
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
    "command_line": "target.process.command_line",
    "cmd_line": "target.process.command_line",
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
    r"(\"[^\r\n\"]*\"|'[^\r\n']*'|“[^\r\n”]*”|/[^\r\n/]+/(?:[ \t]+(?i:nocase))?)"
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
    r"(re\.regex\(\s*\$[A-Za-z_][A-Za-z0-9_.]*\s*,\s*)(?:/([^/\r\n]+)/|`([^`\r\n]+)`)(\s*nocase)?(\s*\))(\s*nocase)?",
    re.IGNORECASE,
)
_YARAL2_RE_REGEX_CALL_RE = re.compile(
    r"re\.regex\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*"
    r"(?:/([^/\r\n]+)/|`([^`\r\n]+)`|\"([^\r\n\"]+)\")(?:[ \t]+(nocase))?\s*\)(?:[ \t]+(nocase))?",
    re.IGNORECASE,
)
_YARAL2_EVENT_COMPARISON_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)"
    r"(\s*(?:!=|=)\s*)"
    r"(\"[^\r\n\"]*\"|'[^\r\n']*'|“[^\r\n”]*”|/[^\r\n/]+/(?:[ \t]+nocase)?|`[^`\r\n]*`(?:[ \t]+nocase)?)"
)
_YARAL2_JOIN_RHS_BINDING_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)"
    r"(\s*(?:!=|=)\s*)"
    r"\$([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_.])"
)
_YARAL2_JOIN_LHS_BINDING_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_.])"
    r"(\s*(?:!=|=)\s*)"
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)(?![A-Za-z0-9_.])"
)
_YARAL2_MATCH_CLAUSE_RE = re.compile(
    r"(\$(?:[A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*\$[A-Za-z_][A-Za-z0-9_]*)*)"
    r"(?:[ \t]+((?:(over|within|for|by)[ \t]+)?(\d+)[ \t]*([A-Za-z]+)))?",
    re.IGNORECASE,
)
_YARAL2_TIME_UNIT_MAP: dict[str, str] = {
    "s": "s",
    "sec": "s",
    "secs": "s",
    "second": "s",
    "seconds": "s",
    "m": "m",
    "min": "m",
    "mins": "m",
    "minute": "m",
    "minutes": "m",
    "h": "h",
    "hr": "h",
    "hrs": "h",
    "hour": "h",
    "hours": "h",
    "d": "d",
    "day": "d",
    "days": "d",
}
VALID_YARAL2_OUTCOME_AGG_FUNCS: tuple[str, ...] = (
    "max",
    "min",
    "sum",
    "count",
    "count_distinct",
    "array",
    "array_distinct",
)
CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS: dict[str, str] = {
    "distinct_count": "count_distinct",
    "count_unique": "count_distinct",
    "dc": "count_distinct",
    "collect_set": "array_distinct",
    "values": "array_distinct",
    "array_agg": "array",
    "collect_list": "array",
    "avg": "max",
    "average": "max",
}
_YARAL2_OUTCOME_LHS_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)(?!\.)\s*=\s*"
)
_YARAL2_OUTCOME_FUNC_CALL_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$",
    re.DOTALL,
)
_YARAL2_COND_NOT_VAR_RE = re.compile(
    r"(?i)\b(not)[ \t]+([#$])([A-Za-z_][A-Za-z0-9_]*)(?!\.)"
)
_YARAL2_CIDR_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_.])(net\.ip_in_range_cidr|ip_in_range_cidr|cidrmatch|cidr_match|ipv4_is_in_range|in_cidr)\s*\(\s*"
    r"(?:"
    r"\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*(\"[^\r\n\"]+\"|'[^\r\n']+'|“[^\r\n”]+”)"
    r"|"
    r"(\"[^\r\n\"]+\"|'[^\r\n']+'|“[^\r\n”]+”)\s*,\s*\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)"
    r")\s*\)",
    re.IGNORECASE,
)
_UDM_CIDR_CLAUSE_RE = re.compile(
    r"(?<![A-Za-z0-9_.$-])net\.ip_in_range_cidr\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*,\s*(\"[^\r\n\"]+\"|'[^\r\n']+'|“[^\r\n”]+”)\s*\)",
    re.IGNORECASE,
)
_YARAL2_CASE_WHEN_RE = re.compile(
    r"^case\s+when\s+(.*?)\s+then\s+(.*?)\s+else\s+(.*?)\s+end$",
    re.IGNORECASE | re.DOTALL,
)
_YARAL2_IF_CALL_RE = re.compile(
    r"^(if|iff|iif)\s*\((.*)\)$",
    re.IGNORECASE | re.DOTALL,
)
_YARAL2_COND_OUTCOME_CMP_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z0-9_]*)(?!\.)"
    r"([ \t]*(>=|<=|!=|==|=|>|<)[ \t]*)"
    r"(-?\d+)(?![A-Za-z0-9_.])"
)

_FRONTMATTER_BLOCK_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

_cache_lock = threading.Lock()
_DOC_INDEX_CACHE: dict[str, tuple[str, list[int]]] = {}
_DOC_SUGGESTION_CACHE: dict[str, list[tuple[int, int]]] = {}
_DOC_RAW_AST_CACHE: dict[str, dict[str, Any]] = {}


def clear_doc_index_cache() -> None:
    """Clears the in-process fallback index cache (used by tests)."""
    with _cache_lock:
        _DOC_INDEX_CACHE.clear()
        _DOC_SUGGESTION_CACHE.clear()
        _DOC_RAW_AST_CACHE.clear()


def _short_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


_EXISTING_REDACTED_TOKEN_RE = re.compile(r"<REDACTED_[A-Z0-9_]+:[^>]+>")

_PATH_LIKE_SEGMENTS: frozenset[str] = frozenset(
    {
        "projects",
        "organizations",
        "folders",
        "billingaccounts",
        "locations",
        "zones",
        "regions",
        "instances",
        "clusters",
        "datasets",
        "tables",
        "buckets",
        "objects",
        "topics",
        "subscriptions",
        "secrets",
        "keyrings",
        "cryptokeys",
        "serviceaccounts",
        "users",
        "repos",
        "apis",
        "services",
        "v1",
        "v1alpha",
        "v1beta",
        "bin",
        "usr",
        "etc",
        "var",
        "opt",
        "home",
        "tmp",
        "dev",
        "proc",
        "sys",
        "lib",
        "local",
        "google",
        "cloud",
        "chronicle",
        "security",
    }
)

TELEMETRY_HAZARD_PATTERNS: tuple[dict[str, Any], ...] = (
    {
        "name": "private_key_block",
        "hazard_class": "leaked_credential",
        "token_label": "REDACTED_PRIVATE_KEY",
        "include_len": False,
        "mitre_technique": "T1552.004",
        "target_group": 0,
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
        "description": "PEM/OpenSSH private key block",
    },
    {
        "name": "dotnet_from_base64_string",
        "hazard_class": "encoded_stager",
        "token_label": "REDACTED_B64",
        "include_len": True,
        "mitre_technique": "T1059.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)(\bFromBase64String\s*\(\s*['\"])([A-Za-z0-9+/=\s]{8,}?)(['\"]\s*\))"
        ),
        "description": ".NET FromBase64String encoded stager payload",
    },
    {
        "name": "powershell_encoded_command",
        "hazard_class": "encoded_stager",
        "token_label": "REDACTED_B64",
        "include_len": True,
        "mitre_technique": "T1059.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)(?:(?<=^)|(?<=[\s\"'`(;]))(-(?:e|en|enc|encodedcommand)[ \t]+)(?!/)([A-Za-z0-9+/=]{8,})(?![A-Za-z0-9+/=._/-])"
        ),
        "description": "PowerShell -EncodedCommand / -Enc Base64 stager payload",
    },
    {
        "name": "powershell_webclient_cradle",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_CRADLE",
        "include_len": False,
        "mitre_technique": "T1059.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)(\(?New-Object[ \t]+(?:System\.)?Net\.WebClient\)?\.Download(?:String|File|Data)\s*\()([^()\r\n]+)(\))"
        ),
        "description": "PowerShell Net.WebClient download cradle arguments",
    },
    {
        "name": "powershell_iwr_iex_cradle",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_CRADLE",
        "include_len": False,
        "mitre_technique": "T1059.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)[ \t]+([^\r\n|;]+?\|[ \t]*(?:Invoke-Expression|iex)\b)"
        ),
        "description": "PowerShell Invoke-WebRequest / Invoke-RestMethod piped to Invoke-Expression cradle",
    },
    {
        "name": "lolbin_certutil_urlcache",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_LOLBIN_ARGS",
        "include_len": False,
        "mitre_technique": "T1105",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(certutil(?:\.exe)?[ \t]+(?:[-/][a-z]+[ \t]+)*[-/]urlcache(?:[ \t]+[-/](?:split|f))*)[ \t]+([^\r\n\"'`]+)"
        ),
        "description": "certutil.exe -urlcache LOLBin ingress transfer arguments",
    },
    {
        "name": "lolbin_bitsadmin_transfer",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_LOLBIN_ARGS",
        "include_len": False,
        "mitre_technique": "T1197",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(bitsadmin(?:\.exe)?[ \t]+/transfer)[ \t]+([^\r\n\"'`]+)"
        ),
        "description": "bitsadmin.exe /transfer LOLBin download cradle arguments",
    },
    {
        "name": "lolbin_mshta_script",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_LOLBIN_ARGS",
        "include_len": False,
        "mitre_technique": "T1218.005",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(mshta(?:\.exe)?[ \t]+(?:vbscript:|javascript:))([^\r\n`]+)"
        ),
        "description": "mshta.exe inline script execution payload",
    },
    {
        "name": "lolbin_regsvr32_scrobj",
        "hazard_class": "lolbin_download_cradle",
        "token_label": "REDACTED_LOLBIN_ARGS",
        "include_len": False,
        "mitre_technique": "T1218.010",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(regsvr32(?:\.exe)?[ \t]+(?:[/\-][snu][ \t]+)*[/\-]i:)([^\r\n\"'`]+)"
        ),
        "description": "regsvr32.exe Squiblydoo COM scriptlet arguments",
    },
    {
        "name": "cred_dump_minidump",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)(\bMiniDump)[ \t]+((?:\d+\b|[A-Za-z]:\\|\\\\)[^\r\n\"'`]*)"
        ),
        "description": "comsvcs.dll MiniDump LSASS memory dump arguments",
    },
    {
        "name": "cred_dump_procdump_lsass",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(procdump(?:64)?(?:\.exe)?[ \t]+(?:[-/][a-z]+[ \t]+)*[-/]ma)[ \t]+([^\r\n\"'`]+)"
        ),
        "description": "Sysinternals procdump -ma process memory dump arguments",
    },
    {
        "name": "cred_dump_ntdsutil_ifm",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.003",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(ntdsutil(?:\.exe)?)[ \t]+([^\r\n`]*?\bifm\b[^\r\n`]*)"
        ),
        "description": "ntdsutil Install From Media (IFM) Active Directory NTDS.dit extraction arguments",
    },
    {
        "name": "cred_dump_reg_save_hive",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.002",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(reg(?:\.exe)?[ \t]+save[ \t]+HKLM\\(?:SAM|SYSTEM|SECURITY))[ \t]+([^\r\n\"'`]+)"
        ),
        "description": "reg.exe save offline SAM/SYSTEM/SECURITY registry hive extraction arguments",
    },
    {
        "name": "cred_dump_mimikatz_sekurlsa",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.001",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(sekurlsa::)(logonpasswords(?:[ \t]+[^\r\n\"'`]+)?)"
        ),
        "description": "Mimikatz sekurlsa::logonpasswords LSASS credential extraction invocation",
    },
    {
        "name": "cred_dump_mimikatz_dcsync",
        "hazard_class": "credential_dump_args",
        "token_label": "REDACTED_DUMP_ARGS",
        "include_len": False,
        "mitre_technique": "T1003.006",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(lsadump::dcsync)[ \t]+([^\r\n\"'`]+)"
        ),
        "description": "Mimikatz lsadump::dcsync Active Directory replication arguments",
    },
    {
        "name": "revshell_dev_tcp",
        "hazard_class": "reverse_shell_stager",
        "token_label": "REDACTED_REVERSE_SHELL",
        "include_len": False,
        "mitre_technique": "T1059.004",
        "target_group": 1,
        "pattern": re.compile(
            r"(/dev/(?:tcp|udp)/[^\s\"'`>&|;]+(?:[ \t]+0>&1)?)"
        ),
        "description": "Linux /dev/tcp or /dev/udp reverse shell socket redirection",
    },
    {
        "name": "revshell_netcat_exec",
        "hazard_class": "reverse_shell_stager",
        "token_label": "REDACTED_REVERSE_SHELL",
        "include_len": False,
        "mitre_technique": "T1059.004",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(nc|ncat|netcat)[ \t]+((?:[^\r\n\"'`|;]*?[ \t]+)?-(?:e|c)[ \t]+/bin/(?:ba)?sh\b[^\r\n\"'`|;]*)"
        ),
        "description": "Netcat -e /bin/sh reverse shell execution arguments",
    },
    {
        "name": "revshell_curl_wget_pipe_sh",
        "hazard_class": "reverse_shell_stager",
        "token_label": "REDACTED_REVERSE_SHELL",
        "include_len": False,
        "mitre_technique": "T1059.004",
        "target_group": 2,
        "pattern": re.compile(
            r"(?i)\b(curl|wget)[ \t]+([^\r\n|;]+?\|[ \t]*(?:sudo[ \t]+)?(?:/bin/)?(?:ba)?sh\b)"
        ),
        "description": "curl/wget pipe-to-shell remote stager execution",
    },
    {
        "name": "gcp_oauth_token",
        "hazard_class": "leaked_credential",
        "token_label": "REDACTED_GCP_TOKEN",
        "include_len": False,
        "mitre_technique": "T1528",
        "target_group": 1,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9._-])(ya29\.[A-Za-z0-9._-]{16,})(?![A-Za-z0-9._-])"
        ),
        "description": "Google Cloud OAuth 2.0 ya29.* bearer access token",
    },
    {
        "name": "jwt_bearer_token",
        "hazard_class": "leaked_credential",
        "token_label": "REDACTED_JWT",
        "include_len": False,
        "mitre_technique": "T1528",
        "target_group": 1,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"
        ),
        "description": "JSON Web Token (JWT) bearer token",
    },
    {
        "name": "aws_access_key_id",
        "hazard_class": "leaked_credential",
        "token_label": "REDACTED_AWS_KEY",
        "include_len": False,
        "mitre_technique": "T1552.001",
        "target_group": 1,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9_-])((?:AKIA|ASIA)[0-9A-Z]{16})(?![A-Za-z0-9_-])"
        ),
        "description": "AWS IAM Access Key ID (AKIA*/ASIA*)",
    },
    {
        "name": "standalone_base64_stager",
        "hazard_class": "encoded_stager",
        "token_label": "REDACTED_B64",
        "include_len": True,
        "mitre_technique": "T1027",
        "target_group": 1,
        "pattern": re.compile(
            r"(?<![A-Za-z0-9+/=._:-])([A-Za-z0-9+/]{64,}={0,2})(?![A-Za-z0-9+/=._:-])"
        ),
        "description": "Standalone 64+ character Base64 stager blob",
    },
)


def _is_false_positive_standalone_b64(blob: str) -> bool:
    """Returns True when a 64+ char Base64 candidate is actually a hex hash or resource path."""
    if re.fullmatch(r"[0-9a-fA-F]+", blob):
        return True
    if blob.startswith("/"):
        return True
    if "/" in blob:
        segments = [seg.lower() for seg in blob.split("/") if seg]
        if any(seg in _PATH_LIKE_SEGMENTS for seg in segments):
            return True
    return False


def _iter_telemetry_hazard_matches(text: str) -> list[dict[str, Any]]:
    """Scans ``text`` against :data:`TELEMETRY_HAZARD_PATTERNS` and returns non-overlapping
    hazard match records sorted ascending by ``char_start``."""
    if not text:
        return []

    claimed_spans: list[tuple[int, int]] = [
        (m.start(0), m.end(0))
        for m in _EXISTING_REDACTED_TOKEN_RE.finditer(text)
    ]
    matches: list[dict[str, Any]] = []

    for rule in TELEMETRY_HAZARD_PATTERNS:
        pattern: re.Pattern[str] = rule["pattern"]
        target_group: int = int(rule["target_group"])
        rule_name: str = str(rule["name"])
        token_label: str = str(rule["token_label"])
        include_len: bool = bool(rule["include_len"])

        for m in pattern.finditer(text):
            full_start, full_end = m.start(0), m.end(0)
            target_start, target_end = m.start(target_group), m.end(target_group)

            while target_end > target_start and text[target_end - 1] in (" ", "\t", "\r"):
                target_end -= 1
            if rule_name == "gcp_oauth_token":
                while target_end > target_start and text[target_end - 1] == ".":
                    target_end -= 1

            if target_end <= target_start:
                continue

            raw_target = text[target_start:target_end]
            if "<REDACTED_" in raw_target or "<REDACTED_" in m.group(0):
                continue

            if rule_name == "standalone_base64_stager" and _is_false_positive_standalone_b64(
                raw_target
            ):
                continue

            if any(
                max(target_start, c_start) < min(target_end, c_end)
                or max(full_start, c_start) < min(full_end, c_end)
                for c_start, c_end in claimed_spans
            ):
                continue

            norm_payload = (
                raw_target.strip()
                if rule_name != "private_key_block"
                else raw_target
            )
            sha_prefix = _short_sha256(norm_payload)
            if include_len:
                replacement = (
                    f"<{token_label}:len={len(norm_payload)},sha256={sha_prefix}>"
                )
            else:
                replacement = f"<{token_label}:sha256={sha_prefix}>"

            mitre_id = str(rule["mitre_technique"])
            ref_url = mitre_technique_url(mitre_id)
            hazard_class = str(rule["hazard_class"])
            desc = str(rule["description"])
            comment_text = (
                f"Deterministic Telemetry & Credential Safety Check ({hazard_class} / "
                f"{rule_name}): Unredacted {desc} detected in shared document. "
                f"Redact sensitive payload/secret to `{replacement}` (preserving "
                f"SHA-256 prefix `{sha_prefix}` for forensic correlation; "
                f"MITRE ATT&CK {mitre_id}: {ref_url})."
            )

            claimed_spans.append((target_start, target_end))
            matches.append(
                {
                    "name": rule_name,
                    "pattern_name": rule_name,
                    "category": hazard_class,
                    "hazard_class": hazard_class,
                    "token_type": token_label,
                    "token_label": token_label,
                    "mitre_technique": mitre_id,
                    "reference_url": ref_url,
                    "description": desc,
                    "char_start": target_start,
                    "char_end": target_end,
                    "raw_target": raw_target,
                    "payload_length": len(norm_payload),
                    "sha256_prefix": sha_prefix,
                    "replacement": replacement,
                    "comment": comment_text,
                }
            )

    matches.sort(key=lambda item: int(item["char_start"]))
    return matches


def sanitize_telemetry_text(text: str) -> str:
    """Redacts adversarial command-line payloads, LOLBin cradles, credential-dump
    arguments, reverse shells, and leaked cloud/API tokens at the tool boundary.

    Replaces verbatim weaponized payloads and live secrets across 22 deterministic
    pattern families (:data:`TELEMETRY_HAZARD_PATTERNS`) with forensic correlation
    tokens (length + 12-char SHA-256 prefix) while preserving 100% of MD5, SHA-1,
    SHA-256, UUID, Windows SID, Chronicle UDM, MITRE ATT&CK, CVE, and GCP resource
    identifiers.
    """
    if not text:
        return text

    matches = _iter_telemetry_hazard_matches(text)
    if not matches:
        return text

    parts: list[str] = []
    cursor = 0
    for item in matches:
        t_start = int(item["char_start"])
        t_end = int(item["char_end"])
        parts.append(text[cursor:t_start])
        parts.append(str(item["replacement"]))
        cursor = t_end
    parts.append(text[cursor:])
    return "".join(parts)


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
    raw_doc: dict[str, Any] | None = None,
) -> None:
    spans = list(pending_suggestion_spans or [])
    with _cache_lock:
        _DOC_INDEX_CACHE[document_id] = (plain_text, index_map)
        _DOC_SUGGESTION_CACHE[document_id] = spans
        if isinstance(raw_doc, dict):
            _DOC_RAW_AST_CACHE[document_id] = raw_doc
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict):
            state["doc_plain_text"] = plain_text
            state["doc_index_map"] = index_map
            state["doc_pending_suggestion_spans"] = spans
            state["doc_id"] = document_id
            if isinstance(raw_doc, dict):
                state["doc_raw_ast"] = raw_doc


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


def _load_doc_raw_ast(
    document_id: str,
    tool_context: Any = None,
) -> dict[str, Any] | None:
    if tool_context is not None:
        state = getattr(tool_context, "state", None)
        if isinstance(state, dict) and state.get("doc_id") == document_id:
            raw_doc = state.get("doc_raw_ast")
            if isinstance(raw_doc, dict):
                return raw_doc
    with _cache_lock:
        return _DOC_RAW_AST_CACHE.get(document_id)


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
    and the raw Google Docs AST for multi-pass review idempotency and italic
    regex wildcard recovery.

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
        raw_doc=doc,
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


_CLOUD_IMDS_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata",
    }
)


def _is_trusted_domain(url: str, trusted_domains: tuple[str, ...]) -> bool:
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    if not host or host in _CLOUD_IMDS_HOSTS:
        return False
    return any(host == dom or host.endswith("." + dom) for dom in trusted_domains)


def find_deterministic_indicator_spans(
    plain_text: str,
    index_map: list[int],
    *,
    trusted_domains: tuple[str, ...] = DEFAULT_TRUSTED_DOC_DOMAINS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans document text for live untrusted URLs (including Cloud IMDS SSRF endpoints) without an LLM.

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
        try:
            host = (urlparse(raw_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host in _CLOUD_IMDS_HOSTS:
            comment_text = (
                "Deterministic Indicator Safety Check (Cloud IMDS SSRF Hazard): "
                f"Live Cloud Instance Metadata Service URL ({host}) auto-linkifies "
                "in Google Docs and poses an SSRF / token-theft replay hazard. "
                "Defang indicator scheme and hostname before distributing the report."
            )
        else:
            comment_text = (
                "Deterministic Indicator Safety Check: Live external URL auto-linkifies "
                "in Google Docs and creates a click hazard for incident responders. "
                "Defang indicator scheme and hostname before distributing the report."
            )
        comments.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "comment": comment_text,
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


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Returns True if ``ip_str`` is a valid IP address inside ``cidr_str``."""
    try:
        clean_ip = str(ip_str or "").strip().strip("\"'“”")
        clean_cidr = str(cidr_str or "").strip().strip("\"'“”")
        if not clean_ip or not clean_cidr:
            return False
        return ipaddress.ip_address(clean_ip) in ipaddress.ip_network(
            clean_cidr, strict=False
        )
    except ValueError:
        return False


def _filter_udm_events_by_cidr_clauses(
    events: list[dict[str, Any]], cidr_filters: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    """Filters a list of Chronicle UDM event dicts by ``(canonical_field, cidr_str)`` pairs."""
    if not cidr_filters:
        return events
    matched: list[dict[str, Any]] = []
    for ev in events:
        fmap = _extract_udm_event_field_values(ev)
        ok = True
        for c_field, cidr_val in cidr_filters:
            obs_ips = fmap.get(c_field, [])
            if not any(_ip_in_cidr(ip_v, cidr_val) for ip_v in obs_ips):
                ok = False
                break
        if ok:
            matched.append(ev)
    return matched


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

    def _replace_cidr_clause(match: re.Match[str]) -> str:
        field_token = match.group(1)
        cidr_lit = match.group(2)
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
            field_token, field_token
        )
        if canonical_field != field_token:
            replacements.append(
                {
                    "invalid_field": field_token,
                    "canonical_field": canonical_field,
                }
            )
        clean_cidr = cidr_lit.strip("\"'“”")
        return f'net.ip_in_range_cidr({canonical_field}, "{clean_cidr}")'

    repaired_query = _UDM_COMPARISON_RE.sub(_replace_clause, query)
    repaired_query = _UDM_CIDR_CLAUSE_RE.sub(_replace_cidr_clause, repaired_query)

    def _exec_search(q_str: str, limit: int) -> dict[str, Any]:
        if siem_search_fn is not None:
            try:
                raw_r = siem_search_fn(
                    query=q_str,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=limit,
                )
            except TypeError:
                raw_r = siem_search_fn(q_str)
        else:
            from .tools import (
                execute_mcp_tool,
                global_mcp_registry,
                init_shared_mcp_tools,
            )

            if not getattr(global_mcp_registry, "_server_map", None):
                init_shared_mcp_tools()

            raw_r = execute_mcp_tool(
                "secops-mcp_search_udm",
                {
                    "query": q_str,
                    "start_time": start_time,
                    "end_time": end_time,
                    "max_events": limit,
                },
            )
        return _parse_siem_search_output(raw_r)

    try:
        cidr_filters: list[tuple[str, str]] = [
            (
                CANONICAL_UDM_FIELD_CORRECTIONS.get(m.group(1), m.group(1)),
                m.group(2).strip("\"'“”"),
            )
            for m in _UDM_CIDR_CLAUSE_RE.finditer(repaired_query)
        ]
        parsed: dict[str, Any] | None = None
        try:
            parsed = _exec_search(repaired_query, max_events)
        except Exception:
            if not cidr_filters:
                raise
            parsed = None

        if cidr_filters and (
            parsed is None
            or ("error" in parsed and "events" not in parsed)
        ):
            stripped_q = _UDM_CIDR_CLAUSE_RE.sub("", repaired_query)
            stripped_q = re.sub(
                r"(?i)^\s*(?:AND|OR)\s+|\s+(?:AND|OR)\s*$", "", stripped_q
            )
            stripped_q = re.sub(
                r"(?i)\b(?:AND|OR)\s+(?:AND|OR)\b", "AND", stripped_q
            ).strip()
            if not stripped_q:
                first_f = cidr_filters[0][0]
                stripped_q = f'{first_f} != ""'
            fallback_parsed = _exec_search(stripped_q, max(max_events, 20))
            if "error" not in fallback_parsed or "events" in fallback_parsed:
                fb_events = fallback_parsed.get("events")
                if isinstance(fb_events, list):
                    filtered_events = _filter_udm_events_by_cidr_clauses(
                        fb_events, cidr_filters
                    )
                    parsed = dict(fallback_parsed)
                    parsed["events"] = filtered_events[:max_events]
                    parsed["total_events"] = len(filtered_events)
                else:
                    parsed = fallback_parsed

        if parsed is None:
            return {
                "status": "error",
                "original_query": query,
                "repaired_query": repaired_query,
                "replacements": replacements,
                "siem_verified": False,
                "event_count": 0,
                "message": "Chronicle SIEM UDM dry-run returned no response.",
            }
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


_CAMEL_BOUNDARY_1_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_BOUNDARY_2_RE = re.compile(r"([a-z0-9])([A-Z])")
_UDM_SNAKE_KEY_OVERRIDES: dict[str, str] = {
    "user_id": "userid",
}
_UDM_ENTITY_ROLE_PREFIXES: tuple[str, ...] = (
    "principal.",
    "target.",
    "src.",
    "about.",
    "security_result.about.",
    "observer.",
    "intermediary.",
)
_UDM_QUERY_CONNECTOR_RE = re.compile(r"^[\s()]*\b(?:AND|OR)\b[\s()]*$", re.IGNORECASE)


def _camel_to_snake(name: str) -> str:
    """Converts a camelCase Chronicle UDM wire key (e.g. ``commandLine``) to canonical snake_case."""
    if not name:
        return ""
    step1 = _CAMEL_BOUNDARY_1_RE.sub(r"\1_\2", str(name))
    step2 = _CAMEL_BOUNDARY_2_RE.sub(r"\1_\2", step1).lower()
    return _UDM_SNAKE_KEY_OVERRIDES.get(step2, step2)


def _extract_udm_event_field_values(udm_event: dict[str, Any]) -> dict[str, list[str]]:
    """Recursively flattens a Chronicle SIEM UDM event dictionary into canonical snake_case UDM field paths.

    Unwraps ``udm_event["udm"]`` when present, normalizes camelCase wire keys (such as
    ``commandLine``, ``emailAddresses``, ``productEventType``, ``resourceType``, and
    ``fullPath``) into canonical snake_case UDM paths (such as ``target.process.command_line``,
    ``principal.user.email_addresses``, ``metadata.product_event_type``, and
    ``target.resource.name``), and sanitizes all scalar values via :func:`sanitize_telemetry_text`.
    """
    field_values: dict[str, list[str]] = {}
    if not isinstance(udm_event, dict):
        return field_values

    root = udm_event.get("udm") if isinstance(udm_event.get("udm"), dict) else udm_event

    def _walk(node: Any, prefix: str) -> None:
        if isinstance(node, dict):
            for raw_key, raw_val in node.items():
                snake_key = _camel_to_snake(str(raw_key))
                if not snake_key:
                    continue
                next_prefix = f"{prefix}.{snake_key}" if prefix else snake_key
                _walk(raw_val, next_prefix)
        elif isinstance(node, list):
            for item in node:
                _walk(item, prefix)
        elif node is not None and not isinstance(node, bool) and prefix:
            raw_str = str(node).strip()
            if not raw_str:
                return
            sanitized_str = sanitize_telemetry_text(raw_str)
            bucket = field_values.setdefault(prefix, [])
            if sanitized_str not in bucket:
                bucket.append(sanitized_str)

    _walk(root, "")
    return field_values


def _is_candidate_udm_field_token(field_token: str) -> bool:
    """Returns True if ``field_token`` is a known UDM shorthand or has a valid UDM top-level prefix."""
    if not field_token:
        return False
    if field_token in CANONICAL_UDM_FIELD_CORRECTIONS:
        return True
    if "." in field_token:
        top_prefix = field_token.split(".", 1)[0]
        if top_prefix in VALID_UDM_TOP_LEVEL_PREFIXES:
            return True
    return False


def extract_udm_query_clauses_from_text(
    plain_text: str,
    index_map: list[int],
) -> list[dict[str, Any]]:
    """Extracts standalone UDM queries and per-clause 1-based UTF-16 spans from ``plain_text``.

    Excludes YARA-L 2.0 ``rule <name> { ... }`` blocks and groups consecutive UDM comparison
    clauses separated by boolean ``AND`` / ``OR`` connectors into query records. Each clause
    record includes 1-based UTF-16 spans for the full clause (``clause_start_index``,
    ``clause_end_index``), the field token (``field_start_index``, ``field_end_index``), and
    the RHS literal or regex (``rhs_start_index``, ``rhs_end_index``).
    """
    if not plain_text or not index_map:
        return []

    rule_blocks = _iter_yaral2_rule_blocks(plain_text)
    excluded_spans = [(int(b["char_start"]), int(b["char_end"])) for b in rule_blocks]

    raw_clauses: list[dict[str, Any]] = []
    cidr_spans: list[tuple[int, int]] = []
    for cidr_m in _UDM_CIDR_CLAUSE_RE.finditer(plain_text):
        c_start, c_end = cidr_m.start(0), cidr_m.end(0)
        if any(max(c_start, r_start) < min(c_end, r_end) for r_start, r_end in excluded_spans):
            continue
        field_token = cidr_m.group(1)
        if not _is_candidate_udm_field_token(field_token):
            continue
        cidr_spans.append((c_start, c_end))
        f_char_start, f_char_end = cidr_m.start(1), cidr_m.end(1) - 1
        rhs_char_start, rhs_char_end = cidr_m.start(2), cidr_m.end(2) - 1
        clause_char_end = c_end - 1
        raw_clauses.append(
            {
                "clause_text": cidr_m.group(0),
                "field_token": field_token,
                "canonical_field": CANONICAL_UDM_FIELD_CORRECTIONS.get(
                    field_token, field_token
                ),
                "operator_raw": "net.ip_in_range_cidr",
                "operator": "net.ip_in_range_cidr",
                "rhs_raw": cidr_m.group(2),
                "is_cidr_clause": True,
                "char_start": c_start,
                "char_end": c_end,
                "clause_start_index": index_map[c_start],
                "clause_end_index": index_map[clause_char_end]
                + _utf16_code_unit_len(plain_text[clause_char_end]),
                "field_start_index": index_map[f_char_start],
                "field_end_index": index_map[f_char_end]
                + _utf16_code_unit_len(plain_text[f_char_end]),
                "rhs_start_index": index_map[rhs_char_start],
                "rhs_end_index": index_map[rhs_char_end]
                + _utf16_code_unit_len(plain_text[rhs_char_end]),
            }
        )

    for match in _UDM_COMPARISON_RE.finditer(plain_text):
        c_start, c_end = match.start(0), match.end(0)
        if any(max(c_start, r_start) < min(c_end, r_end) for r_start, r_end in excluded_spans):
            continue
        if any(max(c_start, cs) < min(c_end, ce) for cs, ce in cidr_spans):
            continue
        field_token = match.group(1)
        if not _is_candidate_udm_field_token(field_token):
            continue

        f_char_start, f_char_end = match.start(1), match.end(1) - 1
        rhs_char_start, rhs_char_end = match.start(3), match.end(3) - 1
        clause_char_end = c_end - 1

        raw_clauses.append(
            {
                "clause_text": match.group(0),
                "field_token": field_token,
                "canonical_field": CANONICAL_UDM_FIELD_CORRECTIONS.get(
                    field_token, field_token
                ),
                "operator_raw": match.group(2),
                "operator": match.group(2).strip(),
                "rhs_raw": match.group(3),
                "is_cidr_clause": False,
                "char_start": c_start,
                "char_end": c_end,
                "clause_start_index": index_map[c_start],
                "clause_end_index": index_map[clause_char_end]
                + _utf16_code_unit_len(plain_text[clause_char_end]),
                "field_start_index": index_map[f_char_start],
                "field_end_index": index_map[f_char_end]
                + _utf16_code_unit_len(plain_text[f_char_end]),
                "rhs_start_index": index_map[rhs_char_start],
                "rhs_end_index": index_map[rhs_char_end]
                + _utf16_code_unit_len(plain_text[rhs_char_end]),
            }
        )

    if not raw_clauses:
        return []

    raw_clauses.sort(key=lambda c: int(c["char_start"]))
    grouped_queries: list[list[dict[str, Any]]] = [[raw_clauses[0]]]
    for clause in raw_clauses[1:]:
        prev_clause = grouped_queries[-1][-1]
        between = plain_text[prev_clause["char_end"] : clause["char_start"]]
        if _UDM_QUERY_CONNECTOR_RE.match(between):
            grouped_queries[-1].append(clause)
        else:
            grouped_queries.append([clause])

    results: list[dict[str, Any]] = []
    for group in grouped_queries:
        q_char_start = group[0]["char_start"]
        q_char_end = group[-1]["char_end"]
        results.append(
            {
                "query_text": plain_text[q_char_start:q_char_end],
                "char_start": q_char_start,
                "char_end": q_char_end,
                "start_index": group[0]["clause_start_index"],
                "end_index": group[-1]["clause_end_index"],
                "clauses": group,
            }
        )
    return results


def _parse_udm_rhs(rhs_raw: str) -> dict[str, Any]:
    """Parses a UDM comparison RHS token into ``{kind, value, nocase}``."""
    stripped = str(rhs_raw or "").strip()
    regex_match = re.match(r"^/([^\r\n/]+)/([ \t]+nocase)?$", stripped, re.IGNORECASE)
    if regex_match is not None:
        return {
            "kind": "regex",
            "value": regex_match.group(1),
            "nocase": bool(regex_match.group(2)),
        }
    if len(stripped) >= 2 and (
        (stripped[0] == '"' and stripped[-1] == '"')
        or (stripped[0] == "'" and stripped[-1] == "'")
        or (stripped[0] == "“" and stripped[-1] == "”")
    ):
        return {
            "kind": "literal",
            "value": stripped[1:-1],
            "nocase": False,
        }
    return {
        "kind": "literal",
        "value": stripped,
        "nocase": False,
    }


def _rhs_matches_observed_value(rhs_parsed: dict[str, Any], observed_val: str) -> bool:
    """Returns True when an observed UDM scalar value satisfies ``rhs_parsed``."""
    if not observed_val:
        return False
    if rhs_parsed.get("kind") == "regex":
        pattern_str = str(rhs_parsed.get("value") or "")
        flags = re.IGNORECASE if rhs_parsed.get("nocase") else 0
        try:
            return re.search(pattern_str, observed_val, flags) is not None
        except re.error:
            return pattern_str.lower() in observed_val.lower()
    target_val = str(rhs_parsed.get("value") or "")
    return observed_val.lower() == target_val.lower()


def _shared_prefix_len(a: str, b: str) -> int:
    """Returns the length of the shared character prefix between ``a`` and ``b``."""
    limit = min(len(a), len(b))
    idx = 0
    while idx < limit and a[idx] == b[idx]:
        idx += 1
    return idx


def _format_canonical_udm_clause(c: dict[str, Any]) -> str:
    """Formats a parsed UDM clause record into canonical UDM query text."""
    if c.get("is_cidr_clause") or c.get("operator") == "net.ip_in_range_cidr":
        clean_cidr = str(c["rhs_raw"]).strip("\"'“”")
        return f'net.ip_in_range_cidr({c["canonical_field"]}, "{clean_cidr}")'
    return f"{c['canonical_field']}{c['operator_raw']}{c['rhs_raw']}"


def _reconstruct_udm_query_with_clause_overrides(
    query_text: str,
    clauses: list[dict[str, Any]],
    *,
    skip_index: int | None = None,
    override_index: int | None = None,
    override_clause_text: str | None = None,
) -> str:
    """Reconstructs a canonicalized UDM query while optionally omitting or overriding one clause."""
    if skip_index is not None:
        kept_clauses: list[str] = []
        for idx, c in enumerate(clauses):
            if idx == skip_index:
                continue
            kept_clauses.append(_format_canonical_udm_clause(c))
        return " AND ".join(kept_clauses)

    out_parts: list[str] = []
    cursor = 0
    for idx, c in enumerate(clauses):
        c_start = int(c["char_start"])
        c_end = int(c["char_end"])
        out_parts.append(query_text[cursor:c_start])
        if idx == override_index and override_clause_text is not None:
            out_parts.append(override_clause_text)
        else:
            out_parts.append(_format_canonical_udm_clause(c))
        cursor = c_end
    out_parts.append(query_text[cursor:])
    return "".join(out_parts)


def diagnose_zero_hit_udm_query(
    query: str,
    *,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 20,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Diagnoses why a syntactically valid or schema-repaired UDM query returns 0 SIEM events.

    1. Runs :func:`verify_udm_query_with_siem` on ``query``. If ``event_count > 0``, returns
       ``zero_hit=False`` immediately.
    2. When ``event_count == 0`` and ``siem_verified=True``, performs clause-by-clause
       ablation against ``siem_search_fn`` to identify the highest-specificity matching
       anchor query (``anchor_event_count > 0``) and the ``failing_clause`` that reduced
       hits to zero.
    3. Flattens sampled UDM events from the anchor query via
       :func:`_extract_udm_event_field_values` and classifies three semantic failure modes:
       - ``exact_match_on_command_line``: Exact ``=`` on a literal that appears as a proper
         substring of observed UDM values (upgraded to ``/.*<escaped>.*/ nocase``).
       - ``entity_role_swap``: Valid UDM field whose entity prefix (``principal.``, ``target.``,
         ``src.``, etc.) does not hold the queried value/regex while a sibling entity role with
         the same subpath matches.
       - ``value_format_mismatch``: Literal filter on a UDM field that is populated in the
         sampled anchor events with a different normalized value (e.g.,
         ``target.resource.name = "projects/base-production"``).
    4. Verifies the synthesized ``recommended_query`` against Chronicle SIEM
       (``pivot_verified=True``, ``pivot_event_count > 0``).
    """
    initial_res = verify_udm_query_with_siem(
        query,
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        siem_search_fn=siem_search_fn,
    )
    repaired_query = str(initial_res.get("repaired_query") or query)
    replacements = list(initial_res.get("replacements") or [])
    if not initial_res.get("siem_verified"):
        return {
            "status": initial_res.get("status", "error"),
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": False,
            "zero_hit": False,
            "event_count": 0,
            "diagnosis_class": None,
            "message": initial_res.get("message", "SIEM verification failed."),
        }

    initial_count = int(initial_res.get("event_count", 0) or 0)
    if initial_count > 0:
        return {
            "status": "success",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": True,
            "zero_hit": False,
            "event_count": initial_count,
            "diagnosis_class": None,
            "anchor_query": repaired_query,
            "anchor_event_count": initial_count,
            "failing_clause": None,
            "failing_clause_index": None,
            "recommended_clause": None,
            "recommended_query": repaired_query,
            "pivot_verified": True,
            "pivot_event_count": initial_count,
            "observed_values": [],
            "siem_response": initial_res.get("siem_response"),
        }

    extracted_queries = extract_udm_query_clauses_from_text(
        query, _build_utf16_index_map(query)
    )
    if not extracted_queries or len(extracted_queries[0].get("clauses", [])) < 2:
        return {
            "status": "success",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": True,
            "zero_hit": True,
            "event_count": 0,
            "diagnosis_class": "insufficient_clauses_for_ablation",
            "anchor_query": None,
            "anchor_event_count": 0,
            "failing_clause": None,
            "failing_clause_index": None,
            "recommended_clause": None,
            "recommended_query": None,
            "pivot_verified": False,
            "pivot_event_count": 0,
            "observed_values": [],
        }

    q_obj = extracted_queries[0]
    clauses: list[dict[str, Any]] = q_obj["clauses"]
    q_text = str(q_obj["query_text"])
    q_char_offset = int(q_obj["char_start"])
    rel_clauses: list[dict[str, Any]] = []
    for c in clauses:
        rel_c = dict(c)
        rel_c["char_start"] = int(c["char_start"]) - q_char_offset
        rel_c["char_end"] = int(c["char_end"]) - q_char_offset
        rel_clauses.append(rel_c)

    ablation_Order = list(range(len(rel_clauses) - 1, -1, -1))
    fallback_anchor: dict[str, Any] | None = None

    for remove_idx in ablation_Order:
        candidate_anchor = _reconstruct_udm_query_with_clause_overrides(
            q_text, rel_clauses, skip_index=remove_idx
        )
        ablation_res = verify_udm_query_with_siem(
            candidate_anchor,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        anchor_count = int(ablation_res.get("event_count", 0) or 0)
        if not ablation_res.get("siem_verified") or anchor_count <= 0:
            continue

        raw_events = (ablation_res.get("siem_response") or {}).get("events")
        anchor_events = raw_events if isinstance(raw_events, list) else []
        merged_field_values: dict[str, list[str]] = {}
        value_event_freq: dict[tuple[str, str], int] = {}
        for ev in anchor_events:
            if not isinstance(ev, dict):
                continue
            ev_map = _extract_udm_event_field_values(ev)
            for f_path, vals in ev_map.items():
                bucket = merged_field_values.setdefault(f_path, [])
                for v in vals:
                    if v not in bucket:
                        bucket.append(v)
                    value_event_freq[(f_path, v)] = (
                        value_event_freq.get((f_path, v), 0) + 1
                    )

        if fallback_anchor is None:
            fallback_anchor = {
                "remove_idx": remove_idx,
                "anchor_query": candidate_anchor,
                "anchor_event_count": anchor_count,
                "merged_field_values": merged_field_values,
            }

        failing_c = rel_clauses[remove_idx]
        orig_field = str(failing_c["field_token"])
        canonical_field = str(failing_c["canonical_field"])
        operator = str(failing_c["operator"])
        operator_raw = str(failing_c["operator_raw"])
        rhs_raw = str(failing_c["rhs_raw"])
        rhs_parsed = _parse_udm_rhs(rhs_raw)
        observed_for_canonical = merged_field_values.get(canonical_field, [])

        diagnosis_class: str | None = None
        recommended_field = canonical_field
        recommended_rhs = rhs_raw
        repair_target = "clause"
        observed_values: list[str] = []
        ranked_value_candidates: list[str] = []

        # 1. exact_match_on_command_line: exact '=' literal that is a proper substring of observed values
        if (
            operator == "="
            and rhs_parsed["kind"] == "literal"
            and rhs_parsed["value"]
            and observed_for_canonical
        ):
            lit_val = str(rhs_parsed["value"])
            lit_lower = lit_val.lower()
            substring_matches = [
                obs
                for obs in observed_for_canonical
                if lit_lower in obs.lower() and lit_lower != obs.lower()
            ]
            exact_matches = [
                obs for obs in observed_for_canonical if lit_lower == obs.lower()
            ]
            if substring_matches and not exact_matches:
                diagnosis_class = "exact_match_on_command_line"
                escaped_lit = re.escape(lit_val)
                recommended_field = canonical_field
                recommended_rhs = f"/.*{escaped_lit}.*/ nocase"
                repair_target = "clause" if orig_field != canonical_field else "rhs"
                observed_values = substring_matches[:5]

        # 2. entity_role_swap: sibling UDM entity role holds the queried literal or regex
        if diagnosis_class is None:
            matched_prefix = next(
                (
                    p
                    for p in _UDM_ENTITY_ROLE_PREFIXES
                    if canonical_field.startswith(p)
                ),
                None,
            )
            if matched_prefix is not None and not any(
                _rhs_matches_observed_value(rhs_parsed, obs)
                for obs in observed_for_canonical
            ):
                subpath = canonical_field[len(matched_prefix) :]
                for sib_prefix in _UDM_ENTITY_ROLE_PREFIXES:
                    if sib_prefix == matched_prefix:
                        continue
                    sib_field = f"{sib_prefix}{subpath}"
                    sib_vals = merged_field_values.get(sib_field, [])
                    matching_sib = [
                        obs
                        for obs in sib_vals
                        if _rhs_matches_observed_value(rhs_parsed, obs)
                    ]
                    if matching_sib:
                        diagnosis_class = "entity_role_swap"
                        recommended_field = sib_field
                        recommended_rhs = rhs_raw
                        repair_target = "field"
                        observed_values = matching_sib[:5]
                        break

        # 3. value_format_mismatch: canonical field is populated in anchor events with a different value
        if (
            diagnosis_class is None
            and operator == "="
            and rhs_parsed["kind"] == "literal"
            and observed_for_canonical
        ):
            lit_val = str(rhs_parsed["value"])
            lit_lower = lit_val.lower()
            ranked_value_candidates = sorted(
                observed_for_canonical,
                key=lambda cand: (
                    _shared_prefix_len(lit_lower, cand.lower()),
                    value_event_freq.get((canonical_field, cand), 0),
                    difflib.SequenceMatcher(None, lit_lower, cand.lower()).ratio(),
                ),
                reverse=True,
            )
            if ranked_value_candidates:
                best_val = ranked_value_candidates[0]
                diagnosis_class = "value_format_mismatch"
                recommended_field = canonical_field
                recommended_rhs = f'"{best_val}"'
                repair_target = "clause" if orig_field != canonical_field else "rhs"
                observed_values = ranked_value_candidates[:5]

        if diagnosis_class is None:
            continue

        recommended_clause = f"{recommended_field}{operator_raw}{recommended_rhs}"
        recommended_query = _reconstruct_udm_query_with_clause_overrides(
            q_text,
            rel_clauses,
            override_index=remove_idx,
            override_clause_text=recommended_clause,
        )
        pivot_res = verify_udm_query_with_siem(
            recommended_query,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        pivot_count = int(pivot_res.get("event_count", 0) or 0)
        pivot_verified = bool(pivot_res.get("siem_verified")) and pivot_count > 0

        if (
            not pivot_verified
            and diagnosis_class == "value_format_mismatch"
            and len(ranked_value_candidates) > 1
        ):
            for alt_val in ranked_value_candidates[1:3]:
                alt_rhs = f'"{alt_val}"'
                alt_clause = f"{recommended_field}{operator_raw}{alt_rhs}"
                alt_query = _reconstruct_udm_query_with_clause_overrides(
                    q_text,
                    rel_clauses,
                    override_index=remove_idx,
                    override_clause_text=alt_clause,
                )
                alt_res = verify_udm_query_with_siem(
                    alt_query,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_search_fn=siem_search_fn,
                )
                alt_count = int(alt_res.get("event_count", 0) or 0)
                if alt_res.get("siem_verified") and alt_count > 0:
                    recommended_rhs = alt_rhs
                    recommended_clause = alt_clause
                    recommended_query = alt_query
                    pivot_count = alt_count
                    pivot_verified = True
                    break

        return {
            "status": "success",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": True,
            "zero_hit": True,
            "event_count": 0,
            "diagnosis_class": diagnosis_class,
            "repair_target": repair_target,
            "anchor_query": candidate_anchor,
            "anchor_event_count": anchor_count,
            "failing_clause": str(failing_c["clause_text"]),
            "failing_clause_index": remove_idx,
            "failing_field": orig_field,
            "canonical_failing_field": canonical_field,
            "failing_rhs": rhs_raw,
            "recommended_field": recommended_field,
            "recommended_rhs": recommended_rhs,
            "recommended_clause": recommended_clause,
            "recommended_query": recommended_query,
            "pivot_verified": pivot_verified,
            "pivot_event_count": pivot_count,
            "observed_values": observed_values,
        }

    if fallback_anchor is not None:
        f_idx = int(fallback_anchor["remove_idx"])
        failing_c = rel_clauses[f_idx]
        return {
            "status": "success",
            "original_query": query,
            "repaired_query": repaired_query,
            "replacements": replacements,
            "siem_verified": True,
            "zero_hit": True,
            "event_count": 0,
            "diagnosis_class": "unclassified_zero_hit_clause",
            "repair_target": None,
            "anchor_query": fallback_anchor["anchor_query"],
            "anchor_event_count": fallback_anchor["anchor_event_count"],
            "failing_clause": str(failing_c["clause_text"]),
            "failing_clause_index": f_idx,
            "failing_field": str(failing_c["field_token"]),
            "canonical_failing_field": str(failing_c["canonical_field"]),
            "failing_rhs": str(failing_c["rhs_raw"]),
            "recommended_field": None,
            "recommended_rhs": None,
            "recommended_clause": None,
            "recommended_query": None,
            "pivot_verified": False,
            "pivot_event_count": 0,
            "observed_values": [],
        }

    return {
        "status": "success",
        "original_query": query,
        "repaired_query": repaired_query,
        "replacements": replacements,
        "siem_verified": True,
        "zero_hit": True,
        "event_count": 0,
        "diagnosis_class": "no_matching_anchor_clause",
        "repair_target": None,
        "anchor_query": None,
        "anchor_event_count": 0,
        "failing_clause": None,
        "failing_clause_index": None,
        "recommended_clause": None,
        "recommended_query": None,
        "pivot_verified": False,
        "pivot_event_count": 0,
        "observed_values": [],
    }


def _format_zero_hit_udm_comment(
    diag_res: dict[str, Any],
    *,
    has_schema_defect: bool,
    udm_doc_url: str,
) -> str:
    """Formats a grounded Google Docs review comment for a diagnosed zero-hit UDM query."""
    diag_class = str(diag_res.get("diagnosis_class") or "zero_hit")
    failing_clause = str(diag_res.get("failing_clause") or "")
    rec_clause = str(diag_res.get("recommended_clause") or "")
    rec_query = str(diag_res.get("recommended_query") or "")
    anchor_query = str(diag_res.get("anchor_query") or "")
    anchor_count = int(diag_res.get("anchor_event_count", 0) or 0)
    pivot_count = int(diag_res.get("pivot_event_count", 0) or 0)
    observed = list(diag_res.get("observed_values") or [])
    observed_preview = observed[0] if observed else ""

    schema_prefix = ""
    if has_schema_defect:
        orig_f = str(diag_res.get("failing_field") or "")
        canon_f = str(diag_res.get("canonical_failing_field") or "")
        schema_prefix = (
            f"Deterministic Chronicle UDM Schema Check: '{orig_f}' is not a valid "
            f"canonical Chronicle UDM field path (use '{canon_f}', {udm_doc_url}). "
        )

    if diag_class == "exact_match_on_command_line":
        reason = (
            f"Zero-Hit UDM Semantic Diagnosis (exact_match_on_command_line): "
            f"Exact string equality in '{failing_clause}' returned 0 SIEM events, whereas "
            f"anchor query '{anchor_query}' matched {anchor_count} events with full command line "
            f"values such as '{observed_preview}'. Use case-insensitive regular expression "
            f"matching '{rec_clause}'."
        )
    elif diag_class == "entity_role_swap":
        orig_f = str(diag_res.get("canonical_failing_field") or diag_res.get("failing_field") or "")
        rec_f = str(diag_res.get("recommended_field") or "")
        reason = (
            f"Zero-Hit UDM Semantic Diagnosis (entity_role_swap): "
            f"Entity role '{orig_f}' in '{failing_clause}' returned 0 SIEM events, whereas "
            f"sibling entity field '{rec_f}' in anchor query '{anchor_query}' ({anchor_count} "
            f"events) holds matching telemetry ('{observed_preview}'). Use '{rec_clause}'."
        )
    elif diag_class == "value_format_mismatch":
        canon_f = str(diag_res.get("canonical_failing_field") or "")
        reason = (
            f"Zero-Hit UDM Semantic Diagnosis (value_format_mismatch): "
            f"Filter '{failing_clause}' returned 0 SIEM events even after UDM field normalization, "
            f"whereas anchor query '{anchor_query}' matched {anchor_count} events where "
            f"'{canon_f}' is normalized as '{observed_preview}'. Use '{rec_clause}'."
        )
    else:
        reason = (
            f"Zero-Hit UDM Semantic Diagnosis ({diag_class}): "
            f"Clause '{failing_clause}' returned 0 SIEM events; replace with '{rec_clause}'."
        )

    return (
        f"{schema_prefix}{reason} "
        f"[SIEM Pivot Verified: query='{rec_query}', events_matched={pivot_count}]"
    )


def verify_and_redline_udm_queries_in_doc(
    document_id: str,
    *,
    run_live_siem_check: bool = False,
    diagnose_zero_hit_queries: bool = True,
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
    """Lints UDM queries in a Google Doc, optionally dry-runs and diagnoses 0-hit queries in Chronicle SIEM, and stages red-lines.

    1. Calls :func:`read_google_doc` to build the 1-based UTF-16 character index map
       and cache ``pending_suggestion_spans``.
    2. Calls :func:`find_udm_field_spans` to locate unprefixed or hallucinated UDM fields,
       automatically skipping any span that overlaps an existing pending suggestion
       (ensuring 100% multi-pass idempotency).
    3. When ``run_live_siem_check=True`` (or ``siem_search_fn`` is provided), executes
       :func:`verify_udm_query_with_siem` on each defective query and enriches the
       anchored Google Docs comment with live SIEM verification metadata.
    4. When ``diagnose_zero_hit_queries=True`` and live SIEM verification is enabled,
       decomposes any multi-clause UDM query returning ``0`` SIEM events via
       :func:`diagnose_zero_hit_udm_query`, upgrading schema-defective zero-hit clauses
       in-place and staging non-overlapping Suggested Edits on syntactically valid
       zero-hit UDM queries (``exact_match_on_command_line``, ``entity_role_swap``,
       ``value_format_mismatch``).
    5. Anchors comments first via :func:`insert_doc_comments` and stages descending-index
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

    raw_doc = _load_doc_raw_ast(document_id, tool_context=tool_context)
    raw_comments, raw_edits, raw_findings = find_udm_field_spans(
        plain_text, index_map, udm_doc_url=udm_doc_url
    )
    if isinstance(raw_doc, dict):
        ic_comments, ic_edits, ic_findings = find_italic_corrupted_regex_spans(
            raw_doc,
            plain_text=plain_text,
            index_map=index_map,
            udm_doc_url=udm_doc_url,
            yaral2_doc_url=DEFAULT_YARAL2_DOC_URL,
        )
        repaired_line_by_orig: dict[str, str] = {}
        for ic_f in ic_findings:
            if ic_f.get("context_kind") == "udm":
                orig_ql = str(ic_f.get("original_query_line") or "")
                rep_ql = str(ic_f.get("query_line") or "")
                if orig_ql and rep_ql:
                    repaired_line_by_orig[orig_ql] = rep_ql
        for f_item in raw_findings:
            ql = str(f_item.get("query_line") or "")
            if ql in repaired_line_by_orig:
                f_item["query_line"] = repaired_line_by_orig[ql]
        for ic_c, ic_e, ic_f in zip(ic_comments, ic_edits, ic_findings):
            if ic_f.get("context_kind") != "udm":
                continue
            ic_span = (int(ic_f["start_index"]), int(ic_f["end_index"]))
            if any(
                _spans_overlap(
                    ic_span, (int(ex_e["start_index"]), int(ex_e["end_index"]))
                )
                for ex_e in raw_edits
            ):
                continue
            raw_comments.append(ic_c)
            raw_edits.append(ic_e)
            raw_findings.append(ic_f)

    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    finding_idx_by_field_span: dict[tuple[int, int], int] = {}
    skipped_existing_suggestion_count = 0
    for c_item, e_item, f_item in zip(raw_comments, raw_edits, raw_findings):
        f_span = (int(f_item["start_index"]), int(f_item["end_index"]))
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        f_idx = len(findings)
        if f_item.get("defect_type") != "italic_corrupted_regex_wildcard":
            finding_idx_by_field_span[f_span] = f_idx
        comments.append(c_item)
        edits.append(e_item)
        findings.append(f_item)

    siem_checks: list[dict[str, Any]] = []
    zero_hit_diagnoses: list[dict[str, Any]] = []
    zero_hit_findings_count = 0
    live_siem_enabled = bool(run_live_siem_check or siem_search_fn is not None)
    query_cache: dict[str, dict[str, Any]] = {}

    if live_siem_enabled and findings:
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

    if live_siem_enabled and diagnose_zero_hit_queries:
        doc_queries = extract_udm_query_clauses_from_text(plain_text, index_map)
        diag_cache: dict[str, dict[str, Any]] = {}
        for q_obj in doc_queries:
            clauses = q_obj.get("clauses", [])
            if len(clauses) < 2:
                continue

            q_span = (int(q_obj["start_index"]), int(q_obj["end_index"]))
            has_static_schema_clause = any(
                c["field_token"] != c["canonical_field"] for c in clauses
            )
            if has_static_schema_clause and any(
                _spans_overlap(q_span, p_span) for p_span in pending_spans
            ):
                continue

            q_text = str(q_obj["query_text"])
            if q_text not in query_cache:
                siem_res = verify_udm_query_with_siem(
                    q_text,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_search_fn=siem_search_fn,
                )
                query_cache[q_text] = siem_res
                siem_checks.append(siem_res)
            else:
                siem_res = query_cache[q_text]

            if not siem_res.get("siem_verified") or int(siem_res.get("event_count", 0) or 0) > 0:
                continue

            if any(_spans_overlap(q_span, p_span) for p_span in pending_spans):
                if not has_static_schema_clause:
                    skipped_existing_suggestion_count += 1
                continue

            if q_text not in diag_cache:
                diag_res = diagnose_zero_hit_udm_query(
                    q_text,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max(max_events, 20),
                    siem_search_fn=siem_search_fn,
                )
                diag_cache[q_text] = diag_res
                zero_hit_diagnoses.append(diag_res)
            else:
                diag_res = diag_cache[q_text]

            if not diag_res.get("pivot_verified") or not diag_res.get("diagnosis_class"):
                continue

            failing_idx = diag_res.get("failing_clause_index")
            if not isinstance(failing_idx, int) or not (0 <= failing_idx < len(clauses)):
                continue

            target_clause = clauses[failing_idx]
            field_span = (
                int(target_clause["field_start_index"]),
                int(target_clause["field_end_index"]),
            )
            existing_f_idx = finding_idx_by_field_span.get(field_span)

            if existing_f_idx is not None:
                c_start = int(target_clause["clause_start_index"])
                c_end = int(target_clause["clause_end_index"])
                c_quote = str(target_clause["clause_text"])
                rec_clause = str(diag_res["recommended_clause"])
                comment_body = _format_zero_hit_udm_comment(
                    diag_res,
                    has_schema_defect=True,
                    udm_doc_url=udm_doc_url,
                )
                comments[existing_f_idx] = {
                    "start_index": c_start,
                    "end_index": c_end,
                    "quote": c_quote,
                    "comment": comment_body,
                }
                edits[existing_f_idx] = {
                    "start_index": c_start,
                    "end_index": c_end,
                    "quote": c_quote,
                    "replacement": rec_clause,
                }
                findings[existing_f_idx].update(
                    {
                        "start_index": c_start,
                        "end_index": c_end,
                        "zero_hit_diagnosis": diag_res["diagnosis_class"],
                        "repair_target": "clause",
                        "failing_clause": c_quote,
                        "recommended_clause": rec_clause,
                        "recommended_query": diag_res["recommended_query"],
                        "anchor_query": diag_res["anchor_query"],
                        "anchor_event_count": diag_res["anchor_event_count"],
                        "pivot_event_count": diag_res["pivot_event_count"],
                        "observed_values": diag_res.get("observed_values", []),
                    }
                )
                zero_hit_findings_count += 1
            else:
                repair_target = str(diag_res.get("repair_target") or "clause")
                if repair_target == "field":
                    t_start = int(target_clause["field_start_index"])
                    t_end = int(target_clause["field_end_index"])
                    t_quote = str(target_clause["field_token"])
                    t_replacement = str(diag_res["recommended_field"])
                elif repair_target == "rhs":
                    t_start = int(target_clause["rhs_start_index"])
                    t_end = int(target_clause["rhs_end_index"])
                    t_quote = str(target_clause["rhs_raw"])
                    t_replacement = str(diag_res["recommended_rhs"])
                else:
                    t_start = int(target_clause["clause_start_index"])
                    t_end = int(target_clause["clause_end_index"])
                    t_quote = str(target_clause["clause_text"])
                    t_replacement = str(diag_res["recommended_clause"])

                if any(_spans_overlap((t_start, t_end), p_span) for p_span in pending_spans):
                    skipped_existing_suggestion_count += 1
                    continue

                if any(
                    _spans_overlap(
                        (t_start, t_end),
                        (int(existing_e["start_index"]), int(existing_e["end_index"])),
                    )
                    for existing_e in edits
                ):
                    continue

                comment_body = _format_zero_hit_udm_comment(
                    diag_res,
                    has_schema_defect=False,
                    udm_doc_url=udm_doc_url,
                )
                comments.append(
                    {
                        "start_index": t_start,
                        "end_index": t_end,
                        "quote": t_quote,
                        "comment": comment_body,
                    }
                )
                edits.append(
                    {
                        "start_index": t_start,
                        "end_index": t_end,
                        "quote": t_quote,
                        "replacement": t_replacement,
                    }
                )
                findings.append(
                    {
                        "invalid_field": str(target_clause["field_token"]),
                        "canonical_field": str(diag_res["recommended_field"]),
                        "start_index": t_start,
                        "end_index": t_end,
                        "clause": str(target_clause["clause_text"]),
                        "query_line": q_text,
                        "zero_hit_diagnosis": diag_res["diagnosis_class"],
                        "repair_target": repair_target,
                        "failing_clause": str(target_clause["clause_text"]),
                        "recommended_clause": str(diag_res["recommended_clause"]),
                        "recommended_query": str(diag_res["recommended_query"]),
                        "anchor_query": str(diag_res["anchor_query"]),
                        "anchor_event_count": int(diag_res["anchor_event_count"]),
                        "pivot_event_count": int(diag_res["pivot_event_count"]),
                        "observed_values": diag_res.get("observed_values", []),
                    }
                )
                zero_hit_findings_count += 1

    if len(findings) > 1:
        ordered = sorted(
            zip(comments, edits, findings),
            key=lambda triple: int(triple[2]["start_index"]),
        )
        comments = [item[0] for item in ordered]
        edits = [item[1] for item in ordered]
        findings = [item[2] for item in ordered]

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
        "zero_hit_findings_count": zero_hit_findings_count,
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "siem_checks": siem_checks,
        "zero_hit_diagnoses": zero_hit_diagnoses,
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


_ITALIC_RE_REGEX_ARG_RE = re.compile(
    r"re\.regex\(\s*(?:\$?[A-Za-z_][A-Za-z0-9_.]*)\s*,\s*(/[^/\r\n]+/|`[^`\r\n]+`)",
    re.IGNORECASE,
)
_ITALIC_UDM_CMP_REGEX_RE = re.compile(
    r"(?:!=|=~|!~|=)[ \t]*(/[^/\r\n]+/)"
)
_ITALIC_NOCASE_REGEX_RE = re.compile(
    r"(/[^\s/\r\n][^/\r\n]*/)(?=[ \t]+nocase\b)",
    re.IGNORECASE,
)


def _restore_italic_wildcards_in_regex_body(
    inner_text: str,
    inner_italics: list[bool],
) -> tuple[str, list[str], int]:
    """Reconstructs ``*...*`` regex wildcards stripped into ``textStyle.italic=True`` runs."""
    if not inner_text or len(inner_text) != len(inner_italics) or not any(inner_italics):
        return inner_text, [], 0

    runs: list[tuple[bool, str]] = []
    cur_italic = inner_italics[0]
    cur_chars = [inner_text[0]]
    for ch, is_it in zip(inner_text[1:], inner_italics[1:]):
        if is_it == cur_italic:
            cur_chars.append(ch)
        else:
            runs.append((cur_italic, "".join(cur_chars)))
            cur_italic = is_it
            cur_chars = [ch]
    runs.append((cur_italic, "".join(cur_chars)))

    out_parts: list[str] = []
    italic_subspans: list[str] = []
    for is_it, segment in runs:
        if not is_it:
            out_parts.append(segment)
            continue
        prev_str = "".join(out_parts)
        need_left = not prev_str.endswith("*") and not segment.startswith("*")
        need_right = not segment.endswith("*")
        wrapped = f"{'*' if need_left else ''}{segment}{'*' if need_right else ''}"
        out_parts.append(wrapped)
        italic_subspans.append(segment)

    restored_inner = "".join(out_parts)
    return restored_inner, italic_subspans, (1 if italic_subspans else 0)


def _iter_italic_corrupted_regex_tokens(
    text: str,
    italic_flags: list[bool],
) -> list[dict[str, Any]]:
    """Finds regex literals in ``text`` whose ``*`` quantifiers were stripped into italic runs."""
    if not text or len(text) != len(italic_flags) or not any(italic_flags):
        return []

    candidate_spans: list[tuple[int, int]] = []
    seen_spans: set[tuple[int, int]] = set()
    for pat in (_ITALIC_RE_REGEX_ARG_RE, _ITALIC_UDM_CMP_REGEX_RE, _ITALIC_NOCASE_REGEX_RE):
        for m in pat.finditer(text):
            sp = (m.start(1), m.end(1))
            if sp not in seen_spans:
                seen_spans.add(sp)
                candidate_spans.append(sp)
    candidate_spans.sort(key=lambda item: item[0])

    results: list[dict[str, Any]] = []
    for tok_start, tok_end in candidate_spans:
        inner_start = tok_start + 1
        inner_end = tok_end - 1
        if inner_end <= inner_start:
            continue
        inner_italics = italic_flags[inner_start:inner_end]
        if not any(inner_italics):
            continue
        # Skip if the entire token including outer delimiters is uniformly italicized
        if italic_flags[tok_start] and italic_flags[tok_end - 1] and all(inner_italics):
            continue
        inner_text = text[inner_start:inner_end]
        restored_inner, italic_subspans, _ = _restore_italic_wildcards_in_regex_body(
            inner_text, inner_italics
        )
        delim = text[tok_start]
        quote = text[tok_start:tok_end]
        replacement = f"{delim}{restored_inner}{delim}"
        if replacement == quote:
            continue
        results.append(
            {
                "tok_start": tok_start,
                "tok_end": tok_end,
                "quote": quote,
                "replacement": replacement,
                "restored_inner": restored_inner,
                "restored_regex": f"/{restored_inner}/",
                "yaral2_backtick_regex": f"`{restored_inner}`",
                "italic_subspans": italic_subspans,
            }
        )
    return results


def find_italic_corrupted_regex_spans(
    doc: dict[str, Any],
    *,
    plain_text: str | None = None,
    index_map: list[int] | None = None,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans a Google Docs AST for regex literals whose ``*`` quantifiers were stripped into ``textStyle.italic=True``.

    When Google Drive converts Markdown containing a regex with two ``*`` quantifiers
    (such as ``/.*cmd.*/``) into a native Google Doc, the Markdown parser treats
    ``*cmd.*`` as ``<em>cmd.</em>``, stripping both ``*`` characters from ``textRun.content``
    (yielding ``/.cmd./``) and setting ``textStyle.italic=True`` on ``cmd.``.

    Walks ``tabs[0].documentTab.body.content`` (or ``body.content``, recursing into
    nested ``table.tableRows[].tableCells[]``) in ``"baseline"`` view mode, tracks
    per-character ``textStyle.italic`` state and 1-based UTF-16 indices, and restores
    ``*...*`` around contiguous italic runs inside UDM and YARA-L 2.0 regex literals
    while ignoring normal prose italics outside regex delimiters.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not isinstance(doc, dict):
        return comments, edits, findings

    tabs = doc.get("tabs", [])
    if tabs:
        body = tabs[0].get("documentTab", {}).get("body", {})
    else:
        body = doc.get("body", {})

    chars: list[str] = []
    extracted_map: list[int] = []
    italic_flags: list[bool] = []

    def _walk_elements(elements: list[dict[str, Any]]) -> None:
        for element in elements:
            if "paragraph" in element:
                for pe in element["paragraph"].get("elements", []):
                    text_run = pe.get("textRun")
                    if not text_run:
                        continue
                    ins_ids = [
                        str(x)
                        for x in (text_run.get("suggestedInsertionIds") or [])
                        if x
                    ]
                    if ins_ids:
                        continue
                    content = text_run.get("content", "")
                    is_italic = bool((text_run.get("textStyle") or {}).get("italic"))
                    start_idx = int(pe.get("startIndex", 0) or 0)
                    utf16_offset = 0
                    for ch in content:
                        chars.append(ch)
                        extracted_map.append(start_idx + utf16_offset)
                        italic_flags.append(is_italic)
                        utf16_offset += _utf16_code_unit_len(ch)
            elif "table" in element:
                for row in element["table"].get("tableRows", []):
                    for cell in row.get("tableCells", []):
                        _walk_elements(cell.get("content", []))

    _walk_elements(body.get("content", []))
    full_text = "".join(chars)
    if not full_text or not any(italic_flags):
        return comments, edits, findings

    use_map = (
        index_map
        if (index_map is not None and len(index_map) == len(full_text))
        else extracted_map
    )

    tokens = _iter_italic_corrupted_regex_tokens(full_text, italic_flags)
    if not tokens:
        return comments, edits, findings

    rule_blocks = _iter_yaral2_rule_blocks(full_text)

    # Precompute line-level UDM query repairs so standalone UDM lines with multiple
    # or single italic-corrupted regex tokens have a wildcard-restored query_line.
    repaired_full_text = full_text
    for tok in sorted(tokens, key=lambda item: int(item["tok_start"]), reverse=True):
        ts = int(tok["tok_start"])
        te = int(tok["tok_end"])
        repaired_full_text = (
            repaired_full_text[:ts]
            + str(tok["replacement"])
            + repaired_full_text[te:]
        )

    for tok in tokens:
        char_start = int(tok["tok_start"])
        char_end = int(tok["tok_end"])
        quote = str(tok["quote"])
        replacement = str(tok["replacement"])
        restored_regex = str(tok["restored_regex"])
        yaral2_backtick_regex = str(tok["yaral2_backtick_regex"])
        italic_subspans = list(tok["italic_subspans"])

        start_idx = use_map[char_start]
        end_idx = use_map[char_end - 1] + _utf16_code_unit_len(full_text[char_end - 1])

        enclosing_block = None
        for b in rule_blocks:
            if int(b["char_start"]) <= char_start < int(b["char_end"]):
                enclosing_block = b
                break

        if enclosing_block is not None:
            context_kind = "yaral2"
            rule_name: str | None = str(enclosing_block["rule_name"])
            local_start: int | None = char_start - int(enclosing_block["char_start"])
            local_end: int | None = char_end - int(enclosing_block["char_start"])
            orig_query_line = ""
            repaired_query_line = ""
            clause_text = quote
            comment_text = (
                f"Deterministic Google Docs Italic-Stripped Regex Wildcard Check in YARA-L 2.0 (YL2) rule '{rule_name}': "
                f"Google Drive Markdown import parsed paired '*' regex wildcards in '{replacement}' as Markdown italics "
                f"(textStyle.italic=True on {italic_subspans!r}), stripping the '*' quantifiers to produce '{quote}'. "
                f"Restore wildcard quantifiers as '{replacement}' (or canonical YARA-L 2.0 backtick regex "
                f"'{yaral2_backtick_regex}') ({yaral2_doc_url})."
            )
        else:
            context_kind = "udm"
            rule_name = None
            local_start = None
            local_end = None
            orig_query_line = _extract_udm_query_from_line(full_text, char_start, quote)
            repaired_query_line = orig_query_line.replace(quote, replacement)
            clause_text = quote
            comment_text = (
                "Deterministic Google Docs Italic-Stripped Regex Wildcard Check: "
                f"Google Drive Markdown import parsed paired '*' regex wildcards in '{replacement}' as Markdown italics "
                f"(textStyle.italic=True on {italic_subspans!r}), stripping the '*' quantifiers to produce '{quote}'. "
                f"Restore wildcard quantifiers as '{replacement}' ({udm_doc_url})."
            )

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
                "defect_type": "italic_corrupted_regex_wildcard",
                "context_kind": context_kind,
                "rule_name": rule_name,
                "quote": quote,
                "replacement": replacement,
                "restored_regex": restored_regex,
                "yaral2_backtick_regex": yaral2_backtick_regex,
                "italic_subspans": italic_subspans,
                "invalid_field": quote,
                "canonical_field": replacement,
                "start_index": start_idx,
                "end_index": end_idx,
                "char_start": char_start,
                "char_end": char_end,
                "local_start": local_start,
                "local_end": local_end,
                "clause": clause_text,
                "query_line": repaired_query_line,
                "original_query_line": orig_query_line,
                "comment": comment_text,
            }
        )

    return comments, edits, findings


def _normalize_yaral2_re_regex_calls(rule_text: str) -> str:
    """Normalizes ``re.regex($var.field, /pattern/ nocase)`` into valid Chronicle YARA-L 2.0
    ``re.regex($var.field, `pattern`) nocase`` syntax."""

    def _replace_call(match: re.Match[str]) -> str:
        prefix = match.group(1)
        pattern = (
            match.group(2)
            if match.group(2) is not None
            else (match.group(3) or "")
        )
        inner_nocase = match.group(4) or ""
        close_paren = match.group(5)
        outer_nocase = match.group(6) or ""
        has_nocase = bool(inner_nocase.strip() or outer_nocase.strip())
        suffix = " nocase" if has_nocase else ""
        return f"{prefix}`{pattern}`{close_paren}{suffix}"

    return _YARAL2_RE_REGEX_SLASH_NORM_RE.sub(_replace_call, rule_text)


_YARAL2_STRINGS_FUNCTION_ALIASES: dict[str, str] = {
    "coalesce": "strings.coalesce",
    "ifnull": "strings.coalesce",
    "nvl": "strings.coalesce",
    "strings.ifnull": "strings.coalesce",
    "strings.nvl": "strings.coalesce",
    "strings.coalesce": "strings.coalesce",
    "concat": "strings.concat",
    "strings.concat": "strings.concat",
    "lower": "strings.to_lower",
    "to_lower": "strings.to_lower",
    "strings.lower": "strings.to_lower",
    "strings.to_lower": "strings.to_lower",
    "upper": "strings.to_upper",
    "to_upper": "strings.to_upper",
    "strings.upper": "strings.to_upper",
    "strings.to_upper": "strings.to_upper",
}

_YARAL2_RE_CAPTURE_FUNCTION_ALIASES: dict[str, str] = {
    "regex_extract": "re.capture",
    "regexp_extract": "re.capture",
    "re.extract": "re.capture",
    "extract": "re.capture",
    "rex": "re.capture",
    "re.capture": "re.capture",
}

_YARAL2_RESERVED_KEYWORDS: frozenset[str] = frozenset(
    {
        "and",
        "or",
        "not",
        "nocase",
        "over",
        "before",
        "after",
        "events",
        "strings",
        "match",
        "outcome",
        "condition",
        "meta",
        "options",
        "regex",
        "cidr",
        "in",
        "true",
        "false",
    }
)

_YARAL2_IN_TUPLE_RE = re.compile(
    r"(?i)(?:(?P<lead_not>\bnot)\s+)?\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s+(?:(?P<mid_not>not)\s+)?in\s*(?P<container>\([^()\r\n]+\)|\[[^\[\]\r\n]+\])(?P<trail_nocase>\s+nocase)?"
)

_YARAL2_REF_LIST_IN_RE = re.compile(
    r"(?i)(?:(?P<lead_not>\bnot)\s+)?\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s+(?:(?P<mid_not>not)\s+)?in\s+(?:(?P<mode>regex|cidr)\s+)?(?P<pct>%?)(?P<list_id>[A-Za-z_][A-Za-z0-9_-]*)"
    r"(?=\s*(?:\r|\n|//|$|\band\b|\bor\b|\bnot\b|\)|\}|\$[A-Za-z_]|\(|[A-Za-z_][A-Za-z0-9_.]*\s*\())"
)

_YARAL2_REF_LIST_EQ_RE = re.compile(
    r"(?i)(?:(?P<lead_not>\bnot)\s+)?\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\.(?P<field>[A-Za-z_][A-Za-z0-9_.]*)"
    r"\s*(?P<op>!=|==|=)\s*(?:(?P<mode>regex|cidr)\s+)?%(?P<list_id>[A-Za-z_][A-Za-z0-9_-]*)"
    r"(?=\s*(?:\r|\n|//|$|\band\b|\bor\b|\bnot\b|\)|\}|\$[A-Za-z_]|\(|[A-Za-z_][A-Za-z0-9_.]*\s*\())"
)

_YARAL2_PAREN_OR_DISJUNCTION_RE = re.compile(
    r"(?i)(?:(?P<lead_not>\bnot)\s+)?\(\s*(?P<body>\$[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*\s*(?:!=|==|=)\s*[^\r\n()]+"
    r"(?:\s+or\s+\$[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*\s*(?:!=|==|=)\s*[^\r\n()]+)+)\s*\)"
)


def _find_matching_paren(text: str, open_paren_idx: int) -> int:
    """Returns the index of the matching ``)`` for ``text[open_paren_idx] == '('``, or ``-1``."""
    if open_paren_idx < 0 or open_paren_idx >= len(text) or text[open_paren_idx] != "(":
        return -1
    depth = 0
    in_quote = False
    quote_ch = ""
    escape = False
    for idx in range(open_paren_idx, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_quote:
            if ch == quote_ch:
                in_quote = False
            continue
        if ch in ('"', "'", "`"):
            in_quote = True
            quote_ch = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _has_capturing_group(pattern_str: str) -> bool:
    """Returns True if ``pattern_str`` contains at least one parenthesized capturing group ``(...)``
    (excluding non-capturing ``(?:...)`` and inline flag groups ``(?i)``)."""
    escape = False
    in_char_class = False
    n = len(pattern_str)
    idx = 0
    while idx < n:
        ch = pattern_str[idx]
        if escape:
            escape = False
            idx += 1
            continue
        if ch == "\\":
            escape = True
            idx += 1
            continue
        if in_char_class:
            if ch == "]":
                in_char_class = False
            idx += 1
            continue
        if ch == "[":
            in_char_class = True
            idx += 1
            continue
        if ch == "(":
            if idx + 1 < n and pattern_str[idx + 1] == "?":
                # Named capture (?P<name>...) or (?<name>...) is capturing; (?:...) and (?i) are not
                if idx + 2 < n and pattern_str[idx + 2] in ("P", "<"):
                    return True
                idx += 1
                continue
            return True
        idx += 1
    return False


def _ensure_re_capture_group(pattern_str: str) -> tuple[str, bool]:
    """Ensures ``pattern_str`` has at least one parenthesized capturing group for ``re.capture()``.
    Returns ``(updated_pattern, added_capture_group)``."""
    if _has_capturing_group(pattern_str):
        return pattern_str, False
    flag_m = re.match(r"^(\(\?[a-zA-Z]+\))(.*)$", pattern_str, flags=re.DOTALL)
    if flag_m is not None:
        return f"{flag_m.group(1)}({flag_m.group(2)})", True
    return f"({pattern_str})", True


def _normalize_yaral2_reference_list_name(raw_name: str) -> str:
    """Normalizes a Chronicle YARA-L 2.0 Reference List identifier to lowercase snake_case."""
    cleaned = str(raw_name or "").strip().lstrip("%")
    norm = re.sub(r"[^a-z0-9_]+", "_", cleaned.lower()).strip("_")
    return norm or "reference_list"


def _rewrite_single_strings_call(
    fn_raw: str, args_str: str
) -> tuple[str, str, str]:
    """Rewrites a single ``strings.*`` function call and canonicalizes its arguments."""
    fn_lower = fn_raw.strip().lower()
    canonical_fn = _YARAL2_STRINGS_FUNCTION_ALIASES.get(fn_lower, fn_raw.strip())
    parts = _split_top_level_comma_args(args_str)
    repaired_parts: list[str] = []
    for part in parts:
        p_strip = part.strip()
        # Recursively repair nested strings.* calls if present
        sub_repairs = _inspect_and_repair_yaral2_strings_functions(
            p_strip, has_match_section=False, is_outcome=False
        )
        if sub_repairs:
            p_repaired = p_strip
            for sr in sorted(
                sub_repairs, key=lambda item: int(item["local_start"]), reverse=True
            ):
                s_i = int(sr["local_start"])
                e_i = int(sr["local_end"])
                p_repaired = p_repaired[:s_i] + str(sr["replacement"]) + p_repaired[e_i:]
            p_strip = p_repaired
        p_canon = _canonicalize_yaral2_expr_fields(p_strip)
        if len(p_canon) >= 2 and p_canon[0] == "'" and p_canon[-1] == "'":
            p_canon = f'"{p_canon[1:-1]}"'
        repaired_parts.append(p_canon)
    return canonical_fn, f"{canonical_fn}({', '.join(repaired_parts)})", fn_raw.strip()


def _inspect_and_repair_yaral2_strings_functions(
    expr_text: str,
    event_vars: list[str] | set[str] | None = None,
    has_match_section: bool = False,
    is_outcome: bool = False,
) -> list[dict[str, Any]]:
    """Detects and deterministically repairs SQL/SPL/KQL string functions in YARA-L 2.0 (``YL2``)
    ``events:`` and ``outcome:`` expressions (`coalesce`, `ifnull`, `nvl`, `concat`, `lower`,
    `upper`, `strings.lower`, `strings.upper`, `strings.ifnull`), canonicalizing inner UDM field
    shorthands and wrapping unaggregated ``outcome:`` assignments in ``array_distinct(...)``
    when ``has_match_section=True``."""
    if not expr_text or not expr_text.strip():
        return []

    repairs: list[dict[str, Any]] = []
    call_head_re = re.compile(r"(?<![A-Za-z0-9_.$%])([A-Za-z_][A-Za-z0-9_.]*)\s*\(")

    if is_outcome:
        lead_ws = len(expr_text) - len(expr_text.lstrip())
        trail_end = len(expr_text.rstrip())
        stripped = expr_text[lead_ws:trail_end]
        if not stripped:
            return []

        outer_agg: str | None = None
        inner_expr = stripped
        m_outer = call_head_re.match(stripped)
        if m_outer is not None:
            close_idx = _find_matching_paren(stripped, m_outer.end() - 1)
            if close_idx == len(stripped) - 1:
                cand_fn = m_outer.group(1)
                cand_lower = cand_fn.lower()
                if cand_lower in VALID_YARAL2_OUTCOME_AGG_FUNCS:
                    outer_agg = cand_lower
                    inner_expr = stripped[m_outer.end() : close_idx].strip()
                elif cand_lower in CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS:
                    outer_agg = CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS[cand_lower]
                    inner_expr = stripped[m_outer.end() : close_idx].strip()

        m_inner = call_head_re.match(inner_expr)
        if m_inner is not None:
            close_inner = _find_matching_paren(inner_expr, m_inner.end() - 1)
            if close_inner == len(inner_expr) - 1:
                fn_raw = m_inner.group(1)
                fn_lower = fn_raw.lower()
                if fn_lower in _YARAL2_STRINGS_FUNCTION_ALIASES:
                    args_str = inner_expr[m_inner.end() : close_inner]
                    canonical_fn, canonical_inner_call, orig_fn = (
                        _rewrite_single_strings_call(fn_raw, args_str)
                    )
                    wrapped_in_agg = False
                    if outer_agg:
                        replacement = f"{outer_agg}({canonical_inner_call})"
                    elif has_match_section:
                        replacement = f"array_distinct({canonical_inner_call})"
                        wrapped_in_agg = True
                    else:
                        replacement = canonical_inner_call
                    if replacement != stripped:
                        repairs.append(
                            {
                                "defect_type": "invalid_strings_function_syntax",
                                "local_start": lead_ws,
                                "local_end": trail_end,
                                "quote": stripped,
                                "replacement": replacement,
                                "invalid_field": orig_fn,
                                "canonical_field": canonical_fn,
                                "raw_function_name": orig_fn,
                                "canonical_function_name": canonical_fn,
                                "canonical_inner_call": canonical_inner_call,
                                "wrapped_in_aggregation": wrapped_in_agg,
                            }
                        )
                    return repairs

    comment_spans = [
        (cm.start(), cm.end())
        for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", expr_text)
    ]
    pos = 0
    while pos < len(expr_text):
        m = call_head_re.search(expr_text, pos)
        if m is None:
            break
        if any(_spans_overlap((m.start(), m.end()), cs) for cs in comment_spans):
            pos = m.end()
            continue
        fn_raw = m.group(1)
        fn_lower = fn_raw.lower()
        open_paren = m.end() - 1
        close_paren = _find_matching_paren(expr_text, open_paren)
        if close_paren == -1:
            pos = m.end()
            continue
        if fn_lower in _YARAL2_STRINGS_FUNCTION_ALIASES:
            args_str = expr_text[open_paren + 1 : close_paren]
            canonical_fn, canonical_call, orig_fn = _rewrite_single_strings_call(
                fn_raw, args_str
            )
            call_start = m.start(1)
            call_end = close_paren + 1
            orig_slice = expr_text[call_start:call_end]
            if canonical_call != orig_slice:
                repairs.append(
                    {
                        "defect_type": "invalid_strings_function_syntax",
                        "local_start": call_start,
                        "local_end": call_end,
                        "quote": orig_slice,
                        "replacement": canonical_call,
                        "invalid_field": orig_fn,
                        "canonical_field": canonical_fn,
                        "raw_function_name": orig_fn,
                        "canonical_function_name": canonical_fn,
                        "canonical_inner_call": canonical_call,
                        "wrapped_in_aggregation": False,
                    }
                )
            pos = call_end
        else:
            pos = open_paren + 1

    return repairs


def _rewrite_single_re_capture_call(
    fn_raw: str, args_str: str
) -> tuple[str, str, bool] | None:
    """Rewrites a single ``re.capture`` / ``regex_extract`` / ``regexp_extract`` / ``re.extract`` /
    ``extract`` / ``rex`` call into canonical ``re.capture($<var>.<canonical_field>, "<pattern>")``."""
    fn_lower = fn_raw.strip().lower()
    if fn_lower not in _YARAL2_RE_CAPTURE_FUNCTION_ALIASES:
        return None
    parts = _split_top_level_comma_args(args_str)
    if len(parts) < 2:
        return None
    target_arg = _canonicalize_yaral2_expr_fields(parts[0].strip())
    pat_arg_raw = parts[1].strip()
    has_nocase = False
    if re.search(r"(?i)\s+nocase$", pat_arg_raw):
        has_nocase = True
        pat_arg_raw = re.sub(r"(?i)\s+nocase$", "", pat_arg_raw).strip()

    was_slash = False
    was_backtick = False
    if len(pat_arg_raw) >= 2 and pat_arg_raw[0] == "/" and pat_arg_raw[-1] == "/":
        was_slash = True
        inner_pat = pat_arg_raw[1:-1]
    elif len(pat_arg_raw) >= 2 and pat_arg_raw[0] == "`" and pat_arg_raw[-1] == "`":
        was_backtick = True
        inner_pat = pat_arg_raw[1:-1]
    elif (
        len(pat_arg_raw) >= 2
        and pat_arg_raw[0] in ('"', "'")
        and pat_arg_raw[-1] == pat_arg_raw[0]
    ):
        inner_pat = pat_arg_raw[1:-1]
    else:
        inner_pat = pat_arg_raw

    if has_nocase and not inner_pat.startswith("(?i)"):
        inner_pat = f"(?i){inner_pat}"

    inner_pat, added_group = _ensure_re_capture_group(inner_pat)

    if was_slash:
        # Escape single backslashes and double quotes for double-quoted YARA-L 2.0 string literal
        escaped_inner = inner_pat.replace("\\", "\\\\").replace('"', '\\"')
        formatted_pat = f'"{escaped_inner}"'
    elif was_backtick:
        formatted_pat = f"`{inner_pat}`"
    else:
        escaped_inner = re.sub(r'(?<!\\)\\(?![\\"])', r"\\\\", inner_pat)
        formatted_pat = f'"{escaped_inner}"'

    canonical_call = f"re.capture({target_arg}, {formatted_pat})"
    return "re.capture", canonical_call, added_group


def _inspect_and_repair_yaral2_re_capture_functions(
    expr_text: str,
    event_vars: list[str] | set[str] | None = None,
    has_match_section: bool = False,
    is_outcome: bool = False,
) -> list[dict[str, Any]]:
    """Detects and deterministically repairs non-canonical regex extraction calls in YARA-L 2.0
    (``YL2``) ``events:`` and ``outcome:`` expressions (``regex_extract``, ``regexp_extract``,
    ``re.extract``, ``extract``, ``rex``, or ``re.capture`` with ``/pattern/`` delimiters,
    shorthand UDM fields, missing parenthesized capture groups ``(...)``, or missing
    ``array_distinct(...)`` aggregation in ``match:``-windowed rules)."""
    if not expr_text or not expr_text.strip():
        return []

    repairs: list[dict[str, Any]] = []
    call_head_re = re.compile(r"(?<![A-Za-z0-9_.$%])([A-Za-z_][A-Za-z0-9_.]*)\s*\(")

    if is_outcome:
        lead_ws = len(expr_text) - len(expr_text.lstrip())
        trail_end = len(expr_text.rstrip())
        stripped = expr_text[lead_ws:trail_end]
        if not stripped:
            return []

        outer_agg: str | None = None
        inner_expr = stripped
        m_outer = call_head_re.match(stripped)
        if m_outer is not None:
            close_idx = _find_matching_paren(stripped, m_outer.end() - 1)
            if close_idx == len(stripped) - 1:
                cand_fn = m_outer.group(1)
                cand_lower = cand_fn.lower()
                if cand_lower in VALID_YARAL2_OUTCOME_AGG_FUNCS:
                    outer_agg = cand_lower
                    inner_expr = stripped[m_outer.end() : close_idx].strip()
                elif cand_lower in CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS:
                    outer_agg = CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS[cand_lower]
                    inner_expr = stripped[m_outer.end() : close_idx].strip()

        m_inner = call_head_re.match(inner_expr)
        if m_inner is not None:
            close_inner = _find_matching_paren(inner_expr, m_inner.end() - 1)
            # Allow optional trailing `nocase` outside `)`
            rem_after = inner_expr[close_inner + 1 :].strip() if close_inner != -1 else "x"
            if close_inner != -1 and (not rem_after or rem_after.lower() == "nocase"):
                fn_raw = m_inner.group(1)
                args_str = inner_expr[m_inner.end() : close_inner]
                if rem_after.lower() == "nocase":
                    args_str = f"{args_str} nocase"
                rewritten = _rewrite_single_re_capture_call(fn_raw, args_str)
                if rewritten is not None:
                    canonical_fn, canonical_inner_call, added_group = rewritten
                    wrapped_in_agg = False
                    if outer_agg:
                        replacement = f"{outer_agg}({canonical_inner_call})"
                    elif has_match_section:
                        replacement = f"array_distinct({canonical_inner_call})"
                        wrapped_in_agg = True
                    else:
                        replacement = canonical_inner_call
                    if replacement != stripped:
                        repairs.append(
                            {
                                "defect_type": "invalid_re_capture_syntax",
                                "local_start": lead_ws,
                                "local_end": trail_end,
                                "quote": stripped,
                                "replacement": replacement,
                                "invalid_field": fn_raw.strip(),
                                "canonical_field": canonical_fn,
                                "raw_function_name": fn_raw.strip(),
                                "canonical_function_name": canonical_fn,
                                "canonical_inner_call": canonical_inner_call,
                                "added_capture_group": added_group,
                                "wrapped_in_aggregation": wrapped_in_agg,
                            }
                        )
                    return repairs

    comment_spans = [
        (cm.start(), cm.end())
        for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", expr_text)
    ]
    pos = 0
    while pos < len(expr_text):
        m = call_head_re.search(expr_text, pos)
        if m is None:
            break
        if any(_spans_overlap((m.start(), m.end()), cs) for cs in comment_spans):
            pos = m.end()
            continue
        fn_raw = m.group(1)
        fn_lower = fn_raw.lower()
        open_paren = m.end() - 1
        close_paren = _find_matching_paren(expr_text, open_paren)
        if close_paren == -1:
            pos = m.end()
            continue
        if fn_lower in _YARAL2_RE_CAPTURE_FUNCTION_ALIASES:
            args_str = expr_text[open_paren + 1 : close_paren]
            call_end = close_paren + 1
            nocase_m = re.match(r"^[ \t]+nocase\b", expr_text[call_end:], flags=re.IGNORECASE)
            if nocase_m is not None:
                args_str = f"{args_str} nocase"
                call_end += nocase_m.end()
            rewritten = _rewrite_single_re_capture_call(fn_raw, args_str)
            if rewritten is not None:
                canonical_fn, canonical_call, added_group = rewritten
                call_start = m.start(1)
                orig_slice = expr_text[call_start:call_end]
                if canonical_call != orig_slice:
                    repairs.append(
                        {
                            "defect_type": "invalid_re_capture_syntax",
                            "local_start": call_start,
                            "local_end": call_end,
                            "quote": orig_slice,
                            "replacement": canonical_call,
                            "invalid_field": fn_raw.strip(),
                            "canonical_field": canonical_fn,
                            "raw_function_name": fn_raw.strip(),
                            "canonical_function_name": canonical_fn,
                            "canonical_inner_call": canonical_call,
                            "added_capture_group": added_group,
                            "wrapped_in_aggregation": False,
                        }
                    )
            pos = call_end
        else:
            pos = open_paren + 1

    return repairs


def _inspect_and_repair_yaral2_in_and_reference_lists(
    events_body: str,
    event_vars: list[str] | set[str] | None = None,
) -> list[dict[str, Any]]:
    """Detects and deterministically repairs SQL/SPL/KQL inline ``in (...)`` / ``in [...]``
    value tuples (`invalid_in_membership_syntax`) and malformed Chronicle YARA-L 2.0 (``YL2``)
    Reference List predicates (`invalid_reference_list_syntax`: missing ``%`` sigil, ``= %list``
    or ``!= %list`` instead of ``in %list``, post-field ``not in %list``, or unnormalized list
    identifiers)."""
    if not events_body or not events_body.strip():
        return []

    comment_spans = [
        (cm.start(), cm.end())
        for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", events_body)
    ]
    repairs: list[dict[str, Any]] = []
    handled_spans: list[tuple[int, int]] = []

    # 1. Inline tuple/array membership: $e.field in ("v1", "v2") or $e.field in ["v1", "v2"]
    for m in _YARAL2_IN_TUPLE_RE.finditer(events_body):
        m_span = (m.start(), m.end())
        if any(_spans_overlap(m_span, cs) for cs in comment_spans):
            continue
        var_name = m.group("var")
        event_var = f"${var_name}"
        field_token = m.group("field")
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
            field_token, field_token
        )
        is_negated = bool(m.group("lead_not") or m.group("mid_not"))
        container = m.group("container")
        nocase_suffix = " nocase" if m.group("trail_nocase") else ""
        raw_items = [
            it.strip()
            for it in _split_top_level_comma_args(container[1:-1])
            if it.strip()
        ]
        if not raw_items:
            continue
        normalized_items: list[str] = []
        for it in raw_items:
            if len(it) >= 2 and it[0] == "'" and it[-1] == "'":
                normalized_items.append(f'"{it[1:-1]}"')
            else:
                normalized_items.append(it)
        yaral2_branches = [
            f"{event_var}.{canonical_field} = {lit}{nocase_suffix}"
            for lit in normalized_items
        ]
        disj_expr = (
            f"({' or '.join(yaral2_branches)})"
            if len(yaral2_branches) > 1
            else yaral2_branches[0]
        )
        replacement = f"not {disj_expr}" if is_negated else disj_expr
        udm_branches = [
            f"{canonical_field} = {lit}{nocase_suffix}"
            for lit in normalized_items
        ]
        udm_inner = (
            f"({' OR '.join(udm_branches)})"
            if len(udm_branches) > 1
            else udm_branches[0]
        )
        udm_clause = f"NOT {udm_inner}" if is_negated else udm_inner
        quote = events_body[m.start() : m.end()]
        handled_spans.append(m_span)
        repairs.append(
            {
                "defect_type": "invalid_in_membership_syntax",
                "local_start": m.start(),
                "local_end": m.end(),
                "quote": quote,
                "replacement": replacement,
                "event_var": event_var,
                "field_token": field_token,
                "canonical_field": f"{event_var}.{canonical_field}",
                "invalid_field": f"{event_var}.{field_token}",
                "values": normalized_items,
                "is_negated": is_negated,
                "udm_clause": udm_clause,
            }
        )

    # 2a. Reference list with `=` or `!=` instead of `in`: $e.field = %list_name
    for m in _YARAL2_REF_LIST_EQ_RE.finditer(events_body):
        m_span = (m.start(), m.end())
        if any(_spans_overlap(m_span, cs) for cs in comment_spans):
            continue
        if any(_spans_overlap(m_span, hs) for hs in handled_spans):
            continue
        var_name = m.group("var")
        event_var = f"${var_name}"
        field_token = m.group("field")
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
            field_token, field_token
        )
        op = m.group("op")
        is_negated = bool(m.group("lead_not") or op == "!=")
        mode_raw = m.group("mode")
        mode_str = f"{mode_raw.lower()} " if mode_raw else ""
        list_id_raw = m.group("list_id")
        norm_list = _normalize_yaral2_reference_list_name(list_id_raw)
        prefix_not = "not " if is_negated else ""
        replacement = (
            f"{prefix_not}{event_var}.{canonical_field} in {mode_str}%{norm_list}"
        )
        quote = events_body[m.start() : m.end()]
        handled_spans.append(m_span)
        repairs.append(
            {
                "defect_type": "invalid_reference_list_syntax",
                "local_start": m.start(),
                "local_end": m.end(),
                "quote": quote,
                "replacement": replacement,
                "event_var": event_var,
                "field_token": field_token,
                "invalid_field": f"{op} %{list_id_raw}",
                "canonical_field": f"%{norm_list}",
                "reference_list_name": norm_list,
                "reference_list_token": f"%{norm_list}",
                "match_mode": mode_raw.lower() if mode_raw else "exact",
                "is_negated": is_negated,
            }
        )

    # 2b. Reference list with `in [regex|cidr] <bare_id>` or `$e.field not in %list` or unnormalized `%List-Name`
    for m in _YARAL2_REF_LIST_IN_RE.finditer(events_body):
        m_span = (m.start(), m.end())
        if any(_spans_overlap(m_span, cs) for cs in comment_spans):
            continue
        if any(_spans_overlap(m_span, hs) for hs in handled_spans):
            continue
        list_id_raw = m.group("list_id")
        if list_id_raw.lower() in _YARAL2_RESERVED_KEYWORDS:
            continue
        var_name = m.group("var")
        event_var = f"${var_name}"
        field_token = m.group("field")
        canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
            field_token, field_token
        )
        pct = m.group("pct") or ""
        mid_not = m.group("mid_not")
        lead_not = m.group("lead_not")
        is_negated = bool(lead_not or mid_not)
        mode_raw = m.group("mode")
        mode_str = f"{mode_raw.lower()} " if mode_raw else ""
        norm_list = _normalize_yaral2_reference_list_name(list_id_raw)
        has_ref_list_syntax_defect = bool(
            pct != "%"
            or mid_not is not None
            or list_id_raw != norm_list
            or (mode_raw and mode_raw != mode_raw.lower())
        )
        if not has_ref_list_syntax_defect:
            continue
        prefix_not = "not " if is_negated else ""
        replacement = (
            f"{prefix_not}{event_var}.{canonical_field} in {mode_str}%{norm_list}"
        )
        quote = events_body[m.start() : m.end()]
        handled_spans.append(m_span)
        repairs.append(
            {
                "defect_type": "invalid_reference_list_syntax",
                "local_start": m.start(),
                "local_end": m.end(),
                "quote": quote,
                "replacement": replacement,
                "event_var": event_var,
                "field_token": field_token,
                "invalid_field": f"{pct}{list_id_raw}",
                "canonical_field": f"%{norm_list}",
                "reference_list_name": norm_list,
                "reference_list_token": f"%{norm_list}",
                "match_mode": mode_raw.lower() if mode_raw else "exact",
                "is_negated": is_negated,
            }
        )

    repairs.sort(key=lambda item: int(item["local_start"]))
    return repairs


def _extract_yaral2_reference_lists(rule_text: str) -> list[str]:
    """Extracts ordered, deduplicated canonical ``%<list_name>`` Reference List tokens
    referenced in a YARA-L 2.0 rule's ``events:`` section."""
    if not rule_text:
        return []
    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    ref_lists: list[str] = []
    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name not in ("events", "strings"):
            continue
        b_start = sm.end()
        b_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(b_start, rule_text.rfind("}"))
        )
        sec_body = rule_text[b_start:b_end]
        comment_spans = [
            (cm.start(), cm.end())
            for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", sec_body)
        ]
        for m in _YARAL2_REF_LIST_IN_RE.finditer(sec_body):
            if any(
                _spans_overlap((m.start(), m.end()), cs) for cs in comment_spans
            ):
                continue
            list_id = m.group("list_id")
            if list_id.lower() in _YARAL2_RESERVED_KEYWORDS:
                continue
            token = f"%{_normalize_yaral2_reference_list_name(list_id)}"
            if token not in ref_lists:
                ref_lists.append(token)
        for m in _YARAL2_REF_LIST_EQ_RE.finditer(sec_body):
            if any(
                _spans_overlap((m.start(), m.end()), cs) for cs in comment_spans
            ):
                continue
            list_id = m.group("list_id")
            token = f"%{_normalize_yaral2_reference_list_name(list_id)}"
            if token not in ref_lists:
                ref_lists.append(token)
    return ref_lists


def extract_yaral2_event_predicates(
    rule_text: str,
    rule_char_start: int = 0,
    full_plain_text: str | None = None,
    index_map: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Extracts ordered event predicates and 1-based UTF-16 spans from a YARA-L 2.0 rule's events section.

    Supports both multi-line YARA-L 2.0 (``YL2``) rules and single-line paragraphs
    collapsed by Google Drive Markdown import, returning predicate records that
    map 1-to-1 with :func:`_extract_retrohunt_udm_query_from_yaral2`.
    Preserves parenthesized multi-value ``OR`` disjunctions (and inline ``in (...)``
    tuples) as disjunctive UDM clauses ``(field = "v1" OR field = "v2")`` and
    gracefully strips ``%<list_name>`` Reference List predicates from raw UDM search.
    """
    if not rule_text:
        return []
    if full_plain_text is None:
        full_plain_text = rule_text
    if index_map is None:
        index_map = _build_utf16_index_map(full_plain_text)

    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    raw_items: list[dict[str, Any]] = []

    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name not in ("events", "strings"):
            continue
        b_start = sm.end()
        b_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(b_start, rule_text.rfind("}"))
        )
        sec_body = rule_text[b_start:b_end]
        if not sec_body.strip():
            continue

        comment_spans = [
            (cm.start(), cm.end())
            for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", sec_body)
        ]
        re_spans: list[tuple[int, int]] = []
        cidr_spans: list[tuple[int, int]] = []
        disj_spans: list[tuple[int, int]] = []
        ref_list_spans: list[tuple[int, int]] = []
        func_cmp_spans: list[tuple[int, int]] = []

        # Record Reference List spans so _YARAL2_EVENT_COMPARISON_RE does not emit
        # `%<list_name>` into raw UDM search queries.
        for rl_m in _YARAL2_REF_LIST_IN_RE.finditer(sec_body):
            m_span = (rl_m.start(), rl_m.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            if rl_m.group("list_id").lower() in _YARAL2_RESERVED_KEYWORDS:
                continue
            ref_list_spans.append(m_span)
        for rl_eq_m in _YARAL2_REF_LIST_EQ_RE.finditer(sec_body):
            m_span = (rl_eq_m.start(), rl_eq_m.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            ref_list_spans.append(m_span)

        # Record inline `in (...)` / `in [...]` tuple membership spans and expand to UDM OR disjunctions
        for in_m in _YARAL2_IN_TUPLE_RE.finditer(sec_body):
            m_span = (in_m.start(), in_m.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            disj_spans.append(m_span)
            var_name = in_m.group("var")
            event_var = f"${var_name}"
            field_token = in_m.group("field")
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            is_negated = bool(in_m.group("lead_not") or in_m.group("mid_not"))
            container = in_m.group("container")
            nocase_suffix = " nocase" if in_m.group("trail_nocase") else ""
            raw_vals = [
                it.strip()
                for it in _split_top_level_comma_args(container[1:-1])
                if it.strip()
            ]
            norm_vals = [
                f'"{it[1:-1]}"'
                if (len(it) >= 2 and it[0] == "'" and it[-1] == "'")
                else it
                for it in raw_vals
            ]
            udm_branches = [
                f"{canonical_field} = {lit}{nocase_suffix}" for lit in norm_vals
            ]
            udm_inner = (
                f"({' OR '.join(udm_branches)})"
                if len(udm_branches) > 1
                else (udm_branches[0] if udm_branches else "")
            )
            udm_clause = f"NOT {udm_inner}" if is_negated else udm_inner
            local_predicate_start = b_start + in_m.start(0)
            local_predicate_end = b_start + in_m.end(0)
            local_var_field_start = b_start + in_m.start("var") - 1
            local_var_field_end = b_start + in_m.end("field")
            local_rhs_start = b_start + in_m.start("container")
            local_rhs_end = b_start + in_m.end("container")
            if udm_clause:
                raw_items.append(
                    {
                        "predicate_kind": "or_disjunction",
                        "predicate_text": rule_text[
                            local_predicate_start:local_predicate_end
                        ],
                        "event_var": event_var,
                        "var_field_token": var_field_token,
                        "field_token": field_token,
                        "canonical_field": canonical_field,
                        "operator": "not in" if is_negated else "in",
                        "operator_raw": "not in" if is_negated else "in",
                        "rhs_raw": container,
                        "regex_pattern": None,
                        "has_nocase": bool(nocase_suffix),
                        "udm_clause": udm_clause,
                        "local_predicate_start": local_predicate_start,
                        "local_predicate_end": local_predicate_end,
                        "local_var_field_start": local_var_field_start,
                        "local_var_field_end": local_var_field_end,
                        "local_rhs_start": local_rhs_start,
                        "local_rhs_end": local_rhs_end,
                    }
                )

        # Record parenthesized `($e.f = "v1" or $e.f = "v2")` disjunctions
        for disj_m in _YARAL2_PAREN_OR_DISJUNCTION_RE.finditer(sec_body):
            m_span = (disj_m.start(), disj_m.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            if any(_spans_overlap(m_span, d_span) for d_span in disj_spans):
                continue
            body_text = disj_m.group("body")
            branch_matches = list(_YARAL2_EVENT_COMPARISON_RE.finditer(body_text))
            if len(branch_matches) < 2:
                continue
            disj_spans.append(m_span)
            is_negated = bool(disj_m.group("lead_not"))
            first_bm = branch_matches[0]
            var_name = first_bm.group(1)
            event_var = f"${var_name}"
            field_token = first_bm.group(2)
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            udm_branches: list[str] = []
            for bm in branch_matches:
                b_field_tok = bm.group(2)
                b_canon = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                    b_field_tok, b_field_tok
                )
                b_op = bm.group(3).strip()
                b_rhs = bm.group(4).strip()
                udm_branches.append(f"{b_canon} {b_op} {b_rhs}")
            udm_inner = f"({' OR '.join(udm_branches)})"
            udm_clause = f"NOT {udm_inner}" if is_negated else udm_inner
            local_predicate_start = b_start + disj_m.start(0)
            local_predicate_end = b_start + disj_m.end(0)
            body_offset = b_start + disj_m.start("body")
            local_var_field_start = body_offset + first_bm.start(1) - 1
            local_var_field_end = body_offset + first_bm.end(2)
            local_rhs_start = body_offset + first_bm.start(4)
            local_rhs_end = body_offset + branch_matches[-1].end(4)
            raw_items.append(
                {
                    "predicate_kind": "or_disjunction",
                    "predicate_text": rule_text[
                        local_predicate_start:local_predicate_end
                    ],
                    "event_var": event_var,
                    "var_field_token": var_field_token,
                    "field_token": field_token,
                    "canonical_field": canonical_field,
                    "operator": "or",
                    "operator_raw": "or",
                    "rhs_raw": body_text,
                    "regex_pattern": None,
                    "has_nocase": any(
                        bool(re.search(r"(?i)\bnocase\s*$", bm.group(4).strip()))
                        for bm in branch_matches
                    ),
                    "udm_clause": udm_clause,
                    "local_predicate_start": local_predicate_start,
                    "local_predicate_end": local_predicate_end,
                    "local_var_field_start": local_var_field_start,
                    "local_var_field_end": local_var_field_end,
                    "local_rhs_start": local_rhs_start,
                    "local_rhs_end": local_rhs_end,
                }
            )

        for cidr_match in _YARAL2_CIDR_CALL_RE.finditer(sec_body):
            m_span = (cidr_match.start(), cidr_match.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            cidr_spans.append(m_span)
            func_name = cidr_match.group(1)
            if cidr_match.group(2) is not None:
                var_name = cidr_match.group(2)
                field_token = cidr_match.group(3)
                cidr_raw = cidr_match.group(4)
                arg_order = "field_first"
                local_var_field_start = b_start + cidr_match.start(2) - 1
                local_var_field_end = b_start + cidr_match.end(3)
                local_rhs_start = b_start + cidr_match.start(4)
                local_rhs_end = b_start + cidr_match.end(4)
            else:
                cidr_raw = cidr_match.group(5)
                var_name = cidr_match.group(6)
                field_token = cidr_match.group(7)
                arg_order = "cidr_first"
                local_var_field_start = b_start + cidr_match.start(6) - 1
                local_var_field_end = b_start + cidr_match.end(7)
                local_rhs_start = b_start + cidr_match.start(5)
                local_rhs_end = b_start + cidr_match.end(5)

            event_var = f"${var_name}"
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            cidr_value = cidr_raw.strip("\"'“”")
            canonical_cidr_lit = f'"{cidr_value}"'
            is_valid_cidr_syntax = bool(
                func_name == "net.ip_in_range_cidr"
                and arg_order == "field_first"
                and cidr_raw == canonical_cidr_lit
            )
            canonical_yaral2_call = (
                f"net.ip_in_range_cidr({event_var}.{canonical_field}, {canonical_cidr_lit})"
            )
            udm_clause = (
                f"net.ip_in_range_cidr({canonical_field}, {canonical_cidr_lit})"
            )
            local_predicate_start = b_start + cidr_match.start(0)
            local_predicate_end = b_start + cidr_match.end(0)

            raw_items.append(
                {
                    "predicate_kind": "cidr",
                    "predicate_text": rule_text[
                        local_predicate_start:local_predicate_end
                    ],
                    "event_var": event_var,
                    "var_field_token": var_field_token,
                    "field_token": field_token,
                    "canonical_field": canonical_field,
                    "operator": "net.ip_in_range_cidr",
                    "operator_raw": func_name,
                    "cidr_function": func_name,
                    "cidr_arg_order": arg_order,
                    "is_valid_cidr_syntax": is_valid_cidr_syntax,
                    "cidr_value": cidr_value,
                    "canonical_yaral2_call": canonical_yaral2_call,
                    "rhs_raw": cidr_raw,
                    "regex_pattern": None,
                    "has_nocase": False,
                    "udm_clause": udm_clause,
                    "local_predicate_start": local_predicate_start,
                    "local_predicate_end": local_predicate_end,
                    "local_var_field_start": local_var_field_start,
                    "local_var_field_end": local_var_field_end,
                    "local_rhs_start": local_rhs_start,
                    "local_rhs_end": local_rhs_end,
                }
            )

        for re_match in _YARAL2_RE_REGEX_CALL_RE.finditer(sec_body):
            m_span = (re_match.start(), re_match.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            if any(_spans_overlap(m_span, cd_span) for cd_span in cidr_spans):
                continue
            re_spans.append(m_span)
            var_name = re_match.group(1)
            event_var = f"${var_name}"
            field_token = re_match.group(2)
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            pattern = (
                re_match.group(3)
                or re_match.group(4)
                or re_match.group(5)
                or ""
            )
            if re_match.group(3) is not None:
                rhs_rel_start = re_match.start(3) - 1
                rhs_rel_end = re_match.end(3) + 1
            elif re_match.group(4) is not None:
                rhs_rel_start = re_match.start(4) - 1
                rhs_rel_end = re_match.end(4) + 1
            else:
                rhs_rel_start = re_match.start(5) - 1
                rhs_rel_end = re_match.end(5) + 1

            has_nocase = bool(re_match.group(6) or re_match.group(7))
            udm_clause = (
                f"{canonical_field} = /{pattern}/ nocase"
                if has_nocase
                else f"{canonical_field} = /{pattern}/"
            )
            local_predicate_start = b_start + re_match.start(0)
            local_predicate_end = b_start + re_match.end(0)
            local_var_field_start = b_start + re_match.start(1) - 1
            local_var_field_end = b_start + re_match.end(2)
            local_rhs_start = b_start + rhs_rel_start
            local_rhs_end = b_start + rhs_rel_end

            raw_items.append(
                {
                    "predicate_kind": "re_regex",
                    "predicate_text": rule_text[
                        local_predicate_start:local_predicate_end
                    ],
                    "event_var": event_var,
                    "var_field_token": var_field_token,
                    "field_token": field_token,
                    "canonical_field": canonical_field,
                    "operator": "re.regex",
                    "operator_raw": "re.regex",
                    "rhs_raw": rule_text[local_rhs_start:local_rhs_end],
                    "regex_pattern": pattern,
                    "has_nocase": has_nocase,
                    "udm_clause": udm_clause,
                    "local_predicate_start": local_predicate_start,
                    "local_predicate_end": local_predicate_end,
                    "local_var_field_start": local_var_field_start,
                    "local_var_field_end": local_var_field_end,
                    "local_rhs_start": local_rhs_start,
                    "local_rhs_end": local_rhs_end,
                }
            )

        # Support strings.to_lower / strings.to_upper / lower / upper comparisons in events:
        str_cmp_re = re.compile(
            r"(?i)\b(?:strings\.(?:to_lower|to_upper|lower|upper)|to_lower|to_upper|lower|upper)\s*\(\s*\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*\)\s*(!=|==|=)\s*(\"[^\r\n\"]*\"|'[^\r\n']*'|`[^\r\n`]*`)(?:\s+nocase)?"
        )
        for sc_m in str_cmp_re.finditer(sec_body):
            m_span = (sc_m.start(), sc_m.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
                continue
            func_cmp_spans.append(m_span)
            var_name = sc_m.group(1)
            event_var = f"${var_name}"
            field_token = sc_m.group(2)
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            op = sc_m.group(3).strip()
            rhs_raw = sc_m.group(4).strip()
            udm_clause = f"{canonical_field} {op} {rhs_raw}"
            local_predicate_start = b_start + sc_m.start(0)
            local_predicate_end = b_start + sc_m.end(0)
            local_var_field_start = b_start + sc_m.start(1) - 1
            local_var_field_end = b_start + sc_m.end(2)
            local_rhs_start = b_start + sc_m.start(4)
            local_rhs_end = b_start + sc_m.end(4)
            raw_items.append(
                {
                    "predicate_kind": "comparison",
                    "predicate_text": rule_text[
                        local_predicate_start:local_predicate_end
                    ],
                    "event_var": event_var,
                    "var_field_token": var_field_token,
                    "field_token": field_token,
                    "canonical_field": canonical_field,
                    "operator": op,
                    "operator_raw": op,
                    "rhs_raw": rhs_raw,
                    "regex_pattern": None,
                    "has_nocase": True,
                    "udm_clause": udm_clause,
                    "local_predicate_start": local_predicate_start,
                    "local_predicate_end": local_predicate_end,
                    "local_var_field_start": local_var_field_start,
                    "local_var_field_end": local_var_field_end,
                    "local_rhs_start": local_rhs_start,
                    "local_rhs_end": local_rhs_end,
                }
            )

        for cmp_match in _YARAL2_EVENT_COMPARISON_RE.finditer(sec_body):
            c_span = (cmp_match.start(), cmp_match.end())
            if any(_spans_overlap(c_span, r_span) for r_span in re_spans):
                continue
            if any(_spans_overlap(c_span, cd_span) for cd_span in cidr_spans):
                continue
            if any(_spans_overlap(c_span, d_span) for d_span in disj_spans):
                continue
            if any(_spans_overlap(c_span, rl_span) for rl_span in ref_list_spans):
                continue
            if any(_spans_overlap(c_span, fc_span) for fc_span in func_cmp_spans):
                continue
            if any(_spans_overlap(c_span, cm_span) for cm_span in comment_spans):
                continue
            var_name = cmp_match.group(1)
            event_var = f"${var_name}"
            field_token = cmp_match.group(2)
            var_field_token = f"{event_var}.{field_token}"
            canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                field_token, field_token
            )
            operator_raw = cmp_match.group(3)
            operator = operator_raw.strip()
            rhs_raw = cmp_match.group(4).strip()
            if rhs_raw.startswith("%"):
                continue
            has_nocase = bool(re.search(r"(?i)\bnocase\s*$", rhs_raw))
            udm_clause = f"{canonical_field} {operator} {rhs_raw}"

            local_predicate_start = b_start + cmp_match.start(0)
            local_predicate_end = b_start + cmp_match.end(0)
            local_var_field_start = b_start + cmp_match.start(1) - 1
            local_var_field_end = b_start + cmp_match.end(2)
            local_rhs_start = b_start + cmp_match.start(4)
            local_rhs_end = b_start + cmp_match.end(4)

            raw_items.append(
                {
                    "predicate_kind": "comparison",
                    "predicate_text": rule_text[
                        local_predicate_start:local_predicate_end
                    ],
                    "event_var": event_var,
                    "var_field_token": var_field_token,
                    "field_token": field_token,
                    "canonical_field": canonical_field,
                    "operator": operator,
                    "operator_raw": operator_raw,
                    "rhs_raw": rhs_raw,
                    "regex_pattern": None,
                    "has_nocase": has_nocase,
                    "udm_clause": udm_clause,
                    "local_predicate_start": local_predicate_start,
                    "local_predicate_end": local_predicate_end,
                    "local_var_field_start": local_var_field_start,
                    "local_var_field_end": local_var_field_end,
                    "local_rhs_start": local_rhs_start,
                    "local_rhs_end": local_rhs_end,
                }
            )

    raw_items.sort(key=lambda item: int(item["local_predicate_start"]))

    def _to_utf16_span(local_s: int, local_e: int) -> tuple[int, int]:
        abs_s = rule_char_start + local_s
        abs_e = rule_char_start + local_e - 1
        return (
            index_map[abs_s],
            index_map[abs_e] + _utf16_code_unit_len(full_plain_text[abs_e]),
        )

    predicates: list[dict[str, Any]] = []
    seen_clauses: set[tuple[str, str]] = set()
    for item in raw_items:
        clause = str(item["udm_clause"])
        dedup_key = (str(item["event_var"]), clause)
        if dedup_key in seen_clauses:
            continue
        seen_clauses.add(dedup_key)
        p_start_idx, p_end_idx = _to_utf16_span(
            int(item["local_predicate_start"]),
            int(item["local_predicate_end"]),
        )
        vf_start_idx, vf_end_idx = _to_utf16_span(
            int(item["local_var_field_start"]),
            int(item["local_var_field_end"]),
        )
        rhs_start_idx, rhs_end_idx = _to_utf16_span(
            int(item["local_rhs_start"]),
            int(item["local_rhs_end"]),
        )
        rec = dict(item)
        rec.update(
            {
                "predicate_index": len(predicates),
                "predicate_start_index": p_start_idx,
                "predicate_end_index": p_end_idx,
                "var_field_start_index": vf_start_idx,
                "var_field_end_index": vf_end_idx,
                "rhs_start_index": rhs_start_idx,
                "rhs_end_index": rhs_end_idx,
            }
        )
        predicates.append(rec)

    return predicates


def _classify_udm_field_semantic_type(field_path: str) -> str:
    """Maps a Chronicle UDM field path to its semantic join-key domain."""
    if not field_path:
        return "generic"
    canonical = CANONICAL_UDM_FIELD_CORRECTIONS.get(
        field_path.strip(), field_path.strip()
    ).lower()
    if canonical == "ip" or canonical.endswith(".ip") or canonical.endswith(".nat_ip"):
        return "ip"
    if (
        canonical == "hostname"
        or canonical.endswith(".hostname")
        or canonical.endswith(".administrative_domain")
    ):
        return "hostname"
    if "email" in canonical:
        return "email"
    if (
        canonical.endswith(".userid")
        or canonical.endswith(".user_display_name")
        or canonical.endswith(".windows_sid")
    ):
        return "user"
    if canonical.endswith(".sha256"):
        return "hash_sha256"
    if canonical.endswith(".md5"):
        return "hash_md5"
    if canonical.endswith(".full_path") or canonical.endswith(".file_path"):
        return "file_path"
    if canonical.endswith(".command_line"):
        return "command_line"
    if (
        canonical.endswith(".resource.name")
        or canonical.endswith(".resource.product_object_id")
    ):
        return "resource_name"
    if canonical == "target.url" or canonical.endswith(".url"):
        return "url"
    if canonical.endswith(".port"):
        return "port"
    return "generic"


def _choose_yaral2_outcome_agg_func(
    outcome_var_name: str, canonical_field: str | None = None
) -> str:
    """Selects the canonical Chronicle YARA-L 2.0 outcome aggregation function for an
    unaggregated outcome variable in a rule with a ``match:`` window."""
    v_lower = (outcome_var_name or "").lower()
    f_lower = (canonical_field or "").lower()
    if (
        v_lower.endswith("count")
        or v_lower.endswith("counts")
        or v_lower.endswith("total")
        or v_lower.startswith("count_")
        or v_lower.startswith("num_")
        or v_lower.startswith("unique_")
    ):
        return "count_distinct"
    if (
        any(
            tok in v_lower
            for tok in (
                "score",
                "severity",
                "bytes",
                "port",
                "risk",
                "max",
                "duration",
            )
        )
        or f_lower.endswith(".port")
        or "bytes" in f_lower
        or "score" in f_lower
    ):
        return "max"
    return "array_distinct"


def _split_top_level_comma_args(args_str: str) -> list[str]:
    """Splits a function argument string by commas at parenthesis depth 0 outside quotes."""
    parts: list[str] = []
    cur_start = 0
    depth = 0
    in_quote = False
    quote_ch = ""
    escape = False
    for idx, ch in enumerate(args_str):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_quote:
            if ch == quote_ch:
                in_quote = False
            continue
        if ch in ('"', "'", "`"):
            in_quote = True
            quote_ch = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(args_str[cur_start:idx].strip())
            cur_start = idx + 1
    parts.append(args_str[cur_start:].strip())
    return parts


def _canonicalize_yaral2_expr_fields(expr_str: str) -> str:
    """Canonicalizes ``$<var>.<field>`` UDM paths, CIDR calls, and ``re.regex`` calls inside an expression."""
    if not expr_str:
        return expr_str

    def _replace_cidr(m: re.Match[str]) -> str:
        if m.group(2) is not None:
            v_n = m.group(2)
            f_t = m.group(3)
            c_r = m.group(4)
        else:
            c_r = m.group(5)
            v_n = m.group(6)
            f_t = m.group(7)
        c_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_t, f_t)
        c_v = c_r.strip("\"'“”")
        return f'net.ip_in_range_cidr(${v_n}.{c_f}, "{c_v}")'

    step1 = _YARAL2_CIDR_CALL_RE.sub(_replace_cidr, expr_str)

    def _replace_vf(m: re.Match[str]) -> str:
        v_n = m.group(1)
        f_p = m.group(2)
        c_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_p, f_p)
        return f"${v_n}.{c_f}"

    step2 = _YARAL2_EVENT_FIELD_RE.sub(_replace_vf, step1)
    return _normalize_yaral2_re_regex_calls(step2)


def _try_parse_numeric(val_str: str) -> int | float | None:
    """Attempts to parse an integer or float literal from ``val_str``."""
    s = str(val_str or "").strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return None


def _parse_yaral2_conditional_expr(rhs_text: str) -> dict[str, Any] | None:
    """Parses ``CASE WHEN <cond> THEN <t> ELSE <f> END``, ``iff(<cond>, <t>, <f>)``, and
    ``if(<cond>, <t>, <f>)`` expressions (standalone or wrapped in an aggregation function)."""
    stripped = str(rhs_text or "").strip()
    if not stripped:
        return None

    outer_agg_func: str | None = None
    canonical_outer_agg_func: str | None = None
    inner_text = stripped

    fn_m = _YARAL2_OUTCOME_FUNC_CALL_RE.match(stripped)
    if fn_m is not None:
        fn_name = fn_m.group(1)
        fn_lower = fn_name.lower()
        if fn_lower in VALID_YARAL2_OUTCOME_AGG_FUNCS:
            outer_agg_func = fn_name
            canonical_outer_agg_func = fn_lower
            inner_text = fn_m.group(2).strip()
        elif fn_lower in CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS:
            outer_agg_func = fn_name
            canonical_outer_agg_func = CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS[
                fn_lower
            ]
            inner_text = fn_m.group(2).strip()

    conditional_kind: str | None = None
    is_valid_conditional_syntax = False
    cond_raw = ""
    true_raw = ""
    false_raw = ""

    cw_m = _YARAL2_CASE_WHEN_RE.match(inner_text)
    if cw_m is not None:
        conditional_kind = "case_when"
        is_valid_conditional_syntax = False
        cond_raw = cw_m.group(1).strip()
        true_raw = cw_m.group(2).strip()
        false_raw = cw_m.group(3).strip()
    else:
        if_m = _YARAL2_IF_CALL_RE.match(inner_text)
        if if_m is not None:
            kw = if_m.group(1)
            kw_lower = kw.lower()
            parts = _split_top_level_comma_args(if_m.group(2))
            if len(parts) == 3:
                conditional_kind = "if" if kw_lower == "if" else "iff"
                is_valid_conditional_syntax = bool(kw == "if")
                cond_raw, true_raw, false_raw = parts[0], parts[1], parts[2]

    if conditional_kind is None:
        return None

    canonical_cond = _canonicalize_yaral2_expr_fields(cond_raw)
    canonical_true = _canonicalize_yaral2_expr_fields(true_raw)
    canonical_false = _canonicalize_yaral2_expr_fields(false_raw)
    canonical_if_expr = (
        f"if({canonical_cond}, {canonical_true}, {canonical_false})"
    )

    return {
        "conditional_kind": conditional_kind,
        "is_valid_conditional_syntax": is_valid_conditional_syntax,
        "outer_agg_func": outer_agg_func,
        "canonical_outer_agg_func": canonical_outer_agg_func,
        "condition_expr": cond_raw,
        "canonical_condition_expr": canonical_cond,
        "true_expr": true_raw,
        "false_expr": false_raw,
        "canonical_true_expr": canonical_true,
        "canonical_false_expr": canonical_false,
        "true_value": _try_parse_numeric(true_raw),
        "false_value": _try_parse_numeric(false_raw),
        "canonical_if_expr": canonical_if_expr,
    }


def _find_top_level_outcome_lhs_matches(
    sec_body: str, comment_spans: list[tuple[int, int]]
) -> list[re.Match[str]]:
    """Finds top-level ``$<outcome_var> =`` assignments in an ``outcome:`` section body
    at parenthesis depth 0 outside comments and string literals."""
    depth_at: list[int] = [0] * (len(sec_body) + 1)
    in_str_at: list[bool] = [False] * (len(sec_body) + 1)
    depth = 0
    in_quote = False
    quote_ch = ""
    escape = False
    for idx, ch in enumerate(sec_body):
        depth_at[idx] = depth
        in_str_at[idx] = in_quote
        if any(c_s <= idx < c_e for c_s, c_e in comment_spans):
            continue
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_quote:
            if ch == quote_ch:
                in_quote = False
            continue
        if ch in ('"', "'", "`"):
            in_quote = True
            quote_ch = ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")" and depth > 0:
            depth -= 1

    matches: list[re.Match[str]] = []
    for m in _YARAL2_OUTCOME_LHS_RE.finditer(sec_body):
        m_span = (m.start(), m.end())
        if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
            continue
        if in_str_at[m.start()] or depth_at[m.start()] != 0:
            continue
        prefix = sec_body[: m.start()].rstrip(" \t")
        if prefix.endswith(("=", "!", "<", ">")):
            continue
        matches.append(m)
    return matches


def _find_outcome_rhs_bounds(
    sec_body: str, rhs_slice_start: int, rhs_slice_end: int
) -> tuple[int, int]:
    """Determines the trimmed ``(start, end)`` local indices inside ``sec_body`` for an
    ``outcome:`` assignment's right-hand side expression."""
    cur = rhs_slice_start
    while cur < rhs_slice_end and sec_body[cur] in (" ", "\t", "\r", "\n"):
        cur += 1
    expr_start = cur
    depth = 0
    in_quote = False
    quote_ch = ""
    escape = False
    expr_end = rhs_slice_end
    for idx in range(expr_start, rhs_slice_end):
        ch = sec_body[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_quote:
            if ch == quote_ch:
                in_quote = False
            continue
        if ch in ('"', "'", "`"):
            in_quote = True
            quote_ch = ch
            continue
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            continue
        if depth == 0:
            if sec_body[idx : idx + 2] == "//":
                expr_end = idx
                break
            if ch in ("\r", "\n"):
                expr_end = idx
                break
    while expr_end > expr_start and sec_body[expr_end - 1] in (
        " ",
        "\t",
        "\r",
        "\n",
    ):
        expr_end -= 1
    return expr_start, expr_end


def extract_yaral2_multi_event_spec(
    rule_text: str,
    rule_char_start: int = 0,
    full_plain_text: str | None = None,
    index_map: list[int] | None = None,
) -> dict[str, Any]:
    """Parses multi-line and Drive-collapsed single-line YARA-L 2.0 (``YL2``) rules into
    per-event-stream UDM queries, cross-event join bindings, ``match:`` clauses,
    ``outcome:`` variable bindings (including ``CASE WHEN`` / ``iff()`` / ``if()`` conditionals),
    ``condition:`` variable tokens, and ``condition_outcome_comparisons`` with exact 1-based UTF-16 spans.
    """
    if full_plain_text is None:
        full_plain_text = rule_text
    if index_map is None:
        index_map = _build_utf16_index_map(full_plain_text)

    def _to_utf16_span(local_s: int, local_e: int) -> tuple[int, int]:
        abs_s = rule_char_start + local_s
        abs_e = rule_char_start + local_e - 1
        return (
            index_map[abs_s],
            index_map[abs_e] + _utf16_code_unit_len(full_plain_text[abs_e]),
        )

    predicates = extract_yaral2_event_predicates(
        rule_text,
        rule_char_start=rule_char_start,
        full_plain_text=full_plain_text,
        index_map=index_map,
    )

    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    event_vars: list[str] = []
    event_var_names: list[str] = []
    raw_join_bindings: list[dict[str, Any]] = []
    join_placeholders: list[str] = []
    match_clauses: list[dict[str, Any]] = []
    outcome_vars: list[str] = []
    outcome_var_names: list[str] = []
    outcome_bindings: list[dict[str, Any]] = []
    outcome_conditionals: list[dict[str, Any]] = []
    condition_tokens: list[dict[str, Any]] = []
    condition_negation_spans: list[dict[str, Any]] = []
    condition_outcome_comparisons: list[dict[str, Any]] = []
    condition_span: dict[str, Any] | None = None

    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        b_start = sm.end()
        b_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(b_start, rule_text.rfind("}"))
        )
        sec_body = rule_text[b_start:b_end]
        if not sec_body.strip():
            continue

        comment_spans = [
            (cm.start(), cm.end())
            for cm in re.finditer(r"(?m)^[ \t]*//[^\r\n]*", sec_body)
        ]

        if sec_name in ("events", "strings"):
            for ev_m in _YARAL2_EVENT_FIELD_RE.finditer(sec_body):
                if any(
                    _spans_overlap((ev_m.start(), ev_m.end()), c_span)
                    for c_span in comment_spans
                ):
                    continue
                vname = ev_m.group(1)
                ev_tok = f"${vname}"
                if ev_tok not in event_vars:
                    event_vars.append(ev_tok)
                    event_var_names.append(vname)

            rhs_binding_spans: list[tuple[int, int]] = []
            for jb_m in _YARAL2_JOIN_RHS_BINDING_RE.finditer(sec_body):
                jb_span = (jb_m.start(), jb_m.end())
                if any(_spans_overlap(jb_span, c_span) for c_span in comment_spans):
                    continue
                rhs_binding_spans.append(jb_span)
                var_name = jb_m.group(1)
                event_var = f"${var_name}"
                field_token = jb_m.group(2)
                var_field_token = f"{event_var}.{field_token}"
                canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                    field_token, field_token
                )
                operator_raw = jb_m.group(3)
                operator = operator_raw.strip()
                ph_name = jb_m.group(4)
                ph_var = f"${ph_name}"

                local_binding_start = b_start + jb_m.start(0)
                local_binding_end = b_start + jb_m.end(0)
                local_vf_start = b_start + jb_m.start(1) - 1
                local_vf_end = b_start + jb_m.end(2)
                local_ph_start = b_start + jb_m.start(4) - 1
                local_ph_end = b_start + jb_m.end(4)

                raw_join_bindings.append(
                    {
                        "binding_text": rule_text[local_binding_start:local_binding_end],
                        "event_var": event_var,
                        "var_field_token": var_field_token,
                        "field_token": field_token,
                        "canonical_field": canonical_field,
                        "semantic_type": _classify_udm_field_semantic_type(
                            canonical_field
                        ),
                        "operator": operator,
                        "operator_raw": operator_raw,
                        "placeholder_var": ph_var,
                        "placeholder_name": ph_name,
                        "local_binding_start": local_binding_start,
                        "local_binding_end": local_binding_end,
                        "local_var_field_start": local_vf_start,
                        "local_var_field_end": local_vf_end,
                        "local_placeholder_start": local_ph_start,
                        "local_placeholder_end": local_ph_end,
                    }
                )

            for jb_m in _YARAL2_JOIN_LHS_BINDING_RE.finditer(sec_body):
                jb_span = (jb_m.start(), jb_m.end())
                if any(_spans_overlap(jb_span, c_span) for c_span in comment_spans):
                    continue
                if any(_spans_overlap(jb_span, r_span) for r_span in rhs_binding_spans):
                    continue
                ph_name = jb_m.group(1)
                ph_var = f"${ph_name}"
                operator_raw = jb_m.group(2)
                operator = operator_raw.strip()
                var_name = jb_m.group(3)
                event_var = f"${var_name}"
                field_token = jb_m.group(4)
                var_field_token = f"{event_var}.{field_token}"
                canonical_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                    field_token, field_token
                )

                local_binding_start = b_start + jb_m.start(0)
                local_binding_end = b_start + jb_m.end(0)
                local_ph_start = b_start + jb_m.start(1) - 1
                local_ph_end = b_start + jb_m.end(1)
                local_vf_start = b_start + jb_m.start(3) - 1
                local_vf_end = b_start + jb_m.end(4)

                raw_join_bindings.append(
                    {
                        "binding_text": rule_text[local_binding_start:local_binding_end],
                        "event_var": event_var,
                        "var_field_token": var_field_token,
                        "field_token": field_token,
                        "canonical_field": canonical_field,
                        "semantic_type": _classify_udm_field_semantic_type(
                            canonical_field
                        ),
                        "operator": operator,
                        "operator_raw": operator_raw,
                        "placeholder_var": ph_var,
                        "placeholder_name": ph_name,
                        "local_binding_start": local_binding_start,
                        "local_binding_end": local_binding_end,
                        "local_var_field_start": local_vf_start,
                        "local_var_field_end": local_vf_end,
                        "local_placeholder_start": local_ph_start,
                        "local_placeholder_end": local_ph_end,
                    }
                )

        elif sec_name == "match":
            for mc_m in _YARAL2_MATCH_CLAUSE_RE.finditer(sec_body):
                mc_span = (mc_m.start(), mc_m.end())
                if any(_spans_overlap(mc_span, c_span) for c_span in comment_spans):
                    continue
                prefix_slice = sec_body[: mc_m.start()]
                if re.search(r"(?i)\b(?:before|after)[ \t]+$", prefix_slice):
                    continue

                vars_group_start = b_start + mc_m.start(1)
                vars_group_text = mc_m.group(1)
                placeholders_list: list[dict[str, Any]] = []
                for ph_tok_m in re.finditer(
                    r"\$([A-Za-z_][A-Za-z0-9_]*)", vars_group_text
                ):
                    loc_s = vars_group_start + ph_tok_m.start(0)
                    loc_e = vars_group_start + ph_tok_m.end(0)
                    u_s, u_e = _to_utf16_span(loc_s, loc_e)
                    placeholders_list.append(
                        {
                            "placeholder_var": ph_tok_m.group(0),
                            "placeholder_name": ph_tok_m.group(1),
                            "local_start": loc_s,
                            "local_end": loc_e,
                            "placeholder_start_index": u_s,
                            "placeholder_end_index": u_e,
                        }
                    )

                window_raw = mc_m.group(2)
                local_win_start: int | None = None
                local_win_end: int | None = None
                win_start_idx: int | None = None
                win_end_idx: int | None = None
                window_valid = False
                window_normalized: str | None = None

                if window_raw is not None:
                    local_win_start = b_start + mc_m.start(2)
                    local_win_end = b_start + mc_m.end(2)
                    win_start_idx, win_end_idx = _to_utf16_span(
                        local_win_start, local_win_end
                    )
                    dur_num = mc_m.group(4) or ""
                    dur_unit_raw = (mc_m.group(5) or "").lower()
                    norm_unit = _YARAL2_TIME_UNIT_MAP.get(dur_unit_raw)
                    if norm_unit and dur_num:
                        window_normalized = f"over {dur_num}{norm_unit}"
                        window_valid = bool(window_raw == window_normalized)

                loc_clause_s = b_start + mc_m.start(0)
                loc_clause_e = b_start + mc_m.end(0)
                c_start_idx, c_end_idx = _to_utf16_span(loc_clause_s, loc_clause_e)
                first_ph = placeholders_list[0] if placeholders_list else {}
                match_clauses.append(
                    {
                        "clause_index": len(match_clauses),
                        "clause_text": rule_text[loc_clause_s:loc_clause_e],
                        "local_clause_start": loc_clause_s,
                        "local_clause_end": loc_clause_e,
                        "clause_start_index": c_start_idx,
                        "clause_end_index": c_end_idx,
                        "placeholders": placeholders_list,
                        "placeholder_var": first_ph.get("placeholder_var"),
                        "placeholder_name": first_ph.get("placeholder_name"),
                        "local_placeholder_start": first_ph.get("local_start"),
                        "local_placeholder_end": first_ph.get("local_end"),
                        "placeholder_start_index": first_ph.get(
                            "placeholder_start_index"
                        ),
                        "placeholder_end_index": first_ph.get("placeholder_end_index"),
                        "window_raw": window_raw,
                        "window_valid": window_valid,
                        "window_normalized": window_normalized,
                        "local_window_start": local_win_start,
                        "local_window_end": local_win_end,
                        "window_start_index": win_start_idx,
                        "window_end_index": win_end_idx,
                    }
                )

        elif sec_name == "outcome":
            lhs_matches = _find_top_level_outcome_lhs_matches(sec_body, comment_spans)
            for k, lhs_m in enumerate(lhs_matches):
                out_var_name = lhs_m.group(1)
                out_var = f"${out_var_name}"
                if out_var not in outcome_vars:
                    outcome_vars.append(out_var)
                    outcome_var_names.append(out_var_name)

                rhs_slice_start = lhs_m.end()
                rhs_slice_end = (
                    lhs_matches[k + 1].start()
                    if k + 1 < len(lhs_matches)
                    else len(sec_body)
                )
                rhs_rel_s, rhs_rel_e = _find_outcome_rhs_bounds(
                    sec_body, rhs_slice_start, rhs_slice_end
                )
                if rhs_rel_e <= rhs_rel_s:
                    continue

                local_var_start = b_start + lhs_m.start(0)
                local_var_end = b_start + lhs_m.end(1)
                local_rhs_start = b_start + rhs_rel_s
                local_rhs_end = b_start + rhs_rel_e
                local_binding_start = local_var_start
                local_binding_end = local_rhs_end

                rhs_text = rule_text[local_rhs_start:local_rhs_end]
                func_name: str | None = None
                canonical_func_name: str | None = None
                is_valid_agg_func = False
                is_non_canonical_agg_func = False
                local_func_start: int | None = None
                local_func_end: int | None = None
                func_start_idx: int | None = None
                func_end_idx: int | None = None

                fn_m = _YARAL2_OUTCOME_FUNC_CALL_RE.match(rhs_text)
                if fn_m is not None:
                    func_name = fn_m.group(1)
                    fn_lower = func_name.lower()
                    local_func_start = local_rhs_start + fn_m.start(1)
                    local_func_end = local_rhs_start + fn_m.end(1)
                    func_start_idx, func_end_idx = _to_utf16_span(
                        local_func_start, local_func_end
                    )
                    if fn_lower in VALID_YARAL2_OUTCOME_AGG_FUNCS:
                        is_valid_agg_func = True
                        canonical_func_name = fn_lower
                    elif fn_lower in CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS:
                        is_non_canonical_agg_func = True
                        canonical_func_name = (
                            CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS[fn_lower]
                        )

                cond_spec = _parse_yaral2_conditional_expr(rhs_text)

                ref_event_vars: list[str] = []
                ref_event_fields: list[dict[str, Any]] = []
                for ef_m in _YARAL2_EVENT_FIELD_RE.finditer(rhs_text):
                    ev_n = ef_m.group(1)
                    ev_tok = f"${ev_n}"
                    f_tok = ef_m.group(2)
                    c_field = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
                    if ev_tok not in ref_event_vars:
                        ref_event_vars.append(ev_tok)
                    if ev_tok not in event_vars and ev_n not in outcome_var_names:
                        event_vars.append(ev_tok)
                        event_var_names.append(ev_n)
                    ef_loc_s = local_rhs_start + ef_m.start(0)
                    ef_loc_e = local_rhs_start + ef_m.end(0)
                    ref_event_fields.append(
                        {
                            "event_var": ev_tok,
                            "field_token": f_tok,
                            "canonical_field": c_field,
                            "var_field_token": f"{ev_tok}.{f_tok}",
                            "local_start": ef_loc_s,
                            "local_end": ef_loc_e,
                        }
                    )

                is_aggregated = bool(is_valid_agg_func)
                bind_u_s, bind_u_e = _to_utf16_span(
                    local_binding_start, local_binding_end
                )
                var_u_s, var_u_e = _to_utf16_span(local_var_start, local_var_end)
                rhs_u_s, rhs_u_e = _to_utf16_span(local_rhs_start, local_rhs_end)

                if cond_spec is not None:
                    cond_spec_enriched = dict(cond_spec)
                    cond_spec_enriched.update(
                        {
                            "outcome_var": out_var,
                            "outcome_var_name": out_var_name,
                            "rhs_text": rhs_text,
                            "local_rhs_start": local_rhs_start,
                            "local_rhs_end": local_rhs_end,
                            "rhs_start_index": rhs_u_s,
                            "rhs_end_index": rhs_u_e,
                        }
                    )
                    outcome_conditionals.append(cond_spec_enriched)
                else:
                    cond_spec_enriched = None

                outcome_bindings.append(
                    {
                        "binding_index": len(outcome_bindings),
                        "outcome_var": out_var,
                        "outcome_var_name": out_var_name,
                        "binding_text": rule_text[
                            local_binding_start:local_binding_end
                        ],
                        "rhs_text": rhs_text,
                        "func_name": func_name,
                        "canonical_func_name": canonical_func_name,
                        "is_valid_agg_func": is_valid_agg_func,
                        "is_non_canonical_agg_func": is_non_canonical_agg_func,
                        "is_aggregated": is_aggregated,
                        "is_conditional": bool(cond_spec_enriched is not None),
                        "is_valid_conditional_syntax": (
                            bool(cond_spec_enriched["is_valid_conditional_syntax"])
                            if cond_spec_enriched is not None
                            else True
                        ),
                        "conditional_spec": cond_spec_enriched,
                        "referenced_event_vars": ref_event_vars,
                        "referenced_event_fields": [
                            str(item["var_field_token"])
                            for item in ref_event_fields
                        ],
                        "referenced_event_field_specs": ref_event_fields,
                        "local_binding_start": local_binding_start,
                        "local_binding_end": local_binding_end,
                        "binding_start_index": bind_u_s,
                        "binding_end_index": bind_u_e,
                        "local_var_start": local_var_start,
                        "local_var_end": local_var_end,
                        "var_start_index": var_u_s,
                        "var_end_index": var_u_e,
                        "local_rhs_start": local_rhs_start,
                        "local_rhs_end": local_rhs_end,
                        "rhs_local_start": local_rhs_start,
                        "rhs_local_end": local_rhs_end,
                        "rhs_start_index": rhs_u_s,
                        "rhs_end_index": rhs_u_e,
                        "local_func_start": local_func_start,
                        "local_func_end": local_func_end,
                        "func_local_start": local_func_start,
                        "func_local_end": local_func_end,
                        "func_start_index": func_start_idx,
                        "func_end_index": func_end_idx,
                    }
                )

        elif sec_name == "condition":
            # Trim comments and surrounding whitespace to locate the condition expression span
            cleaned_lines: list[tuple[int, int]] = []
            for line_m in re.finditer(r"[^\r\n]+", sec_body):
                l_text = line_m.group(0)
                c_pos = l_text.find("//")
                eff_text = l_text[:c_pos] if c_pos != -1 else l_text
                stripped = eff_text.strip()
                if not stripped:
                    continue
                l_lead = len(eff_text) - len(eff_text.lstrip())
                l_trail = len(eff_text.rstrip())
                cleaned_lines.append(
                    (line_m.start() + l_lead, line_m.start() + l_trail)
                )
            if cleaned_lines:
                loc_cond_s = b_start + cleaned_lines[0][0]
                loc_cond_e = b_start + cleaned_lines[-1][1]
                cond_u_s, cond_u_e = _to_utf16_span(loc_cond_s, loc_cond_e)
                condition_span = {
                    "condition_text": rule_text[loc_cond_s:loc_cond_e],
                    "local_start": loc_cond_s,
                    "local_end": loc_cond_e,
                    "start_index": cond_u_s,
                    "end_index": cond_u_e,
                }

            not_span_by_var_start: dict[int, dict[str, Any]] = {}
            for nm in _YARAL2_COND_NOT_VAR_RE.finditer(sec_body):
                n_span = (nm.start(), nm.end())
                if any(_spans_overlap(n_span, cs) for cs in comment_spans):
                    continue
                sigil = nm.group(2)
                v_name = nm.group(3)
                loc_s = b_start + nm.start(0)
                loc_e = b_start + nm.end(0)
                var_loc_s = b_start + nm.start(2)
                u_s, u_e = _to_utf16_span(loc_s, loc_e)
                neg_rec = {
                    "negation_text": rule_text[loc_s:loc_e],
                    "quote": rule_text[loc_s:loc_e],
                    "sigil": sigil,
                    "var_name": v_name,
                    "event_var": f"${v_name}",
                    "replacement": f"!{sigil}{v_name}",
                    "local_start": loc_s,
                    "local_end": loc_e,
                    "local_var_start": var_loc_s,
                    "start_index": u_s,
                    "end_index": u_e,
                }
                condition_negation_spans.append(neg_rec)
                not_span_by_var_start[var_loc_s] = neg_rec

            for cm in _YARAL2_COND_VAR_RE.finditer(sec_body):
                c_span = (cm.start(), cm.end())
                if any(_spans_overlap(c_span, cs) for cs in comment_spans):
                    continue
                sigil = cm.group(1)
                v_name = cm.group(2)
                loc_s = b_start + cm.start(0)
                loc_e = b_start + cm.end(0)
                u_s, u_e = _to_utf16_span(loc_s, loc_e)

                prefix = sec_body[: cm.start(0)]
                suffix = sec_body[cm.end(0) :]
                has_bang = prefix.rstrip(" \t").endswith("!")
                not_span_info = not_span_by_var_start.get(loc_s)
                is_zero_cardinality = bool(
                    sigil == "#"
                    and (
                        re.match(r"^[ \t]*(?:==?[ \t]*0\b|<[ \t]*1\b)", suffix)
                        or re.search(r"\b0[ \t]*==?[ \t]*$", prefix)
                    )
                )
                is_negated = bool(
                    has_bang or not_span_info is not None or is_zero_cardinality
                )
                in_comparison = bool(
                    sigil == "#"
                    or re.match(
                        r"^[ \t]*(?:>=|<=|!=|==|=|>|<)[ \t]*-?\d+", suffix
                    )
                    or re.search(
                        r"-?\d+[ \t]*(?:>=|<=|!=|==|=|>|<)[ \t]*$", prefix
                    )
                )
                condition_tokens.append(
                    {
                        "sigil": sigil,
                        "var_name": v_name,
                        "token_text": f"{sigil}{v_name}",
                        "var_token": f"{sigil}{v_name}",
                        "is_negated": is_negated,
                        "in_comparison": in_comparison,
                        "local_start": loc_s,
                        "local_end": loc_e,
                        "start_index": u_s,
                        "end_index": u_e,
                    }
                )

            for oc_m in _YARAL2_COND_OUTCOME_CMP_RE.finditer(sec_body):
                oc_span = (oc_m.start(), oc_m.end())
                if any(_spans_overlap(oc_span, cs) for cs in comment_spans):
                    continue
                v_name = oc_m.group(1)
                out_var = f"${v_name}"
                op_raw = oc_m.group(2)
                op_str = oc_m.group(3)
                rhs_str = oc_m.group(4)
                try:
                    thresh_val = int(rhs_str)
                except ValueError:
                    continue
                loc_cmp_s = b_start + oc_m.start(0)
                loc_cmp_e = b_start + oc_m.end(0)
                loc_var_s = b_start + oc_m.start(0)
                loc_var_e = b_start + oc_m.end(1)
                loc_rhs_s = b_start + oc_m.start(4)
                loc_rhs_e = b_start + oc_m.end(4)
                cmp_u_s, cmp_u_e = _to_utf16_span(loc_cmp_s, loc_cmp_e)
                var_u_s, var_u_e = _to_utf16_span(loc_var_s, loc_var_e)
                rhs_u_s, rhs_u_e = _to_utf16_span(loc_rhs_s, loc_rhs_e)
                condition_outcome_comparisons.append(
                    {
                        "comparison_index": len(condition_outcome_comparisons),
                        "comparison_text": rule_text[loc_cmp_s:loc_cmp_e],
                        "outcome_var": out_var,
                        "outcome_var_name": v_name,
                        "is_declared_outcome_var": bool(
                            v_name in outcome_var_names
                        ),
                        "operator": op_str,
                        "operator_raw": op_raw,
                        "threshold_raw": rhs_str,
                        "threshold_value": thresh_val,
                        "local_comparison_start": loc_cmp_s,
                        "local_comparison_end": loc_cmp_e,
                        "local_var_start": loc_var_s,
                        "local_var_end": loc_var_e,
                        "local_rhs_start": loc_rhs_s,
                        "local_rhs_end": loc_rhs_e,
                        "comparison_start_index": cmp_u_s,
                        "comparison_end_index": cmp_u_e,
                        "var_start_index": var_u_s,
                        "var_end_index": var_u_e,
                        "rhs_start_index": rhs_u_s,
                        "rhs_end_index": rhs_u_e,
                    }
                )

    raw_join_bindings.sort(key=lambda item: int(item["local_binding_start"]))
    join_bindings: list[dict[str, Any]] = []
    for item in raw_join_bindings:
        b_s, b_e = _to_utf16_span(
            int(item["local_binding_start"]), int(item["local_binding_end"])
        )
        vf_s, vf_e = _to_utf16_span(
            int(item["local_var_field_start"]), int(item["local_var_field_end"])
        )
        ph_s, ph_e = _to_utf16_span(
            int(item["local_placeholder_start"]), int(item["local_placeholder_end"])
        )
        rec = dict(item)
        rec.update(
            {
                "binding_index": len(join_bindings),
                "binding_start_index": b_s,
                "binding_end_index": b_e,
                "var_field_start_index": vf_s,
                "var_field_end_index": vf_e,
                "placeholder_start_index": ph_s,
                "placeholder_end_index": ph_e,
            }
        )
        join_bindings.append(rec)
        ph_var = str(item["placeholder_var"])
        if ph_var not in join_placeholders:
            join_placeholders.append(ph_var)

    negated_event_vars: list[str] = []
    for ct in condition_tokens:
        v_name = str(ct["var_name"])
        ev_tok = f"${v_name}"
        if ct.get("is_negated") and ev_tok in event_vars:
            if ev_tok not in negated_event_vars:
                negated_event_vars.append(ev_tok)
    positive_event_vars: list[str] = [
        ev for ev in event_vars if ev not in negated_event_vars
    ]
    is_non_existence = bool(negated_event_vars)

    per_event_predicates: dict[str, list[dict[str, Any]]] = {
        ev: [] for ev in event_vars
    }
    for pred in predicates:
        ev = str(pred["event_var"])
        per_event_predicates.setdefault(ev, []).append(pred)

    per_event_udm_queries: dict[str, str] = {
        ev: " AND ".join(str(p["udm_clause"]) for p in preds)
        for ev, preds in per_event_predicates.items()
    }
    reference_lists = _extract_yaral2_reference_lists(rule_text)

    return {
        "event_vars": event_vars,
        "event_var_names": event_var_names,
        "positive_event_vars": positive_event_vars,
        "negated_event_vars": negated_event_vars,
        "is_non_existence": is_non_existence,
        "is_multi_event": len(event_vars) >= 2,
        "predicates": predicates,
        "per_event_predicates": per_event_predicates,
        "per_event_udm_queries": per_event_udm_queries,
        "reference_lists": reference_lists,
        "join_bindings": join_bindings,
        "join_placeholders": join_placeholders,
        "match_clauses": match_clauses,
        "outcome_vars": outcome_vars,
        "outcome_var_names": outcome_var_names,
        "outcome_bindings": outcome_bindings,
        "outcome_conditionals": outcome_conditionals,
        "condition_tokens": condition_tokens,
        "condition_negation_spans": condition_negation_spans,
        "condition_outcome_comparisons": condition_outcome_comparisons,
        "condition_span": condition_span,
    }


def extract_yaral2_event_streams(
    rule_text: str,
    rule_char_start: int = 0,
    full_plain_text: str | None = None,
    index_map: list[int] | None = None,
) -> dict[str, Any]:
    """Extracts per-event-stream UDM queries, predicates, and Reference List metadata
    (``reference_lists``) from a single-event or multi-event YARA-L 2.0 (``YL2``) rule."""
    spec = extract_yaral2_multi_event_spec(
        rule_text,
        rule_char_start=rule_char_start,
        full_plain_text=full_plain_text,
        index_map=index_map,
    )
    retrohunt_query, retrohunt_clauses = _extract_retrohunt_udm_query_from_yaral2(
        rule_text
    )
    return {
        "event_vars": spec["event_vars"],
        "positive_event_vars": spec["positive_event_vars"],
        "negated_event_vars": spec["negated_event_vars"],
        "is_multi_event": spec["is_multi_event"],
        "is_non_existence": spec["is_non_existence"],
        "predicates": spec["predicates"],
        "per_event_predicates": spec["per_event_predicates"],
        "per_event_udm_queries": spec["per_event_udm_queries"],
        "retrohunt_udm_query": retrohunt_query,
        "retrohunt_clauses": retrohunt_clauses,
        "reference_lists": spec["reference_lists"],
        "join_bindings": spec["join_bindings"],
    }


def _extract_retrohunt_udm_query_from_yaral2(
    rule_text: str,
) -> tuple[str, list[str]]:
    """Extracts a Chronicle UDM retrohunt search query and clause list from a YARA-L 2.0 rule's events section."""
    predicates = extract_yaral2_event_predicates(rule_text)
    clauses: list[str] = []
    for p in predicates:
        c = str(p["udm_clause"])
        if c not in clauses:
            clauses.append(c)
    return " AND ".join(clauses), clauses


def _select_best_outcome_var_for_condition_token(
    cond_var: str,
    in_comparison: bool,
    candidate_outcome_vars: list[str],
    outcome_bindings: list[dict[str, Any]],
) -> str:
    """Chooses the best matching declared ``outcome:`` variable name for an undeclared
    ``condition:`` variable token."""
    if len(candidate_outcome_vars) == 1:
        return candidate_outcome_vars[0]
    cond_parts = {p for p in cond_var.lower().split("_") if p}
    binding_by_name = {
        str(ob["outcome_var_name"]): ob for ob in outcome_bindings
    }
    best_var = candidate_outcome_vars[0]
    best_score = -1
    for cand in candidate_outcome_vars:
        cand_lower = cand.lower()
        cand_parts = {p for p in cand_lower.split("_") if p}
        score = len(cond_parts & cand_parts) * 10
        ob = binding_by_name.get(cand, {})
        c_func = str(ob.get("canonical_func_name") or ob.get("func_name") or "").lower()
        if in_comparison:
            if c_func in ("count_distinct", "count", "max", "min", "sum") or any(
                tok in cand_lower
                for tok in ("count", "score", "total", "risk", "severity", "max")
            ):
                score += 5
            elif c_func in ("array_distinct", "array"):
                score -= 3
        if score > best_score:
            best_score = score
            best_var = cand
    return best_var


_YARAL2_META_ENTRY_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(?:"([^"\r\n]*)"|\'([^\'\r\n]*)\'|([^\s"\'\r\n]+))'
)


def extract_yaral2_meta_spec(
    rule_text: str,
    rule_char_start: int = 0,
    full_plain_text: str | None = None,
    index_map: list[int] | None = None,
) -> dict[str, Any]:
    """Parses the ``meta:`` section of a multi-line or Drive-collapsed single-line
    YARA-L 2.0 (``YL2``) rule and returns ordered key-value entries with exact
    1-based UTF-16 spans and an ``insertion_anchor`` for synthesizing missing keys.
    """
    src_text = full_plain_text if full_plain_text is not None else rule_text
    if index_map is None:
        index_map = _build_utf16_index_map(src_text)

    def _local_span_to_utf16(local_s: int, local_e: int) -> tuple[int, int]:
        if local_e <= local_s:
            abs_s = rule_char_start + local_s
            idx = index_map[abs_s] if 0 <= abs_s < len(index_map) else 1
            return idx, idx
        abs_s = rule_char_start + local_s
        abs_e = rule_char_start + local_e - 1
        s_idx = index_map[abs_s]
        e_idx = index_map[abs_e] + _utf16_code_unit_len(src_text[abs_e])
        return s_idx, e_idx

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = str(blocks[0]["rule_name"]) if blocks else "unknown_rule"

    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    meta_sec: dict[str, Any] | None = None
    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name != "meta":
            continue
        token_text = sm.group(0).lstrip(" \t")
        token_local_start = sm.end() - len(token_text)
        token_local_end = sm.end()
        body_local_start = sm.end()
        body_local_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(body_local_start, rule_text.rfind("}"))
        )
        meta_sec = {
            "token_text": token_text,
            "token_start": token_local_start,
            "token_end": token_local_end,
            "body_start": body_local_start,
            "body_end": body_local_end,
            "body": rule_text[body_local_start:body_local_end],
        }
        break

    if meta_sec is None:
        return {
            "rule_name": rule_name,
            "has_meta": False,
            "meta_token": "",
            "local_meta_token_start": 0,
            "local_meta_token_end": 0,
            "meta_token_start_index": 1,
            "meta_token_end_index": 1,
            "is_collapsed": False,
            "indent": "    ",
            "entries": [],
            "entries_by_key": {},
            "insertion_anchor": None,
        }

    tok_start = int(meta_sec["token_start"])
    tok_end = int(meta_sec["token_end"])
    tok_s_idx, tok_e_idx = _local_span_to_utf16(tok_start, tok_end)
    body_start = int(meta_sec["body_start"])
    meta_body = str(meta_sec["body"])

    entries: list[dict[str, Any]] = []
    entries_by_key: dict[str, dict[str, Any]] = {}
    for m in _YARAL2_META_ENTRY_RE.finditer(meta_body):
        key = m.group(1).strip()
        local_entry_start = body_start + m.start(0)
        local_entry_end = body_start + m.end(0)
        entry_text = rule_text[local_entry_start:local_entry_end]
        if m.group(2) is not None:
            val_str = m.group(2)
            local_val_inner_start = body_start + m.start(2)
            local_val_inner_end = body_start + m.end(2)
            local_val_start = local_val_inner_start - 1
            local_val_end = local_val_inner_end + 1
        elif m.group(3) is not None:
            val_str = m.group(3)
            local_val_inner_start = body_start + m.start(3)
            local_val_inner_end = body_start + m.end(3)
            local_val_start = local_val_inner_start - 1
            local_val_end = local_val_inner_end + 1
        else:
            val_str = m.group(4) or ""
            local_val_inner_start = body_start + m.start(4)
            local_val_inner_end = body_start + m.end(4)
            local_val_start = local_val_inner_start
            local_val_end = local_val_inner_end

        e_s_idx, e_e_idx = _local_span_to_utf16(local_entry_start, local_entry_end)
        v_s_idx, v_e_idx = _local_span_to_utf16(local_val_start, local_val_end)
        vi_s_idx, vi_e_idx = _local_span_to_utf16(
            local_val_inner_start, local_val_inner_end
        )
        entry_rec = {
            "key": key,
            "value": val_str,
            "raw_value_literal": rule_text[local_val_start:local_val_end],
            "entry_text": entry_text,
            "local_entry_start": local_entry_start,
            "local_entry_end": local_entry_end,
            "entry_start_index": e_s_idx,
            "entry_end_index": e_e_idx,
            "local_value_start": local_val_start,
            "local_value_end": local_val_end,
            "value_start_index": v_s_idx,
            "value_end_index": v_e_idx,
            "local_value_inner_start": local_val_inner_start,
            "local_value_inner_end": local_val_inner_end,
            "value_inner_start_index": vi_s_idx,
            "value_inner_end_index": vi_e_idx,
        }
        entries.append(entry_rec)
        entries_by_key[key] = entry_rec

    if entries:
        first_rel = entries[0]["local_entry_start"] - body_start
        is_collapsed = "\n" not in meta_body[:first_rel]
        last_entry = entries[-1]
        if is_collapsed:
            indent = " "
        else:
            line_s = rule_text.rfind("\n", 0, last_entry["local_entry_start"]) + 1
            prefix = rule_text[line_s : last_entry["local_entry_start"]]
            indent = prefix if prefix and prefix.strip() == "" else "    "
        insertion_anchor: dict[str, Any] = {
            "anchor_kind": "last_entry",
            "key": last_entry["key"],
            "quote": last_entry["entry_text"],
            "local_start": last_entry["local_entry_start"],
            "local_end": last_entry["local_entry_end"],
            "start_index": last_entry["entry_start_index"],
            "end_index": last_entry["entry_end_index"],
        }
    else:
        is_collapsed = "\n" not in meta_body
        indent = " " if is_collapsed else "    "
        insertion_anchor = {
            "anchor_kind": "meta_header",
            "key": "",
            "quote": str(meta_sec["token_text"]),
            "local_start": tok_start,
            "local_end": tok_end,
            "start_index": tok_s_idx,
            "end_index": tok_e_idx,
        }

    return {
        "rule_name": rule_name,
        "has_meta": True,
        "meta_token": str(meta_sec["token_text"]),
        "local_meta_token_start": tok_start,
        "local_meta_token_end": tok_end,
        "meta_token_start_index": tok_s_idx,
        "meta_token_end_index": tok_e_idx,
        "is_collapsed": is_collapsed,
        "indent": indent,
        "entries": entries,
        "entries_by_key": entries_by_key,
        "insertion_anchor": insertion_anchor,
    }


def infer_yaral2_mitre_from_events(rule_text: str) -> dict[str, Any] | None:
    """Deterministically infers the canonical MITRE ATT&CK technique, tactic, and
    reference URL from a YARA-L 2.0 (``YL2``) rule's ``events:`` (or ``strings:``)
    UDM predicates and rule identifier, deliberately excluding the ``meta:`` block
    so stale or contradictory ``meta:`` text cannot bias inference.
    """
    if not rule_text or not rule_text.strip():
        return None

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = str(blocks[0]["rule_name"]) if blocks else ""
    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    event_bodies: list[str] = []
    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name not in ("events", "strings"):
            continue
        body_start = sm.end()
        body_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(body_start, rule_text.rfind("}"))
        )
        event_bodies.append(rule_text[body_start:body_end])

    ev_text = "\n".join(event_bodies).lower()
    if not ev_text.strip():
        return None
    ctx = f"{rule_name.lower()}\n{ev_text}"

    canonical_id: str | None = None
    evidence_reason = ""

    # 1. OS Credential Dumping (T1003.001 LSASS, T1003.003 NTDS, T1003.002 SAM)
    if any(
        kw in ev_text
        for kw in (
            "lsass",
            "comsvcs.dll",
            "minidump",
            "procdump",
            "sekurlsa",
            "mimikatz",
            "lsass.dmp",
        )
    ):
        canonical_id = "T1003.001"
        evidence_reason = (
            "LSASS process memory dump predicates in events: (lsass / comsvcs.dll MiniDump)"
        )
    elif any(
        kw in ev_text for kw in ("ntds.dit", "ntdsutil", "lsadump::dcsync", "dcsync")
    ):
        canonical_id = "T1003.003"
        evidence_reason = "Active Directory NTDS.dit extraction predicates in events:"
    elif any(
        kw in ev_text for kw in ("hklm\\sam", "hklm\\\\sam", "sam.hiv", "reg save")
    ):
        canonical_id = "T1003.002"
        evidence_reason = "Security Account Manager (SAM) hive extraction predicates in events:"

    # 2. Create or Modify System Process: Windows Service (T1543.003)
    elif any(
        kw in ev_text
        for kw in (
            "derpservice",
            "sc.exe create",
            "sc create",
            "new-service",
            "service_creation",
        )
    ):
        canonical_id = "T1543.003"
        evidence_reason = (
            "Windows Service creation/persistence predicates in events: (DERPService / sc.exe create)"
        )

    # 3. Command and Scripting Interpreter: PowerShell (T1059.001)
    elif any(
        kw in ev_text
        for kw in (
            "powershell",
            "pwsh",
            "-enc",
            "-encodedcommand",
            "invoke-expression",
            "frombase64string",
            "downloadstring",
            "empire",
        )
    ):
        canonical_id = "T1059.001"
        evidence_reason = "PowerShell interpreter/stager execution predicates in events:"

    # 4. System Binary Proxy Execution (T1218.*)
    elif "rundll32" in ev_text:
        canonical_id = "T1218.011"
        evidence_reason = "rundll32.exe proxy execution predicates in events:"
    elif "regsvr32" in ev_text or "scrobj.dll" in ev_text:
        canonical_id = "T1218.010"
        evidence_reason = "regsvr32.exe proxy execution predicates in events:"
    elif "mshta" in ev_text or ".hta" in ev_text:
        canonical_id = "T1218.005"
        evidence_reason = "mshta.exe proxy execution predicates in events:"
    elif "cmstp" in ev_text:
        canonical_id = "T1218.003"
        evidence_reason = "cmstp.exe proxy execution predicates in events:"

    # 5. Command and Scripting Interpreter: Windows Command Shell (T1059.003)
    elif any(
        kw in ev_text
        for kw in (
            "cmd.exe",
            "cmd\\.exe",
            "cmd /c",
            ".*cmd.*",
            ".cmd.",
            "batch script",
            ".bat",
        )
    ):
        canonical_id = "T1059.003"
        evidence_reason = "Windows Command Shell (cmd.exe) execution predicates in events:"

    # 6. Command and Scripting Interpreter: Unix Shell (T1059.004)
    elif any(
        kw in ev_text
        for kw in ("/bin/bash", "/bin/sh", "bash -c", "bash -i", "/dev/tcp/", "zsh")
    ):
        canonical_id = "T1059.004"
        evidence_reason = "Unix Shell (/bin/bash or /bin/sh) execution predicates in events:"

    # 7. Account Manipulation: Additional Cloud Credentials (T1098.001)
    elif any(
        kw in ev_text
        for kw in (
            "serviceaccountkeys.create",
            "createaccesskey",
            "oauth client",
            "additional cloud credentials",
        )
    ):
        canonical_id = "T1098.001"
        evidence_reason = "cloud credential or service account key creation predicates in events:"

    # 8. Account Manipulation: Additional Cloud Roles (T1098.003)
    elif any(
        kw in ev_text
        for kw in (
            "setiampolicy",
            "resource_permissions_change",
            "roles/editor",
            "roles/owner",
            "roles/iam",
            "role binding",
        )
    ) or (
        "gcp_cloudaudit" in ev_text
        and any(
            kw in ctx
            for kw in (
                "privilege",
                "role",
                "iam",
                "setiam",
                "projects/base-production",
                "projects/base-analytics",
                "admin",
            )
        )
    ):
        canonical_id = "T1098.003"
        evidence_reason = (
            "cloud IAM role/policy modification predicates in events: (GCP_CLOUDAUDIT / SetIamPolicy / target.resource.name)"
        )

    # 9. Valid Accounts: Cloud Accounts (T1078.004)
    elif any(
        kw in ev_text
        for kw in (
            "gserviceaccount.com",
            "serviceaccount:",
            "workspace_activity",
            "user_login",
            "cloud_identity",
            "okta",
        )
    ):
        canonical_id = "T1078.004"
        evidence_reason = "cloud identity or service account authentication predicates in events:"

    if canonical_id is None or canonical_id not in CANONICAL_MITRE_TECHNIQUES:
        return None

    target_meta = CANONICAL_MITRE_TECHNIQUES[canonical_id]
    return {
        "canonical_id": canonical_id,
        "canonical_name": target_meta["canonical_name"],
        "short_name": target_meta["short_name"],
        "tactic": target_meta["tactic"],
        "reference_url": mitre_technique_url(canonical_id),
        "evidence_reason": evidence_reason,
    }


def _find_rule_meta_mitre_defects(
    rule_text: str,
    rule_name: str,
    *,
    synthesize_missing_meta: bool = True,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> list[dict[str, Any]]:
    """Evaluates a single YARA-L 2.0 rule's ``meta:`` block for missing MITRE ATT&CK
    attribution keys and technique/tactic/URL consistency defects.
    """
    meta_spec = extract_yaral2_meta_spec(rule_text)
    if not meta_spec.get("has_meta"):
        return []

    inferred = infer_yaral2_mitre_from_events(rule_text)
    entries_by_key: dict[str, dict[str, Any]] = meta_spec["entries_by_key"]
    tech_entry = entries_by_key.get("mitre_attack_technique")
    tactic_entry = entries_by_key.get("mitre_attack_tactic")
    url_entry = entries_by_key.get("mitre_attack_url")

    effective_tech_id: str | None = None
    evidence_reason = ""
    if inferred is not None:
        effective_tech_id = str(inferred["canonical_id"])
        evidence_reason = str(inferred["evidence_reason"])
    elif tech_entry is not None:
        cited_raw = str(tech_entry["value"]).strip().upper()
        if cited_raw in DEPRECATED_MITRE_TECHNIQUE_MAP:
            effective_tech_id = DEPRECATED_MITRE_TECHNIQUE_MAP[cited_raw][
                "canonical_id"
            ]
            evidence_reason = f"deprecated pre-subtechnique ID '{cited_raw}'"
        elif cited_raw in CANONICAL_MITRE_TECHNIQUES:
            effective_tech_id = cited_raw
            evidence_reason = (
                f"declared meta: mitre_attack_technique '{cited_raw}'"
            )

    if effective_tech_id is None or effective_tech_id not in CANONICAL_MITRE_TECHNIQUES:
        return []

    target_meta = CANONICAL_MITRE_TECHNIQUES[effective_tech_id]
    canonical_name = str(target_meta["canonical_name"])
    canonical_tactic = str(target_meta["tactic"])
    canonical_url = mitre_technique_url(effective_tech_id)

    defects: list[dict[str, Any]] = []
    mismatched_keys: set[str] = set()

    # (1) mitre_attack_technique mismatch (deprecated, sibling sub-technique, or cross-family)
    if tech_entry is not None:
        cited_tech = str(tech_entry["value"]).strip()
        cited_tech_upper = cited_tech.upper()
        if cited_tech_upper != effective_tech_id:
            mismatched_keys.add("mitre_attack_technique")
            if cited_tech_upper in DEPRECATED_MITRE_TECHNIQUE_MAP:
                cited_label = DEPRECATED_MITRE_TECHNIQUE_MAP[cited_tech_upper][
                    "deprecated_name"
                ]
            elif cited_tech_upper in CANONICAL_MITRE_TECHNIQUES:
                cited_label = CANONICAL_MITRE_TECHNIQUES[cited_tech_upper][
                    "canonical_name"
                ]
            else:
                cited_label = cited_tech or "empty"
            if int(tech_entry["local_value_inner_end"]) > int(
                tech_entry["local_value_inner_start"]
            ):
                l_start = int(tech_entry["local_value_inner_start"])
                l_end = int(tech_entry["local_value_inner_end"])
                quote = cited_tech
                replacement = effective_tech_id
            else:
                l_start = int(tech_entry["local_value_start"])
                l_end = int(tech_entry["local_value_end"])
                quote = str(tech_entry["raw_value_literal"])
                replacement = f'"{effective_tech_id}"'
            defects.append(
                {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "meta_mitre_technique_mismatch",
                    "meta_key": "mitre_attack_technique",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_tech,
                    "canonical_field": effective_tech_id,
                    "canonical_id": effective_tech_id,
                    "canonical_name": canonical_name,
                    "tactic": canonical_tactic,
                    "reference_url": canonical_url,
                    "evidence_reason": evidence_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: MITRE ATT&CK Technique Check in rule '{rule_name}': "
                        f"meta: mitre_attack_technique '{cited_tech}' ({cited_label}) contradicts {evidence_reason}. "
                        f"Replace '{quote}' with '{replacement}' ({canonical_name}, Tactic: {canonical_tactic}, "
                        f"{canonical_url} | {yaral2_doc_url})."
                    ),
                }
            )

    # (2) mitre_attack_tactic mismatch
    if tactic_entry is not None:
        cited_tactic = str(tactic_entry["value"]).strip()
        allowed_tactics = {canonical_tactic.lower()}
        for part in canonical_tactic.split("/"):
            p_clean = part.strip().lower()
            if p_clean:
                allowed_tactics.add(p_clean)
        if cited_tactic.lower() not in allowed_tactics:
            mismatched_keys.add("mitre_attack_tactic")
            if int(tactic_entry["local_value_inner_end"]) > int(
                tactic_entry["local_value_inner_start"]
            ):
                l_start = int(tactic_entry["local_value_inner_start"])
                l_end = int(tactic_entry["local_value_inner_end"])
                quote = cited_tactic
                replacement = canonical_tactic
            else:
                l_start = int(tactic_entry["local_value_start"])
                l_end = int(tactic_entry["local_value_end"])
                quote = str(tactic_entry["raw_value_literal"])
                replacement = f'"{canonical_tactic}"'
            defects.append(
                {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "meta_mitre_tactic_mismatch",
                    "meta_key": "mitre_attack_tactic",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_tactic,
                    "canonical_field": canonical_tactic,
                    "canonical_id": effective_tech_id,
                    "canonical_name": canonical_name,
                    "tactic": canonical_tactic,
                    "reference_url": canonical_url,
                    "evidence_reason": evidence_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: MITRE ATT&CK Tactic Check in rule '{rule_name}': "
                        f"meta: mitre_attack_tactic '{cited_tactic}' contradicts canonical technique "
                        f"'{effective_tech_id}' ({canonical_name}), which belongs to tactic '{canonical_tactic}'. "
                        f"Replace '{quote}' with '{replacement}' ({canonical_url} | {yaral2_doc_url})."
                    ),
                }
            )

    # (3) mitre_attack_url mismatch (dot-separated sub-technique 404 path or wrong technique URL)
    if url_entry is not None:
        cited_url = str(url_entry["value"]).strip()
        if cited_url != canonical_url:
            mismatched_keys.add("mitre_attack_url")
            has_dot_subtech = bool(
                re.search(r"/techniques/T\d{4}\.\d{3}", cited_url, re.IGNORECASE)
            )
            url_reason = (
                "uses dot-separated sub-technique path (which returns HTTP 404 on attack.mitre.org instead of slash-delimited '/techniques/Txxxx/xxx/')"
                if has_dot_subtech
                else f"does not match canonical technique '{effective_tech_id}' ({canonical_name})"
            )
            if int(url_entry["local_value_inner_end"]) > int(
                url_entry["local_value_inner_start"]
            ):
                l_start = int(url_entry["local_value_inner_start"])
                l_end = int(url_entry["local_value_inner_end"])
                quote = cited_url
                replacement = canonical_url
            else:
                l_start = int(url_entry["local_value_start"])
                l_end = int(url_entry["local_value_end"])
                quote = str(url_entry["raw_value_literal"])
                replacement = f'"{canonical_url}"'
            defects.append(
                {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "meta_mitre_url_mismatch",
                    "meta_key": "mitre_attack_url",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_url,
                    "canonical_field": canonical_url,
                    "canonical_id": effective_tech_id,
                    "canonical_name": canonical_name,
                    "tactic": canonical_tactic,
                    "reference_url": canonical_url,
                    "evidence_reason": evidence_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: MITRE ATT&CK URL Check in rule '{rule_name}': "
                        f"meta: mitre_attack_url '{cited_url}' {url_reason}. "
                        f"Replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                    ),
                }
            )

    # (4) Synthesize missing mitre_attack_technique, mitre_attack_tactic, and mitre_attack_url
    if synthesize_missing_meta and inferred is not None:
        expected_pairs = [
            ("mitre_attack_technique", effective_tech_id),
            ("mitre_attack_tactic", canonical_tactic),
            ("mitre_attack_url", canonical_url),
        ]
        missing_pairs = [
            (k, v) for k, v in expected_pairs if k not in entries_by_key
        ]
        anchor = meta_spec.get("insertion_anchor")
        if missing_pairs and isinstance(anchor, dict):
            anchor_start = int(anchor["local_start"])
            anchor_end = int(anchor["local_end"])
            anchor_quote = str(anchor["quote"])
            anchor_key = str(anchor.get("key") or "")
            anchor_base_text = anchor_quote
            # If the insertion anchor is itself one of the mismatched entries, fold its repair
            # into the anchor replacement so no two edits overlap.
            if anchor_key in mismatched_keys:
                repaired_val_map = dict(expected_pairs)
                if anchor_key in repaired_val_map:
                    anchor_base_text = f'{anchor_key} = "{repaired_val_map[anchor_key]}"'
                defects = [
                    d
                    for d in defects
                    if not _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (anchor_start, anchor_end),
                    )
                ]
            if meta_spec["is_collapsed"]:
                synthesized_suffix = " " + " ".join(
                    f'{k} = "{v}"' for k, v in missing_pairs
                )
            else:
                indent = str(meta_spec["indent"])
                synthesized_suffix = "".join(
                    f'\n{indent}{k} = "{v}"' for k, v in missing_pairs
                )
            replacement = anchor_base_text + synthesized_suffix
            missing_key_names = [k for k, _ in missing_pairs]
            defects.append(
                {
                    "local_start": anchor_start,
                    "local_end": anchor_end,
                    "defect_type": "missing_meta_mitre_attribution",
                    "meta_key": ",".join(missing_key_names),
                    "synthesized_keys": missing_key_names,
                    "quote": anchor_quote,
                    "replacement": replacement,
                    "invalid_field": anchor_quote,
                    "canonical_field": effective_tech_id,
                    "canonical_id": effective_tech_id,
                    "canonical_name": canonical_name,
                    "tactic": canonical_tactic,
                    "reference_url": canonical_url,
                    "evidence_reason": evidence_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: MITRE ATT&CK Attribution Synthesis in rule '{rule_name}': "
                        f"meta: section omits {', '.join(missing_key_names)} for {evidence_reason}. "
                        f"Add mitre_attack_technique = \"{effective_tech_id}\" ({canonical_name}), "
                        f"mitre_attack_tactic = \"{canonical_tactic}\", and "
                        f"mitre_attack_url = \"{canonical_url}\" ({canonical_url} | {yaral2_doc_url})."
                    ),
                }
            )

    defects.sort(key=lambda d: int(d["local_start"]))
    return defects


def find_yaral2_meta_mitre_spans(
    plain_text: str,
    index_map: list[int],
    *,
    synthesize_missing_meta: bool = True,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for YARA-L 2.0 (``YL2``) detection rules and computes
    non-overlapping 1-based UTF-16 spans for ``meta:`` MITRE ATT&CK attribution
    synthesis and consistency defects:
    - ``missing_meta_mitre_attribution``
    - ``meta_mitre_technique_mismatch``
    - ``meta_mitre_tactic_mismatch``
    - ``meta_mitre_url_mismatch``
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    for block in _iter_yaral2_rule_blocks(plain_text):
        rule_name = str(block["rule_name"])
        rule_char_start = int(block["char_start"])
        rule_text = str(block["rule_text"])
        meta_defects = _find_rule_meta_mitre_defects(
            rule_text,
            rule_name,
            synthesize_missing_meta=synthesize_missing_meta,
            yaral2_doc_url=yaral2_doc_url,
        )
        if not meta_defects:
            continue

        repaired_rule = rule_text
        for defect in sorted(
            meta_defects, key=lambda d: int(d["local_start"]), reverse=True
        ):
            l_s = int(defect["local_start"])
            l_e = int(defect["local_end"])
            repaired_rule = (
                repaired_rule[:l_s]
                + str(defect["replacement"])
                + repaired_rule[l_e:]
            )
        repaired_rule = _normalize_yaral2_re_regex_calls(repaired_rule)

        for defect in meta_defects:
            abs_start = rule_char_start + int(defect["local_start"])
            abs_end = rule_char_start + int(defect["local_end"]) - 1
            start_idx = index_map[abs_start]
            end_idx = index_map[abs_end] + _utf16_code_unit_len(
                plain_text[abs_end]
            )
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
            f_rec: dict[str, Any] = {
                "rule_name": rule_name,
                "defect_type": defect["defect_type"],
                "meta_key": defect.get("meta_key", ""),
                "invalid_field": defect["invalid_field"],
                "canonical_field": defect["canonical_field"],
                "canonical_id": defect["canonical_id"],
                "canonical_name": defect["canonical_name"],
                "tactic": defect["tactic"],
                "reference_url": defect["reference_url"],
                "evidence_reason": defect.get("evidence_reason", ""),
                "quote": quote,
                "replacement": replacement,
                "start_index": start_idx,
                "end_index": end_idx,
                "original_rule_text": rule_text,
                "repaired_rule_text": repaired_rule,
            }
            if "synthesized_keys" in defect:
                f_rec["synthesized_keys"] = defect["synthesized_keys"]
            findings.append(f_rec)

    return comments, edits, findings


VALID_YARAL2_META_SEVERITIES: tuple[str, ...] = (
    "INFORMATIONAL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

CANONICAL_YARAL2_SEVERITY_ALIASES: dict[str, str] = {
    "SEV0": "CRITICAL",
    "SEV-0": "CRITICAL",
    "SEV1": "CRITICAL",
    "SEV-1": "CRITICAL",
    "P0": "CRITICAL",
    "P-0": "CRITICAL",
    "P1": "CRITICAL",
    "P-1": "CRITICAL",
    "URGENT": "CRITICAL",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "SEV2": "HIGH",
    "SEV-2": "HIGH",
    "P2": "HIGH",
    "P-2": "HIGH",
    "MAJOR": "HIGH",
    "IMPORTANT": "HIGH",
    "HI": "HIGH",
    "SEV3": "MEDIUM",
    "SEV-3": "MEDIUM",
    "P3": "MEDIUM",
    "P-3": "MEDIUM",
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "WARN": "MEDIUM",
    "NORMAL": "MEDIUM",
    "MED": "MEDIUM",
    "SEV4": "LOW",
    "SEV-4": "LOW",
    "P4": "LOW",
    "P-4": "LOW",
    "MINOR": "LOW",
    "LO": "LOW",
    "SEV5": "INFORMATIONAL",
    "SEV-5": "INFORMATIONAL",
    "P5": "INFORMATIONAL",
    "P-5": "INFORMATIONAL",
    "INFO": "INFORMATIONAL",
    "DEBUG": "INFORMATIONAL",
    "TRACE": "INFORMATIONAL",
    "NONE": "INFORMATIONAL",
}

CANONICAL_MITRE_TO_RUNBOOK_SKILL: dict[str, dict[str, Any]] = {
    "T1098": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": ("compromised-user-account-response",),
        "supporting_skills": (),
    },
    "T1098.001": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": ("compromised-user-account-response",),
        "supporting_skills": (),
    },
    "T1098.003": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": ("compromised-user-account-response",),
        "supporting_skills": (),
    },
    "T1078": {
        "canonical_skill": "suspicious-login-triage",
        "allowed_skills": (
            "suspicious-login-triage",
            "compromised-user-account-response",
        ),
        "supporting_skills": ("compromised-user-account-response",),
    },
    "T1078.001": {
        "canonical_skill": "suspicious-login-triage",
        "allowed_skills": (
            "suspicious-login-triage",
            "compromised-user-account-response",
        ),
        "supporting_skills": ("compromised-user-account-response",),
    },
    "T1078.002": {
        "canonical_skill": "suspicious-login-triage",
        "allowed_skills": (
            "suspicious-login-triage",
            "compromised-user-account-response",
        ),
        "supporting_skills": ("compromised-user-account-response",),
    },
    "T1078.003": {
        "canonical_skill": "suspicious-login-triage",
        "allowed_skills": (
            "suspicious-login-triage",
            "compromised-user-account-response",
        ),
        "supporting_skills": ("compromised-user-account-response",),
    },
    "T1078.004": {
        "canonical_skill": "suspicious-login-triage",
        "allowed_skills": (
            "suspicious-login-triage",
            "compromised-user-account-response",
        ),
        "supporting_skills": ("compromised-user-account-response",),
    },
    "T1059": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1059.001": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1059.003": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1059.004": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1218": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1218.003": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1218.005": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1218.010": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1218.011": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1543": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1543.003": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1505.003": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1546.013": {
        "canonical_skill": "malware-incident-response",
        "allowed_skills": (
            "malware-incident-response",
            "basic-endpoint-triage-isolation",
        ),
        "supporting_skills": ("basic-endpoint-triage-isolation",),
    },
    "T1003": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": (
            "compromised-user-account-response",
            "guided-ttp-hunt-credential-access",
        ),
        "supporting_skills": ("guided-ttp-hunt-credential-access",),
    },
    "T1003.001": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": (
            "compromised-user-account-response",
            "guided-ttp-hunt-credential-access",
        ),
        "supporting_skills": ("guided-ttp-hunt-credential-access",),
    },
    "T1003.002": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": (
            "compromised-user-account-response",
            "guided-ttp-hunt-credential-access",
        ),
        "supporting_skills": ("guided-ttp-hunt-credential-access",),
    },
    "T1003.003": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": (
            "compromised-user-account-response",
            "guided-ttp-hunt-credential-access",
        ),
        "supporting_skills": ("guided-ttp-hunt-credential-access",),
    },
    "T1550.002": {
        "canonical_skill": "compromised-user-account-response",
        "allowed_skills": (
            "compromised-user-account-response",
            "guided-ttp-hunt-credential-access",
        ),
        "supporting_skills": ("guided-ttp-hunt-credential-access",),
    },
}

_DEFAULT_LOCAL_SKILL_REGISTRY: Any = None


def _get_default_skill_registry() -> Any:
    """Returns a cached local ``SkillRegistry`` instance from the repository's ``skills/`` directory."""
    global _DEFAULT_LOCAL_SKILL_REGISTRY
    if _DEFAULT_LOCAL_SKILL_REGISTRY is not None:
        return _DEFAULT_LOCAL_SKILL_REGISTRY
    try:
        from pathlib import Path
        from skills.registry import SkillRegistry

        repo_skills_dir = Path(__file__).resolve().parents[3] / "skills"
        if repo_skills_dir.is_dir():
            _DEFAULT_LOCAL_SKILL_REGISTRY = SkillRegistry(str(repo_skills_dir))
        else:
            _DEFAULT_LOCAL_SKILL_REGISTRY = SkillRegistry()
    except Exception:
        _DEFAULT_LOCAL_SKILL_REGISTRY = None
    return _DEFAULT_LOCAL_SKILL_REGISTRY


def _map_risk_score_to_yaral2_severity(score: float | int) -> tuple[str, str]:
    """Maps a numeric Chronicle Risk Analytics ``$risk_score`` (`1..100`) to its
    canonical YARA-L 2.0 ``meta: severity`` tier and score band string.
    """
    val = float(score)
    if val >= 90:
        return "CRITICAL", "90..100"
    if val >= 70:
        return "HIGH", "70..89"
    if val >= 40:
        return "MEDIUM", "40..69"
    if val >= 20:
        return "LOW", "20..39"
    return "INFORMATIONAL", "1..19"


_NUMERIC_OUTCOME_RHS_RE = re.compile(
    r"^\s*(?:([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*)?(\d+(?:\.\d+)?)\s*\)?\s*$"
)


def infer_yaral2_severity_from_risk_score(rule_text: str) -> dict[str, Any] | None:
    """Inspects a YARA-L 2.0 (``YL2``) rule's ``outcome:`` and ``condition:`` sections
    for ``$risk_score`` (or ``*$score*`` / ``*severity*``) bindings and maps the numeric
    score (`1..100`) to its canonical Chronicle ``meta: severity`` tier:
    - ``90..100`` -> ``"CRITICAL"``
    - ``70..89``  -> ``"HIGH"``
    - ``40..69``  -> ``"MEDIUM"``
    - ``20..39``  -> ``"LOW"``
    - ``1..19``   -> ``"INFORMATIONAL"``
    """
    if not rule_text or not rule_text.strip():
        return None

    multi_spec = extract_yaral2_multi_event_spec(rule_text)
    outcome_bindings: list[dict[str, Any]] = list(
        multi_spec.get("outcome_bindings") or []
    )

    def _is_risk_score_var(var_name: str) -> bool:
        vn = var_name.lower().lstrip("$")
        return vn == "risk_score" or "risk_score" in vn or vn.endswith("score")

    prioritized_bindings = sorted(
        outcome_bindings,
        key=lambda ob: (
            0
            if str(ob.get("outcome_var_name", "")).lower() == "risk_score"
            else (
                1
                if _is_risk_score_var(str(ob.get("outcome_var_name", "")))
                else 2
            )
        ),
    )

    for ob in prioritized_bindings:
        var_name = str(ob.get("outcome_var_name") or "")
        if not _is_risk_score_var(var_name):
            continue
        outcome_var = str(ob.get("outcome_var") or f"${var_name}")
        rhs_text = str(ob.get("rhs_text") or "").strip()
        cond_spec = ob.get("conditional_spec")
        if isinstance(cond_spec, dict):
            t_val = cond_spec.get("true_value")
            f_val = cond_spec.get("false_value")
            primary_num: float | None = None
            if isinstance(t_val, (int, float)):
                primary_num = float(t_val)
            elif isinstance(f_val, (int, float)):
                primary_num = float(f_val)
            if primary_num is not None and primary_num > 0:
                canon_sev, band = _map_risk_score_to_yaral2_severity(primary_num)
                score_val: int | float = (
                    int(primary_num)
                    if float(primary_num).is_integer()
                    else float(primary_num)
                )
                return {
                    "canonical_severity": canon_sev,
                    "risk_score": score_val,
                    "score_band": band,
                    "outcome_var": outcome_var,
                    "source": "outcome_conditional",
                    "evidence_reason": (
                        f"outcome: {outcome_var} = {rhs_text} assigns primary conditional risk score {score_val} (band {band} -> {canon_sev})"
                    ),
                }

        num_m = _NUMERIC_OUTCOME_RHS_RE.match(rhs_text)
        if num_m:
            raw_num = float(num_m.group(2))
            if raw_num > 0:
                canon_sev, band = _map_risk_score_to_yaral2_severity(raw_num)
                score_val = (
                    int(raw_num) if float(raw_num).is_integer() else float(raw_num)
                )
                return {
                    "canonical_severity": canon_sev,
                    "risk_score": score_val,
                    "score_band": band,
                    "outcome_var": outcome_var,
                    "source": "outcome_binding",
                    "evidence_reason": (
                        f"outcome: {outcome_var} = {rhs_text} assigns risk score {score_val} (band {band} -> {canon_sev})"
                    ),
                }

    for cmp_rec in multi_spec.get("condition_outcome_comparisons") or []:
        var_name = str(cmp_rec.get("outcome_var_name") or "")
        if not _is_risk_score_var(var_name):
            continue
        outcome_var = str(cmp_rec.get("outcome_var") or f"${var_name}")
        op = str(cmp_rec.get("op") or ">=")
        thresh_raw = cmp_rec.get("threshold_value")
        if not isinstance(thresh_raw, (int, float)):
            continue
        eff_val = float(thresh_raw) + (1.0 if op == ">" else 0.0)
        if eff_val > 0:
            canon_sev, band = _map_risk_score_to_yaral2_severity(eff_val)
            score_val = (
                int(eff_val) if float(eff_val).is_integer() else float(eff_val)
            )
            cmp_text = str(
                cmp_rec.get("comparison_text")
                or f"{outcome_var} {op} {thresh_raw}"
            )
            return {
                "canonical_severity": canon_sev,
                "risk_score": score_val,
                "score_band": band,
                "outcome_var": outcome_var,
                "source": "condition_threshold",
                "evidence_reason": (
                    f"condition: '{cmp_text}' requires risk score {score_val} (band {band} -> {canon_sev})"
                ),
            }

    return None


def infer_yaral2_runbook_skill_from_rule(
    rule_text: str,
    *,
    skill_registry: Any = None,
) -> dict[str, Any] | None:
    """Deterministically infers the canonical ``SOC Runbooks`` operational playbook slug
    (``meta: runbook_skill``) from a YARA-L 2.0 (``YL2``) rule's ``events:`` (or ``strings:``)
    UDM predicates and MITRE ATT&CK technique, validating the resolved skill against
    ``SkillRegistry`` / ``DriveSkillRegistry``.
    """
    if not rule_text or not rule_text.strip():
        return None

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = str(blocks[0]["rule_name"]) if blocks else ""
    sec_matches = list(_YARAL2_SECTION_HEADER_RE.finditer(rule_text))
    event_bodies: list[str] = []
    for i, sm in enumerate(sec_matches):
        sec_name = sm.group(1).lower()
        if sec_name not in ("events", "strings"):
            continue
        body_start = sm.end()
        body_end = (
            sec_matches[i + 1].start()
            if i + 1 < len(sec_matches)
            else max(body_start, rule_text.rfind("}"))
        )
        event_bodies.append(rule_text[body_start:body_end])

    ev_text = "\n".join(event_bodies).lower()
    if not ev_text.strip():
        return None
    ctx = f"{rule_name.lower()}\n{ev_text}"

    registry = (
        skill_registry
        if skill_registry is not None
        else _get_default_skill_registry()
    )

    canonical_skill: str | None = None
    allowed_skills: tuple[str, ...] = ()
    supporting_skills: tuple[str, ...] = ()
    mitre_id: str | None = None
    evidence_reason = ""

    # 1. Ransomware / Volume Shadow Copy deletion / mass encryption indicators
    if any(
        kw in ctx
        for kw in (
            "vssadmin",
            "delete shadows",
            "shadowcopy",
            "wbadmin delete",
            "recoveryenabled",
            "ransom",
            ".locked",
            ".encrypted",
            "t1486",
            "t1490",
        )
    ):
        canonical_skill = "ransomware-response"
        allowed_skills = ("ransomware-response",)
        supporting_skills = ("basic-endpoint-triage-isolation",)
        mitre_id = "T1486"
        evidence_reason = (
            "ransomware/shadow-copy deletion predicates in events: (vssadmin / shadowcopy / ransomware)"
        )

    # 2. Phishing / Email delivery / malicious attachment or credential harvest link indicators
    elif any(
        kw in ctx
        for kw in (
            "network.email",
            "email_transaction",
            "phish",
            "spearphish",
            "mail.from",
            "t1566",
        )
    ):
        canonical_skill = "phishing-response"
        allowed_skills = ("phishing-response",)
        supporting_skills = ("compromised-user-account-response",)
        mitre_id = "T1566"
        evidence_reason = (
            "email/phishing delivery predicates in events: (network.email / phishing)"
        )

    # 3. Map from inferred MITRE ATT&CK technique in events:
    else:
        inferred_mitre = infer_yaral2_mitre_from_events(rule_text)
        if inferred_mitre is not None:
            mitre_id = str(inferred_mitre["canonical_id"])
            mitre_reason = str(inferred_mitre["evidence_reason"])
            rb_map = CANONICAL_MITRE_TO_RUNBOOK_SKILL.get(mitre_id)
            if rb_map is None and "." in mitre_id:
                rb_map = CANONICAL_MITRE_TO_RUNBOOK_SKILL.get(
                    mitre_id.split(".", 1)[0]
                )
            if rb_map is not None:
                canonical_skill = str(rb_map["canonical_skill"])
                allowed_skills = tuple(rb_map.get("allowed_skills", (canonical_skill,)))
                supporting_skills = tuple(rb_map.get("supporting_skills", ()))
                evidence_reason = (
                    f"inferred MITRE technique {mitre_id} ({inferred_mitre['canonical_name']}) from {mitre_reason}"
                )

    if canonical_skill is None:
        return None

    category = "incident-response"
    description = ""
    skill_verified = False
    if registry is not None and hasattr(registry, "get_skill"):
        skill_meta = registry.get_skill(canonical_skill)
        if skill_meta is not None:
            skill_verified = True
            category = str(getattr(skill_meta, "category", "") or category)
            description = str(getattr(skill_meta, "description", "") or "")

    return {
        "canonical_skill": canonical_skill,
        "category": category,
        "description": description,
        "allowed_skills": list(allowed_skills),
        "supporting_skills": list(supporting_skills),
        "mitre_technique_id": mitre_id or "",
        "skill_verified": skill_verified,
        "evidence_reason": evidence_reason,
    }


def _find_rule_meta_runbook_and_severity_defects(
    rule_text: str,
    rule_name: str,
    *,
    verify_meta_severity: bool = True,
    verify_meta_runbook: bool = True,
    synthesize_missing_runbook: bool = True,
    skill_registry: Any = None,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> list[dict[str, Any]]:
    """Evaluates a single YARA-L 2.0 (``YL2``) rule's ``meta:`` block for:
    1. ``invalid_meta_severity``: non-canonical severity label (``"SEV1"``, ``"P1"``,
       ``"WARN"``, ``"INFO"``) instead of Chronicle's 5 canonical severity tiers
       (``"CRITICAL"``, ``"HIGH"``, ``"MEDIUM"``, ``"LOW"``, ``"INFORMATIONAL"``).
    2. ``meta_severity_risk_score_mismatch``: valid ``meta: severity`` tier that
       contradicts the rule's ``outcome:`` or ``condition:`` ``$risk_score`` band.
    3. ``meta_runbook_skill_mismatch``: ``meta: runbook_skill`` (or ``runbook``) slug
       that either does not exist in ``SkillRegistry`` / ``DriveSkillRegistry`` or
       routes the rule to the wrong operational response domain.
    4. ``missing_meta_runbook_skill``: ``meta:`` omits ``runbook_skill`` (and ``runbook``);
       synthesizes ``runbook_skill = "<canonical_skill>"`` on the ``insertion_anchor``.
    """
    meta_spec = extract_yaral2_meta_spec(rule_text)
    if not meta_spec.get("has_meta"):
        return []

    registry = (
        skill_registry
        if skill_registry is not None
        else _get_default_skill_registry()
    )
    entries_by_key: dict[str, dict[str, Any]] = meta_spec["entries_by_key"]
    defects: list[dict[str, Any]] = []
    repaired_entry_values: dict[str, str] = {}
    repaired_entry_defects: dict[str, dict[str, Any]] = {}

    risk_info = infer_yaral2_severity_from_risk_score(rule_text)
    inferred_rb = infer_yaral2_runbook_skill_from_rule(
        rule_text, skill_registry=registry
    )

    # (1) & (2) Severity validation and risk_score consistency check
    if verify_meta_severity:
        sev_entry = entries_by_key.get("severity")
        if sev_entry is not None:
            cited_sev = str(sev_entry["value"]).strip()
            cited_sev_upper = cited_sev.upper()
            if cited_sev_upper not in VALID_YARAL2_META_SEVERITIES:
                alias_sev = CANONICAL_YARAL2_SEVERITY_ALIASES.get(cited_sev_upper)
                if risk_info is not None and (
                    alias_sev is None
                    or alias_sev == str(risk_info["canonical_severity"])
                ):
                    canonical_sev = str(risk_info["canonical_severity"])
                    sev_reason = (
                        f"is not one of Chronicle YARA-L 2.0's 5 canonical severity tiers "
                        f"{list(VALID_YARAL2_META_SEVERITIES)} and {risk_info['evidence_reason']}"
                    )
                elif alias_sev is not None:
                    canonical_sev = alias_sev
                    sev_reason = (
                        f"uses non-canonical PagerDuty/Jira/Splunk severity label '{cited_sev}' "
                        f"instead of Chronicle YARA-L 2.0's 5 canonical severity tiers {list(VALID_YARAL2_META_SEVERITIES)}"
                    )
                elif risk_info is not None:
                    canonical_sev = str(risk_info["canonical_severity"])
                    sev_reason = (
                        f"is not a canonical Chronicle YARA-L 2.0 severity tier and {risk_info['evidence_reason']}"
                    )
                else:
                    canonical_sev = "MEDIUM"
                    sev_reason = (
                        f"is not one of Chronicle YARA-L 2.0's 5 canonical severity tiers {list(VALID_YARAL2_META_SEVERITIES)}"
                    )

                if int(sev_entry["local_value_inner_end"]) > int(
                    sev_entry["local_value_inner_start"]
                ):
                    l_start = int(sev_entry["local_value_inner_start"])
                    l_end = int(sev_entry["local_value_inner_end"])
                    quote = cited_sev
                    replacement = canonical_sev
                else:
                    l_start = int(sev_entry["local_value_start"])
                    l_end = int(sev_entry["local_value_end"])
                    quote = str(sev_entry["raw_value_literal"])
                    replacement = f'"{canonical_sev}"'

                sev_defect: dict[str, Any] = {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "invalid_meta_severity",
                    "meta_key": "severity",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_sev,
                    "canonical_field": canonical_sev,
                    "cited_severity": cited_sev,
                    "canonical_severity": canonical_sev,
                    "risk_score": (
                        risk_info["risk_score"] if risk_info is not None else None
                    ),
                    "score_band": (
                        risk_info["score_band"] if risk_info is not None else ""
                    ),
                    "evidence_reason": sev_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: Severity Tier Check in rule '{rule_name}': "
                        f"meta: severity '{cited_sev}' {sev_reason}. "
                        f"Replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                    ),
                }
                defects.append(sev_defect)
                repaired_entry_values["severity"] = canonical_sev
                repaired_entry_defects["severity"] = sev_defect
            elif (
                risk_info is not None
                and cited_sev_upper != str(risk_info["canonical_severity"])
            ):
                canonical_sev = str(risk_info["canonical_severity"])
                if int(sev_entry["local_value_inner_end"]) > int(
                    sev_entry["local_value_inner_start"]
                ):
                    l_start = int(sev_entry["local_value_inner_start"])
                    l_end = int(sev_entry["local_value_inner_end"])
                    quote = cited_sev
                    replacement = canonical_sev
                else:
                    l_start = int(sev_entry["local_value_start"])
                    l_end = int(sev_entry["local_value_end"])
                    quote = str(sev_entry["raw_value_literal"])
                    replacement = f'"{canonical_sev}"'

                sev_defect = {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "meta_severity_risk_score_mismatch",
                    "meta_key": "severity",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_sev,
                    "canonical_field": canonical_sev,
                    "cited_severity": cited_sev,
                    "canonical_severity": canonical_sev,
                    "risk_score": risk_info["risk_score"],
                    "score_band": str(risk_info["score_band"]),
                    "evidence_reason": str(risk_info["evidence_reason"]),
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: Severity-to-Risk-Score Consistency Check in rule '{rule_name}': "
                        f"meta: severity '{cited_sev}' contradicts {risk_info['evidence_reason']}. "
                        f"Align meta: severity with Chronicle Risk Analytics band {risk_info['score_band']} "
                        f"by replacing '{quote}' with '{replacement}' ({yaral2_doc_url})."
                    ),
                }
                defects.append(sev_defect)
                repaired_entry_values["severity"] = canonical_sev
                repaired_entry_defects["severity"] = sev_defect

    # (3) & (4) Runbook skill routing validation and synthesis
    if verify_meta_runbook and inferred_rb is not None:
        canonical_skill = str(inferred_rb["canonical_skill"])
        allowed_skills = set(inferred_rb.get("allowed_skills") or [canonical_skill])
        skill_category = str(inferred_rb.get("category") or "incident-response")
        skill_verified = bool(inferred_rb.get("skill_verified", False))
        rb_reason = str(inferred_rb.get("evidence_reason") or "")

        rb_key = (
            "runbook_skill"
            if "runbook_skill" in entries_by_key
            else ("runbook" if "runbook" in entries_by_key else None)
        )
        rb_entry = entries_by_key.get(rb_key) if rb_key is not None else None

        if rb_entry is not None and rb_key is not None:
            cited_skill = str(rb_entry["value"]).strip()
            exists_in_registry = False
            cited_category = ""
            if registry is not None and hasattr(registry, "get_skill"):
                cited_meta = registry.get_skill(cited_skill)
                if cited_meta is not None:
                    exists_in_registry = True
                    cited_category = str(getattr(cited_meta, "category", "") or "")
            else:
                exists_in_registry = cited_skill in allowed_skills

            if not exists_in_registry or cited_skill not in allowed_skills:
                if not exists_in_registry:
                    mismatch_detail = (
                        f"is not a registered operational playbook in SkillRegistry / SOC Runbooks "
                        f"(would fail load_skill('{cited_skill}') at incident response time)"
                    )
                else:
                    cat_note = f" (category: {cited_category})" if cited_category else ""
                    mismatch_detail = (
                        f"routes to '{cited_skill}'{cat_note}, which mismatches {rb_reason}"
                    )

                if int(rb_entry["local_value_inner_end"]) > int(
                    rb_entry["local_value_inner_start"]
                ):
                    l_start = int(rb_entry["local_value_inner_start"])
                    l_end = int(rb_entry["local_value_inner_end"])
                    quote = cited_skill
                    replacement = canonical_skill
                else:
                    l_start = int(rb_entry["local_value_start"])
                    l_end = int(rb_entry["local_value_end"])
                    quote = str(rb_entry["raw_value_literal"])
                    replacement = f'"{canonical_skill}"'

                rb_defect: dict[str, Any] = {
                    "local_start": l_start,
                    "local_end": l_end,
                    "defect_type": "meta_runbook_skill_mismatch",
                    "meta_key": rb_key,
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cited_skill,
                    "canonical_field": canonical_skill,
                    "cited_skill": cited_skill,
                    "canonical_skill": canonical_skill,
                    "skill_category": skill_category,
                    "allowed_skills": sorted(allowed_skills),
                    "skill_verified": skill_verified,
                    "evidence_reason": rb_reason,
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) meta: Runbook Routing Check in rule '{rule_name}': "
                        f"meta: {rb_key} '{cited_skill}' {mismatch_detail}. "
                        f"Replace '{quote}' with verified SOC Runbooks skill '{replacement}' "
                        f"(category: {skill_category} | {yaral2_doc_url})."
                    ),
                }
                defects.append(rb_defect)
                repaired_entry_values[rb_key] = canonical_skill
                repaired_entry_defects[rb_key] = rb_defect

        elif synthesize_missing_runbook:
            anchor = meta_spec.get("insertion_anchor")
            if isinstance(anchor, dict):
                anchor_start = int(anchor["local_start"])
                anchor_end = int(anchor["local_end"])
                anchor_quote = str(anchor["quote"])
                anchor_key = str(anchor.get("key") or "")
                anchor_base_text = anchor_quote
                folded_types: list[str] = []
                repaired_anchor_val: str | None = None

                if anchor_key in repaired_entry_values:
                    repaired_anchor_val = repaired_entry_values[anchor_key]
                    anchor_base_text = f'{anchor_key} = "{repaired_anchor_val}"'
                    orig_anchor_def = repaired_entry_defects.get(anchor_key)
                    if orig_anchor_def is not None:
                        folded_types.append(str(orig_anchor_def["defect_type"]))
                    defects = [
                        d
                        for d in defects
                        if not _spans_overlap(
                            (int(d["local_start"]), int(d["local_end"])),
                            (anchor_start, anchor_end),
                        )
                    ]

                folded_types.append("missing_meta_runbook_skill")
                if meta_spec["is_collapsed"]:
                    synthesized_suffix = f' runbook_skill = "{canonical_skill}"'
                else:
                    indent = str(meta_spec["indent"])
                    synthesized_suffix = (
                        f'\n{indent}runbook_skill = "{canonical_skill}"'
                    )
                replacement = anchor_base_text + synthesized_suffix

                comment_parts: list[str] = []
                if anchor_key in repaired_entry_defects:
                    comment_parts.append(
                        str(repaired_entry_defects[anchor_key]["comment"])
                    )
                comment_parts.append(
                    f"Deterministic YARA-L 2.0 (YL2) meta: Runbook Routing Synthesis in rule '{rule_name}': "
                    f"meta: section omits 'runbook_skill' for {rb_reason}. "
                    f"Add runbook_skill = \"{canonical_skill}\" (SkillRegistry verified={skill_verified}, "
                    f"category: {skill_category} | {yaral2_doc_url})."
                )

                synth_defect: dict[str, Any] = {
                    "local_start": anchor_start,
                    "local_end": anchor_end,
                    "defect_type": "missing_meta_runbook_skill",
                    "meta_key": "runbook_skill",
                    "synthesized_keys": ["runbook_skill"],
                    "folded_defect_types": folded_types,
                    "quote": anchor_quote,
                    "replacement": replacement,
                    "invalid_field": anchor_quote,
                    "canonical_field": canonical_skill,
                    "canonical_skill": canonical_skill,
                    "skill_category": skill_category,
                    "allowed_skills": sorted(allowed_skills),
                    "skill_verified": skill_verified,
                    "evidence_reason": rb_reason,
                    "comment": " ".join(comment_parts),
                }
                if repaired_anchor_val is not None:
                    synth_defect["repaired_anchor_key"] = anchor_key
                    synth_defect["repaired_anchor_value"] = repaired_anchor_val
                    if anchor_key == "severity":
                        synth_defect["canonical_severity"] = repaired_anchor_val
                        orig_sev_def = repaired_entry_defects.get("severity", {})
                        if "cited_severity" in orig_sev_def:
                            synth_defect["cited_severity"] = orig_sev_def[
                                "cited_severity"
                            ]
                        if orig_sev_def.get("risk_score") is not None:
                            synth_defect["risk_score"] = orig_sev_def["risk_score"]
                        if orig_sev_def.get("score_band"):
                            synth_defect["score_band"] = orig_sev_def["score_band"]
                defects.append(synth_defect)

    defects.sort(key=lambda d: int(d["local_start"]))
    return defects


def _merge_yaral2_meta_defects(
    rule_text: str,
    rule_name: str,
    meta_mitre_defects: list[dict[str, Any]],
    meta_rb_sev_defects: list[dict[str, Any]],
    *,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> list[dict[str, Any]]:
    """Merges ``meta:`` MITRE ATT&CK defects and ``meta:`` Runbook/Severity defects
    so that any combination of ``insertion_anchor`` value repairs (e.g. ``severity = "LOW"``
    -> ``severity = "HIGH"``), ``missing_meta_mitre_attribution``, and
    ``missing_meta_runbook_skill`` folds into a single non-overlapping edit on the
    ``insertion_anchor`` span.
    """
    if not meta_mitre_defects:
        return list(meta_rb_sev_defects)
    if not meta_rb_sev_defects:
        return list(meta_mitre_defects)

    meta_spec = extract_yaral2_meta_spec(rule_text)
    anchor = meta_spec.get("insertion_anchor")
    if not isinstance(anchor, dict):
        combined = list(meta_mitre_defects) + list(meta_rb_sev_defects)
        combined.sort(key=lambda d: int(d["local_start"]))
        return combined

    anchor_start = int(anchor["local_start"])
    anchor_end = int(anchor["local_end"])
    anchor_quote = str(anchor["quote"])
    anchor_key = str(anchor.get("key") or "")

    all_candidates = list(meta_mitre_defects) + list(meta_rb_sev_defects)
    anchor_overlapping = [
        d
        for d in all_candidates
        if _spans_overlap(
            (int(d["local_start"]), int(d["local_end"])),
            (anchor_start, anchor_end),
        )
    ]
    non_anchor = [
        d
        for d in all_candidates
        if not _spans_overlap(
            (int(d["local_start"]), int(d["local_end"])),
            (anchor_start, anchor_end),
        )
    ]

    has_anchor_synthesis = any(
        d.get("defect_type")
        in ("missing_meta_mitre_attribution", "missing_meta_runbook_skill")
        for d in anchor_overlapping
    )
    if len(anchor_overlapping) <= 1 or not has_anchor_synthesis:
        combined = non_anchor + anchor_overlapping
        combined.sort(key=lambda d: int(d["local_start"]))
        return combined

    # Determine the repaired base text for the insertion_anchor assignment itself
    anchor_base_text = anchor_quote
    repaired_anchor_val: str | None = None
    for d in anchor_overlapping:
        if d.get("repaired_anchor_key") == anchor_key and d.get(
            "repaired_anchor_value"
        ):
            repaired_anchor_val = str(d["repaired_anchor_value"])
            anchor_base_text = f'{anchor_key} = "{repaired_anchor_val}"'
            break
        if (
            d.get("meta_key") == anchor_key
            and d.get("defect_type")
            not in ("missing_meta_mitre_attribution", "missing_meta_runbook_skill")
        ):
            repaired_anchor_val = str(d["canonical_field"])
            anchor_base_text = f'{anchor_key} = "{repaired_anchor_val}"'
            break

    synthesized_pairs: list[tuple[str, str]] = []
    synthesized_keys: list[str] = []
    folded_types: list[str] = []
    comments_list: list[str] = []
    merged_extra: dict[str, Any] = {}

    for d in anchor_overlapping:
        for ft in d.get("folded_defect_types") or [str(d["defect_type"])]:
            if ft not in folded_types:
                folded_types.append(ft)
        c_txt = str(d.get("comment") or "")
        if c_txt and c_txt not in comments_list:
            comments_list.append(c_txt)
        for k_Copy in (
            "canonical_id",
            "canonical_name",
            "tactic",
            "reference_url",
            "canonical_skill",
            "cited_skill",
            "skill_category",
            "allowed_skills",
            "skill_verified",
            "canonical_severity",
            "cited_severity",
            "risk_score",
            "score_band",
            "evidence_reason",
        ):
            if k_Copy in d and d[k_Copy] is not None and k_Copy not in merged_extra:
                merged_extra[k_Copy] = d[k_Copy]

        if d.get("defect_type") == "missing_meta_mitre_attribution":
            for k in d.get("synthesized_keys") or []:
                if k == "mitre_attack_technique" and d.get("canonical_id"):
                    synthesized_pairs.append((k, str(d["canonical_id"])))
                    synthesized_keys.append(k)
                elif k == "mitre_attack_tactic" and d.get("tactic"):
                    synthesized_pairs.append((k, str(d["tactic"])))
                    synthesized_keys.append(k)
                elif k == "mitre_attack_url" and d.get("reference_url"):
                    synthesized_pairs.append((k, str(d["reference_url"])))
                    synthesized_keys.append(k)
        elif d.get("defect_type") == "missing_meta_runbook_skill":
            if d.get("canonical_skill") and "runbook_skill" not in synthesized_keys:
                synthesized_pairs.append(
                    ("runbook_skill", str(d["canonical_skill"]))
                )
                synthesized_keys.append("runbook_skill")

    if meta_spec["is_collapsed"]:
        suffix = (
            " " + " ".join(f'{k} = "{v}"' for k, v in synthesized_pairs)
            if synthesized_pairs
            else ""
        )
    else:
        indent = str(meta_spec["indent"])
        suffix = "".join(f'\n{indent}{k} = "{v}"' for k, v in synthesized_pairs)

    replacement = anchor_base_text + suffix
    primary_defect_type = (
        "missing_meta_runbook_skill"
        if "missing_meta_runbook_skill" in folded_types
        and "missing_meta_mitre_attribution" not in folded_types
        else (
            "missing_meta_mitre_attribution"
            if "missing_meta_mitre_attribution" in folded_types
            else folded_types[-1]
        )
    )
    canonical_field_val = str(
        merged_extra.get("canonical_skill")
        or merged_extra.get("canonical_id")
        or repaired_anchor_val
        or ""
    )

    merged_defect: dict[str, Any] = {
        "local_start": anchor_start,
        "local_end": anchor_end,
        "defect_type": primary_defect_type,
        "meta_key": ",".join(synthesized_keys) if synthesized_keys else anchor_key,
        "synthesized_keys": synthesized_keys,
        "folded_defect_types": folded_types,
        "quote": anchor_quote,
        "replacement": replacement,
        "invalid_field": anchor_quote,
        "canonical_field": canonical_field_val,
        "comment": " ".join(comments_list),
    }
    merged_defect.update(merged_extra)
    if repaired_anchor_val is not None:
        merged_defect["repaired_anchor_key"] = anchor_key
        merged_defect["repaired_anchor_value"] = repaired_anchor_val

    result = non_anchor + [merged_defect]
    result.sort(key=lambda d: int(d["local_start"]))
    return result


def find_yaral2_meta_runbook_and_severity_spans(
    plain_text: str,
    index_map: list[int],
    *,
    verify_meta_severity: bool = True,
    verify_meta_runbook: bool = True,
    synthesize_missing_runbook: bool = True,
    skill_registry: Any = None,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for YARA-L 2.0 (``YL2``) detection rules and computes
    non-overlapping 1-based UTF-16 spans for ``meta:`` severity-to-risk-score
    consistency and ``SkillRegistry`` operational runbook routing defects:
    - ``invalid_meta_severity``
    - ``meta_severity_risk_score_mismatch``
    - ``meta_runbook_skill_mismatch``
    - ``missing_meta_runbook_skill``
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    for block in _iter_yaral2_rule_blocks(plain_text):
        rule_name = str(block["rule_name"])
        rule_char_start = int(block["char_start"])
        rule_text = str(block["rule_text"])
        meta_defects = _find_rule_meta_runbook_and_severity_defects(
            rule_text,
            rule_name,
            verify_meta_severity=verify_meta_severity,
            verify_meta_runbook=verify_meta_runbook,
            synthesize_missing_runbook=synthesize_missing_runbook,
            skill_registry=skill_registry,
            yaral2_doc_url=yaral2_doc_url,
        )
        if not meta_defects:
            continue

        repaired_rule = rule_text
        for defect in sorted(
            meta_defects, key=lambda d: int(d["local_start"]), reverse=True
        ):
            l_s = int(defect["local_start"])
            l_e = int(defect["local_end"])
            repaired_rule = (
                repaired_rule[:l_s]
                + str(defect["replacement"])
                + repaired_rule[l_e:]
            )
        repaired_rule = _normalize_yaral2_re_regex_calls(repaired_rule)

        for defect in meta_defects:
            abs_start = rule_char_start + int(defect["local_start"])
            abs_end = rule_char_start + int(defect["local_end"]) - 1
            start_idx = index_map[abs_start]
            end_idx = index_map[abs_end] + _utf16_code_unit_len(
                plain_text[abs_end]
            )
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
            f_rec: dict[str, Any] = {
                "rule_name": rule_name,
                "defect_type": defect["defect_type"],
                "meta_key": defect.get("meta_key", ""),
                "invalid_field": defect["invalid_field"],
                "canonical_field": defect["canonical_field"],
                "quote": quote,
                "replacement": replacement,
                "start_index": start_idx,
                "end_index": end_idx,
                "original_rule_text": rule_text,
                "repaired_rule_text": repaired_rule,
            }
            for extra_key in (
                "cited_severity",
                "canonical_severity",
                "risk_score",
                "score_band",
                "cited_skill",
                "canonical_skill",
                "skill_category",
                "allowed_skills",
                "skill_verified",
                "synthesized_keys",
                "folded_defect_types",
                "repaired_anchor_key",
                "repaired_anchor_value",
                "evidence_reason",
            ):
                if extra_key in defect:
                    f_rec[extra_key] = defect[extra_key]
            findings.append(f_rec)

    return comments, edits, findings


def find_yaral2_rule_spans(
    plain_text: str,
    index_map: list[int],
    *,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
    doc: dict[str, Any] | None = None,
    verify_meta_mitre: bool = False,
    synthesize_missing_meta: bool = False,
    verify_meta_runbook: bool = False,
    verify_meta_severity: bool = False,
    synthesize_missing_runbook: bool = False,
    skill_registry: Any = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for single-event and multi-event YARA-L 2.0 (``YL2``) detection rules
    and computes 1-based UTF-16 spans.

    Detects deterministic YARA-L 2.0 defect classes without an LLM:
    1. Standard YARA (``strings:``) vs. Chronicle YARA-L 2.0 (``events:``) section confusion,
       explicitly distinguishing standard YARA (file/payload byte-pattern matching) from
       YARA-L 2.0 / YL2 (Chronicle SIEM UDM event detection rules).
    2. Event-variable-prefixed invalid UDM fields (``$<var>.<field_path>`` in comparisons,
       join bindings, ``outcome:`` expressions, or inside YARA-L 2.0 function calls such as
       ``re.regex($<var>.<field_path>, ...)``), non-canonical CIDR function calls
       (``invalid_cidr_function_syntax``: ``cidrmatch(...)``, ``ipv4_is_in_range(...)``,
       ``in_cidr(...)``, or reversed arguments -> ``net.ip_in_range_cidr($<var>.<canonical_field>, "<cidr>")``),
       and Google Drive Markdown-imported italic-corrupted regex wildcards
       (``italic_corrupted_regex_wildcard``: ``/.cmd./`` with ``textStyle.italic=True`` -> ``/.*cmd.*/``).
    3. Cross-event join semantic type contradictions (``cross_event_join_type_mismatch``) where
       two event streams bind the same join placeholder ``$<join_key>`` to incompatible UDM domains
       (e.g. ``$e1.principal.ip = $ip`` paired with ``$e2.principal.hostname = $ip``).
    4. ``match:`` section placeholder variable mismatches (``match_placeholder_mismatch``) and
       invalid ``match:`` time window syntax or verbose units (``invalid_match_window_syntax``,
       normalized to ``over <N><s|m|h|d>``).
    5. ``outcome:`` section non-YARA-L SQL/Splunk aggregation functions
       (``invalid_outcome_aggregation_function``: ``distinct_count`` -> ``count_distinct``,
       ``collect_set`` -> ``array_distinct``, ``avg`` -> ``max``), SQL/Splunk conditional
       scoring expressions (``invalid_outcome_conditional_syntax``: ``CASE WHEN ... END`` and
       ``iff(...)`` -> ``if(...)``, wrapped in ``max(if(...))`` when top-level in a ``match:``
       rule), and unaggregated event fields in rules with a ``match:`` window
       (``unaggregated_outcome_in_match_rule``).
    6. Single-event (``condition_variable_mismatch``), multi-event
       (``multi_event_condition_mismatch``), ``outcome:`` threshold variable
       (``condition_outcome_variable_mismatch``), and non-existence negation syntax
       (``invalid_condition_negation_syntax``: ``not $e2`` -> ``!$e2``) condition errors.
    7. Optional ``meta:`` block MITRE ATT&CK attribution synthesis and consistency checks
       (when ``verify_meta_mitre=True``): ``missing_meta_mitre_attribution`` (when
       ``synthesize_missing_meta=True``), ``meta_mitre_technique_mismatch``,
       ``meta_mitre_tactic_mismatch``, and ``meta_mitre_url_mismatch``.
    8. Optional ``meta:`` block severity-to-risk-score consistency and ``SkillRegistry``
       runbook routing checks (when ``verify_meta_severity=True`` or ``verify_meta_runbook=True``):
       ``invalid_meta_severity``, ``meta_severity_risk_score_mismatch``,
       ``meta_runbook_skill_mismatch``, and ``missing_meta_runbook_skill`` (when
       ``synthesize_missing_runbook=True``).

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

    italic_regex_by_rule: dict[str, list[dict[str, Any]]] = {}
    if isinstance(doc, dict):
        _ir_comments, _ir_edits, ir_findings = find_italic_corrupted_regex_spans(
            doc,
            udm_doc_url=udm_doc_url,
            yaral2_doc_url=yaral2_doc_url,
        )
        for ir_f in ir_findings:
            if ir_f.get("context_kind") == "yaral2" and ir_f.get("rule_name"):
                italic_regex_by_rule.setdefault(
                    str(ir_f["rule_name"]), []
                ).append(ir_f)

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

        multi_spec = extract_yaral2_multi_event_spec(
            rule_text,
            rule_char_start=rule_char_start,
            full_plain_text=plain_text,
            index_map=index_map,
        )
        declared_event_vars: list[str] = list(multi_spec["event_var_names"])
        declared_outcome_vars: list[str] = list(multi_spec["outcome_var_names"])
        declared_outcome_set: set[str] = set(declared_outcome_vars)
        ordered_placeholder_names: list[str] = [
            ph.lstrip("$") for ph in multi_spec["join_placeholders"]
        ]
        declared_placeholder_vars: set[str] = set(ordered_placeholder_names)
        for sec in sections:
            if sec["name"] in ("events", "strings"):
                for ph_m in _YARAL2_PLACEHOLDER_RHS_RE.finditer(sec["body"]):
                    p_name = ph_m.group(1)
                    declared_placeholder_vars.add(p_name)
                    if p_name not in ordered_placeholder_names:
                        ordered_placeholder_names.append(p_name)
                for ph_m in _YARAL2_PLACEHOLDER_LHS_RE.finditer(sec["body"]):
                    p_name = ph_m.group(1)
                    declared_placeholder_vars.add(p_name)
                    if p_name not in ordered_placeholder_names:
                        ordered_placeholder_names.append(p_name)

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

        # (b2) Non-canonical CIDR function calls in events:/strings: (cidrmatch, ipv4_is_in_range, in_cidr, or reversed args)
        for pred in multi_spec["predicates"]:
            if pred.get("predicate_kind") != "cidr":
                continue
            if pred.get("is_valid_cidr_syntax"):
                continue
            local_start = int(pred["local_predicate_start"])
            local_end = int(pred["local_predicate_end"])
            quote = str(pred["predicate_text"])
            replacement = str(pred["canonical_yaral2_call"])
            cidr_fn = str(pred.get("cidr_function") or quote)
            rule_defects = [
                d
                for d in rule_defects
                if not _spans_overlap(
                    (int(d["local_start"]), int(d["local_end"])),
                    (local_start, local_end),
                )
            ]
            rule_defects.append(
                {
                    "local_start": local_start,
                    "local_end": local_end,
                    "defect_type": "invalid_cidr_function_syntax",
                    "event_var": str(pred["event_var"]),
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": cidr_fn,
                    "canonical_field": "net.ip_in_range_cidr",
                    "comment": (
                        f"Deterministic YARA-L 2.0 (YL2) CIDR Function Check in rule '{rule_name}': "
                        f"'{quote}' uses non-canonical CIDR function syntax '{cidr_fn}(...)'. "
                        f"Chronicle YARA-L 2.0 requires 'net.ip_in_range_cidr(<udm_ip_field>, \"<cidr>\")'; "
                        f"replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                    ),
                }
            )

        # (b3) Italic-corrupted regex wildcards inside YARA-L 2.0 rules (Google Drive Markdown import)
        for ir_f in italic_regex_by_rule.get(rule_name, []):
            raw_loc_s = ir_f.get("local_start")
            raw_loc_e = ir_f.get("local_end")
            if raw_loc_s is None or raw_loc_e is None:
                continue
            local_start = int(raw_loc_s)
            local_end = int(raw_loc_e)
            if (
                local_start < 0
                or local_end > len(rule_text)
                or local_start >= local_end
            ):
                continue
            if any(
                _spans_overlap(
                    (int(d["local_start"]), int(d["local_end"])),
                    (local_start, local_end),
                )
                for d in rule_defects
            ):
                continue
            quote = str(ir_f["quote"])
            if rule_text[local_start:local_end] != quote:
                continue
            replacement = str(ir_f["replacement"])
            rule_defects.append(
                {
                    "local_start": local_start,
                    "local_end": local_end,
                    "defect_type": "italic_corrupted_regex_wildcard",
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": str(ir_f["invalid_field"]),
                    "canonical_field": str(ir_f["canonical_field"]),
                    "restored_regex": str(ir_f["restored_regex"]),
                    "yaral2_backtick_regex": str(ir_f["yaral2_backtick_regex"]),
                    "italic_subspans": list(ir_f.get("italic_subspans", [])),
                    "comment": str(ir_f["comment"]),
                }
            )

        in_membership_repairs: list[dict[str, Any]] = []
        strings_function_repairs: list[dict[str, Any]] = []
        re_capture_repairs: list[dict[str, Any]] = []

        # (b4) SQL/SPL/KQL inline `in (...)` / `in [...]` tuple membership, Reference List `%<list_name>`,
        # `strings.*` functions, and `re.capture()` calls in `events:` / `strings:` sections
        for sec in sections:
            if sec["name"] not in ("events", "strings"):
                continue
            b_offset = int(sec["body_start"])
            sec_body = str(sec["body"])

            for in_rep in _inspect_and_repair_yaral2_in_and_reference_lists(
                sec_body, event_vars=declared_event_vars
            ):
                local_start = b_offset + int(in_rep["local_start"])
                local_end = b_offset + int(in_rep["local_end"])
                quote = str(in_rep["quote"])
                replacement = str(in_rep["replacement"])
                d_type = str(in_rep["defect_type"])
                rule_defects = [
                    d
                    for d in rule_defects
                    if not _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (local_start, local_end),
                    )
                ]
                if d_type == "invalid_in_membership_syntax":
                    in_membership_repairs.append(
                        {
                            "quote": quote,
                            "replacement": replacement,
                            "event_var": in_rep["event_var"],
                            "invalid_field": in_rep["invalid_field"],
                            "canonical_field": in_rep["canonical_field"],
                            "values": in_rep["values"],
                            "is_negated": in_rep["is_negated"],
                            "udm_clause": in_rep["udm_clause"],
                        }
                    )
                    comment_msg = (
                        f"Deterministic YARA-L 2.0 (YL2) IN-Tuple Membership Check in rule '{rule_name}': "
                        f"'{quote}' uses SQL/SPL/KQL inline tuple/array membership syntax, whereas "
                        f"Chronicle YARA-L 2.0 reserves 'in' for Reference Lists ('%<list_name>') and "
                        f"requires parenthesized boolean disjunctions for inline value lists. Replace "
                        f"'{quote}' with '{replacement}' ({yaral2_doc_url})."
                    )
                else:
                    comment_msg = (
                        f"Deterministic YARA-L 2.0 (YL2) Reference List Syntax Check in rule '{rule_name}': "
                        f"'{quote}' uses non-canonical Reference List syntax ('{in_rep['invalid_field']}'). "
                        f"Chronicle YARA-L 2.0 Reference Lists require 'in [regex |cidr ]%<list_name>' "
                        f"with a leading '%' sigil; replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                    )
                defect_entry: dict[str, Any] = {
                    "local_start": local_start,
                    "local_end": local_end,
                    "defect_type": d_type,
                    "event_var": str(in_rep["event_var"]),
                    "quote": quote,
                    "replacement": replacement,
                    "invalid_field": str(in_rep["invalid_field"]),
                    "canonical_field": str(in_rep["canonical_field"]),
                    "comment": comment_msg,
                }
                if "reference_list_name" in in_rep:
                    defect_entry["reference_list_name"] = in_rep[
                        "reference_list_name"
                    ]
                    defect_entry["reference_list_token"] = in_rep[
                        "reference_list_token"
                    ]
                rule_defects.append(defect_entry)

            for str_rep in _inspect_and_repair_yaral2_strings_functions(
                sec_body,
                event_vars=declared_event_vars,
                has_match_section=False,
                is_outcome=False,
            ):
                local_start = b_offset + int(str_rep["local_start"])
                local_end = b_offset + int(str_rep["local_end"])
                if any(
                    _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (local_start, local_end),
                    )
                    and d.get("defect_type") != "invalid_udm_field"
                    for d in rule_defects
                ):
                    continue
                rule_defects = [
                    d
                    for d in rule_defects
                    if not _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (local_start, local_end),
                    )
                ]
                quote = str(str_rep["quote"])
                replacement = str(str_rep["replacement"])
                strings_function_repairs.append(
                    {
                        "section": "events",
                        "quote": quote,
                        "replacement": replacement,
                        "raw_function_name": str_rep["raw_function_name"],
                        "canonical_function_name": str_rep[
                            "canonical_function_name"
                        ],
                    }
                )
                rule_defects.append(
                    {
                        "local_start": local_start,
                        "local_end": local_end,
                        "defect_type": "invalid_strings_function_syntax",
                        "quote": quote,
                        "replacement": replacement,
                        "invalid_field": str(str_rep["invalid_field"]),
                        "canonical_field": str(str_rep["canonical_field"]),
                        "comment": (
                            f"Deterministic YARA-L 2.0 (YL2) Strings Function Check in rule '{rule_name}': "
                            f"'{quote}' uses non-canonical string function syntax '{str_rep['raw_function_name']}(...)'. "
                            f"Chronicle YARA-L 2.0 requires the 'strings.' namespace ('{str_rep['canonical_function_name']}(...)') "
                            f"and canonical UDM field paths; replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                        ),
                    }
                )

            for cap_rep in _inspect_and_repair_yaral2_re_capture_functions(
                sec_body,
                event_vars=declared_event_vars,
                has_match_section=False,
                is_outcome=False,
            ):
                local_start = b_offset + int(cap_rep["local_start"])
                local_end = b_offset + int(cap_rep["local_end"])
                if any(
                    _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (local_start, local_end),
                    )
                    and d.get("defect_type") != "invalid_udm_field"
                    for d in rule_defects
                ):
                    continue
                rule_defects = [
                    d
                    for d in rule_defects
                    if not _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (local_start, local_end),
                    )
                ]
                quote = str(cap_rep["quote"])
                replacement = str(cap_rep["replacement"])
                re_capture_repairs.append(
                    {
                        "section": "events",
                        "quote": quote,
                        "replacement": replacement,
                        "raw_function_name": cap_rep["raw_function_name"],
                        "canonical_function_name": cap_rep[
                            "canonical_function_name"
                        ],
                    }
                )
                rule_defects.append(
                    {
                        "local_start": local_start,
                        "local_end": local_end,
                        "defect_type": "invalid_re_capture_syntax",
                        "quote": quote,
                        "replacement": replacement,
                        "invalid_field": str(cap_rep["invalid_field"]),
                        "canonical_field": str(cap_rep["canonical_field"]),
                        "comment": (
                            f"Deterministic YARA-L 2.0 (YL2) Regex Capture Function Check in rule '{rule_name}': "
                            f"'{quote}' uses non-canonical regex extraction syntax '{cap_rep['raw_function_name']}(...)'. "
                            f"Chronicle YARA-L 2.0 requires 're.capture(<udm_field>, \"<capture_group_regex>\")'; "
                            f"replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                        ),
                    }
                )

        # (c) Cross-event join semantic type mismatch ($e1.principal.ip = $ip vs $e2.principal.hostname = $ip)
        if multi_spec["is_multi_event"]:
            bindings_by_ph: dict[str, list[dict[str, Any]]] = {}
            for jb in multi_spec["join_bindings"]:
                bindings_by_ph.setdefault(str(jb["placeholder_var"]), []).append(jb)
            for ph_var, p_bindings in bindings_by_ph.items():
                if len(p_bindings) < 2:
                    continue
                primary_b = p_bindings[0]
                primary_sem = str(primary_b["semantic_type"])
                primary_canon = str(primary_b["canonical_field"])
                primary_ev = str(primary_b["event_var"])
                if primary_sem == "generic":
                    continue
                for jb in p_bindings[1:]:
                    jb_sem = str(jb["semantic_type"])
                    if jb_sem == "generic" or jb_sem == primary_sem:
                        continue
                    local_start = int(jb["local_var_field_start"])
                    local_end = int(jb["local_var_field_end"])
                    quote = str(jb["var_field_token"])
                    jb_ev = str(jb["event_var"])
                    replacement = f"{jb_ev}.{primary_canon}"
                    rule_defects = [
                        d
                        for d in rule_defects
                        if not (
                            int(d["local_start"]) == local_start
                            and int(d["local_end"]) == local_end
                        )
                    ]
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "cross_event_join_type_mismatch",
                            "event_var": jb_ev,
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": str(jb["field_token"]),
                            "canonical_field": primary_canon,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Cross-Event Join Type Check in rule '{rule_name}': "
                                f"'{quote}' binds join placeholder '{ph_var}' to UDM semantic type '{jb_sem}' "
                                f"('{jb['canonical_field']}'), contradicting '{primary_ev}.{primary_canon} = {ph_var}' "
                                f"(semantic type '{primary_sem}'). Replace '{quote}' with '{replacement}' ({udm_doc_url})."
                            ),
                        }
                    )

        # (d) 'match:' placeholder variable mismatch and invalid window syntax
        if multi_spec["match_clauses"]:
            matched_ph_names = {
                str(p["placeholder_name"])
                for mc in multi_spec["match_clauses"]
                for p in mc["placeholders"]
            }
            unused_ph_names = [
                p for p in ordered_placeholder_names if p not in matched_ph_names
            ]
            for mc in multi_spec["match_clauses"]:
                for p in mc["placeholders"]:
                    ph_name = str(p["placeholder_name"])
                    if (
                        ph_name in declared_placeholder_vars
                        or ph_name in declared_event_vars
                    ):
                        continue
                    target_ph = (
                        unused_ph_names.pop(0)
                        if unused_ph_names
                        else (
                            ordered_placeholder_names[0]
                            if ordered_placeholder_names
                            else (
                                declared_event_vars[0]
                                if declared_event_vars
                                else None
                            )
                        )
                    )
                    if not target_ph:
                        continue
                    local_start = int(p["local_start"])
                    local_end = int(p["local_end"])
                    quote = str(p["placeholder_var"])
                    replacement = f"${target_ph}"
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "match_placeholder_mismatch",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Match Placeholder Check in rule '{rule_name}': "
                                f"match section references undeclared placeholder '{quote}', while the events "
                                f"section binds join placeholder '{replacement}'. Replace '{quote}' with "
                                f"'{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )

                win_raw = mc.get("window_raw")
                win_norm = mc.get("window_normalized")
                if (
                    win_raw
                    and not mc.get("window_valid")
                    and win_norm
                    and mc.get("local_window_start") is not None
                    and mc.get("local_window_end") is not None
                ):
                    local_start = int(mc["local_window_start"])
                    local_end = int(mc["local_window_end"])
                    quote = str(win_raw)
                    replacement = str(win_norm)
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "invalid_match_window_syntax",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Match Window Syntax Check in rule '{rule_name}': "
                                f"'{quote}' is not valid Chronicle YARA-L 2.0 match window syntax. "
                                f"Use canonical 'over <N><s|m|h|d>' syntax '{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )

        # (d2) 'outcome:' section non-canonical conditionals, strings.*, re.capture(), aggregation functions, and unaggregated fields in match rules
        if multi_spec["outcome_bindings"]:
            has_match_section = bool(multi_spec["match_clauses"])
            for ob in multi_spec["outcome_bindings"]:
                cond_spec = ob.get("conditional_spec")
                ob_rhs_text = str(ob["rhs_text"])
                ob_str_repairs = _inspect_and_repair_yaral2_strings_functions(
                    ob_rhs_text,
                    event_vars=declared_event_vars,
                    has_match_section=has_match_section,
                    is_outcome=True,
                )
                ob_cap_repairs = _inspect_and_repair_yaral2_re_capture_functions(
                    ob_rhs_text,
                    event_vars=declared_event_vars,
                    has_match_section=has_match_section,
                    is_outcome=True,
                )
                if (
                    isinstance(cond_spec, dict)
                    and not cond_spec.get("is_valid_conditional_syntax", True)
                ):
                    local_start = int(ob["local_rhs_start"])
                    local_end = int(ob["local_rhs_end"])
                    quote = ob_rhs_text
                    canon_if = str(cond_spec["canonical_if_expr"])
                    if ob.get("canonical_func_name"):
                        agg_fn = str(ob["canonical_func_name"])
                        replacement = f"{agg_fn}({canon_if})"
                    elif has_match_section:
                        first_canon_field = (
                            str(
                                ob["referenced_event_field_specs"][0][
                                    "canonical_field"
                                ]
                            )
                            if ob["referenced_event_field_specs"]
                            else ""
                        )
                        agg_fn = (
                            "max"
                            if (
                                cond_spec.get("true_value") is not None
                                or cond_spec.get("false_value") is not None
                            )
                            else _choose_yaral2_outcome_agg_func(
                                str(ob["outcome_var_name"]), first_canon_field
                            )
                        )
                        replacement = f"{agg_fn}({canon_if})"
                    else:
                        replacement = canon_if
                    rule_defects = [
                        d
                        for d in rule_defects
                        if not _spans_overlap(
                            (int(d["local_start"]), int(d["local_end"])),
                            (local_start, local_end),
                        )
                    ]
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "invalid_outcome_conditional_syntax",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Outcome Conditional Check in rule '{rule_name}': "
                                f"outcome variable '{ob['outcome_var']}' uses SQL/Splunk conditional syntax "
                                f"'{quote}'. Replace with canonical Chronicle YARA-L 2.0 conditional "
                                f"'{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )
                elif ob_str_repairs:
                    sr = ob_str_repairs[0]
                    local_start = int(ob["local_rhs_start"]) + int(
                        sr["local_start"]
                    )
                    local_end = int(ob["local_rhs_start"]) + int(
                        sr["local_end"]
                    )
                    quote = str(sr["quote"])
                    replacement = str(sr["replacement"])
                    strings_function_repairs.append(
                        {
                            "section": "outcome",
                            "outcome_var": str(ob["outcome_var"]),
                            "quote": quote,
                            "replacement": replacement,
                            "raw_function_name": sr["raw_function_name"],
                            "canonical_function_name": sr[
                                "canonical_function_name"
                            ],
                            "wrapped_in_aggregation": sr.get(
                                "wrapped_in_aggregation", False
                            ),
                        }
                    )
                    rule_defects = [
                        d
                        for d in rule_defects
                        if not _spans_overlap(
                            (int(d["local_start"]), int(d["local_end"])),
                            (local_start, local_end),
                        )
                    ]
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "invalid_strings_function_syntax",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": str(sr["invalid_field"]),
                            "canonical_field": str(sr["canonical_field"]),
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Strings Function Check in rule '{rule_name}': "
                                f"outcome variable '{ob['outcome_var']}' uses non-canonical string function "
                                f"'{quote}'. Replace with canonical Chronicle YARA-L 2.0 expression "
                                f"'{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )
                elif ob_cap_repairs:
                    cr = ob_cap_repairs[0]
                    local_start = int(ob["local_rhs_start"]) + int(
                        cr["local_start"]
                    )
                    local_end = int(ob["local_rhs_start"]) + int(
                        cr["local_end"]
                    )
                    quote = str(cr["quote"])
                    replacement = str(cr["replacement"])
                    re_capture_repairs.append(
                        {
                            "section": "outcome",
                            "outcome_var": str(ob["outcome_var"]),
                            "quote": quote,
                            "replacement": replacement,
                            "raw_function_name": cr["raw_function_name"],
                            "canonical_function_name": cr[
                                "canonical_function_name"
                            ],
                            "added_capture_group": cr.get(
                                "added_capture_group", False
                            ),
                            "wrapped_in_aggregation": cr.get(
                                "wrapped_in_aggregation", False
                            ),
                        }
                    )
                    rule_defects = [
                        d
                        for d in rule_defects
                        if not _spans_overlap(
                            (int(d["local_start"]), int(d["local_end"])),
                            (local_start, local_end),
                        )
                    ]
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "invalid_re_capture_syntax",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": str(cr["invalid_field"]),
                            "canonical_field": str(cr["canonical_field"]),
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Regex Capture Function Check in rule '{rule_name}': "
                                f"outcome variable '{ob['outcome_var']}' uses non-canonical regex extraction "
                                f"'{quote}'. Replace with canonical Chronicle YARA-L 2.0 expression "
                                f"'{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )
                elif (
                    ob["is_non_canonical_agg_func"]
                    and ob.get("local_func_start") is not None
                    and ob.get("local_func_end") is not None
                    and ob.get("canonical_func_name")
                ):
                    local_start = int(ob["local_func_start"])
                    local_end = int(ob["local_func_end"])
                    quote = str(ob["func_name"])
                    replacement = str(ob["canonical_func_name"])
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "invalid_outcome_aggregation_function",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Outcome Aggregation Check in rule '{rule_name}': "
                                f"outcome variable '{ob['outcome_var']}' uses non-YARA-L SQL/Splunk aggregation "
                                f"function '{quote}(...)'. Replace '{quote}' with canonical Chronicle YARA-L 2.0 "
                                f"aggregation '{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )
                elif (
                    has_match_section
                    and ob["referenced_event_field_specs"]
                    and not ob["is_aggregated"]
                ):
                    local_start = int(ob["local_rhs_start"])
                    local_end = int(ob["local_rhs_end"])
                    quote = ob_rhs_text
                    canonical_rhs = _canonicalize_yaral2_expr_fields(quote)
                    first_canon_field = str(
                        ob["referenced_event_field_specs"][0]["canonical_field"]
                    )
                    if isinstance(cond_spec, dict) and (
                        cond_spec.get("true_value") is not None
                        or cond_spec.get("false_value") is not None
                    ):
                        agg_func = "max"
                    else:
                        agg_func = _choose_yaral2_outcome_agg_func(
                            str(ob["outcome_var_name"]), first_canon_field
                        )
                    replacement = f"{agg_func}({canonical_rhs})"
                    # Supersede any inner invalid_udm_field defect overlapping this RHS span
                    rule_defects = [
                        d
                        for d in rule_defects
                        if not _spans_overlap(
                            (int(d["local_start"]), int(d["local_end"])),
                            (local_start, local_end),
                        )
                    ]
                    rule_defects.append(
                        {
                            "local_start": local_start,
                            "local_end": local_end,
                            "defect_type": "unaggregated_outcome_in_match_rule",
                            "quote": quote,
                            "replacement": replacement,
                            "invalid_field": quote,
                            "canonical_field": replacement,
                            "comment": (
                                f"Deterministic YARA-L 2.0 (YL2) Outcome Aggregation Check in rule '{rule_name}': "
                                f"outcome variable '{ob['outcome_var']} = {quote}' references an unaggregated "
                                f"UDM event field in a rule with a 'match:' window. Wrap the canonical UDM "
                                f"expression in '{agg_func}(...)' as '{replacement}' ({yaral2_doc_url})."
                            ),
                        }
                    )

        # (e) Condition variable and negation syntax checks (single-event, multi-event, outcome, !$e2)
        if declared_event_vars:
            cond_tokens = multi_spec["condition_tokens"]
            cond_span = multi_spec["condition_span"]
            cond_neg_spans = multi_spec["condition_negation_spans"]

            referenced_valid_events = {
                str(ct["var_name"])
                for ct in cond_tokens
                if str(ct["var_name"]) in declared_event_vars
            }
            missing_declared = [
                v
                for v in declared_event_vars
                if v not in referenced_valid_events
            ]
            referenced_valid_outcomes = {
                str(ct["var_name"])
                for ct in cond_tokens
                if str(ct["var_name"]) in declared_outcome_set
            }
            unused_outcomes = [
                v
                for v in declared_outcome_vars
                if v not in referenced_valid_outcomes
            ]

            handled_var_starts: set[int] = set()
            for neg_s in cond_neg_spans:
                v_name = str(neg_s["var_name"])
                sigil = str(neg_s["sigil"])
                var_loc_s = int(neg_s["local_var_start"])
                local_start = int(neg_s["local_start"])
                local_end = int(neg_s["local_end"])
                quote = str(neg_s["negation_text"])
                if (
                    v_name not in declared_event_vars
                    and v_name not in declared_placeholder_vars
                    and v_name not in declared_outcome_set
                ):
                    target_ev = (
                        missing_declared.pop(0)
                        if missing_declared
                        else declared_event_vars[-1]
                    )
                    replacement = f"!{sigil}{target_ev}"
                else:
                    replacement = f"!{sigil}{v_name}"
                handled_var_starts.add(var_loc_s)
                rule_defects.append(
                    {
                        "local_start": local_start,
                        "local_end": local_end,
                        "defect_type": "invalid_condition_negation_syntax",
                        "quote": quote,
                        "replacement": replacement,
                        "invalid_field": quote,
                        "canonical_field": replacement,
                        "comment": (
                            f"Deterministic YARA-L 2.0 (YL2) Condition Negation Syntax Check in rule '{rule_name}': "
                            f"'{quote}' uses SQL/Python-style 'not' keyword in the condition section. "
                            f"Chronicle YARA-L 2.0 non-existence correlation requires '!' negation syntax; "
                            f"replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                        ),
                    }
                )

            undeclared_tokens = [
                ct
                for ct in cond_tokens
                if int(ct["local_start"]) not in handled_var_starts
                and str(ct["var_name"]) not in declared_event_vars
                and str(ct["var_name"]) not in declared_placeholder_vars
                and str(ct["var_name"]) not in declared_outcome_set
            ]

            if undeclared_tokens:
                for ct in undeclared_tokens:
                    sigil = str(ct["sigil"])
                    cond_var = str(ct["var_name"])
                    in_cmp = bool(ct.get("in_comparison"))
                    local_start = int(ct["local_start"])
                    local_end = int(ct["local_end"])
                    quote = str(ct["token_text"])

                    if (
                        declared_outcome_vars
                        and sigil == "$"
                        and (in_cmp or not missing_declared)
                    ):
                        cand_outcomes = (
                            unused_outcomes
                            if unused_outcomes
                            else declared_outcome_vars
                        )
                        target_out = _select_best_outcome_var_for_condition_token(
                            cond_var,
                            in_cmp,
                            cand_outcomes,
                            multi_spec["outcome_bindings"],
                        )
                        if target_out in unused_outcomes:
                            unused_outcomes.remove(target_out)
                        replacement = f"${target_out}"
                        rule_defects.append(
                            {
                                "local_start": local_start,
                                "local_end": local_end,
                                "defect_type": "condition_outcome_variable_mismatch",
                                "quote": quote,
                                "replacement": replacement,
                                "invalid_field": quote,
                                "canonical_field": replacement,
                                "comment": (
                                    f"Deterministic YARA-L 2.0 (YL2) Condition Outcome Variable Check in rule '{rule_name}': "
                                    f"condition references undeclared variable '{quote}' in threshold comparison, "
                                    f"while the outcome section declares {', '.join('$' + v for v in declared_outcome_vars)}. "
                                    f"Replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                                ),
                            }
                        )
                    elif len(declared_event_vars) == 1:
                        canonical_ev = declared_event_vars[0]
                        if missing_declared:
                            missing_declared.clear()
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
                    else:
                        target_ev = (
                            missing_declared.pop(0)
                            if missing_declared
                            else declared_event_vars[-1]
                        )
                        replacement = f"{sigil}{target_ev}"
                        rule_defects.append(
                            {
                                "local_start": local_start,
                                "local_end": local_end,
                                "defect_type": "multi_event_condition_mismatch",
                                "quote": quote,
                                "replacement": replacement,
                                "invalid_field": quote,
                                "canonical_field": replacement,
                                "comment": (
                                    f"Deterministic YARA-L 2.0 (YL2) Multi-Event Condition Check in rule '{rule_name}': "
                                    f"condition references undeclared event variable '{quote}', while the events "
                                    f"section declares {', '.join('$' + v for v in declared_event_vars)}. "
                                    f"Replace '{quote}' with '{replacement}' ({yaral2_doc_url})."
                                ),
                            }
                        )
            elif (
                len(declared_event_vars) >= 2
                and missing_declared
                and cond_span is not None
                and not cond_neg_spans
            ):
                local_start = int(cond_span["local_start"])
                local_end = int(cond_span["local_end"])
                quote = str(cond_span["condition_text"])
                replacement = " and ".join(f"${v}" for v in declared_event_vars)
                rule_defects.append(
                    {
                        "local_start": local_start,
                        "local_end": local_end,
                        "defect_type": "multi_event_condition_mismatch",
                        "quote": quote,
                        "replacement": replacement,
                        "invalid_field": quote,
                        "canonical_field": replacement,
                        "comment": (
                            f"Deterministic YARA-L 2.0 (YL2) Multi-Event Condition Check in rule '{rule_name}': "
                            f"condition '{quote}' omits declared correlated event variable(s) "
                            f"{', '.join('$' + v for v in missing_declared)}. "
                            f"Replace condition expression with '{replacement}' ({yaral2_doc_url})."
                        ),
                    }
                )

        if verify_meta_mitre or verify_meta_runbook or verify_meta_severity:
            # Evaluate meta: defects against a rule copy that includes repaired outcome:/events:
            # expressions so conditional risk_score bindings (e.g. CASE WHEN -> max(if(...)))
            # and repaired UDM fields inform severity and runbook inference.
            prelim_rule_text = rule_text
            for d_pre in sorted(
                rule_defects, key=lambda d: int(d["local_start"]), reverse=True
            ):
                ps = int(d_pre["local_start"])
                pe = int(d_pre["local_end"])
                prelim_rule_text = (
                    prelim_rule_text[:ps]
                    + str(d_pre["replacement"])
                    + prelim_rule_text[pe:]
                )
            meta_mitre_defs = (
                _find_rule_meta_mitre_defects(
                    rule_text,
                    rule_name,
                    synthesize_missing_meta=synthesize_missing_meta,
                    yaral2_doc_url=yaral2_doc_url,
                )
                if verify_meta_mitre
                else []
            )
            meta_rb_sev_defs = (
                _find_rule_meta_runbook_and_severity_defects(
                    rule_text,
                    rule_name,
                    verify_meta_severity=verify_meta_severity,
                    verify_meta_runbook=verify_meta_runbook,
                    synthesize_missing_runbook=synthesize_missing_runbook,
                    skill_registry=skill_registry,
                    yaral2_doc_url=yaral2_doc_url,
                )
                if (verify_meta_runbook or verify_meta_severity)
                else []
            )
            merged_meta_defs = _merge_yaral2_meta_defects(
                rule_text,
                rule_name,
                meta_mitre_defs,
                meta_rb_sev_defs,
                yaral2_doc_url=yaral2_doc_url,
            )
            for md in merged_meta_defs:
                m_start = int(md["local_start"])
                m_end = int(md["local_end"])
                if any(
                    _spans_overlap(
                        (int(d["local_start"]), int(d["local_end"])),
                        (m_start, m_end),
                    )
                    for d in rule_defects
                ):
                    continue
                rule_defects.append(md)

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
        repaired_multi_spec = extract_yaral2_multi_event_spec(repaired_rule)
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
            f_record: dict[str, Any] = {
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
                "is_multi_event": repaired_multi_spec["is_multi_event"],
                "per_event_udm_queries": repaired_multi_spec[
                    "per_event_udm_queries"
                ],
                "retrohunt_udm_query": retrohunt_query,
                "retrohunt_clauses": retrohunt_clauses,
                "reference_lists": list(
                    repaired_multi_spec.get("reference_lists") or []
                ),
                "in_membership_repairs": list(in_membership_repairs),
                "strings_function_repairs": list(strings_function_repairs),
                "re_capture_repairs": list(re_capture_repairs),
            }
            for extra_key in (
                "meta_key",
                "canonical_id",
                "canonical_name",
                "tactic",
                "reference_url",
                "synthesized_keys",
                "folded_defect_types",
                "repaired_anchor_key",
                "repaired_anchor_value",
                "cited_severity",
                "canonical_severity",
                "risk_score",
                "score_band",
                "cited_skill",
                "canonical_skill",
                "skill_category",
                "allowed_skills",
                "skill_verified",
                "evidence_reason",
                "reference_list_name",
                "reference_list_token",
            ):
                if extra_key in defect:
                    f_record[extra_key] = defect[extra_key]
            if "restored_regex" in defect:
                f_record["restored_regex"] = defect["restored_regex"]
                f_record["yaral2_backtick_regex"] = defect.get(
                    "yaral2_backtick_regex", ""
                )
                f_record["italic_subspans"] = defect.get("italic_subspans", [])
            findings.append(f_record)

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


def _validate_yaral2_rule_with_compiler(
    candidate_rule_text: str,
    *,
    siem_validate_fn: Any = None,
) -> tuple[bool, str]:
    """Compiles a YARA-L 2.0 (``YL2``) rule via Chronicle's ``validate_rule`` endpoint."""

    def _call_validate(rule_str: str) -> tuple[bool, str]:
        if siem_validate_fn is not None:
            try:
                raw_val = siem_validate_fn(rule_text=rule_str)
            except TypeError:
                raw_val = siem_validate_fn(rule_str)
        else:
            from .tools import execute_mcp_tool

            raw_val = execute_mcp_tool(
                "secops-mcp_validate_rule",
                {"rule_text": rule_str},
            )
        parsed_val = _parse_siem_validate_output(raw_val)
        return bool(parsed_val["compiler_verified"]), str(
            parsed_val["compiler_output"]
        )

    try:
        comp_ok, comp_out = _call_validate(candidate_rule_text)
        if (
            not comp_ok
            and "reference list version fetching: metadata unavailable for reference list"
            in comp_out.lower()
        ):
            probe_rule = re.sub(
                r"(?i)(?:\bnot\s+)?(\$[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*)\s+in\s+(?:(?:regex|cidr)\s+)?%([A-Za-z_][A-Za-z0-9_]*)",
                r'\1 != "__yaral2_ref_list_probe_\2__"',
                candidate_rule_text,
            )
            if probe_rule != candidate_rule_text:
                probe_ok, probe_out = _call_validate(probe_rule)
                if probe_ok:
                    return (
                        True,
                        f"{probe_out} (reference list syntax verified; tenant metadata probe bypassed)",
                    )
        return comp_ok, comp_out
    except Exception as err:
        return False, f"Chronicle validate_rule call failed: {err}"


def _run_multi_event_siem_retrohunt(
    rule_text: str,
    *,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 20,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Executes per-event-stream UDM queries in Chronicle SIEM for a multi-event YARA-L 2.0 rule
    and computes shared join-key values (or non-existence set-difference join keys
    ``positive_join_values - negated_join_values`` when ``condition: $e1 and !$e2`` is present)."""
    spec = extract_yaral2_multi_event_spec(rule_text)
    event_vars: list[str] = list(spec["event_vars"])
    positive_event_vars: list[str] = list(
        spec.get("positive_event_vars") or event_vars
    )
    negated_event_vars: list[str] = list(spec.get("negated_event_vars") or [])
    is_non_existence: bool = bool(spec.get("is_non_existence"))
    per_event_queries: dict[str, str] = dict(spec["per_event_udm_queries"])
    per_event_counts: dict[str, int] = {}
    per_event_responses: dict[str, dict[str, Any]] = {}
    per_event_field_values: dict[str, dict[str, list[str]]] = {}
    per_event_event_maps: dict[str, list[dict[str, list[str]]]] = {}

    for ev in event_vars:
        q = per_event_queries.get(ev, "")
        if not q:
            per_event_counts[ev] = 0
            per_event_responses[ev] = {"siem_verified": False, "event_count": 0}
            per_event_field_values[ev] = {}
            per_event_event_maps[ev] = []
            continue
        ev_res = verify_udm_query_with_siem(
            q,
            start_time=start_time,
            end_time=end_time,
            max_events=max(max_events, 20),
            siem_search_fn=siem_search_fn,
        )
        per_event_responses[ev] = ev_res
        per_event_counts[ev] = int(ev_res.get("event_count", 0) or 0)
        raw_events = (ev_res.get("siem_response") or {}).get("events")
        events_list = raw_events if isinstance(raw_events, list) else []
        merged_fields: dict[str, list[str]] = {}
        ev_maps: list[dict[str, list[str]]] = []
        for ev_obj in events_list:
            if not isinstance(ev_obj, dict):
                continue
            f_map = _extract_udm_event_field_values(ev_obj)
            ev_maps.append(f_map)
            for f_path, vals in f_map.items():
                bucket = merged_fields.setdefault(f_path, [])
                for v in vals:
                    if v not in bucket:
                        bucket.append(v)
        per_event_field_values[ev] = merged_fields
        per_event_event_maps[ev] = ev_maps

    join_placeholders: list[str] = list(spec["join_placeholders"])
    join_placeholder = join_placeholders[0] if join_placeholders else None
    join_bindings: list[dict[str, Any]] = list(spec["join_bindings"])
    per_event_join_values: dict[str, list[str]] = {}
    positive_join_values: list[str] = []
    suppressed_join_values: list[str] = []
    shared_join_values: list[str] = []
    correlated_event_count = 0
    sample_limit = max(max_events, 20)

    def _pushdown_candidates_into_bindings(
        anchor_ev: str,
        candidate_vals: list[str],
        target_bindings: list[dict[str, Any]],
    ) -> None:
        for trunc_b in target_bindings:
            trunc_ev = str(trunc_b["event_var"])
            if trunc_ev == anchor_ev:
                continue
            trunc_q = per_event_queries.get(trunc_ev, "")
            trunc_field = str(trunc_b["canonical_field"])
            if not trunc_q or not trunc_field:
                continue
            for cand_val in candidate_vals[:3]:
                pushed_q = f'{trunc_q} AND {trunc_field} = "{cand_val}"'
                pushed_res = verify_udm_query_with_siem(
                    pushed_q,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=sample_limit,
                    siem_search_fn=siem_search_fn,
                )
                if (
                    pushed_res.get("siem_verified")
                    and int(pushed_res.get("event_count", 0) or 0) > 0
                ):
                    pushed_events = (
                        pushed_res.get("siem_response") or {}
                    ).get("events")
                    if isinstance(pushed_events, list):
                        for ev_obj in pushed_events:
                            if not isinstance(ev_obj, dict):
                                continue
                            f_map = _extract_udm_event_field_values(ev_obj)
                            per_event_event_maps.setdefault(
                                trunc_ev, []
                            ).append(f_map)
                            for f_path, vals in f_map.items():
                                bucket = per_event_field_values.setdefault(
                                    trunc_ev, {}
                                ).setdefault(f_path, [])
                                for v in vals:
                                    if v not in bucket:
                                        bucket.append(v)
                    if cand_val not in per_event_join_values.setdefault(
                        trunc_ev, []
                    ):
                        per_event_join_values[trunc_ev].append(cand_val)

    if join_placeholder is not None:
        ph_bindings = [
            b for b in join_bindings if str(b["placeholder_var"]) == join_placeholder
        ]
        for b in ph_bindings:
            ev = str(b["event_var"])
            c_field = str(b["canonical_field"])
            vals = per_event_field_values.get(ev, {}).get(c_field, [])
            per_event_join_values[ev] = list(vals)

        if is_non_existence and positive_event_vars:
            pos_bindings = [
                b
                for b in ph_bindings
                if str(b["event_var"]) in positive_event_vars
            ]
            neg_bindings = [
                b
                for b in ph_bindings
                if str(b["event_var"]) in negated_event_vars
            ]
            if len(pos_bindings) == 1:
                pos_ev = str(pos_bindings[0]["event_var"])
                positive_join_values = list(
                    per_event_join_values.get(pos_ev, [])
                )
            elif len(pos_bindings) >= 2:
                if all(
                    bool(per_event_join_values.get(str(b["event_var"])))
                    for b in pos_bindings
                ):
                    first_ev = str(pos_bindings[0]["event_var"])
                    first_vals = per_event_join_values.get(first_ev, [])
                    other_sets = [
                        {
                            v.lower()
                            for v in per_event_join_values.get(
                                str(b["event_var"]), []
                            )
                        }
                        for b in pos_bindings[1:]
                    ]
                    positive_join_values = [
                        v
                        for v in first_vals
                        if all(v.lower() in s for s in other_sets)
                    ]
                if not positive_join_values:
                    sel_pos = [
                        b
                        for b in pos_bindings
                        if 1
                        <= len(
                            per_event_join_values.get(str(b["event_var"]), [])
                        )
                        <= 5
                    ]
                    trunc_pos = [
                        b
                        for b in pos_bindings
                        if per_event_counts.get(str(b["event_var"]), 0)
                        >= sample_limit
                    ]
                    if sel_pos and trunc_pos:
                        anchor_b = min(
                            sel_pos,
                            key=lambda b: len(
                                per_event_join_values.get(
                                    str(b["event_var"]), []
                                )
                            ),
                        )
                        _pushdown_candidates_into_bindings(
                            str(anchor_b["event_var"]),
                            per_event_join_values.get(
                                str(anchor_b["event_var"]), []
                            ),
                            trunc_pos,
                        )
                        first_ev = str(pos_bindings[0]["event_var"])
                        first_vals = per_event_join_values.get(first_ev, [])
                        other_sets = [
                            {
                                v.lower()
                                for v in per_event_join_values.get(
                                    str(b["event_var"]), []
                                )
                            }
                            for b in pos_bindings[1:]
                        ]
                        positive_join_values = [
                            v
                            for v in first_vals
                            if all(v.lower() in s for s in other_sets)
                        ]

            if positive_join_values and neg_bindings:
                trunc_neg = [
                    b
                    for b in neg_bindings
                    if per_event_counts.get(str(b["event_var"]), 0)
                    >= sample_limit
                ]
                if trunc_neg:
                    _pushdown_candidates_into_bindings(
                        str(pos_bindings[0]["event_var"])
                        if pos_bindings
                        else "",
                        positive_join_values,
                        trunc_neg,
                    )

            negated_join_values: list[str] = []
            for nb in neg_bindings:
                for v in per_event_join_values.get(str(nb["event_var"]), []):
                    if v not in negated_join_values:
                        negated_join_values.append(v)
            negated_lower = {v.lower() for v in negated_join_values}
            suppressed_join_values = [
                v for v in positive_join_values if v.lower() in negated_lower
            ]
            shared_join_values = [
                v
                for v in positive_join_values
                if v.lower() not in negated_lower
            ]

            if shared_join_values and pos_bindings:
                shared_lower = {v.lower() for v in shared_join_values}
                pos_corr_counts: list[int] = []
                for b in pos_bindings:
                    ev = str(b["event_var"])
                    c_field = str(b["canonical_field"])
                    ev_maps = per_event_event_maps.get(ev, [])
                    if ev_maps:
                        matched_cnt = sum(
                            1
                            for em in ev_maps
                            if any(
                                v.lower() in shared_lower
                                for v in em.get(c_field, [])
                            )
                        )
                    else:
                        matched_cnt = per_event_counts.get(ev, 0)
                    pos_corr_counts.append(matched_cnt)
                if pos_corr_counts and all(c > 0 for c in pos_corr_counts):
                    correlated_event_count = sum(pos_corr_counts)
        else:
            if len(ph_bindings) >= 2 and all(
                bool(per_event_join_values.get(str(b["event_var"])))
                for b in ph_bindings
            ):
                first_ev = str(ph_bindings[0]["event_var"])
                first_vals = per_event_join_values.get(first_ev, [])
                other_sets = [
                    {
                        v.lower()
                        for v in per_event_join_values.get(
                            str(b["event_var"]), []
                        )
                    }
                    for b in ph_bindings[1:]
                ]
                shared_join_values = [
                    v
                    for v in first_vals
                    if all(v.lower() in s for s in other_sets)
                ]

            if not shared_join_values and len(ph_bindings) >= 2:
                selective_bindings = [
                    b
                    for b in ph_bindings
                    if 1
                    <= len(per_event_join_values.get(str(b["event_var"]), []))
                    <= 5
                ]
                truncated_bindings = [
                    b
                    for b in ph_bindings
                    if per_event_counts.get(str(b["event_var"]), 0)
                    >= sample_limit
                ]
                if selective_bindings and truncated_bindings:
                    anchor_b = min(
                        selective_bindings,
                        key=lambda b: len(
                            per_event_join_values.get(str(b["event_var"]), [])
                        ),
                    )
                    anchor_ev = str(anchor_b["event_var"])
                    anchor_vals = per_event_join_values.get(anchor_ev, [])
                    _pushdown_candidates_into_bindings(
                        anchor_ev, anchor_vals, truncated_bindings
                    )

                    first_ev = str(ph_bindings[0]["event_var"])
                    first_vals = per_event_join_values.get(first_ev, [])
                    other_sets = [
                        {
                            v.lower()
                            for v in per_event_join_values.get(
                                str(b["event_var"]), []
                            )
                        }
                        for b in ph_bindings[1:]
                    ]
                    shared_join_values = [
                        v
                        for v in first_vals
                        if all(v.lower() in s for s in other_sets)
                    ]

            positive_join_values = list(shared_join_values)
            if shared_join_values:
                shared_lower = {v.lower() for v in shared_join_values}
                stream_corr_counts: list[int] = []
                for b in ph_bindings:
                    ev = str(b["event_var"])
                    c_field = str(b["canonical_field"])
                    ev_maps = per_event_event_maps.get(ev, [])
                    if ev_maps:
                        matched_cnt = sum(
                            1
                            for em in ev_maps
                            if any(
                                v.lower() in shared_lower
                                for v in em.get(c_field, [])
                            )
                        )
                    else:
                        matched_cnt = per_event_counts.get(ev, 0)
                    stream_corr_counts.append(matched_cnt)
                if stream_corr_counts and all(c > 0 for c in stream_corr_counts):
                    correlated_event_count = sum(stream_corr_counts)

    siem_verified = (
        all(bool(r.get("siem_verified")) for r in per_event_responses.values())
        if per_event_responses
        else False
    )
    summary_query = " | ".join(
        f"{ev}: {q}" for ev, q in per_event_queries.items() if q
    )

    return {
        "is_multi_event": True,
        "is_non_existence": is_non_existence,
        "siem_verified": siem_verified,
        "event_vars": event_vars,
        "positive_event_vars": positive_event_vars,
        "negated_event_vars": negated_event_vars,
        "per_event_queries": per_event_queries,
        "per_event_counts": per_event_counts,
        "per_event_join_values": per_event_join_values,
        "per_event_responses": per_event_responses,
        "per_event_field_values": per_event_field_values,
        "per_event_event_maps": per_event_event_maps,
        "join_placeholder": join_placeholder,
        "join_bindings": join_bindings,
        "positive_join_values": positive_join_values,
        "suppressed_join_values": suppressed_join_values,
        "shared_join_values": shared_join_values,
        "correlated_event_count": correlated_event_count,
        "summary_query": summary_query,
    }


def _synthesize_yaral2_predicate_pivot(
    diagnosis_class: str,
    orig_pred: dict[str, Any],
    rep_pred: dict[str, Any],
    udm_diag: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    """Synthesizes ``(recommended_field, recommended_rhs, recommended_yaral2_predicate,
    recommended_span_target, recommended_span_replacement)`` for a zero-hit YARA-L 2.0
    event predicate."""
    event_var = str(orig_pred["event_var"])
    recommended_field = str(
        udm_diag.get("recommended_field") or rep_pred["canonical_field"]
    )
    recommended_rhs = str(udm_diag.get("recommended_rhs") or rep_pred["rhs_raw"])
    recommended_clause = str(udm_diag.get("recommended_clause") or "")

    if diagnosis_class == "exact_match_on_command_line":
        pat_m = re.search(r"/([^/\r\n]+)/", recommended_clause)
        if pat_m:
            regex_pattern = pat_m.group(1)
        else:
            raw_lit = str(orig_pred["rhs_raw"]).strip("\"'“”`")
            regex_pattern = f".*{re.escape(raw_lit)}.*"
        recommended_yaral2_predicate = (
            f"re.regex({event_var}.{recommended_field}, `{regex_pattern}`) nocase"
        )
        recommended_span_target = "predicate"
        recommended_span_replacement = recommended_yaral2_predicate
    elif diagnosis_class == "entity_role_swap":
        new_var_field = f"{event_var}.{recommended_field}"
        if rep_pred["predicate_kind"] == "re_regex":
            pred_str = str(rep_pred["predicate_text"])
            rel_vf_s = int(rep_pred["local_var_field_start"]) - int(
                rep_pred["local_predicate_start"]
            )
            rel_vf_e = int(rep_pred["local_var_field_end"]) - int(
                rep_pred["local_predicate_start"]
            )
            recommended_yaral2_predicate = (
                pred_str[:rel_vf_s] + new_var_field + pred_str[rel_vf_e:]
            )
        else:
            op_str = str(rep_pred["operator"] or "=")
            recommended_yaral2_predicate = (
                f"{new_var_field} {op_str} {rep_pred['rhs_raw']}"
            )
        recommended_span_target = "var_field"
        recommended_span_replacement = new_var_field
    else:
        op_str = str(rep_pred["operator"] or "=")
        if op_str == "re.regex":
            op_str = "="
        recommended_yaral2_predicate = (
            f"{event_var}.{recommended_field} {op_str} {recommended_rhs}"
        )
        recommended_span_target = "predicate"
        recommended_span_replacement = recommended_yaral2_predicate

    return (
        recommended_field,
        recommended_rhs,
        recommended_yaral2_predicate,
        recommended_span_target,
        recommended_span_replacement,
    )


def _evaluate_yaral2_atomic_cond_on_event_map(
    atom_expr: str, em: dict[str, list[str]]
) -> bool:
    """Evaluates an atomic YARA-L 2.0 conditional predicate against a flattened UDM event map."""
    expr = str(atom_expr or "").strip()
    while expr.startswith("(") and expr.endswith(")"):
        expr = expr[1:-1].strip()
    if not expr:
        return False

    cidr_m = _YARAL2_CIDR_CALL_RE.search(expr)
    if cidr_m is not None:
        if cidr_m.group(2) is not None:
            f_tok = cidr_m.group(3)
            c_raw = cidr_m.group(4)
        else:
            c_raw = cidr_m.group(5)
            f_tok = cidr_m.group(7)
        canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
        cidr_val = c_raw.strip("\"'“”")
        vals = em.get(canon_f, [])
        return any(_ip_in_cidr(v, cidr_val) for v in vals)

    rx_m = _YARAL2_RE_REGEX_CALL_RE.search(expr)
    if rx_m is not None:
        f_tok = rx_m.group(2)
        pat_lit = rx_m.group(3)
        nocase_flag = bool((rx_m.group(4) or "").strip() or (rx_m.group(5) or "").strip())
        canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
        pat_str = pat_lit[1:-1] if len(pat_lit) >= 2 else pat_lit
        flags = re.IGNORECASE if nocase_flag else 0
        vals = em.get(canon_f, [])
        try:
            comp_re = re.compile(pat_str, flags)
            return any(comp_re.search(v) is not None for v in vals)
        except re.error:
            return any(
                (pat_str.lower() in v.lower() if nocase_flag else pat_str in v)
                for v in vals
            )

    num_cmp_m = re.match(
        r"^\$([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_.]*)\s*(>=|<=|!=|==|=|>|<)\s*(.+)$",
        expr,
    )
    if num_cmp_m is not None:
        f_tok = num_cmp_m.group(2)
        op_str = num_cmp_m.group(3)
        rhs_raw = num_cmp_m.group(4).strip()
        nocase_suffix = False
        if re.search(r"(?i)\s+nocase$", rhs_raw):
            nocase_suffix = True
            rhs_raw = re.sub(r"(?i)\s+nocase$", "", rhs_raw).strip()
        canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
        vals = em.get(canon_f, [])
        rhs_num = _try_parse_numeric(rhs_raw)
        if rhs_num is not None and op_str in (">=", "<=", ">", "<"):
            for v in vals:
                v_num = _try_parse_numeric(v)
                if v_num is None:
                    continue
                if op_str == ">=" and v_num >= rhs_num:
                    return True
                if op_str == "<=" and v_num <= rhs_num:
                    return True
                if op_str == ">" and v_num > rhs_num:
                    return True
                if op_str == "<" and v_num < rhs_num:
                    return True
            return False
        if rhs_raw.startswith("/") and (
            rhs_raw.endswith("/") or rhs_raw.lower().endswith("/ nocase")
        ):
            pat_s = rhs_raw.strip()
            nc = nocase_suffix
            if pat_s.lower().endswith("nocase"):
                nc = True
                pat_s = pat_s[:-6].strip()
            if pat_s.startswith("/") and pat_s.endswith("/") and len(pat_s) >= 2:
                pat_s = pat_s[1:-1]
            try:
                cre = re.compile(pat_s, re.IGNORECASE if nc else 0)
                matched = any(cre.search(v) is not None for v in vals)
            except re.error:
                matched = any(pat_s.lower() in v.lower() for v in vals)
            return (not matched) if op_str == "!=" else matched

        rhs_clean = rhs_raw.strip("\"'“”`")
        if op_str in ("=", "=="):
            if nocase_suffix:
                return any(v.lower() == rhs_clean.lower() for v in vals)
            return any(
                v == rhs_clean or v.lower() == rhs_clean.lower() for v in vals
            )
        if op_str == "!=":
            if not vals:
                return False
            return all(v.lower() != rhs_clean.lower() for v in vals)

    return False


def _evaluate_yaral2_condition_on_event_map(
    cond_expr: str, em: dict[str, list[str]]
) -> bool:
    """Evaluates a (possibly compound ``and``/``or``) YARA-L 2.0 conditional expression
    against a flattened UDM event map."""
    expr = str(cond_expr or "").strip()
    if not expr:
        return False
    or_parts = re.split(r"(?i)\s+\bor\b\s+", expr)
    if len(or_parts) > 1:
        return any(
            _evaluate_yaral2_condition_on_event_map(part, em)
            for part in or_parts
        )
    and_parts = re.split(r"(?i)\s+\band\b\s+", expr)
    if len(and_parts) > 1:
        return all(
            _evaluate_yaral2_atomic_cond_on_event_map(part, em)
            for part in and_parts
        )
    return _evaluate_yaral2_atomic_cond_on_event_map(expr, em)


def _normalize_event_map_for_outcome_eval(
    em_or_event: dict[str, Any],
) -> dict[str, list[str]]:
    """Normalizes either a raw UDM event dict or a flattened ``dict[str, list[str]]``
    into a canonical flattened UDM field map."""
    if not isinstance(em_or_event, dict):
        return {}
    flat: dict[str, list[str]] = {}
    has_nested = any(isinstance(v, dict) for v in em_or_event.values()) or any(
        k in em_or_event
        for k in (
            "udm",
            "metadata",
            "principal",
            "target",
            "src",
            "observer",
            "network",
            "security_result",
            "about",
        )
    )
    if has_nested:
        flat.update(_extract_udm_event_field_values(em_or_event))
    for k, v in em_or_event.items():
        if isinstance(v, list):
            strs = [str(x) for x in v if x is not None and str(x) != ""]
            if strs:
                flat.setdefault(str(k), []).extend(
                    x for x in strs if x not in flat.get(str(k), [])
                )
        elif isinstance(v, (str, int, float)) and str(v) != "":
            flat.setdefault(str(k), [])
            if str(v) not in flat[str(k)]:
                flat[str(k)].append(str(v))
    return flat


def _evaluate_single_event_outcome_row(
    first_arg: str | dict[str, Any],
    second_arg: dict[str, Any] | str,
) -> Any:
    """Evaluates a YARA-L 2.0 (``YL2``) ``outcome:`` expression (including ``strings.coalesce``,
    ``strings.concat``, ``strings.to_lower``, ``strings.to_upper``, ``re.capture``, ``if(...)``,
    and UDM field references) against a single UDM event dict or flattened event map."""
    if isinstance(first_arg, dict) and isinstance(second_arg, str):
        expr_raw = second_arg
        em = _normalize_event_map_for_outcome_eval(first_arg)
    else:
        expr_raw = str(first_arg or "")
        em = _normalize_event_map_for_outcome_eval(
            second_arg if isinstance(second_arg, dict) else {}
        )

    expr = expr_raw.strip()
    if not expr:
        return ""

    # 1. Conditional expression (if / iff / CASE WHEN)
    cond_spec = _parse_yaral2_conditional_expr(expr)
    if isinstance(cond_spec, dict):
        canon_cond = str(cond_spec["canonical_condition_expr"])
        cond_ok = _evaluate_yaral2_condition_on_event_map(canon_cond, em)
        branch_expr = (
            str(cond_spec["canonical_true_expr"])
            if cond_ok
            else str(cond_spec["canonical_false_expr"])
        )
        branch_num = (
            cond_spec.get("true_value")
            if cond_ok
            else cond_spec.get("false_value")
        )
        if branch_num is not None:
            return branch_num
        return _evaluate_single_event_outcome_row(branch_expr, em)

    # 2. Unwrap outer aggregation function if present (array_distinct, array, max, min, count, etc.)
    call_head_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
    m_call = call_head_re.match(expr)
    if m_call is not None:
        open_p = m_call.end() - 1
        close_p = _find_matching_paren(expr, open_p)
        rem_tail = expr[close_p + 1 :].strip() if close_p != -1 else "x"
        if close_p != -1 and (not rem_tail or rem_tail.lower() == "nocase"):
            fn_name = m_call.group(1).strip()
            fn_lower = fn_name.lower()
            inner_args_str = expr[open_p + 1 : close_p].strip()
            if (
                fn_lower in VALID_YARAL2_OUTCOME_AGG_FUNCS
                or fn_lower in CANONICAL_YARAL2_OUTCOME_AGG_CORRECTIONS
            ):
                return _evaluate_single_event_outcome_row(inner_args_str, em)

            if fn_lower in _YARAL2_STRINGS_FUNCTION_ALIASES:
                canon_fn = _YARAL2_STRINGS_FUNCTION_ALIASES[fn_lower]
                parts = _split_top_level_comma_args(inner_args_str)
                if canon_fn == "strings.coalesce":
                    for part in parts:
                        val = _evaluate_single_event_outcome_row(part, em)
                        if val is not None and str(val) != "":
                            return val
                    return ""
                if canon_fn == "strings.concat":
                    ref_fields = list(_YARAL2_EVENT_FIELD_RE.finditer(inner_args_str))
                    if ref_fields:
                        any_field_populated = False
                        for rf in ref_fields:
                            cf = CANONICAL_UDM_FIELD_CORRECTIONS.get(
                                rf.group(2), rf.group(2)
                            )
                            if em.get(cf):
                                any_field_populated = True
                                break
                        if not any_field_populated:
                            return ""
                    pieces: list[str] = []
                    for part in parts:
                        val = _evaluate_single_event_outcome_row(part, em)
                        pieces.append("" if val is None else str(val))
                    return "".join(pieces)
                if canon_fn == "strings.to_lower":
                    if not parts:
                        return ""
                    val = _evaluate_single_event_outcome_row(parts[0], em)
                    return str(val).lower() if val is not None and str(val) != "" else ""
                if canon_fn == "strings.to_upper":
                    if not parts:
                        return ""
                    val = _evaluate_single_event_outcome_row(parts[0], em)
                    return str(val).upper() if val is not None and str(val) != "" else ""

            if fn_lower in _YARAL2_RE_CAPTURE_FUNCTION_ALIASES:
                parts = _split_top_level_comma_args(inner_args_str)
                if len(parts) < 2:
                    return ""
                target_expr = parts[0].strip()
                pat_raw = parts[1].strip()
                has_nocase = bool(rem_tail.lower() == "nocase")
                if re.search(r"(?i)\s+nocase$", pat_raw):
                    has_nocase = True
                    pat_raw = re.sub(r"(?i)\s+nocase$", "", pat_raw).strip()

                vf_m = _YARAL2_EVENT_FIELD_RE.match(target_expr)
                if vf_m is not None:
                    f_tok = vf_m.group(2)
                    canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
                    candidate_strs = list(em.get(canon_f, []))
                else:
                    ev_val = _evaluate_single_event_outcome_row(target_expr, em)
                    candidate_strs = (
                        [str(ev_val)]
                        if ev_val is not None and str(ev_val) != ""
                        else []
                    )
                if not candidate_strs:
                    return ""

                was_double_quoted = bool(
                    len(pat_raw) >= 2 and pat_raw[0] in ('"', "'") and pat_raw[-1] == pat_raw[0]
                )
                if (
                    len(pat_raw) >= 2
                    and pat_raw[0] in ('"', "'", "`", "/")
                    and pat_raw[-1] == pat_raw[0]
                ):
                    inner_pat = pat_raw[1:-1]
                else:
                    inner_pat = pat_raw
                if has_nocase and not inner_pat.startswith("(?i)"):
                    inner_pat = f"(?i){inner_pat}"
                inner_pat, _ = _ensure_re_capture_group(inner_pat)

                pat_candidates: list[str] = []
                if was_double_quoted and "\\\\" in inner_pat:
                    pat_candidates.append(
                        inner_pat.replace("\\\\", "\\").replace('\\"', '"')
                    )
                if inner_pat not in pat_candidates:
                    pat_candidates.append(inner_pat)

                flags = re.IGNORECASE if has_nocase else 0
                for cand_pat in pat_candidates:
                    try:
                        cre = re.compile(cand_pat, flags)
                    except re.error:
                        continue
                    for s_val in candidate_strs:
                        m_rx = cre.search(s_val)
                        if m_rx is not None:
                            if m_rx.groups():
                                for g_val in m_rx.groups():
                                    if g_val is not None:
                                        return str(g_val)
                            return str(m_rx.group(0))
                return ""

    # 3. Bare event field `$var.field`
    vf_m = _YARAL2_EVENT_FIELD_RE.match(expr)
    if vf_m is not None and vf_m.end() == len(expr):
        f_tok = vf_m.group(2)
        canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
        vals = em.get(canon_f, [])
        return vals[0] if vals else ""

    # 4. Numeric or quoted string literal
    num_val = _try_parse_numeric(expr)
    if num_val is not None:
        return num_val
    if (
        len(expr) >= 2
        and expr[0] in ('"', "'", "`", "“", "”")
        and expr[-1] in ('"', "'", "`", "“", "”")
    ):
        return expr[1:-1]
    return expr


def _resolve_yaral2_branch_value_on_event_map(
    branch_expr: str,
    numeric_val: int | float | None,
    em: dict[str, list[str]],
) -> Any:
    """Resolves a conditional true/false branch expression against a flattened UDM event map."""
    if numeric_val is not None:
        return numeric_val
    expr = str(branch_expr or "").strip()
    vf_m = _YARAL2_EVENT_FIELD_RE.match(expr)
    if vf_m is not None and vf_m.end() == len(expr):
        f_tok = vf_m.group(2)
        canon_f = CANONICAL_UDM_FIELD_CORRECTIONS.get(f_tok, f_tok)
        vals = em.get(canon_f, [])
        if vals:
            parsed_n = _try_parse_numeric(vals[0])
            return parsed_n if parsed_n is not None else vals[0]
        return 0
    row_val = _evaluate_single_event_outcome_row(expr, em)
    if row_val is not None and str(row_val) != "":
        parsed_n = _try_parse_numeric(str(row_val))
        return parsed_n if parsed_n is not None else row_val
    return expr.strip("\"'“”`")


def _compare_outcome_threshold(
    empirical_val: int | float,
    operator: str,
    threshold_val: int | float,
) -> bool:
    """Returns True if ``empirical_val <operator> threshold_val`` holds."""
    if operator == ">=":
        return empirical_val >= threshold_val
    if operator == ">":
        return empirical_val > threshold_val
    if operator == "<=":
        return empirical_val <= threshold_val
    if operator == "<":
        return empirical_val < threshold_val
    if operator in ("=", "=="):
        return empirical_val == threshold_val
    if operator == "!=":
        return empirical_val != threshold_val
    return False


def _outcome_rhs_uses_strings_or_re_capture(rhs_text: str) -> bool:
    """Returns True if an ``outcome:`` RHS expression invokes a ``strings.*`` or ``re.capture()`` function."""
    if not rhs_text:
        return False
    call_head_re = re.compile(r"(?<![A-Za-z0-9_.$%])([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
    for m in call_head_re.finditer(rhs_text):
        fn_l = m.group(1).lower()
        if (
            fn_l in _YARAL2_STRINGS_FUNCTION_ALIASES
            or fn_l in _YARAL2_RE_CAPTURE_FUNCTION_ALIASES
        ):
            return True
    return False


def evaluate_yaral2_outcome_thresholds(
    rule_text: str,
    siem_events_or_retrohunt: Any = None,
    *,
    siem_events: list[dict[str, Any]] | None = None,
    retrohunt_result: dict[str, Any] | None = None,
    multi_event_retrohunt: dict[str, Any] | None = None,
    _orig_rule_text: str | None = None,
) -> dict[str, Any]:
    """Evaluates YARA-L 2.0 (``YL2``) ``outcome:`` aggregations (``count_distinct``, ``count``,
    ``max``, ``min``, ``sum``, ``array_distinct``, ``array``, ``if(...)`` conditionals,
    ``strings.coalesce(...)``, ``strings.concat(...)``, ``strings.to_lower(...)``,
    ``strings.to_upper(...)``, and ``re.capture(...)``) against matched single-event or
    multi-event/non-existence SIEM UDM events and verifies whether ``condition:`` outcome
    thresholds (e.g. ``$event_count >= 5``, ``$risk_score >= 95``) are satisfied or suppress
    rule detections (``uncalibrated_outcome_threshold``).
    """
    orig_rule = _orig_rule_text if _orig_rule_text is not None else rule_text
    orig_map = _build_utf16_index_map(orig_rule)
    _c, _e, static_findings = find_yaral2_rule_spans(orig_rule, orig_map)
    if static_findings:
        repaired_rule_text = str(static_findings[0]["repaired_rule_text"])
    else:
        repaired_rule_text = _normalize_yaral2_re_regex_calls(rule_text)

    blocks = _iter_yaral2_rule_blocks(orig_rule)
    rule_name = blocks[0]["rule_name"] if blocks else "unknown_rule"

    orig_spec = extract_yaral2_multi_event_spec(orig_rule)
    rep_spec = extract_yaral2_multi_event_spec(repaired_rule_text)
    event_vars: list[str] = list(rep_spec["event_vars"] or ["$e"])

    source = (
        siem_events_or_retrohunt
        if siem_events_or_retrohunt is not None
        else (
            multi_event_retrohunt
            if multi_event_retrohunt is not None
            else (
                retrohunt_result
                if retrohunt_result is not None
                else siem_events
            )
        )
    )

    per_event_filtered_maps: dict[str, list[dict[str, list[str]]]] = {
        ev: [] for ev in event_vars
    }
    per_event_filtered_counts: dict[str, int] = {ev: 0 for ev in event_vars}
    events_matched = 0

    if isinstance(source, dict) and (
        source.get("is_multi_event")
        or isinstance(source.get("multi_event_retrohunt"), dict)
        or isinstance(source.get("per_event_events"), dict)
        or isinstance(source.get("per_event_event_maps"), dict)
    ):
        me_dict = (
            source["multi_event_retrohunt"]
            if isinstance(source.get("multi_event_retrohunt"), dict)
            else source
        )
        raw_ev_maps = dict(me_dict.get("per_event_event_maps") or {})
        raw_ev_events = dict(me_dict.get("per_event_events") or {})
        raw_ev_resps = dict(me_dict.get("per_event_responses") or {})
        raw_ev_counts = dict(me_dict.get("per_event_counts") or {})
        shared_join_vals = list(me_dict.get("shared_join_values") or [])
        shared_lower = {v.lower() for v in shared_join_vals}
        join_ph = me_dict.get("join_placeholder")
        j_bindings = list(
            me_dict.get("join_bindings") or rep_spec["join_bindings"]
        )
        join_field_by_ev: dict[str, str] = {}
        for jb in j_bindings:
            if join_ph is None or str(jb.get("placeholder_var")) == str(join_ph):
                join_field_by_ev[str(jb["event_var"])] = str(
                    jb["canonical_field"]
                )

        for ev in event_vars:
            ev_maps = list(raw_ev_maps.get(ev) or [])
            if not ev_maps and ev in raw_ev_events:
                for ev_obj in raw_ev_events[ev]:
                    if isinstance(ev_obj, dict):
                        ev_maps.append(
                            _normalize_event_map_for_outcome_eval(ev_obj)
                        )
            if not ev_maps and ev in raw_ev_resps:
                resp_events = (
                    (raw_ev_resps[ev].get("siem_response") or {}).get("events")
                    if isinstance(raw_ev_resps[ev], dict)
                    else None
                )
                if isinstance(resp_events, list):
                    for ev_obj in resp_events:
                        if isinstance(ev_obj, dict):
                            ev_maps.append(
                                _normalize_event_map_for_outcome_eval(ev_obj)
                            )
            j_field = join_field_by_ev.get(ev)
            if shared_lower and j_field and ev_maps:
                matched_maps = [
                    em
                    for em in ev_maps
                    if any(
                        v.lower() in shared_lower for v in em.get(j_field, [])
                    )
                ]
                if matched_maps:
                    ev_maps = matched_maps
            per_event_filtered_maps[ev] = ev_maps
            per_event_filtered_counts[ev] = (
                len(ev_maps)
                if ev_maps
                else int(raw_ev_counts.get(ev, 0) or 0)
            )

        if "correlated_event_count" in me_dict:
            events_matched = int(me_dict.get("correlated_event_count", 0) or 0)
        else:
            pos_evs = list(rep_spec.get("positive_event_vars") or event_vars)
            events_matched = sum(
                per_event_filtered_counts.get(ev, 0) for ev in pos_evs
            )
    else:
        raw_events_list: list[dict[str, Any]] = []
        explicit_count: int | None = None
        if isinstance(source, list):
            raw_events_list = [e for e in source if isinstance(e, dict)]
        elif isinstance(source, dict):
            if "siem_response" in source and isinstance(
                source["siem_response"], dict
            ):
                ev_l = source["siem_response"].get("events")
                if isinstance(ev_l, list):
                    raw_events_list = [e for e in ev_l if isinstance(e, dict)]
            elif "events" in source and isinstance(source["events"], list):
                raw_events_list = [
                    e for e in source["events"] if isinstance(e, dict)
                ]
            elif any(
                k in source
                for k in ("udm", "metadata", "principal", "target", "src")
            ) or any("." in str(k) for k in source):
                raw_events_list = [source]
            if "event_count" in source:
                explicit_count = int(source.get("event_count", 0) or 0)
            elif "retrohunt_event_count" in source:
                explicit_count = int(
                    source.get("retrohunt_event_count", 0) or 0
                )

        ev_maps = [
            _normalize_event_map_for_outcome_eval(ev_obj)
            for ev_obj in raw_events_list
        ]
        events_matched = (
            explicit_count
            if explicit_count is not None and explicit_count > len(ev_maps)
            else len(ev_maps)
        )
        for ev in event_vars:
            per_event_filtered_maps[ev] = list(ev_maps)
            per_event_filtered_counts[ev] = events_matched

    outcome_values: dict[str, Any] = {}
    computed_string_outcomes: dict[str, Any] = {}
    outcome_evaluations: list[dict[str, Any]] = []

    for ob in rep_spec["outcome_bindings"]:
        out_var = str(ob["outcome_var"])
        out_var_name = str(ob["outcome_var_name"])
        rhs_text = str(ob.get("rhs_text") or "").strip()
        agg_fn = (
            str(ob["canonical_func_name"]).lower()
            if ob.get("canonical_func_name")
            else None
        )
        cond_spec = ob.get("conditional_spec")
        ref_evs = list(ob.get("referenced_event_vars") or [])
        target_ev = ref_evs[0] if ref_evs else event_vars[0]
        ev_maps = per_event_filtered_maps.get(target_ev, [])
        ev_cnt = per_event_filtered_counts.get(target_ev, len(ev_maps))
        uses_str_or_cap = _outcome_rhs_uses_strings_or_re_capture(rhs_text)

        computed_val: Any = 0
        per_event_samples: list[Any] = []

        if isinstance(cond_spec, dict):
            canon_cond = str(cond_spec["canonical_condition_expr"])
            true_expr = str(cond_spec["canonical_true_expr"])
            false_expr = str(cond_spec["canonical_false_expr"])
            true_num = cond_spec.get("true_value")
            false_num = cond_spec.get("false_value")
            for em in ev_maps:
                cond_ok = _evaluate_yaral2_condition_on_event_map(
                    canon_cond, em
                )
                b_val = (
                    _resolve_yaral2_branch_value_on_event_map(
                        true_expr, true_num, em
                    )
                    if cond_ok
                    else _resolve_yaral2_branch_value_on_event_map(
                        false_expr, false_num, em
                    )
                )
                per_event_samples.append(b_val)
            if not per_event_samples and ev_cnt > 0:
                fallback_val = (
                    false_num
                    if false_num is not None
                    else (true_num if true_num is not None else 0)
                )
                per_event_samples = [fallback_val] * ev_cnt

            num_samples = [
                v for v in per_event_samples if isinstance(v, (int, float))
            ]
            eff_agg = agg_fn or (
                "max" if rep_spec["match_clauses"] else None
            )
            if eff_agg == "max":
                computed_val = max(num_samples) if num_samples else 0
            elif eff_agg == "min":
                computed_val = min(num_samples) if num_samples else 0
            elif eff_agg == "sum":
                computed_val = sum(num_samples) if num_samples else 0
            elif eff_agg == "count":
                computed_val = len(per_event_samples)
            elif eff_agg == "count_distinct":
                computed_val = len(
                    {str(v) for v in per_event_samples if v is not None}
                )
            elif eff_agg == "array_distinct":
                computed_val = list(
                    dict.fromkeys(
                        str(v)
                        for v in per_event_samples
                        if v is not None and str(v) != ""
                    )
                )
            elif eff_agg == "array":
                computed_val = [
                    str(v)
                    for v in per_event_samples
                    if v is not None and str(v) != ""
                ]
            else:
                computed_val = (
                    max(num_samples)
                    if num_samples
                    else (per_event_samples[0] if per_event_samples else 0)
                )
        elif uses_str_or_cap:
            for em in ev_maps:
                row_val = _evaluate_single_event_outcome_row(rhs_text, em)
                if row_val is not None and str(row_val) != "":
                    per_event_samples.append(row_val)
            if agg_fn == "count_distinct":
                computed_val = len({str(v) for v in per_event_samples})
            elif agg_fn == "count":
                computed_val = len(per_event_samples)
            elif agg_fn in ("max", "min", "sum"):
                nums = [
                    n
                    for n in (
                        _try_parse_numeric(str(v)) for v in per_event_samples
                    )
                    if n is not None
                ]
                if agg_fn == "max":
                    computed_val = (
                        max(nums)
                        if nums
                        else (
                            max(str(v) for v in per_event_samples)
                            if per_event_samples
                            else ""
                        )
                    )
                elif agg_fn == "min":
                    computed_val = (
                        min(nums)
                        if nums
                        else (
                            min(str(v) for v in per_event_samples)
                            if per_event_samples
                            else ""
                        )
                    )
                else:
                    computed_val = sum(nums) if nums else 0
            elif agg_fn == "array_distinct":
                computed_val = list(
                    dict.fromkeys(str(v) for v in per_event_samples)
                )
            elif agg_fn == "array":
                computed_val = [str(v) for v in per_event_samples]
            else:
                computed_val = (
                    per_event_samples[0] if per_event_samples else ""
                )
            computed_string_outcomes[out_var] = computed_val
        else:
            ref_specs = list(ob.get("referenced_event_field_specs") or [])
            first_field = (
                str(ref_specs[0]["canonical_field"]) if ref_specs else None
            )
            for idx_em, em in enumerate(ev_maps):
                vals = em.get(first_field, []) if first_field else []
                if vals:
                    per_event_samples.extend(vals)
                elif first_field == "metadata.id":
                    per_event_samples.append(f"__event_{target_ev}_{idx_em}")
            if (
                not per_event_samples
                and ev_cnt > 0
                and first_field == "metadata.id"
            ):
                per_event_samples = [
                    f"__event_{target_ev}_{i}" for i in range(ev_cnt)
                ]
            if not per_event_samples and not ref_specs and ev_cnt > 0:
                rhs_stripped = rhs_text
                fn_m = _YARAL2_OUTCOME_FUNC_CALL_RE.match(rhs_stripped)
                inner_const = (
                    fn_m.group(2).strip() if fn_m is not None else rhs_stripped
                )
                const_num = _try_parse_numeric(inner_const)
                if const_num is not None:
                    per_event_samples = [const_num] * ev_cnt

            if agg_fn == "count_distinct":
                computed_val = (
                    len({str(v) for v in per_event_samples})
                    if per_event_samples
                    else ev_cnt
                )
            elif agg_fn == "count":
                computed_val = (
                    len(per_event_samples) if per_event_samples else ev_cnt
                )
            elif agg_fn in ("max", "min", "sum"):
                nums = [
                    n
                    for n in (
                        _try_parse_numeric(str(v)) for v in per_event_samples
                    )
                    if n is not None
                ]
                if agg_fn == "max":
                    computed_val = max(nums) if nums else 0
                elif agg_fn == "min":
                    computed_val = min(nums) if nums else 0
                else:
                    computed_val = sum(nums) if nums else 0
            elif agg_fn == "array_distinct":
                computed_val = list(
                    dict.fromkeys(str(v) for v in per_event_samples)
                )
            elif agg_fn == "array":
                computed_val = [str(v) for v in per_event_samples]
            else:
                if per_event_samples:
                    n0 = _try_parse_numeric(str(per_event_samples[0]))
                    computed_val = (
                        n0 if n0 is not None else per_event_samples[0]
                    )
                else:
                    computed_val = 0

        if isinstance(computed_val, float) and computed_val.is_integer():
            computed_val = int(computed_val)
        if isinstance(computed_val, (str, list)) and out_var not in computed_string_outcomes:
            computed_string_outcomes[out_var] = computed_val
        outcome_values[out_var] = computed_val
        outcome_evaluations.append(
            {
                "outcome_var": out_var,
                "outcome_var_name": out_var_name,
                "event_var": target_ev,
                "canonical_func_name": agg_fn,
                "is_conditional": bool(isinstance(cond_spec, dict)),
                "uses_strings_or_re_capture": uses_str_or_cap,
                "empirical_value": computed_val,
                "sample_values": per_event_samples[:10],
            }
        )

    orig_cmps = list(orig_spec["condition_outcome_comparisons"])
    rep_cmps = list(rep_spec["condition_outcome_comparisons"])
    condition_comparisons: list[dict[str, Any]] = []
    uncalibrated_comparisons: list[dict[str, Any]] = []

    for c_idx, rep_cmp in enumerate(rep_cmps):
        orig_cmp = orig_cmps[c_idx] if c_idx < len(orig_cmps) else rep_cmp
        out_var = str(rep_cmp["outcome_var"])
        op = str(rep_cmp["operator"])
        thresh_val = int(rep_cmp["threshold_value"])
        emp_val = outcome_values.get(out_var)
        if not isinstance(emp_val, (int, float)):
            continue
        emp_num: int | float = (
            int(emp_val)
            if isinstance(emp_val, float) and emp_val.is_integer()
            else emp_val
        )
        satisfied = (
            _compare_outcome_threshold(emp_num, op, thresh_val)
            if events_matched > 0
            else False
        )
        rec_op = (
            ">="
            if op in (">=", ">")
            else ("<=" if op in ("<=", "<") else "=")
        )
        rec_thresh = emp_num
        rec_cmp = f"{out_var} {rec_op} {rec_thresh}"
        cmp_entry = {
            "comparison_index": c_idx,
            "comparison_text": str(orig_cmp["comparison_text"]),
            "outcome_var": out_var,
            "outcome_var_name": str(rep_cmp["outcome_var_name"]),
            "operator": op,
            "threshold_value": thresh_val,
            "empirical_value": emp_num,
            "satisfied": satisfied,
            "recommended_operator": rec_op,
            "recommended_threshold": rec_thresh,
            "recommended_comparison": rec_cmp,
            "local_comparison_start": int(orig_cmp["local_comparison_start"]),
            "local_comparison_end": int(orig_cmp["local_comparison_end"]),
            "local_rhs_start": int(orig_cmp["local_rhs_start"]),
            "local_rhs_end": int(orig_cmp["local_rhs_end"]),
            "rep_local_comparison_start": int(
                rep_cmp["local_comparison_start"]
            ),
            "rep_local_comparison_end": int(rep_cmp["local_comparison_end"]),
            "rep_local_rhs_start": int(rep_cmp["local_rhs_start"]),
            "rep_local_rhs_end": int(rep_cmp["local_rhs_end"]),
            "comparison_start_index": int(orig_cmp["comparison_start_index"]),
            "comparison_end_index": int(orig_cmp["comparison_end_index"]),
            "rhs_start_index": int(orig_cmp["rhs_start_index"]),
            "rhs_end_index": int(orig_cmp["rhs_end_index"]),
        }
        condition_comparisons.append(cmp_entry)
        if events_matched > 0 and not satisfied:
            uncalibrated_comparisons.append(cmp_entry)

    calibrated_rule_text = repaired_rule_text
    for uc in sorted(
        uncalibrated_comparisons,
        key=lambda item: int(item["rep_local_comparison_start"]),
        reverse=True,
    ):
        rs = int(uc["rep_local_comparison_start"])
        re_end = int(uc["rep_local_comparison_end"])
        calibrated_rule_text = (
            calibrated_rule_text[:rs]
            + str(uc["recommended_comparison"])
            + calibrated_rule_text[re_end:]
        )

    has_outcome_thresholds = bool(condition_comparisons)
    all_thresholds_satisfied = (
        all(bool(c["satisfied"]) for c in condition_comparisons)
        if has_outcome_thresholds
        else True
    )
    threshold_suppressed = bool(
        events_matched > 0
        and has_outcome_thresholds
        and not all_thresholds_satisfied
    )
    effective_detections = (
        events_matched
        if (not has_outcome_thresholds or all_thresholds_satisfied)
        else 0
    )

    return {
        "rule_name": rule_name,
        "events_matched": events_matched,
        "has_outcome_thresholds": has_outcome_thresholds,
        "outcome_values": outcome_values,
        "computed_string_outcomes": computed_string_outcomes,
        "outcome_evaluations": outcome_evaluations,
        "condition_comparisons": condition_comparisons,
        "uncalibrated_comparisons": uncalibrated_comparisons,
        "all_thresholds_satisfied": all_thresholds_satisfied,
        "threshold_suppressed": threshold_suppressed,
        "effective_detections": effective_detections,
        "repaired_rule_text": repaired_rule_text,
        "calibrated_rule_text": calibrated_rule_text,
    }


def diagnose_zero_hit_yaral2_rule(
    rule_text: str,
    *,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 20,
    siem_validate_fn: Any = None,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Diagnoses a zero-hit or threshold-suppressed single-event or multi-event YARA-L 2.0
    (``YL2``) detection rule against historical UDM telemetry and synthesizes a
    compiler-verified YARA-L 2.0 pivot.

    1. Repairs any static YARA-L 2.0 syntax/schema/correlation/outcome/CIDR/conditional
       defects via :func:`find_yaral2_rule_spans`.
    2. For multi-event correlation and non-existence rules (``is_multi_event=True``), executes
       per-stream UDM queries via :func:`_run_multi_event_siem_retrohunt`:
       - When correlated events match (``correlated_event_count > 0``) but ``condition:``
         outcome thresholds suppress all detections, diagnoses ``uncalibrated_outcome_threshold``
         via :func:`evaluate_yaral2_outcome_thresholds` and calibrates the threshold(s).
       - When individual streams match events but share 0 join-key values, detects
         ``cross_event_join_entity_role_swap`` and pivots the swapped stream's join binding
         to the matching sibling entity role.
       - When a positive event stream in a multi-event or non-existence (``$e1 and !$e2``)
         rule matches 0 SIEM events, runs clause ablation on that stream via
         :func:`diagnose_zero_hit_udm_query`, maps ``failing_clause_index`` back to the
         stream's event predicate, splices the repaired predicate into ``pivoted_rule_text``,
         verifies compilation via Chronicle's ``validate_rule`` API, and re-runs
         :func:`_run_multi_event_siem_retrohunt` to confirm ``correlated_event_count > 0``.
    3. For single-event rules, extracts ordered ``events:`` predicates via
       :func:`extract_yaral2_event_predicates`, checks for ``uncalibrated_outcome_threshold``
       when ``events:`` match ``> 0`` UDM events, or invokes :func:`diagnose_zero_hit_udm_query`
       when ``events:`` match ``0`` UDM events, and compiles ``pivoted_rule_text`` via
       Chronicle's ``validate_rule`` API.
    """
    synthetic_map = _build_utf16_index_map(rule_text)
    _comments, _edits, static_findings = find_yaral2_rule_spans(
        rule_text, synthetic_map
    )

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = blocks[0]["rule_name"] if blocks else "unknown_rule"

    if static_findings:
        repaired_rule_text = str(static_findings[0]["repaired_rule_text"])
    else:
        repaired_rule_text = _normalize_yaral2_re_regex_calls(rule_text)

    orig_spec = extract_yaral2_multi_event_spec(rule_text)
    repaired_spec = extract_yaral2_multi_event_spec(repaired_rule_text)
    orig_predicates = orig_spec["predicates"]
    repaired_predicates = repaired_spec["predicates"]

    compiler_verified, compiler_output = _validate_yaral2_rule_with_compiler(
        repaired_rule_text, siem_validate_fn=siem_validate_fn
    )

    if repaired_spec["is_multi_event"]:
        me_retro = _run_multi_event_siem_retrohunt(
            repaired_rule_text,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        summary_query = str(me_retro["summary_query"])
        initial_corr_count = int(me_retro["correlated_event_count"])

        if initial_corr_count > 0 and me_retro["siem_verified"]:
            outcome_eval = evaluate_yaral2_outcome_thresholds(
                repaired_rule_text,
                me_retro,
                _orig_rule_text=rule_text,
            )
            if outcome_eval["threshold_suppressed"]:
                pivoted_rule_text = str(outcome_eval["calibrated_rule_text"])
                pivot_compiler_verified, pivot_compiler_output = (
                    _validate_yaral2_rule_with_compiler(
                        pivoted_rule_text, siem_validate_fn=siem_validate_fn
                    )
                )
                first_uc = outcome_eval["uncalibrated_comparisons"][0]
                return {
                    "status": "success",
                    "rule_name": rule_name,
                    "original_rule_text": rule_text,
                    "repaired_rule_text": repaired_rule_text,
                    "pivoted_rule_text": pivoted_rule_text,
                    "static_findings": static_findings,
                    "has_schema_defect": bool(static_findings),
                    "is_multi_event": True,
                    "compiler_verified": compiler_verified,
                    "compiler_output": compiler_output,
                    "retrohunt_udm_query": summary_query,
                    "initial_event_count": initial_corr_count,
                    "event_count": initial_corr_count,
                    "effective_detections": 0,
                    "calibrated_effective_detections": initial_corr_count,
                    "zero_hit": True,
                    "diagnosis_class": "uncalibrated_outcome_threshold",
                    "failure_reason": "uncalibrated_outcome_threshold",
                    "anchor_query": summary_query,
                    "anchor_event_count": initial_corr_count,
                    "failing_predicate_index": None,
                    "failing_join_binding_index": None,
                    "failing_outcome_comparison_index": int(
                        first_uc["comparison_index"]
                    ),
                    "failing_predicate": first_uc,
                    "recommended_field": str(first_uc["outcome_var"]),
                    "recommended_rhs": str(first_uc["recommended_threshold"]),
                    "recommended_yaral2_predicate": str(
                        first_uc["recommended_comparison"]
                    ),
                    "recommended_span_target": "condition_outcome_comparison",
                    "recommended_span_replacement": str(
                        first_uc["recommended_comparison"]
                    ),
                    "pivoted_retrohunt_udm_query": summary_query,
                    "recommended_query": summary_query,
                    "pivot_verified": True,
                    "pivot_event_count": initial_corr_count,
                    "pivot_compiler_verified": pivot_compiler_verified,
                    "pivot_compiler_output": pivot_compiler_output,
                    "outcome_evaluation": outcome_eval,
                    "outcome_values": outcome_eval["outcome_values"],
                    "uncalibrated_comparisons": outcome_eval[
                        "uncalibrated_comparisons"
                    ],
                    "shared_join_values": list(me_retro["shared_join_values"]),
                    "observed_values": [
                        f"{uc['outcome_var']}={uc['empirical_value']}"
                        for uc in outcome_eval["uncalibrated_comparisons"]
                    ],
                    "sample_observed_values": [
                        f"{uc['outcome_var']}={uc['empirical_value']}"
                        for uc in outcome_eval["uncalibrated_comparisons"]
                    ],
                    "multi_event_retrohunt": me_retro,
                }

        if initial_corr_count > 0 or not me_retro["siem_verified"]:
            outcome_eval = evaluate_yaral2_outcome_thresholds(
                repaired_rule_text,
                me_retro,
                _orig_rule_text=rule_text,
            )
            return {
                "status": "success" if me_retro["siem_verified"] else "error",
                "rule_name": rule_name,
                "original_rule_text": rule_text,
                "repaired_rule_text": repaired_rule_text,
                "pivoted_rule_text": repaired_rule_text,
                "static_findings": static_findings,
                "has_schema_defect": bool(static_findings),
                "is_multi_event": True,
                "compiler_verified": compiler_verified,
                "compiler_output": compiler_output,
                "retrohunt_udm_query": summary_query,
                "initial_event_count": initial_corr_count,
                "event_count": initial_corr_count,
                "effective_detections": int(
                    outcome_eval["effective_detections"]
                ),
                "zero_hit": initial_corr_count == 0,
                "diagnosis_class": None,
                "failure_reason": None,
                "failing_predicate_index": None,
                "failing_join_binding_index": None,
                "failing_predicate": None,
                "recommended_field": None,
                "recommended_rhs": None,
                "recommended_yaral2_predicate": None,
                "recommended_span_target": None,
                "recommended_span_replacement": None,
                "pivoted_retrohunt_udm_query": summary_query,
                "recommended_query": summary_query,
                "pivot_verified": initial_corr_count > 0,
                "pivot_event_count": initial_corr_count,
                "pivot_compiler_verified": compiler_verified,
                "pivot_compiler_output": compiler_output,
                "outcome_evaluation": outcome_eval,
                "outcome_values": outcome_eval["outcome_values"],
                "uncalibrated_comparisons": [],
                "shared_join_values": list(me_retro["shared_join_values"]),
                "observed_values": list(me_retro["shared_join_values"]),
                "sample_observed_values": list(me_retro["shared_join_values"]),
                "multi_event_retrohunt": me_retro,
            }

        rep_bindings = list(me_retro["join_bindings"])
        orig_bindings = list(orig_spec["join_bindings"])
        per_ev_counts = dict(me_retro["per_event_counts"])
        per_ev_join_vals = dict(me_retro["per_event_join_values"])
        per_ev_field_vals = dict(me_retro["per_event_field_values"])
        positive_event_vars = list(
            me_retro.get("positive_event_vars") or repaired_spec["event_vars"]
        )

        # (a) Cross-event join entity-role swap when all streams matched events
        if (
            per_ev_counts
            and all(c > 0 for c in per_ev_counts.values())
            and len(rep_bindings) >= 2
        ):
            for b_idx, jb in enumerate(rep_bindings):
                ev = str(jb["event_var"])
                c_field = str(jb["canonical_field"])
                ph_var = str(jb["placeholder_var"])
                other_bindings = [
                    ob
                    for idx2, ob in enumerate(rep_bindings)
                    if idx2 != b_idx and str(ob["placeholder_var"]) == ph_var
                ]
                if not other_bindings:
                    continue
                other_val_lists = [
                    per_ev_join_vals.get(str(ob["event_var"]), [])
                    for ob in other_bindings
                ]
                if not all(other_val_lists):
                    continue
                other_lower = set.intersection(
                    *[{v.lower() for v in vl} for vl in other_val_lists]
                )
                if not other_lower:
                    continue

                matched_prefix = next(
                    (
                        p
                        for p in _UDM_ENTITY_ROLE_PREFIXES
                        if c_field.startswith(p)
                    ),
                    None,
                )
                if matched_prefix is None:
                    continue
                subpath = c_field[len(matched_prefix) :]
                for sib_prefix in _UDM_ENTITY_ROLE_PREFIXES:
                    if sib_prefix == matched_prefix:
                        continue
                    sib_field = f"{sib_prefix}{subpath}"
                    sib_vals = per_ev_field_vals.get(ev, {}).get(sib_field, [])
                    candidate_shared = [
                        v for v in sib_vals if v.lower() in other_lower
                    ]
                    if not candidate_shared:
                        continue

                    orig_b = (
                        orig_bindings[b_idx]
                        if b_idx < len(orig_bindings)
                        else jb
                    )
                    new_var_field = f"{ev}.{sib_field}"
                    recommended_yaral2_predicate = (
                        f"{new_var_field} {jb['operator']} {ph_var}"
                    )
                    rep_vf_s = int(jb["local_var_field_start"])
                    rep_vf_e = int(jb["local_var_field_end"])
                    pivoted_rule_text = (
                        repaired_rule_text[:rep_vf_s]
                        + new_var_field
                        + repaired_rule_text[rep_vf_e:]
                    )
                    pivot_compiler_verified, pivot_compiler_output = (
                        _validate_yaral2_rule_with_compiler(
                            pivoted_rule_text, siem_validate_fn=siem_validate_fn
                        )
                    )
                    pivoted_me_retro = _run_multi_event_siem_retrohunt(
                        pivoted_rule_text,
                        start_time=start_time,
                        end_time=end_time,
                        max_events=max_events,
                        siem_search_fn=siem_search_fn,
                    )
                    pivot_count = int(
                        pivoted_me_retro["correlated_event_count"]
                    )
                    pivoted_summary_query = str(
                        pivoted_me_retro["summary_query"]
                    )
                    failing_pred_dict = {
                        "predicate_kind": "join_binding",
                        "predicate_text": str(orig_b["binding_text"]),
                        "event_var": str(orig_b["event_var"]),
                        "var_field_token": str(orig_b["var_field_token"]),
                        "field_token": str(orig_b["field_token"]),
                        "canonical_field": str(orig_b["canonical_field"]),
                        "operator": str(orig_b["operator"]),
                        "rhs_raw": str(orig_b["placeholder_var"]),
                        "placeholder_var": str(orig_b["placeholder_var"]),
                        "binding_index": b_idx,
                        "predicate_start_index": int(
                            orig_b["binding_start_index"]
                        ),
                        "predicate_end_index": int(orig_b["binding_end_index"]),
                        "var_field_start_index": int(
                            orig_b["var_field_start_index"]
                        ),
                        "var_field_end_index": int(
                            orig_b["var_field_end_index"]
                        ),
                        "rhs_start_index": int(
                            orig_b["placeholder_start_index"]
                        ),
                        "rhs_end_index": int(orig_b["placeholder_end_index"]),
                    }
                    has_schema_defect = bool(
                        orig_b["field_token"] != orig_b["canonical_field"]
                    )
                    return {
                        "status": "success",
                        "rule_name": rule_name,
                        "original_rule_text": rule_text,
                        "repaired_rule_text": repaired_rule_text,
                        "pivoted_rule_text": pivoted_rule_text,
                        "static_findings": static_findings,
                        "has_schema_defect": has_schema_defect,
                        "is_multi_event": True,
                        "compiler_verified": compiler_verified,
                        "compiler_output": compiler_output,
                        "retrohunt_udm_query": summary_query,
                        "initial_event_count": 0,
                        "event_count": 0,
                        "zero_hit": True,
                        "diagnosis_class": "cross_event_join_entity_role_swap",
                        "failure_reason": "cross_event_join_entity_role_swap",
                        "anchor_query": str(
                            me_retro["per_event_queries"].get(ev, "")
                        ),
                        "anchor_event_count": int(per_ev_counts.get(ev, 0)),
                        "failing_predicate_index": b_idx,
                        "failing_join_binding_index": b_idx,
                        "failing_predicate": failing_pred_dict,
                        "repaired_failing_predicate": jb,
                        "recommended_field": sib_field,
                        "recommended_rhs": ph_var,
                        "recommended_yaral2_predicate": recommended_yaral2_predicate,
                        "recommended_span_target": "var_field",
                        "recommended_span_replacement": new_var_field,
                        "pivoted_retrohunt_udm_query": pivoted_summary_query,
                        "recommended_query": pivoted_summary_query,
                        "pivot_verified": pivot_count > 0,
                        "pivot_event_count": pivot_count,
                        "pivot_compiler_verified": pivot_compiler_verified,
                        "pivot_compiler_output": pivot_compiler_output,
                        "shared_join_values": candidate_shared,
                        "observed_values": candidate_shared,
                        "sample_observed_values": candidate_shared,
                        "multi_event_retrohunt": pivoted_me_retro,
                    }

        # (b) Positive event stream in multi-event / non-existence rule matched 0 events
        for ev in positive_event_vars:
            if per_ev_counts.get(ev, 0) > 0:
                continue
            ev_repaired_preds = list(
                repaired_spec["per_event_predicates"].get(ev, [])
            )
            ev_orig_preds = list(orig_spec["per_event_predicates"].get(ev, []))
            ev_query = str(me_retro["per_event_queries"].get(ev, ""))
            if not ev_query or len(ev_repaired_preds) < 2:
                continue

            ev_udm_diag = diagnose_zero_hit_udm_query(
                ev_query,
                start_time=start_time,
                end_time=end_time,
                max_events=max_events,
                siem_search_fn=siem_search_fn,
            )
            ev_clause_idx = ev_udm_diag.get("failing_clause_index")
            if (
                not ev_udm_diag.get("zero_hit")
                or not ev_udm_diag.get("pivot_verified")
                or not isinstance(ev_clause_idx, int)
                or not (0 <= ev_clause_idx < len(ev_repaired_preds))
            ):
                continue

            rep_pred = ev_repaired_preds[ev_clause_idx]
            global_pred_idx = int(rep_pred["predicate_index"])
            orig_pred = (
                ev_orig_preds[ev_clause_idx]
                if ev_clause_idx < len(ev_orig_preds)
                else (
                    orig_predicates[global_pred_idx]
                    if global_pred_idx < len(orig_predicates)
                    else rep_pred
                )
            )
            diag_cls = str(ev_udm_diag.get("diagnosis_class") or "")
            has_schema_defect = bool(
                orig_pred["field_token"] != orig_pred["canonical_field"]
            )
            (
                rec_field,
                rec_rhs,
                rec_yaral2_pred,
                rec_span_target,
                rec_span_rep,
            ) = _synthesize_yaral2_predicate_pivot(
                diag_cls, orig_pred, rep_pred, ev_udm_diag
            )
            rep_p_s = int(rep_pred["local_predicate_start"])
            rep_p_e = int(rep_pred["local_predicate_end"])
            pivoted_rule_text = (
                repaired_rule_text[:rep_p_s]
                + rec_yaral2_pred
                + repaired_rule_text[rep_p_e:]
            )
            pivot_compiler_verified, pivot_compiler_output = (
                _validate_yaral2_rule_with_compiler(
                    pivoted_rule_text, siem_validate_fn=siem_validate_fn
                )
            )
            pivoted_me_retro = _run_multi_event_siem_retrohunt(
                pivoted_rule_text,
                start_time=start_time,
                end_time=end_time,
                max_events=max_events,
                siem_search_fn=siem_search_fn,
            )
            pivot_count = int(
                pivoted_me_retro.get("correlated_event_count", 0) or 0
            )
            pivoted_summary_query = str(
                pivoted_me_retro.get("summary_query") or ""
            )
            observed_vals = list(ev_udm_diag.get("observed_values") or [])
            shared_vals = list(pivoted_me_retro.get("shared_join_values") or [])
            return {
                "status": "success",
                "rule_name": rule_name,
                "original_rule_text": rule_text,
                "repaired_rule_text": repaired_rule_text,
                "pivoted_rule_text": pivoted_rule_text,
                "static_findings": static_findings,
                "has_schema_defect": has_schema_defect,
                "is_multi_event": True,
                "compiler_verified": compiler_verified,
                "compiler_output": compiler_output,
                "retrohunt_udm_query": summary_query,
                "initial_event_count": 0,
                "event_count": 0,
                "zero_hit": True,
                "diagnosis_class": diag_cls,
                "failure_reason": diag_cls,
                "anchor_query": str(ev_udm_diag.get("anchor_query") or ""),
                "anchor_event_count": int(
                    ev_udm_diag.get("anchor_event_count", 0) or 0
                ),
                "failing_event_var": ev,
                "failing_predicate_index": global_pred_idx,
                "failing_join_binding_index": None,
                "failing_predicate": orig_pred,
                "repaired_failing_predicate": rep_pred,
                "recommended_field": rec_field,
                "recommended_rhs": rec_rhs,
                "recommended_yaral2_predicate": rec_yaral2_pred,
                "recommended_span_target": rec_span_target,
                "recommended_span_replacement": rec_span_rep,
                "pivoted_retrohunt_udm_query": pivoted_summary_query,
                "recommended_query": pivoted_summary_query,
                "pivot_verified": pivot_count > 0,
                "pivot_event_count": pivot_count,
                "pivot_compiler_verified": pivot_compiler_verified,
                "pivot_compiler_output": pivot_compiler_output,
                "shared_join_values": shared_vals,
                "observed_values": observed_vals if observed_vals else shared_vals,
                "sample_observed_values": (
                    observed_vals if observed_vals else shared_vals
                ),
                "multi_event_retrohunt": pivoted_me_retro,
            }

        return {
            "status": "success",
            "rule_name": rule_name,
            "original_rule_text": rule_text,
            "repaired_rule_text": repaired_rule_text,
            "pivoted_rule_text": repaired_rule_text,
            "static_findings": static_findings,
            "has_schema_defect": bool(static_findings),
            "is_multi_event": True,
            "compiler_verified": compiler_verified,
            "compiler_output": compiler_output,
            "retrohunt_udm_query": summary_query,
            "initial_event_count": 0,
            "event_count": 0,
            "zero_hit": True,
            "diagnosis_class": "multi_event_no_shared_join_values",
            "failure_reason": "multi_event_no_shared_join_values",
            "failing_predicate_index": None,
            "failing_join_binding_index": None,
            "failing_predicate": None,
            "recommended_field": None,
            "recommended_rhs": None,
            "recommended_yaral2_predicate": None,
            "recommended_span_target": None,
            "recommended_span_replacement": None,
            "pivoted_retrohunt_udm_query": None,
            "recommended_query": None,
            "pivot_verified": False,
            "pivot_event_count": 0,
            "pivot_compiler_verified": compiler_verified,
            "pivot_compiler_output": compiler_output,
            "shared_join_values": [],
            "observed_values": [],
            "sample_observed_values": [],
            "multi_event_retrohunt": me_retro,
        }

    retrohunt_udm_query = " AND ".join(
        str(p["udm_clause"]) for p in repaired_predicates
    )

    if not retrohunt_udm_query:
        return {
            "status": "error",
            "rule_name": rule_name,
            "original_rule_text": rule_text,
            "repaired_rule_text": repaired_rule_text,
            "pivoted_rule_text": repaired_rule_text,
            "static_findings": static_findings,
            "has_schema_defect": bool(static_findings),
            "compiler_verified": compiler_verified,
            "compiler_output": compiler_output,
            "retrohunt_udm_query": retrohunt_udm_query,
            "initial_event_count": 0,
            "event_count": 0,
            "zero_hit": True,
            "diagnosis_class": None,
            "failure_reason": None,
            "failing_predicate_index": None,
            "failing_predicate": None,
            "recommended_field": None,
            "recommended_rhs": None,
            "recommended_yaral2_predicate": None,
            "recommended_span_target": None,
            "recommended_span_replacement": None,
            "pivoted_retrohunt_udm_query": None,
            "recommended_query": None,
            "pivot_verified": False,
            "pivot_event_count": 0,
            "pivot_compiler_verified": compiler_verified,
            "pivot_compiler_output": compiler_output,
            "observed_values": [],
            "sample_observed_values": [],
        }

    # Check if events: query already matches > 0 UDM events and only condition: outcome thresholds suppress detections
    initial_siem_res = verify_udm_query_with_siem(
        retrohunt_udm_query,
        start_time=start_time,
        end_time=end_time,
        max_events=max(max_events, 20),
        siem_search_fn=siem_search_fn,
    )
    initial_event_count = int(initial_siem_res.get("event_count", 0) or 0)
    if initial_siem_res.get("siem_verified") and initial_event_count > 0:
        outcome_eval = evaluate_yaral2_outcome_thresholds(
            repaired_rule_text,
            initial_siem_res,
            _orig_rule_text=rule_text,
        )
        if outcome_eval["threshold_suppressed"]:
            pivoted_rule_text = str(outcome_eval["calibrated_rule_text"])
            pivot_compiler_verified, pivot_compiler_output = (
                _validate_yaral2_rule_with_compiler(
                    pivoted_rule_text, siem_validate_fn=siem_validate_fn
                )
            )
            first_uc = outcome_eval["uncalibrated_comparisons"][0]
            return {
                "status": "success",
                "rule_name": rule_name,
                "original_rule_text": rule_text,
                "repaired_rule_text": repaired_rule_text,
                "pivoted_rule_text": pivoted_rule_text,
                "static_findings": static_findings,
                "has_schema_defect": bool(static_findings),
                "is_multi_event": False,
                "compiler_verified": compiler_verified,
                "compiler_output": compiler_output,
                "retrohunt_udm_query": retrohunt_udm_query,
                "initial_event_count": initial_event_count,
                "event_count": initial_event_count,
                "effective_detections": 0,
                "calibrated_effective_detections": initial_event_count,
                "zero_hit": True,
                "diagnosis_class": "uncalibrated_outcome_threshold",
                "failure_reason": "uncalibrated_outcome_threshold",
                "anchor_query": retrohunt_udm_query,
                "anchor_event_count": initial_event_count,
                "failing_predicate_index": None,
                "failing_outcome_comparison_index": int(
                    first_uc["comparison_index"]
                ),
                "failing_predicate": first_uc,
                "recommended_field": str(first_uc["outcome_var"]),
                "recommended_rhs": str(first_uc["recommended_threshold"]),
                "recommended_yaral2_predicate": str(
                    first_uc["recommended_comparison"]
                ),
                "recommended_span_target": "condition_outcome_comparison",
                "recommended_span_replacement": str(
                    first_uc["recommended_comparison"]
                ),
                "pivoted_retrohunt_udm_query": retrohunt_udm_query,
                "recommended_query": retrohunt_udm_query,
                "pivot_verified": True,
                "pivot_event_count": initial_event_count,
                "pivot_compiler_verified": pivot_compiler_verified,
                "pivot_compiler_output": pivot_compiler_output,
                "outcome_evaluation": outcome_eval,
                "outcome_values": outcome_eval["outcome_values"],
                "uncalibrated_comparisons": outcome_eval[
                    "uncalibrated_comparisons"
                ],
                "observed_values": [
                    f"{uc['outcome_var']}={uc['empirical_value']}"
                    for uc in outcome_eval["uncalibrated_comparisons"]
                ],
                "sample_observed_values": [
                    f"{uc['outcome_var']}={uc['empirical_value']}"
                    for uc in outcome_eval["uncalibrated_comparisons"]
                ],
            }
        return {
            "status": "success",
            "rule_name": rule_name,
            "original_rule_text": rule_text,
            "repaired_rule_text": repaired_rule_text,
            "pivoted_rule_text": repaired_rule_text,
            "static_findings": static_findings,
            "has_schema_defect": bool(static_findings),
            "compiler_verified": compiler_verified,
            "compiler_output": compiler_output,
            "retrohunt_udm_query": retrohunt_udm_query,
            "initial_event_count": initial_event_count,
            "event_count": initial_event_count,
            "effective_detections": int(outcome_eval["effective_detections"]),
            "zero_hit": False,
            "diagnosis_class": None,
            "failure_reason": None,
            "failing_predicate_index": None,
            "failing_predicate": None,
            "recommended_field": None,
            "recommended_rhs": None,
            "recommended_yaral2_predicate": None,
            "recommended_span_target": None,
            "recommended_span_replacement": None,
            "pivoted_retrohunt_udm_query": retrohunt_udm_query,
            "recommended_query": retrohunt_udm_query,
            "pivot_verified": True,
            "pivot_event_count": initial_event_count,
            "pivot_compiler_verified": compiler_verified,
            "pivot_compiler_output": compiler_output,
            "outcome_evaluation": outcome_eval,
            "outcome_values": outcome_eval["outcome_values"],
            "uncalibrated_comparisons": [],
            "observed_values": [],
            "sample_observed_values": [],
        }

    if len(repaired_predicates) < 2:
        return {
            "status": "success",
            "rule_name": rule_name,
            "original_rule_text": rule_text,
            "repaired_rule_text": repaired_rule_text,
            "pivoted_rule_text": repaired_rule_text,
            "static_findings": static_findings,
            "has_schema_defect": bool(static_findings),
            "compiler_verified": compiler_verified,
            "compiler_output": compiler_output,
            "retrohunt_udm_query": retrohunt_udm_query,
            "initial_event_count": 0,
            "event_count": 0,
            "zero_hit": True,
            "diagnosis_class": None,
            "failure_reason": None,
            "failing_predicate_index": None,
            "failing_predicate": None,
            "recommended_field": None,
            "recommended_rhs": None,
            "recommended_yaral2_predicate": None,
            "recommended_span_target": None,
            "recommended_span_replacement": None,
            "pivoted_retrohunt_udm_query": None,
            "recommended_query": None,
            "pivot_verified": False,
            "pivot_event_count": 0,
            "pivot_compiler_verified": compiler_verified,
            "pivot_compiler_output": compiler_output,
            "observed_values": [],
            "sample_observed_values": [],
        }

    udm_diag = diagnose_zero_hit_udm_query(
        retrohunt_udm_query,
        start_time=start_time,
        end_time=end_time,
        max_events=max_events,
        siem_search_fn=siem_search_fn,
    )
    initial_event_count = int(udm_diag.get("event_count", 0) or 0)
    diagnosis_class = udm_diag.get("diagnosis_class")
    failing_idx = udm_diag.get("failing_clause_index")

    if (
        not udm_diag.get("zero_hit")
        or not udm_diag.get("pivot_verified")
        or not isinstance(failing_idx, int)
        or not (0 <= failing_idx < len(repaired_predicates))
    ):
        return {
            "status": "success",
            "rule_name": rule_name,
            "original_rule_text": rule_text,
            "repaired_rule_text": repaired_rule_text,
            "pivoted_rule_text": repaired_rule_text,
            "static_findings": static_findings,
            "has_schema_defect": bool(static_findings),
            "compiler_verified": compiler_verified,
            "compiler_output": compiler_output,
            "retrohunt_udm_query": retrohunt_udm_query,
            "initial_event_count": initial_event_count,
            "event_count": initial_event_count,
            "zero_hit": bool(udm_diag.get("zero_hit")),
            "diagnosis_class": diagnosis_class,
            "failure_reason": diagnosis_class,
            "anchor_query": udm_diag.get("anchor_query"),
            "anchor_event_count": int(udm_diag.get("anchor_event_count", 0) or 0),
            "failing_predicate_index": failing_idx,
            "failing_predicate": (
                orig_predicates[failing_idx]
                if isinstance(failing_idx, int)
                and 0 <= failing_idx < len(orig_predicates)
                else None
            ),
            "recommended_field": udm_diag.get("recommended_field"),
            "recommended_rhs": udm_diag.get("recommended_rhs"),
            "recommended_yaral2_predicate": None,
            "recommended_span_target": None,
            "recommended_span_replacement": None,
            "pivoted_retrohunt_udm_query": udm_diag.get("recommended_query"),
            "recommended_query": udm_diag.get("recommended_query"),
            "pivot_verified": False,
            "pivot_event_count": int(udm_diag.get("pivot_event_count", 0) or 0),
            "pivot_compiler_verified": compiler_verified,
            "pivot_compiler_output": compiler_output,
            "observed_values": list(udm_diag.get("observed_values") or []),
            "sample_observed_values": list(udm_diag.get("observed_values") or []),
        }

    orig_pred = (
        orig_predicates[failing_idx]
        if failing_idx < len(orig_predicates)
        else repaired_predicates[failing_idx]
    )
    rep_pred = repaired_predicates[failing_idx]
    has_schema_defect = bool(
        orig_pred["field_token"] != orig_pred["canonical_field"]
    )
    (
        recommended_field,
        recommended_rhs,
        recommended_yaral2_predicate,
        recommended_span_target,
        recommended_span_replacement,
    ) = _synthesize_yaral2_predicate_pivot(
        str(diagnosis_class or ""), orig_pred, rep_pred, udm_diag
    )

    rep_p_start = int(rep_pred["local_predicate_start"])
    rep_p_end = int(rep_pred["local_predicate_end"])
    pivoted_rule_text = (
        repaired_rule_text[:rep_p_start]
        + recommended_yaral2_predicate
        + repaired_rule_text[rep_p_end:]
    )

    pivot_compiler_verified, pivot_compiler_output = (
        _validate_yaral2_rule_with_compiler(
            pivoted_rule_text, siem_validate_fn=siem_validate_fn
        )
    )
    observed_vals = list(udm_diag.get("observed_values") or [])
    pivoted_query = str(udm_diag.get("recommended_query") or "")
    pivot_count = int(udm_diag.get("pivot_event_count", 0) or 0)

    return {
        "status": "success",
        "rule_name": rule_name,
        "original_rule_text": rule_text,
        "repaired_rule_text": repaired_rule_text,
        "pivoted_rule_text": pivoted_rule_text,
        "static_findings": static_findings,
        "has_schema_defect": has_schema_defect,
        "compiler_verified": compiler_verified,
        "compiler_output": compiler_output,
        "retrohunt_udm_query": retrohunt_udm_query,
        "initial_event_count": initial_event_count,
        "event_count": initial_event_count,
        "zero_hit": True,
        "diagnosis_class": str(diagnosis_class),
        "failure_reason": str(diagnosis_class),
        "anchor_query": str(udm_diag.get("anchor_query") or ""),
        "anchor_event_count": int(udm_diag.get("anchor_event_count", 0) or 0),
        "failing_predicate_index": failing_idx,
        "failing_predicate": orig_pred,
        "repaired_failing_predicate": rep_pred,
        "recommended_field": recommended_field,
        "recommended_rhs": recommended_rhs,
        "recommended_yaral2_predicate": recommended_yaral2_predicate,
        "recommended_span_target": recommended_span_target,
        "recommended_span_replacement": recommended_span_replacement,
        "pivoted_retrohunt_udm_query": pivoted_query,
        "recommended_query": pivoted_query,
        "pivot_verified": True,
        "pivot_event_count": pivot_count,
        "pivot_compiler_verified": pivot_compiler_verified,
        "pivot_compiler_output": pivot_compiler_output,
        "observed_values": observed_vals,
        "sample_observed_values": observed_vals,
    }


def _format_zero_hit_yaral2_comment(
    diag_res: dict[str, Any],
    *,
    rule_name: str,
    has_schema_defect: bool = False,
    uncalibrated_comparison: dict[str, Any] | None = None,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> str:
    """Formats a grounded Google Docs review comment for a zero-hit or threshold-suppressed
    YARA-L 2.0 (``YL2``) predicate/condition pivot."""
    diag_class = str(
        diag_res.get("diagnosis_class")
        or diag_res.get("failure_reason")
        or "zero_hit"
    )
    failing_pred = (
        uncalibrated_comparison
        if isinstance(uncalibrated_comparison, dict)
        else (diag_res.get("failing_predicate") or {})
    )
    orig_pred_text = str(
        failing_pred.get("comparison_text")
        or failing_pred.get("predicate_text")
        or ""
    )
    orig_var_field = str(failing_pred.get("var_field_token") or "")
    orig_field = str(failing_pred.get("field_token") or "")
    canon_field = str(failing_pred.get("canonical_field") or "")
    event_var = str(failing_pred.get("event_var") or "$e")
    rec_field = str(diag_res.get("recommended_field") or canon_field)
    rec_pred = str(
        failing_pred.get("recommended_comparison")
        or diag_res.get("recommended_yaral2_predicate")
        or ""
    )
    rec_span_rep = str(
        failing_pred.get("recommended_comparison")
        or diag_res.get("recommended_span_replacement")
        or rec_pred
    )
    anchor_query = str(diag_res.get("anchor_query") or "")
    anchor_count = int(diag_res.get("anchor_event_count", 0) or 0)
    pivoted_query = str(diag_res.get("pivoted_retrohunt_udm_query") or "")
    pivot_count = int(diag_res.get("pivot_event_count", 0) or 0)
    observed = list(diag_res.get("observed_values") or [])
    observed_preview = observed[0] if observed else ""
    compiler_status = (
        "PASSED" if diag_res.get("pivot_compiler_verified") else "FAILED"
    )

    schema_prefix = ""
    if has_schema_defect and orig_var_field:
        schema_prefix = (
            f"Deterministic YARA-L 2.0 (YL2) UDM Schema Check in rule '{rule_name}': "
            f"'{orig_var_field}' references non-canonical Chronicle UDM field '{orig_field}' "
            f"(canonical: '{event_var}.{canon_field}', {udm_doc_url}). "
        )

    if diag_class == "uncalibrated_outcome_threshold":
        out_var = str(failing_pred.get("outcome_var") or rec_field)
        thresh_val = failing_pred.get("threshold_value")
        emp_val = failing_pred.get("empirical_value")
        reason = (
            f"Uncalibrated YARA-L 2.0 (YL2) Outcome Threshold Diagnosis in rule '{rule_name}' "
            f"(uncalibrated_outcome_threshold): Condition threshold '{orig_pred_text}' suppresses "
            f"100% of detections across {pivot_count} matched Chronicle SIEM UDM event(s) because "
            f"outcome variable '{out_var}' evaluates empirically to {emp_val} (vs. threshold {thresh_val}). "
            f"Calibrate condition comparison to '{rec_span_rep}' ({yaral2_doc_url})."
        )
    elif diag_class == "exact_match_on_command_line":
        reason = (
            f"Zero-Hit YARA-L 2.0 (YL2) Retrohunt Diagnosis in rule '{rule_name}' "
            f"(exact_match_on_command_line): Exact string equality in '{orig_pred_text}' "
            f"returned 0 Chronicle SIEM UDM events, whereas ablated anchor query "
            f"'{anchor_query}' matched {anchor_count} events with full command-line "
            f"arguments such as '{observed_preview}'. Replace with YARA-L 2.0 regex "
            f"predicate '{rec_pred}' ({yaral2_doc_url})."
        )
    elif diag_class == "entity_role_swap":
        reason = (
            f"Zero-Hit YARA-L 2.0 (YL2) Retrohunt Diagnosis in rule '{rule_name}' "
            f"(entity_role_swap): Event variable field '{orig_var_field}' in "
            f"'{orig_pred_text}' returned 0 Chronicle SIEM UDM events, whereas sibling "
            f"UDM entity role '{event_var}.{rec_field}' in ablated anchor query "
            f"'{anchor_query}' ({anchor_count} events) holds matching telemetry "
            f"('{observed_preview}'). Replace '{orig_var_field}' with "
            f"'{rec_span_rep}' ({udm_doc_url})."
        )
    elif diag_class == "cross_event_join_entity_role_swap":
        shared_vals = list(diag_res.get("shared_join_values") or observed)
        shared_preview = shared_vals[0] if shared_vals else observed_preview
        reason = (
            f"Zero-Hit Multi-Event YARA-L 2.0 (YL2) Correlation Join Diagnosis in rule '{rule_name}' "
            f"(cross_event_join_entity_role_swap): Join binding '{orig_pred_text}' on '{orig_var_field}' "
            f"produced 0 shared join keys across correlated UDM event streams, whereas sibling UDM "
            f"entity role '{rec_span_rep}' shares join key '{shared_preview}' across streams "
            f"({pivot_count} correlated events). Replace '{orig_var_field}' with "
            f"'{rec_span_rep}' ({udm_doc_url})."
        )
    elif diag_class == "value_format_mismatch":
        reason = (
            f"Zero-Hit YARA-L 2.0 (YL2) Retrohunt Diagnosis in rule '{rule_name}' "
            f"(value_format_mismatch): Predicate '{orig_pred_text}' returned 0 Chronicle "
            f"SIEM UDM events even after UDM field normalization, whereas ablated anchor "
            f"query '{anchor_query}' matched {anchor_count} events where "
            f"'{rec_field}' is populated as '{observed_preview}'. Replace predicate with "
            f"'{rec_pred}' ({yaral2_doc_url})."
        )
    else:
        reason = (
            f"Zero-Hit YARA-L 2.0 (YL2) Retrohunt Diagnosis in rule '{rule_name}' "
            f"({diag_class}): Predicate '{orig_pred_text}' returned 0 Chronicle SIEM UDM "
            f"events; replace with '{rec_span_rep}' ({yaral2_doc_url})."
        )

    return (
        f"{schema_prefix}{reason} "
        f"[Chronicle YARA-L 2.0 Compiler Verified: {compiler_status} | "
        f"Retrohunt Pivot Verified: query='{pivoted_query}', events_matched={pivot_count}]"
    )


def verify_yaral2_rule_with_siem(
    rule_text: str,
    *,
    run_retrohunt_check: bool = True,
    diagnose_zero_hit_retrohunt: bool = True,
    verify_meta_mitre: bool = False,
    synthesize_missing_meta: bool = False,
    verify_meta_runbook: bool = False,
    verify_meta_severity: bool = False,
    synthesize_missing_runbook: bool = False,
    skill_registry: Any = None,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 10,
    siem_validate_fn: Any = None,
    siem_search_fn: Any = None,
    doc: dict[str, Any] | None = None,
    repaired_rule_override: str | None = None,
) -> dict[str, Any]:
    """Repairs a candidate single-event or multi-event YARA-L 2.0 (``YL2``) rule, compiles it
    via Chronicle ``validate_rule``, dry-runs its ``events:`` predicates (or per-stream
    multi-event correlation / non-existence set-difference queries) against historical
    Chronicle UDM telemetry, and evaluates ``outcome:`` threshold calibration against
    ``condition:`` comparisons.
    """
    synthetic_map = _build_utf16_index_map(rule_text)
    _comments, _edits, findings = find_yaral2_rule_spans(
        rule_text,
        synthetic_map,
        doc=doc,
        verify_meta_mitre=verify_meta_mitre,
        synthesize_missing_meta=synthesize_missing_meta,
        verify_meta_runbook=verify_meta_runbook,
        verify_meta_severity=verify_meta_severity,
        synthesize_missing_runbook=synthesize_missing_runbook,
        skill_registry=skill_registry,
    )

    blocks = _iter_yaral2_rule_blocks(rule_text)
    rule_name = blocks[0]["rule_name"] if blocks else "unknown_rule"

    if repaired_rule_override and repaired_rule_override.strip():
        repaired_rule_text = _normalize_yaral2_re_regex_calls(
            repaired_rule_override
        )
        retrohunt_udm_query, retrohunt_clauses = (
            _extract_retrohunt_udm_query_from_yaral2(repaired_rule_text)
        )
    elif findings:
        repaired_rule_text = str(findings[0]["repaired_rule_text"])
        retrohunt_udm_query = str(findings[0]["retrohunt_udm_query"])
        retrohunt_clauses = list(findings[0].get("retrohunt_clauses") or [])
    else:
        repaired_rule_text = _normalize_yaral2_re_regex_calls(rule_text)
        retrohunt_udm_query, retrohunt_clauses = (
            _extract_retrohunt_udm_query_from_yaral2(repaired_rule_text)
        )

    repaired_spec = extract_yaral2_multi_event_spec(repaired_rule_text)
    is_multi_event = bool(repaired_spec["is_multi_event"])

    compiler_verified, compiler_output = _validate_yaral2_rule_with_compiler(
        repaired_rule_text, siem_validate_fn=siem_validate_fn
    )

    retrohunt_verified = False
    retrohunt_event_count = 0
    retrohunt_res: dict[str, Any] = {}
    multi_event_retrohunt: dict[str, Any] | None = None
    retrohunt_initial_zero_hit_query: str | None = None
    pivoted_rule_text = repaired_rule_text
    zero_hit_diagnosis: dict[str, Any] | None = None
    outcome_evaluation: dict[str, Any] | None = None

    if run_retrohunt_check and is_multi_event:
        multi_event_retrohunt = _run_multi_event_siem_retrohunt(
            repaired_rule_text,
            start_time=start_time,
            end_time=end_time,
            max_events=max(max_events, 20),
            siem_search_fn=siem_search_fn,
        )
        retrohunt_res = multi_event_retrohunt
        retrohunt_verified = bool(multi_event_retrohunt.get("siem_verified"))
        retrohunt_event_count = int(
            multi_event_retrohunt.get("correlated_event_count", 0) or 0
        )
        retrohunt_udm_query = str(
            multi_event_retrohunt.get("summary_query") or retrohunt_udm_query
        )
        outcome_evaluation = evaluate_yaral2_outcome_thresholds(
            repaired_rule_text,
            multi_event_retrohunt,
            _orig_rule_text=rule_text,
        )

        if (
            retrohunt_verified
            and (
                retrohunt_event_count == 0
                or outcome_evaluation.get("threshold_suppressed")
            )
            and diagnose_zero_hit_retrohunt
        ):
            zero_hit_diagnosis = diagnose_zero_hit_yaral2_rule(
                rule_text,
                start_time=start_time,
                end_time=end_time,
                max_events=max(max_events, 20),
                siem_validate_fn=siem_validate_fn,
                siem_search_fn=siem_search_fn,
            )
            if zero_hit_diagnosis.get("pivot_verified") and zero_hit_diagnosis.get(
                "pivot_compiler_verified"
            ):
                if retrohunt_event_count == 0:
                    retrohunt_initial_zero_hit_query = retrohunt_udm_query
                retrohunt_udm_query = str(
                    zero_hit_diagnosis["pivoted_retrohunt_udm_query"]
                )
                retrohunt_event_count = int(
                    zero_hit_diagnosis["pivot_event_count"]
                )
                pivoted_rule_text = str(zero_hit_diagnosis["pivoted_rule_text"])
                compiler_verified = bool(
                    zero_hit_diagnosis["pivot_compiler_verified"]
                )
                compiler_output = str(
                    zero_hit_diagnosis["pivot_compiler_output"]
                )
                if isinstance(
                    zero_hit_diagnosis.get("multi_event_retrohunt"), dict
                ):
                    multi_event_retrohunt = zero_hit_diagnosis[
                        "multi_event_retrohunt"
                    ]
                    retrohunt_res = multi_event_retrohunt

    elif run_retrohunt_check and retrohunt_udm_query:
        retrohunt_res = verify_udm_query_with_siem(
            retrohunt_udm_query,
            start_time=start_time,
            end_time=end_time,
            max_events=max(max_events, 20),
            siem_search_fn=siem_search_fn,
        )
        retrohunt_verified = bool(retrohunt_res.get("siem_verified"))
        retrohunt_event_count = int(retrohunt_res.get("event_count", 0) or 0)
        outcome_evaluation = evaluate_yaral2_outcome_thresholds(
            repaired_rule_text,
            retrohunt_res,
            _orig_rule_text=rule_text,
        )

        if (
            retrohunt_verified
            and (
                (retrohunt_event_count == 0 and len(retrohunt_clauses) >= 2)
                or outcome_evaluation.get("threshold_suppressed")
            )
            and diagnose_zero_hit_retrohunt
        ):
            zero_hit_diagnosis = diagnose_zero_hit_yaral2_rule(
                rule_text,
                start_time=start_time,
                end_time=end_time,
                max_events=max(max_events, 20),
                siem_validate_fn=siem_validate_fn,
                siem_search_fn=siem_search_fn,
            )
            if zero_hit_diagnosis.get("pivot_verified") and zero_hit_diagnosis.get(
                "pivot_compiler_verified"
            ):
                if retrohunt_event_count == 0:
                    retrohunt_initial_zero_hit_query = retrohunt_udm_query
                retrohunt_udm_query = str(
                    zero_hit_diagnosis["pivoted_retrohunt_udm_query"]
                )
                retrohunt_event_count = int(
                    zero_hit_diagnosis["pivot_event_count"]
                )
                pivoted_rule_text = str(zero_hit_diagnosis["pivoted_rule_text"])
                compiler_verified = bool(
                    zero_hit_diagnosis["pivot_compiler_verified"]
                )
                compiler_output = str(
                    zero_hit_diagnosis["pivot_compiler_output"]
                )

        # Fallback: if a multi-clause GCP Cloud Audit query yields 0 hits due to a restrictive
        # target.resource.name literal and no value-level UDM payload was available to pivot,
        # relax to the remaining core clauses.
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
        "pivoted_rule_text": pivoted_rule_text,
        "findings": findings,
        "is_multi_event": is_multi_event,
        "is_non_existence": bool(repaired_spec.get("is_non_existence")),
        "reference_lists": list(repaired_spec.get("reference_lists") or []),
        "compiler_verified": compiler_verified,
        "compiler_output": compiler_output,
        "retrohunt_udm_query": retrohunt_udm_query,
        "retrohunt_verified": retrohunt_verified,
        "retrohunt_event_count": retrohunt_event_count,
        "retrohunt_response": retrohunt_res,
    }
    if outcome_evaluation is not None:
        result["outcome_evaluation"] = outcome_evaluation
        result["outcome_values"] = outcome_evaluation.get("outcome_values", {})
        result["computed_string_outcomes"] = outcome_evaluation.get(
            "computed_string_outcomes", {}
        )
    if multi_event_retrohunt is not None:
        result["multi_event_retrohunt"] = multi_event_retrohunt
    if retrohunt_initial_zero_hit_query is not None:
        result["retrohunt_initial_zero_hit_query"] = retrohunt_initial_zero_hit_query
    if zero_hit_diagnosis is not None:
        result["zero_hit_diagnosis"] = zero_hit_diagnosis
    return result


def verify_and_redline_yaral2_rules_in_doc(
    document_id: str,
    *,
    run_live_siem_check: bool = False,
    diagnose_zero_hit_retrohunt: bool = True,
    verify_meta_mitre: bool = False,
    synthesize_missing_meta: bool = False,
    verify_meta_runbook: bool = False,
    verify_meta_severity: bool = False,
    synthesize_missing_runbook: bool = False,
    skill_registry: Any = None,
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
    """Lints single-event and multi-event YARA-L 2.0 (``YL2``) rules (including ``outcome:``
    aggregations, ``if()`` conditionals, ``net.ip_in_range_cidr()`` CIDR calls, ``!$e2``
    non-existence correlation, ``condition:`` outcome threshold calibration, and optional
    ``meta:`` MITRE ATT&CK attribution synthesis, severity-to-risk-score consistency, and
    ``SkillRegistry`` runbook routing checks) in a Google Doc, optionally compiles and
    retrohunts them in Chronicle SIEM, and stages non-destructive Suggested Edits
    (``writeMode="SUGGEST"``).

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 character index map
       and ``pending_suggestion_spans``.
    2. Calls :func:`find_yaral2_rule_spans` and skips any span that overlaps an existing
       pending suggestion (guaranteeing multi-pass idempotency).
    3. When ``run_live_siem_check=True`` (or ``siem_validate_fn`` / ``siem_search_fn`` is
       provided), verifies every YARA-L 2.0 rule in the document via
       :func:`verify_yaral2_rule_with_siem` and :func:`diagnose_zero_hit_yaral2_rule`,
       upgrading combined static-schema + zero-hit value predicates in-place and staging
       compiler-verified ``writeMode="SUGGEST"`` pivots for syntactically valid zero-hit
       or ``uncalibrated_outcome_threshold`` rules.
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

    raw_doc = _load_doc_raw_ast(document_id, tool_context=tool_context)
    raw_comments, raw_edits, raw_findings = find_yaral2_rule_spans(
        plain_text,
        index_map,
        udm_doc_url=udm_doc_url,
        yaral2_doc_url=yaral2_doc_url,
        doc=raw_doc,
        verify_meta_mitre=verify_meta_mitre,
        synthesize_missing_meta=synthesize_missing_meta,
        verify_meta_runbook=verify_meta_runbook,
        verify_meta_severity=verify_meta_severity,
        synthesize_missing_runbook=synthesize_missing_runbook,
        skill_registry=skill_registry,
    )
    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    static_rules_all: set[str] = set()
    static_rules_kept: set[str] = set()
    raw_var_field_spans: set[tuple[int, int]] = set()
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    finding_idx_by_var_field_span: dict[tuple[int, int], int] = {}
    skipped_existing_suggestion_count = 0

    for c_item, e_item, f_item in zip(raw_comments, raw_edits, raw_findings):
        r_name = str(f_item.get("rule_name") or "")
        if r_name:
            static_rules_all.add(r_name)
        f_span = (int(f_item["start_index"]), int(f_item["end_index"]))
        if f_item.get("defect_type") == "invalid_udm_field":
            raw_var_field_spans.add(f_span)
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        if r_name:
            static_rules_kept.add(r_name)
        f_idx = len(findings)
        if f_item.get("defect_type") == "invalid_udm_field":
            finding_idx_by_var_field_span[f_span] = f_idx
        comments.append(c_item)
        edits.append(e_item)
        findings.append(f_item)

    siem_rule_checks: list[dict[str, Any]] = []
    zero_hit_yaral2_diagnoses: list[dict[str, Any]] = []
    zero_hit_yaral2_findings_count = 0
    live_siem_enabled = bool(
        run_live_siem_check
        or siem_validate_fn is not None
        or siem_search_fn is not None
    )

    if live_siem_enabled:
        rule_blocks_by_name = {
            str(b["rule_name"]): b for b in _iter_yaral2_rule_blocks(plain_text)
        }
        rule_cache: dict[str, dict[str, Any]] = {}
        upgraded_finding_indices: set[int] = set()

        for idx, finding in enumerate(list(findings)):
            r_name = str(finding.get("rule_name") or "")
            orig_rule = str(finding.get("original_rule_text") or "")
            cache_key = r_name or orig_rule
            if cache_key not in rule_cache:
                rule_check = verify_yaral2_rule_with_siem(
                    orig_rule,
                    run_retrohunt_check=True,
                    diagnose_zero_hit_retrohunt=diagnose_zero_hit_retrohunt,
                    verify_meta_mitre=verify_meta_mitre,
                    synthesize_missing_meta=synthesize_missing_meta,
                    verify_meta_runbook=verify_meta_runbook,
                    verify_meta_severity=verify_meta_severity,
                    synthesize_missing_runbook=synthesize_missing_runbook,
                    skill_registry=skill_registry,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_validate_fn=siem_validate_fn,
                    siem_search_fn=siem_search_fn,
                    doc=raw_doc,
                    repaired_rule_override=str(
                        finding.get("repaired_rule_text") or ""
                    ),
                )
                rule_cache[cache_key] = rule_check
                siem_rule_checks.append(rule_check)
                zh_diag = rule_check.get("zero_hit_diagnosis")
                if (
                    isinstance(zh_diag, dict)
                    and zh_diag.get("pivot_verified")
                    and zh_diag.get("pivot_compiler_verified")
                ):
                    zero_hit_yaral2_diagnoses.append(zh_diag)
                    b_info = rule_blocks_by_name.get(r_name)
                    if b_info is not None:
                        doc_multi_spec = extract_yaral2_multi_event_spec(
                            orig_rule,
                            rule_char_start=int(b_info["char_start"]),
                            full_plain_text=plain_text,
                            index_map=index_map,
                        )
                        doc_preds = doc_multi_spec["predicates"]
                        doc_out_cmps = doc_multi_spec[
                            "condition_outcome_comparisons"
                        ]
                        f_pred_idx = zh_diag.get("failing_predicate_index")
                        if (
                            zh_diag.get("diagnosis_class")
                            == "uncalibrated_outcome_threshold"
                        ):
                            for uc in zh_diag.get(
                                "uncalibrated_comparisons", []
                            ):
                                c_idx = int(uc["comparison_index"])
                                if not (0 <= c_idx < len(doc_out_cmps)):
                                    continue
                                target_cmp = doc_out_cmps[c_idx]
                                t_start = int(
                                    target_cmp["comparison_start_index"]
                                )
                                t_end = int(target_cmp["comparison_end_index"])
                                t_quote = str(target_cmp["comparison_text"])
                                t_replacement = str(
                                    uc["recommended_comparison"]
                                )
                                if any(
                                    _spans_overlap((t_start, t_end), p_span)
                                    for p_span in pending_spans
                                ):
                                    skipped_existing_suggestion_count += 1
                                    continue
                                if any(
                                    _spans_overlap(
                                        (t_start, t_end),
                                        (
                                            int(ex_e["start_index"]),
                                            int(ex_e["end_index"]),
                                        ),
                                    )
                                    for ex_e in edits
                                ):
                                    continue
                                comment_body = _format_zero_hit_yaral2_comment(
                                    zh_diag,
                                    rule_name=r_name,
                                    has_schema_defect=False,
                                    uncalibrated_comparison=uc,
                                    udm_doc_url=udm_doc_url,
                                    yaral2_doc_url=yaral2_doc_url,
                                )
                                comments.append(
                                    {
                                        "start_index": t_start,
                                        "end_index": t_end,
                                        "quote": t_quote,
                                        "comment": comment_body,
                                    }
                                )
                                edits.append(
                                    {
                                        "start_index": t_start,
                                        "end_index": t_end,
                                        "quote": t_quote,
                                        "replacement": t_replacement,
                                    }
                                )
                                findings.append(
                                    {
                                        "rule_name": r_name,
                                        "defect_type": "uncalibrated_outcome_threshold",
                                        "invalid_field": t_quote,
                                        "canonical_field": t_replacement,
                                        "quote": t_quote,
                                        "replacement": t_replacement,
                                        "start_index": t_start,
                                        "end_index": t_end,
                                        "original_rule_text": orig_rule,
                                        "repaired_rule_text": zh_diag[
                                            "pivoted_rule_text"
                                        ],
                                        "pivoted_rule_text": zh_diag[
                                            "pivoted_rule_text"
                                        ],
                                        "is_multi_event": bool(
                                            zh_diag.get("is_multi_event", False)
                                        ),
                                        "retrohunt_udm_query": zh_diag[
                                            "pivoted_retrohunt_udm_query"
                                        ],
                                        "zero_hit_diagnosis": "uncalibrated_outcome_threshold",
                                        "failure_reason": "uncalibrated_outcome_threshold",
                                        "outcome_var": str(uc["outcome_var"]),
                                        "threshold_value": uc[
                                            "threshold_value"
                                        ],
                                        "empirical_value": uc[
                                            "empirical_value"
                                        ],
                                        "outcome_values": zh_diag.get(
                                            "outcome_values", {}
                                        ),
                                        "recommended_yaral2_predicate": t_replacement,
                                        "recommended_span_target": "condition_outcome_comparison",
                                        "anchor_query": zh_diag["anchor_query"],
                                        "anchor_event_count": zh_diag[
                                            "anchor_event_count"
                                        ],
                                        "pivot_event_count": zh_diag[
                                            "pivot_event_count"
                                        ],
                                        "pivot_compiler_verified": zh_diag[
                                            "pivot_compiler_verified"
                                        ],
                                        "shared_join_values": zh_diag.get(
                                            "shared_join_values", []
                                        ),
                                        "observed_values": zh_diag.get(
                                            "observed_values", []
                                        ),
                                    }
                                )
                                zero_hit_yaral2_findings_count += 1
                        elif (
                            zh_diag.get("diagnosis_class")
                            != "cross_event_join_entity_role_swap"
                            and isinstance(f_pred_idx, int)
                            and (0 <= f_pred_idx < len(doc_preds))
                        ):
                            target_pred = doc_preds[f_pred_idx]
                            vf_span = (
                                int(target_pred["var_field_start_index"]),
                                int(target_pred["var_field_end_index"]),
                            )
                            existing_f_idx = finding_idx_by_var_field_span.get(
                                vf_span
                            )
                            if existing_f_idx is not None:
                                p_start = int(target_pred["predicate_start_index"])
                                p_end = int(target_pred["predicate_end_index"])
                                p_quote = str(target_pred["predicate_text"])
                                rec_rep = str(
                                    zh_diag["recommended_span_replacement"]
                                )
                                comment_body = _format_zero_hit_yaral2_comment(
                                    zh_diag,
                                    rule_name=r_name,
                                    has_schema_defect=True,
                                    udm_doc_url=udm_doc_url,
                                    yaral2_doc_url=yaral2_doc_url,
                                )
                                comments[existing_f_idx] = {
                                    "start_index": p_start,
                                    "end_index": p_end,
                                    "quote": p_quote,
                                    "comment": comment_body,
                                }
                                edits[existing_f_idx] = {
                                    "start_index": p_start,
                                    "end_index": p_end,
                                    "quote": p_quote,
                                    "replacement": rec_rep,
                                }
                                findings[existing_f_idx].update(
                                    {
                                        "start_index": p_start,
                                        "end_index": p_end,
                                        "quote": p_quote,
                                        "replacement": rec_rep,
                                        "repaired_rule_text": zh_diag[
                                            "pivoted_rule_text"
                                        ],
                                        "pivoted_rule_text": zh_diag[
                                            "pivoted_rule_text"
                                        ],
                                        "retrohunt_udm_query": zh_diag[
                                            "pivoted_retrohunt_udm_query"
                                        ],
                                        "zero_hit_diagnosis": zh_diag[
                                            "diagnosis_class"
                                        ],
                                        "failure_reason": zh_diag[
                                            "failure_reason"
                                        ],
                                        "recommended_yaral2_predicate": zh_diag[
                                            "recommended_yaral2_predicate"
                                        ],
                                        "recommended_span_target": zh_diag[
                                            "recommended_span_target"
                                        ],
                                        "anchor_query": zh_diag["anchor_query"],
                                        "anchor_event_count": zh_diag[
                                            "anchor_event_count"
                                        ],
                                        "pivot_event_count": zh_diag[
                                            "pivot_event_count"
                                        ],
                                        "pivot_compiler_verified": zh_diag[
                                            "pivot_compiler_verified"
                                        ],
                                        "shared_join_values": zh_diag.get(
                                            "shared_join_values", []
                                        ),
                                        "observed_values": zh_diag.get(
                                            "observed_values", []
                                        ),
                                    }
                                )
                                upgraded_finding_indices.add(existing_f_idx)
                                zero_hit_yaral2_findings_count += 1
                            else:
                                span_target = str(
                                    zh_diag.get("recommended_span_target")
                                    or "predicate"
                                )
                                if span_target == "var_field":
                                    t_start = int(
                                        target_pred["var_field_start_index"]
                                    )
                                    t_end = int(
                                        target_pred["var_field_end_index"]
                                    )
                                    t_quote = str(target_pred["var_field_token"])
                                elif span_target == "rhs":
                                    t_start = int(target_pred["rhs_start_index"])
                                    t_end = int(target_pred["rhs_end_index"])
                                    t_quote = str(target_pred["rhs_raw"])
                                else:
                                    t_start = int(
                                        target_pred["predicate_start_index"]
                                    )
                                    t_end = int(
                                        target_pred["predicate_end_index"]
                                    )
                                    t_quote = str(target_pred["predicate_text"])
                                t_replacement = str(
                                    zh_diag["recommended_span_replacement"]
                                )
                                inv_field_tok = str(
                                    target_pred["var_field_token"]
                                )
                                canon_field_tok = f"{target_pred['event_var']}.{zh_diag['recommended_field']}"
                                if any(
                                    _spans_overlap((t_start, t_end), p_span)
                                    for p_span in pending_spans
                                ):
                                    skipped_existing_suggestion_count += 1
                                elif not any(
                                    _spans_overlap(
                                        (t_start, t_end),
                                        (
                                            int(ex_e["start_index"]),
                                            int(ex_e["end_index"]),
                                        ),
                                    )
                                    for ex_e in edits
                                ):
                                    comment_body = _format_zero_hit_yaral2_comment(
                                        zh_diag,
                                        rule_name=r_name,
                                        has_schema_defect=False,
                                        udm_doc_url=udm_doc_url,
                                        yaral2_doc_url=yaral2_doc_url,
                                    )
                                    comments.append(
                                        {
                                            "start_index": t_start,
                                            "end_index": t_end,
                                            "quote": t_quote,
                                            "comment": comment_body,
                                        }
                                    )
                                    edits.append(
                                        {
                                            "start_index": t_start,
                                            "end_index": t_end,
                                            "quote": t_quote,
                                            "replacement": t_replacement,
                                        }
                                    )
                                    findings.append(
                                        {
                                            "rule_name": r_name,
                                            "defect_type": "zero_hit_retrohunt_predicate",
                                            "invalid_field": inv_field_tok,
                                            "canonical_field": canon_field_tok,
                                            "quote": t_quote,
                                            "replacement": t_replacement,
                                            "start_index": t_start,
                                            "end_index": t_end,
                                            "original_rule_text": orig_rule,
                                            "repaired_rule_text": zh_diag[
                                                "pivoted_rule_text"
                                            ],
                                            "pivoted_rule_text": zh_diag[
                                                "pivoted_rule_text"
                                            ],
                                            "is_multi_event": bool(
                                                zh_diag.get(
                                                    "is_multi_event", False
                                                )
                                            ),
                                            "retrohunt_udm_query": zh_diag[
                                                "pivoted_retrohunt_udm_query"
                                            ],
                                            "zero_hit_diagnosis": zh_diag[
                                                "diagnosis_class"
                                            ],
                                            "failure_reason": zh_diag[
                                                "failure_reason"
                                            ],
                                            "recommended_yaral2_predicate": zh_diag[
                                                "recommended_yaral2_predicate"
                                            ],
                                            "recommended_span_target": span_target,
                                            "anchor_query": zh_diag[
                                                "anchor_query"
                                            ],
                                            "anchor_event_count": zh_diag[
                                                "anchor_event_count"
                                            ],
                                            "pivot_event_count": zh_diag[
                                                "pivot_event_count"
                                            ],
                                            "pivot_compiler_verified": zh_diag[
                                                "pivot_compiler_verified"
                                            ],
                                            "shared_join_values": zh_diag.get(
                                                "shared_join_values", []
                                            ),
                                            "observed_values": zh_diag.get(
                                                "observed_values", []
                                            ),
                                        }
                                    )
                                    zero_hit_yaral2_findings_count += 1
            else:
                rule_check = rule_cache[cache_key]

            if idx in upgraded_finding_indices:
                continue

            findings[idx]["repaired_rule_text"] = rule_check.get(
                "pivoted_rule_text", rule_check.get("repaired_rule_text")
            )
            findings[idx]["retrohunt_udm_query"] = rule_check.get(
                "retrohunt_udm_query"
            )
            if rule_check.get("compiler_verified"):
                me_info = rule_check.get("multi_event_retrohunt")
                computed_outcomes_part = ""
                if rule_check.get("computed_string_outcomes"):
                    computed_outcomes_part = (
                        f", computed_outcomes={rule_check['computed_string_outcomes']}"
                    )
                ref_lists_part = ""
                if rule_check.get("reference_lists"):
                    ref_lists_part = (
                        f", reference_lists={rule_check['reference_lists']}"
                    )
                if isinstance(me_info, dict) and me_info.get("is_multi_event"):
                    if me_info.get("is_non_existence"):
                        comments[idx]["comment"] = (
                            f"{comments[idx]['comment']} "
                            f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                            f"Non-Existence Retrohunt Set-Difference: "
                            f"shared_join_values={me_info.get('shared_join_values', [])}, "
                            f"suppressed_join_values={me_info.get('suppressed_join_values', [])}, "
                            f"events_matched={rule_check['retrohunt_event_count']}"
                            f"{computed_outcomes_part}{ref_lists_part}]"
                        )
                    else:
                        comments[idx]["comment"] = (
                            f"{comments[idx]['comment']} "
                            f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                            f"Multi-Event Retrohunt Correlation: "
                            f"shared_join_values={me_info.get('shared_join_values', [])}, "
                            f"events_matched={rule_check['retrohunt_event_count']}"
                            f"{computed_outcomes_part}{ref_lists_part}]"
                        )
                else:
                    comments[idx]["comment"] = (
                        f"{comments[idx]['comment']} "
                        f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                        f"Retrohunt Dry-Run: query='{rule_check['retrohunt_udm_query']}', "
                        f"events_matched={rule_check['retrohunt_event_count']}"
                        f"{computed_outcomes_part}{ref_lists_part}]"
                    )

        if diagnose_zero_hit_retrohunt:
            for block in _iter_yaral2_rule_blocks(plain_text):
                r_name = str(block["rule_name"])
                if r_name in static_rules_kept:
                    continue
                orig_rule = str(block["rule_text"])
                rule_char_start = int(block["char_start"])
                rule_char_end = int(block["char_end"])
                doc_multi_spec = extract_yaral2_multi_event_spec(
                    orig_rule,
                    rule_char_start=rule_char_start,
                    full_plain_text=plain_text,
                    index_map=index_map,
                )
                doc_preds = doc_multi_spec["predicates"]
                doc_out_cmps = doc_multi_spec["condition_outcome_comparisons"]
                if r_name in static_rules_all:
                    if pending_spans:
                        rule_check = verify_yaral2_rule_with_siem(
                            orig_rule,
                            run_retrohunt_check=True,
                            diagnose_zero_hit_retrohunt=True,
                            start_time=start_time,
                            end_time=end_time,
                            max_events=max_events,
                            siem_validate_fn=siem_validate_fn,
                            siem_search_fn=siem_search_fn,
                        )
                        zh_diag = rule_check.get("zero_hit_diagnosis")
                        f_pred_idx = (
                            zh_diag.get("failing_predicate_index")
                            if isinstance(zh_diag, dict)
                            else None
                        )
                        if (
                            isinstance(zh_diag, dict)
                            and zh_diag.get("pivot_verified")
                            and zh_diag.get("pivot_compiler_verified")
                            and zh_diag.get("diagnosis_class")
                            == "uncalibrated_outcome_threshold"
                        ):
                            for uc in zh_diag.get(
                                "uncalibrated_comparisons", []
                            ):
                                c_idx = int(uc["comparison_index"])
                                if 0 <= c_idx < len(doc_out_cmps):
                                    target_cmp = doc_out_cmps[c_idx]
                                    cmp_span = (
                                        int(
                                            target_cmp["comparison_start_index"]
                                        ),
                                        int(target_cmp["comparison_end_index"]),
                                    )
                                    if any(
                                        _spans_overlap(cmp_span, p_span)
                                        for p_span in pending_spans
                                    ):
                                        skipped_existing_suggestion_count += 1
                        elif (
                            isinstance(zh_diag, dict)
                            and zh_diag.get("pivot_verified")
                            and zh_diag.get("pivot_compiler_verified")
                            and zh_diag.get("diagnosis_class")
                            != "cross_event_join_entity_role_swap"
                            and isinstance(f_pred_idx, int)
                            and (0 <= f_pred_idx < len(doc_preds))
                        ):
                            target_pred = doc_preds[f_pred_idx]
                            vf_span = (
                                int(target_pred["var_field_start_index"]),
                                int(target_pred["var_field_end_index"]),
                            )
                            if vf_span not in raw_var_field_spans:
                                p_span_cand = (
                                    int(target_pred["predicate_start_index"]),
                                    int(target_pred["predicate_end_index"]),
                                )
                                if any(
                                    _spans_overlap(p_span_cand, p_span)
                                    for p_span in pending_spans
                                ):
                                    skipped_existing_suggestion_count += 1
                    continue
                if (
                    len(doc_preds) < 2
                    and not doc_multi_spec["is_multi_event"]
                    and not doc_out_cmps
                ):
                    continue

                rule_span = (
                    index_map[rule_char_start],
                    index_map[rule_char_end - 1]
                    + _utf16_code_unit_len(plain_text[rule_char_end - 1]),
                )
                normalized_rule = _normalize_yaral2_re_regex_calls(orig_rule)

                if doc_multi_spec["is_multi_event"]:
                    initial_me = _run_multi_event_siem_retrohunt(
                        normalized_rule,
                        start_time=start_time,
                        end_time=end_time,
                        max_events=max(max_events, 20),
                        siem_search_fn=siem_search_fn,
                    )
                    if not initial_me.get("siem_verified"):
                        continue
                    initial_hits = int(
                        initial_me.get("correlated_event_count", 0) or 0
                    )
                    if initial_hits > 0:
                        initial_out_eval = evaluate_yaral2_outcome_thresholds(
                            normalized_rule,
                            initial_me,
                            _orig_rule_text=orig_rule,
                        )
                        if not initial_out_eval["threshold_suppressed"]:
                            comp_ok, comp_out = (
                                _validate_yaral2_rule_with_compiler(
                                    normalized_rule,
                                    siem_validate_fn=siem_validate_fn,
                                )
                            )
                            siem_rule_checks.append(
                                {
                                    "status": "success" if comp_ok else "error",
                                    "rule_name": r_name,
                                    "original_rule_text": orig_rule,
                                    "repaired_rule_text": normalized_rule,
                                    "pivoted_rule_text": normalized_rule,
                                    "findings": [],
                                    "is_multi_event": True,
                                    "is_non_existence": bool(
                                        initial_me.get("is_non_existence")
                                    ),
                                    "compiler_verified": comp_ok,
                                    "compiler_output": comp_out,
                                    "retrohunt_udm_query": str(
                                        initial_me.get("summary_query") or ""
                                    ),
                                    "retrohunt_verified": True,
                                    "retrohunt_event_count": initial_hits,
                                    "retrohunt_response": initial_me,
                                    "multi_event_retrohunt": initial_me,
                                    "outcome_evaluation": initial_out_eval,
                                    "outcome_values": initial_out_eval[
                                        "outcome_values"
                                    ],
                                }
                            )
                            continue
                else:
                    retrohunt_query = " AND ".join(
                        str(p["udm_clause"]) for p in doc_preds
                    )
                    initial_siem = verify_udm_query_with_siem(
                        retrohunt_query,
                        start_time=start_time,
                        end_time=end_time,
                        max_events=max(max_events, 20),
                        siem_search_fn=siem_search_fn,
                    )
                    if not initial_siem.get("siem_verified"):
                        continue
                    initial_hits = int(initial_siem.get("event_count", 0) or 0)
                    if initial_hits > 0:
                        initial_out_eval = evaluate_yaral2_outcome_thresholds(
                            normalized_rule,
                            initial_siem,
                            _orig_rule_text=orig_rule,
                        )
                        if not initial_out_eval["threshold_suppressed"]:
                            comp_ok, comp_out = (
                                _validate_yaral2_rule_with_compiler(
                                    normalized_rule,
                                    siem_validate_fn=siem_validate_fn,
                                )
                            )
                            siem_rule_checks.append(
                                {
                                    "status": "success" if comp_ok else "error",
                                    "rule_name": r_name,
                                    "original_rule_text": orig_rule,
                                    "repaired_rule_text": normalized_rule,
                                    "pivoted_rule_text": normalized_rule,
                                    "findings": [],
                                    "is_multi_event": False,
                                    "compiler_verified": comp_ok,
                                    "compiler_output": comp_out,
                                    "retrohunt_udm_query": retrohunt_query,
                                    "retrohunt_verified": True,
                                    "retrohunt_event_count": initial_hits,
                                    "retrohunt_response": initial_siem,
                                    "outcome_evaluation": initial_out_eval,
                                    "outcome_values": initial_out_eval[
                                        "outcome_values"
                                    ],
                                }
                            )
                            continue

                rule_check = verify_yaral2_rule_with_siem(
                    orig_rule,
                    run_retrohunt_check=True,
                    diagnose_zero_hit_retrohunt=True,
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_validate_fn=siem_validate_fn,
                    siem_search_fn=siem_search_fn,
                )
                siem_rule_checks.append(rule_check)
                zh_diag = rule_check.get("zero_hit_diagnosis")
                if not (
                    isinstance(zh_diag, dict)
                    and zh_diag.get("pivot_verified")
                    and zh_diag.get("pivot_compiler_verified")
                ):
                    if any(
                        _spans_overlap(rule_span, p_span)
                        for p_span in pending_spans
                    ):
                        skipped_existing_suggestion_count += 1
                    continue

                zero_hit_yaral2_diagnoses.append(zh_diag)
                span_target = str(
                    zh_diag.get("recommended_span_target") or "predicate"
                )

                if (
                    zh_diag.get("diagnosis_class")
                    == "uncalibrated_outcome_threshold"
                ):
                    for uc in zh_diag.get("uncalibrated_comparisons", []):
                        c_idx = int(uc["comparison_index"])
                        if not (0 <= c_idx < len(doc_out_cmps)):
                            continue
                        target_cmp = doc_out_cmps[c_idx]
                        t_start = int(target_cmp["comparison_start_index"])
                        t_end = int(target_cmp["comparison_end_index"])
                        t_quote = str(target_cmp["comparison_text"])
                        t_replacement = str(uc["recommended_comparison"])
                        if any(
                            _spans_overlap((t_start, t_end), p_span)
                            for p_span in pending_spans
                        ):
                            skipped_existing_suggestion_count += 1
                            continue
                        if any(
                            _spans_overlap(
                                (t_start, t_end),
                                (
                                    int(existing_e["start_index"]),
                                    int(existing_e["end_index"]),
                                ),
                            )
                            for existing_e in edits
                        ):
                            continue
                        comment_body = _format_zero_hit_yaral2_comment(
                            zh_diag,
                            rule_name=r_name,
                            has_schema_defect=False,
                            uncalibrated_comparison=uc,
                            udm_doc_url=udm_doc_url,
                            yaral2_doc_url=yaral2_doc_url,
                        )
                        comments.append(
                            {
                                "start_index": t_start,
                                "end_index": t_end,
                                "quote": t_quote,
                                "comment": comment_body,
                            }
                        )
                        edits.append(
                            {
                                "start_index": t_start,
                                "end_index": t_end,
                                "quote": t_quote,
                                "replacement": t_replacement,
                            }
                        )
                        findings.append(
                            {
                                "rule_name": r_name,
                                "defect_type": "uncalibrated_outcome_threshold",
                                "invalid_field": t_quote,
                                "canonical_field": t_replacement,
                                "quote": t_quote,
                                "replacement": t_replacement,
                                "start_index": t_start,
                                "end_index": t_end,
                                "original_rule_text": orig_rule,
                                "repaired_rule_text": zh_diag[
                                    "pivoted_rule_text"
                                ],
                                "pivoted_rule_text": zh_diag[
                                    "pivoted_rule_text"
                                ],
                                "is_multi_event": bool(
                                    zh_diag.get("is_multi_event", False)
                                ),
                                "retrohunt_udm_query": zh_diag[
                                    "pivoted_retrohunt_udm_query"
                                ],
                                "zero_hit_diagnosis": "uncalibrated_outcome_threshold",
                                "failure_reason": "uncalibrated_outcome_threshold",
                                "outcome_var": str(uc["outcome_var"]),
                                "threshold_value": uc["threshold_value"],
                                "empirical_value": uc["empirical_value"],
                                "outcome_values": zh_diag.get(
                                    "outcome_values", {}
                                ),
                                "recommended_yaral2_predicate": t_replacement,
                                "recommended_span_target": "condition_outcome_comparison",
                                "anchor_query": zh_diag["anchor_query"],
                                "anchor_event_count": zh_diag[
                                    "anchor_event_count"
                                ],
                                "pivot_event_count": zh_diag[
                                    "pivot_event_count"
                                ],
                                "pivot_compiler_verified": zh_diag[
                                    "pivot_compiler_verified"
                                ],
                                "shared_join_values": zh_diag.get(
                                    "shared_join_values", []
                                ),
                                "observed_values": zh_diag.get(
                                    "observed_values", []
                                ),
                            }
                        )
                        zero_hit_yaral2_findings_count += 1
                    continue

                if (
                    zh_diag.get("diagnosis_class")
                    == "cross_event_join_entity_role_swap"
                ):
                    jb_idx = zh_diag.get("failing_join_binding_index")
                    doc_jbs = doc_multi_spec["join_bindings"]
                    if not isinstance(jb_idx, int) or not (
                        0 <= jb_idx < len(doc_jbs)
                    ):
                        continue
                    target_jb = doc_jbs[jb_idx]
                    t_start = int(target_jb["var_field_start_index"])
                    t_end = int(target_jb["var_field_end_index"])
                    t_quote = str(target_jb["var_field_token"])
                    inv_field_tok = str(target_jb["var_field_token"])
                    canon_field_tok = f"{target_jb['event_var']}.{zh_diag['recommended_field']}"
                else:
                    f_pred_idx = zh_diag.get("failing_predicate_index")
                    if not isinstance(f_pred_idx, int) or not (
                        0 <= f_pred_idx < len(doc_preds)
                    ):
                        continue
                    target_pred = doc_preds[f_pred_idx]
                    if span_target == "var_field":
                        t_start = int(target_pred["var_field_start_index"])
                        t_end = int(target_pred["var_field_end_index"])
                        t_quote = str(target_pred["var_field_token"])
                    elif span_target == "rhs":
                        t_start = int(target_pred["rhs_start_index"])
                        t_end = int(target_pred["rhs_end_index"])
                        t_quote = str(target_pred["rhs_raw"])
                    else:
                        t_start = int(target_pred["predicate_start_index"])
                        t_end = int(target_pred["predicate_end_index"])
                        t_quote = str(target_pred["predicate_text"])
                    inv_field_tok = str(target_pred["var_field_token"])
                    canon_field_tok = f"{target_pred['event_var']}.{zh_diag['recommended_field']}"

                t_replacement = str(zh_diag["recommended_span_replacement"])

                if any(
                    _spans_overlap((t_start, t_end), p_span)
                    for p_span in pending_spans
                ):
                    skipped_existing_suggestion_count += 1
                    continue

                if any(
                    _spans_overlap(
                        (t_start, t_end),
                        (int(existing_e["start_index"]), int(existing_e["end_index"])),
                    )
                    for existing_e in edits
                ):
                    continue

                comment_body = _format_zero_hit_yaral2_comment(
                    zh_diag,
                    rule_name=r_name,
                    has_schema_defect=False,
                    udm_doc_url=udm_doc_url,
                    yaral2_doc_url=yaral2_doc_url,
                )
                comments.append(
                    {
                        "start_index": t_start,
                        "end_index": t_end,
                        "quote": t_quote,
                        "comment": comment_body,
                    }
                )
                edits.append(
                    {
                        "start_index": t_start,
                        "end_index": t_end,
                        "quote": t_quote,
                        "replacement": t_replacement,
                    }
                )
                findings.append(
                    {
                        "rule_name": r_name,
                        "defect_type": "zero_hit_retrohunt_predicate",
                        "invalid_field": inv_field_tok,
                        "canonical_field": canon_field_tok,
                        "quote": t_quote,
                        "replacement": t_replacement,
                        "start_index": t_start,
                        "end_index": t_end,
                        "original_rule_text": orig_rule,
                        "repaired_rule_text": zh_diag["pivoted_rule_text"],
                        "pivoted_rule_text": zh_diag["pivoted_rule_text"],
                        "is_multi_event": bool(
                            zh_diag.get("is_multi_event", False)
                        ),
                        "retrohunt_udm_query": zh_diag[
                            "pivoted_retrohunt_udm_query"
                        ],
                        "zero_hit_diagnosis": zh_diag["diagnosis_class"],
                        "failure_reason": zh_diag["failure_reason"],
                        "recommended_yaral2_predicate": zh_diag[
                            "recommended_yaral2_predicate"
                        ],
                        "recommended_span_target": span_target,
                        "anchor_query": zh_diag["anchor_query"],
                        "anchor_event_count": zh_diag["anchor_event_count"],
                        "pivot_event_count": zh_diag["pivot_event_count"],
                        "pivot_compiler_verified": zh_diag[
                            "pivot_compiler_verified"
                        ],
                        "shared_join_values": zh_diag.get(
                            "shared_join_values", []
                        ),
                        "observed_values": zh_diag.get("observed_values", []),
                    }
                )
                zero_hit_yaral2_findings_count += 1

    if len(findings) > 1:
        ordered = sorted(
            zip(comments, edits, findings),
            key=lambda triple: int(triple[2]["start_index"]),
        )
        comments = [item[0] for item in ordered]
        edits = [item[1] for item in ordered]
        findings = [item[2] for item in ordered]

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

    yaral2_in_membership_repaired = sum(
        1
        for f in findings
        if f.get("defect_type") == "invalid_in_membership_syntax"
    )
    yaral2_reference_lists_repaired = sum(
        1
        for f in findings
        if f.get("defect_type") == "invalid_reference_list_syntax"
    )
    yaral2_strings_functions_repaired = sum(
        1
        for f in findings
        if f.get("defect_type") == "invalid_strings_function_syntax"
    )
    yaral2_re_capture_repaired = sum(
        1
        for f in findings
        if f.get("defect_type") == "invalid_re_capture_syntax"
    )

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "yaral2_findings_count": len(findings),
        "yaral2_in_membership_repaired": yaral2_in_membership_repaired,
        "yaral2_reference_lists_repaired": yaral2_reference_lists_repaired,
        "yaral2_strings_functions_repaired": yaral2_strings_functions_repaired,
        "yaral2_re_capture_repaired": yaral2_re_capture_repaired,
        "zero_hit_yaral2_findings_count": zero_hit_yaral2_findings_count,
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "siem_rule_checks": siem_rule_checks,
        "zero_hit_yaral2_diagnoses": zero_hit_yaral2_diagnoses,
        "comments": comments_res,
        "edits": edits_res,
    }


verify_and_repair_yaral2_rules_in_doc = verify_and_redline_yaral2_rules_in_doc


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


def find_telemetry_hazard_spans(
    plain_text: str,
    index_map: list[int],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans Google Doc ``plain_text`` for unredacted telemetry hazards and live secrets without an LLM.

    Covers all 22 deterministic rules in :data:`TELEMETRY_HAZARD_PATTERNS`
    (encoded PowerShell flags, ``.NET`` ``FromBase64String`` calls, standalone
    64+ char Base64 stagers, PowerShell & LOLBin download cradles, credential
    dumpers & offline SAM/SYSTEM/SECURITY hive dumps, Linux reverse shells &
    ``curl|bash`` pipe-to-shell stagers, and leaked ``ya29.`` GCP OAuth2,
    ``eyJ`` JWT, ``AKIA``/``ASIA`` AWS keys, and PEM private keys) while
    strictly preserving forensic identifiers (MD5, SHA-1, SHA-256, UUIDs,
    Windows SIDs, GCP resource paths, Chronicle UDM fields, and MITRE/CVE IDs).

    Returns ``(comments, edits, findings)`` using exact 1-based UTF-16
    ``start_index`` and ``end_index`` coordinates so :func:`insert_doc_comments`
    and :func:`propose_doc_suggested_edits` can stage red-lines directly via
    the Google Docs API v1 without ever echoing sensitive payloads or live
    credentials through an LLM.
    """
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    if not plain_text or not index_map:
        return comments, edits, findings

    matches = _iter_telemetry_hazard_matches(plain_text)
    for item in matches:
        char_start = int(item["char_start"])
        char_end = int(item["char_end"]) - 1
        if char_start < 0 or char_end >= len(index_map) or char_start > char_end:
            continue
        start_idx = index_map[char_start]
        end_idx = index_map[char_end] + _utf16_code_unit_len(plain_text[char_end])
        replacement = str(item["replacement"])
        comment_text = str(item["comment"])
        comments.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_idx,
                "end_index": end_idx,
                "replacement": replacement,
            }
        )
        findings.append(
            {
                "name": item["name"],
                "category": item["category"],
                "token_type": item["token_type"],
                "sha256_prefix": item["sha256_prefix"],
                "payload_length": item["payload_length"],
                "start_index": start_idx,
                "end_index": end_idx,
                "replacement": replacement,
                "comment": comment_text,
            }
        )

    return comments, edits, findings


def sanitize_and_redline_telemetry_in_doc(
    document_id: str,
    tool_context: Any = None,
    *,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Scans a Google Doc for unredacted offensive telemetry payloads and leaked secrets and stages ``writeMode="SUGGEST"`` red-lines.

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 ``index_map``
       and ``pending_suggestion_spans``.
    2. Runs :func:`find_telemetry_hazard_spans` across the document text to locate
       encoded PowerShell commands, ``.NET`` Base64 decoders, standalone Base64
       stagers, LOLBin download cradles, credential-dumping arguments, Linux
       reverse shells, and leaked cloud/API tokens (``ya29.``, ``eyJ``, ``AKIA``,
       PEM private keys) without echoing them through an LLM.
    3. Skips any span overlapping an existing pending suggestion
       (``skipped_existing_suggestion_count``) for multi-pass idempotency.
    4. Anchors forensic safety comments first via :func:`insert_doc_comments`.
    5. Stages descending-index ``writeMode="SUGGEST"`` redaction replacements
       second via :func:`propose_doc_suggested_edits`.
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

    raw_comments, raw_edits, raw_findings = find_telemetry_hazard_spans(
        plain_text, index_map
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
                "findings": findings,
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
                "findings": findings,
                "comments": comments_res,
                "edits": edits_res,
            }

    return {
        "status": "success",
        "document_id": document_id,
        "title": read_res.get("title", ""),
        "char_count": read_res.get("char_count", 0),
        "telemetry_hazard_findings_count": len(findings),
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
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
    include_telemetry_hazard_stage_a: bool = True,
    include_credential_containment_stage_a: bool = True,
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
    2. Runs Stage A (:func:`find_leaked_credential_containment_spans` when
       ``include_credential_containment_stage_a=True``,
       :func:`find_telemetry_hazard_spans` when
       ``include_telemetry_hazard_stage_a=True``,
       :func:`find_deterministic_indicator_spans`,
       :func:`find_udm_field_spans` when ``include_udm_stage_a=True``,
       :func:`find_yaral2_rule_spans` when ``include_yaral2_stage_a=True``, and
       :func:`find_mitre_and_cve_spans` when ``include_mitre_cve_stage_a=True``)
       to locate leaked credentials, destructive/ineffective containment CLIs,
       unredacted telemetry payloads/secrets, live untrusted URLs,
       standalone Chronicle UDM field defects, YARA-L 2.0 rule defects, and
       MITRE ATT&CK / CVE defects by numeric UTF-16 span without echoing them
       through an LLM.
    3. Deduplicates Stage A spans against overlapping Stage B
       ``semantic_comments`` and ``semantic_edits`` and skips any span that
       overlaps an existing pending suggestion (multi-pass idempotency).
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

    raw_doc = _load_doc_raw_ast(document_id, tool_context=tool_context)
    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    try:
        stage_b_comments = _parse_json_or_list(semantic_comments)
        stage_b_edits = _parse_json_or_list(semantic_edits)
    except json.JSONDecodeError as err:
        return {"status": "error", "message": f"Invalid semantic review JSON: {err}"}

    existing_comment_spans = [
        sp
        for item in stage_b_comments
        if (sp := _resolve_item_span(plain_text, index_map, item)) is not None
    ]
    existing_edit_spans = [
        sp
        for item in stage_b_edits
        if (sp := _resolve_item_span(plain_text, index_map, item)) is not None
    ]

    stage_a_credential_containment_count = 0
    deduped_credential_containment_comments: list[dict[str, Any]] = []
    deduped_credential_containment_edits: list[dict[str, Any]] = []
    if include_credential_containment_stage_a:
        cc_comments, cc_edits, cc_findings = (
            find_leaked_credential_containment_spans(
                plain_text,
                index_map,
                redact_unredacted_credentials=include_telemetry_hazard_stage_a,
                synthesize_missing_revocation=False,
            )
        )
        stage_a_credential_containment_count = len(cc_findings)
        for c_item in cc_comments:
            c_span = (c_item["start_index"], c_item["end_index"])
            if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
                deduped_credential_containment_comments.append(c_item)
                existing_comment_spans.append(c_span)
        for e_item in cc_edits:
            e_span = (e_item["start_index"], e_item["end_index"])
            if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
                deduped_credential_containment_edits.append(e_item)
                existing_edit_spans.append(e_span)

    stage_a_telemetry_hazard_count = 0
    deduped_telemetry_comments: list[dict[str, Any]] = []
    deduped_telemetry_edits: list[dict[str, Any]] = []
    if include_telemetry_hazard_stage_a:
        th_comments, th_edits, th_findings = find_telemetry_hazard_spans(
            plain_text, index_map
        )
        stage_a_telemetry_hazard_count = len(th_findings)
        for c_item in th_comments:
            c_span = (c_item["start_index"], c_item["end_index"])
            if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
                deduped_telemetry_comments.append(c_item)
                existing_comment_spans.append(c_span)
        for e_item in th_edits:
            e_span = (e_item["start_index"], e_item["end_index"])
            if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
                deduped_telemetry_edits.append(e_item)
                existing_edit_spans.append(e_span)

    raw_url_comments, raw_url_edits = find_deterministic_indicator_spans(
        plain_text, index_map
    )
    stage_a_comments: list[dict[str, Any]] = []
    stage_a_edits: list[dict[str, Any]] = []
    for c_item in raw_url_comments:
        c_span = (c_item["start_index"], c_item["end_index"])
        if not any(_spans_overlap(c_span, ex) for ex in existing_comment_spans):
            stage_a_comments.append(c_item)
            existing_comment_spans.append(c_span)
    for e_item in raw_url_edits:
        e_span = (e_item["start_index"], e_item["end_index"])
        if not any(_spans_overlap(e_span, ex) for ex in existing_edit_spans):
            stage_a_edits.append(e_item)
            existing_edit_spans.append(e_span)

    stage_a_udm_count = 0
    stage_a_italic_regex_count = 0
    deduped_udm_comments: list[dict[str, Any]] = []
    deduped_udm_edits: list[dict[str, Any]] = []
    if include_udm_stage_a:
        udm_comments, udm_edits, udm_findings = find_udm_field_spans(
            plain_text, index_map
        )
        if isinstance(raw_doc, dict):
            ir_comments, ir_edits, ir_findings = (
                find_italic_corrupted_regex_spans(
                    raw_doc,
                    plain_text=plain_text,
                    index_map=index_map,
                )
            )
            stage_a_italic_regex_count = len(ir_findings)
            for ir_c, ir_e, ir_f in zip(ir_comments, ir_edits, ir_findings):
                if ir_f.get("context_kind") == "udm":
                    udm_comments.append(ir_c)
                    udm_edits.append(ir_e)
                    udm_findings.append(ir_f)
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
            plain_text, index_map, doc=raw_doc
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
        deduped_credential_containment_comments
        + deduped_telemetry_comments
        + stage_a_comments
        + deduped_udm_comments
        + deduped_yaral2_comments
        + deduped_mitre_cve_comments
        + stage_b_comments
    )
    raw_all_edits = (
        deduped_credential_containment_edits
        + deduped_telemetry_edits
        + stage_a_edits
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
        "stage_a_credential_containment_count": stage_a_credential_containment_count,
        "stage_a_telemetry_hazard_count": stage_a_telemetry_hazard_count,
        "stage_a_url_count": len(stage_a_edits),
        "stage_a_udm_count": stage_a_udm_count,
        "stage_a_yaral2_count": stage_a_yaral2_count,
        "stage_a_mitre_cve_count": stage_a_mitre_cve_count,
        "stage_a_italic_regex_count": stage_a_italic_regex_count,
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
    include_credential_containment_stage_a: bool = True,
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
        include_credential_containment_stage_a=include_credential_containment_stage_a,
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
        "stage_a_credential_containment_count": review_res.get(
            "stage_a_credential_containment_count", 0
        ),
        "stage_a_telemetry_hazard_count": review_res.get("stage_a_telemetry_hazard_count", 0),
        "stage_a_url_count": review_res.get("stage_a_url_count", 0),
        "stage_a_udm_count": review_res.get("stage_a_udm_count", 0),
        "stage_a_yaral2_count": review_res.get("stage_a_yaral2_count", 0),
        "stage_a_mitre_cve_count": review_res.get("stage_a_mitre_cve_count", 0),
        "stage_a_italic_regex_count": review_res.get("stage_a_italic_regex_count", 0),
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


_NAMED_STYLE_HEADING_PREFIX: dict[str, str] = {
    "TITLE": "# ",
    "SUBTITLE": "## ",
    "HEADING_1": "# ",
    "HEADING_2": "## ",
    "HEADING_3": "### ",
    "HEADING_4": "#### ",
    "HEADING_5": "##### ",
    "HEADING_6": "###### ",
}
_ORDERED_LIST_GLYPH_TYPES: frozenset[str] = frozenset(
    {
        "DECIMAL",
        "ZERO_DECIMAL",
        "UPPER_ALPHA",
        "ALPHA",
        "UPPER_ROMAN",
        "ROMAN",
    }
)
_EXISTING_ORDERED_LIST_RE = re.compile(r"^\d+\.\s+")


def reconstruct_markdown_from_doc_ast(
    doc: dict[str, Any],
    *,
    view_mode: str = "accepted",
    accept_suggestion_ids: str | list[str] | set[str] | tuple[str, ...] | None = None,
    recover_italic_regex_wildcards: bool = True,
) -> dict[str, Any]:
    """Reconstructs structural Markdown from a Google Docs API v1 AST.

    Walks ``tabs[0].documentTab.body.content`` (or ``body.content``) and ``lists``
    (``tabs[0].documentTab.lists`` or ``doc.get("lists", {})``), honoring
    ``view_mode`` (``"accepted"``, ``"baseline"``, or ``"inline"``) and
    ``accept_suggestion_ids``:
    1. Reconstructs Markdown ``#`` through ``######`` headings from
       ``paragraph.paragraphStyle.namedStyleType`` when the paragraph text does
       not already start with ``#``.
    2. Reconstructs ordered (``1. ``, ``2. ``, ...) and unordered (``- ``) list
       items from ``paragraph.bullet`` (``listId``, ``nestingLevel``) and
       ``lists[listId].listProperties.nestingLevels[nestingLevel].glyphType``
       with ``2 * nestingLevel`` space indentation.
    3. Reconstructs pipe-delimited Markdown tables (``| col1 | col2 |`` +
       ``| --- | --- |``) from ``element["table"]["tableRows"]``.
    4. When ``recover_italic_regex_wildcards=True``, automatically restores
       paired ``*`` wildcard quantifiers that Google Drive's Markdown importer
       silently converted into ``textStyle.italic=True`` runs inside UDM or
       YARA-L 2.0 regex literals (e.g. ``/.cmd./`` -> ``/.*cmd.*/``).
    """
    if view_mode not in ("baseline", "accepted", "inline"):
        raise ValueError(f"Unsupported view_mode: {view_mode!r}")

    accepted_set = _normalize_suggestion_ids(accept_suggestion_ids)
    tabs = doc.get("tabs", [])
    if tabs:
        doc_tab = tabs[0].get("documentTab", {})
        body = doc_tab.get("body", {})
        lists_map = doc_tab.get("lists") or doc.get("lists") or {}
    else:
        body = doc.get("body", {})
        lists_map = doc.get("lists") or {}

    def _should_include_text_run(del_ids: list[str], ins_ids: list[str]) -> bool:
        if view_mode == "inline":
            return True
        if view_mode == "baseline":
            return not bool(ins_ids)
        if accepted_set is None:
            return not bool(del_ids)
        if ins_ids and not any(sid in accepted_set for sid in ins_ids):
            return False
        if del_ids and any(sid in accepted_set for sid in del_ids):
            return False
        return True

    def _is_ordered_list_level(list_id: str, nesting_level: int) -> bool:
        if not list_id or not isinstance(lists_map, dict):
            return False
        list_spec = lists_map.get(list_id)
        if not isinstance(list_spec, dict):
            return False
        levels = list_spec.get("listProperties", {}).get("nestingLevels", [])
        if not isinstance(levels, list) or not (0 <= nesting_level < len(levels)):
            return False
        lvl = levels[nesting_level]
        if not isinstance(lvl, dict):
            return False
        glyph_type = str(lvl.get("glyphType") or "").upper()
        if glyph_type in _ORDERED_LIST_GLYPH_TYPES:
            return True
        glyph_fmt = str(lvl.get("glyphFormat") or "")
        if "%" in glyph_fmt and not lvl.get("glyphSymbol"):
            return True
        return False

    headings_reconstructed_count = 0
    list_items_reconstructed_count = 0
    tables_reconstructed_count = 0
    italic_regex_wildcards_recovered_count = 0

    def _extract_paragraph_text(paragraph: dict[str, Any]) -> str:
        nonlocal italic_regex_wildcards_recovered_count
        p_chars: list[str] = []
        p_italics: list[bool] = []
        for pe in paragraph.get("elements", []):
            text_run = pe.get("textRun")
            if not text_run:
                continue
            del_ids = [
                str(x)
                for x in (text_run.get("suggestedDeletionIds") or [])
                if x
            ]
            ins_ids = [
                str(x)
                for x in (text_run.get("suggestedInsertionIds") or [])
                if x
            ]
            if not _should_include_text_run(del_ids, ins_ids):
                continue
            content = str(text_run.get("content") or "")
            is_italic = bool(text_run.get("textStyle", {}).get("italic"))
            for ch in content:
                p_chars.append(ch)
                p_italics.append(is_italic)

        raw_p = "".join(p_chars)
        if recover_italic_regex_wildcards and any(p_italics):
            tokens = _iter_italic_corrupted_regex_tokens(raw_p, p_italics)
            if tokens:
                rebuilt = raw_p
                for tok in sorted(
                    tokens, key=lambda t: int(t["tok_start"]), reverse=True
                ):
                    t_s = int(tok["tok_start"])
                    t_e = int(tok["tok_end"])
                    rebuilt = (
                        rebuilt[:t_s]
                        + str(tok["restored_regex"])
                        + rebuilt[t_e:]
                    )
                italic_regex_wildcards_recovered_count += len(tokens)
                raw_p = rebuilt
        return raw_p.rstrip("\r\n")

    output_lines: list[str] = []
    list_counters: dict[tuple[str, int], int] = {}

    for element in body.get("content", []):
        if "paragraph" in element:
            paragraph = element["paragraph"]
            line_text = _extract_paragraph_text(paragraph)
            stripped = line_text.strip()
            p_style = paragraph.get("paragraphStyle", {})
            named_style = (
                str(p_style.get("namedStyleType") or "NORMAL_TEXT")
                if isinstance(p_style, dict)
                else "NORMAL_TEXT"
            )
            bullet = paragraph.get("bullet")

            if isinstance(bullet, dict) and stripped:
                list_id = str(bullet.get("listId") or "default_list")
                nesting_level = int(bullet.get("nestingLevel", 0) or 0)
                for lid, lvl in list(list_counters.keys()):
                    if lid == list_id and lvl > nesting_level:
                        del list_counters[(lid, lvl)]
                count = list_counters.get((list_id, nesting_level), 0) + 1
                list_counters[(list_id, nesting_level)] = count
                indent = "  " * nesting_level
                clean_item = line_text.lstrip()
                if _is_ordered_list_level(list_id, nesting_level):
                    if not _EXISTING_ORDERED_LIST_RE.match(clean_item):
                        line_text = f"{indent}{count}. {clean_item}"
                        list_items_reconstructed_count += 1
                    else:
                        line_text = f"{indent}{clean_item}"
                else:
                    if not clean_item.startswith(("- ", "* ", "+ ")):
                        line_text = f"{indent}- {clean_item}"
                        list_items_reconstructed_count += 1
                    else:
                        line_text = f"{indent}{clean_item}"
            else:
                if stripped:
                    list_counters.clear()
                heading_prefix = _NAMED_STYLE_HEADING_PREFIX.get(named_style)
                if heading_prefix and stripped:
                    clean_heading = line_text.lstrip()
                    if not clean_heading.startswith("#"):
                        line_text = f"{heading_prefix}{clean_heading}"
                        headings_reconstructed_count += 1
                    if output_lines and output_lines[-1].strip():
                        output_lines.append("")
            output_lines.append(line_text)

        elif "table" in element:
            list_counters.clear()
            table_rows = element["table"].get("tableRows", [])
            rendered_rows: list[list[str]] = []
            max_cols = 0
            for row in table_rows:
                cells = row.get("tableCells", [])
                row_vals: list[str] = []
                for cell in cells:
                    cell_parts: list[str] = []
                    for c_el in cell.get("content", []):
                        if "paragraph" in c_el:
                            c_line = _extract_paragraph_text(c_el["paragraph"]).strip()
                            if c_line:
                                cell_parts.append(c_line)
                    cell_str = "<br>".join(cell_parts).replace("|", "\\|")
                    row_vals.append(cell_str)
                if row_vals:
                    max_cols = max(max_cols, len(row_vals))
                    rendered_rows.append(row_vals)
            if rendered_rows and max_cols > 0:
                tables_reconstructed_count += 1
                if output_lines and output_lines[-1].strip():
                    output_lines.append("")
                for r_idx, r_vals in enumerate(rendered_rows):
                    padded = r_vals + [""] * (max_cols - len(r_vals))
                    output_lines.append("| " + " | ".join(padded) + " |")
                    if r_idx == 0:
                        output_lines.append(
                            "| " + " | ".join(["---"] * max_cols) + " |"
                        )
                output_lines.append("")

    markdown_text = "\n".join(output_lines)
    if markdown_text and not markdown_text.endswith("\n"):
        markdown_text += "\n"

    return {
        "markdown": markdown_text,
        "headings_reconstructed_count": headings_reconstructed_count,
        "list_items_reconstructed_count": list_items_reconstructed_count,
        "tables_reconstructed_count": tables_reconstructed_count,
        "italic_regex_wildcards_recovered_count": italic_regex_wildcards_recovered_count,
    }


def list_doc_comments(
    document_id: str,
    *,
    include_resolved: bool = True,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Lists native review comments on a Google Doc via Google Drive API v3 ``files.comments``.

    Queries ``GET https://www.googleapis.com/drive/v3/files/{document_id}/comments``
    and classifies comments into resolved and unresolved sets so runbook promotion
    workflows can enforce an Unresolved Comment Governance Gate before overwriting
    production runbooks in ``SOC Runbooks``.
    """
    try:
        token = resolve_docs_token(tool_context, token_source=token_source)
    except (DriveRegistryConfigError, DriveMcpError) as err:
        return {"status": "error", "message": str(err)}

    url = f"{DRIVE_FILES_API_BASE_URL}/{document_id}/comments"
    headers = _build_docs_headers(token, quota_project=quota_project)
    base_params: dict[str, str] = {
        "fields": (
            "comments(id,content,resolved,deleted,createdTime,modifiedTime,"
            "author(displayName),quotedFileContent,anchor),nextPageToken"
        ),
        "includeDeleted": "false",
        "pageSize": "100",
    }

    raw_comments: list[dict[str, Any]] = []
    page_token = ""
    try:
        with httpx.Client(
            timeout=DEFAULT_DOCS_TIMEOUT_SECONDS, transport=transport
        ) as http:
            for _ in range(5):
                params = dict(base_params)
                if page_token:
                    params["pageToken"] = page_token
                resp = http.get(url, params=params, headers=headers)
                if resp.status_code != 200:
                    return {
                        "status": "error",
                        "document_id": document_id,
                        "message": (
                            f"Google Drive comments API returned HTTP {resp.status_code}: "
                            f"{resp.text[:300]}"
                        ),
                    }
                payload = resp.json()
                batch = payload.get("comments", [])
                if isinstance(batch, list):
                    raw_comments.extend(c for c in batch if isinstance(c, dict))
                page_token = str(payload.get("nextPageToken") or "").strip()
                if not page_token:
                    break
    except httpx.HTTPError as err:
        return {
            "status": "error",
            "document_id": document_id,
            "message": f"HTTP transport error listing doc comments: {err}",
        }

    all_records: list[dict[str, Any]] = []
    unresolved_comments: list[dict[str, Any]] = []
    resolved_comments: list[dict[str, Any]] = []

    for c in raw_comments:
        if bool(c.get("deleted", False)):
            continue
        is_resolved = bool(c.get("resolved", False))
        quoted_obj = c.get("quotedFileContent")
        quoted_value = (
            str(quoted_obj.get("value") or "")
            if isinstance(quoted_obj, dict)
            else ""
        )
        author_obj = c.get("author")
        author_name = (
            str(author_obj.get("displayName") or "")
            if isinstance(author_obj, dict)
            else ""
        )
        rec = {
            "id": str(c.get("id") or ""),
            "content": str(c.get("content") or ""),
            "resolved": is_resolved,
            "author": author_name,
            "quoted_text": quoted_value,
            "anchor": str(c.get("anchor") or ""),
            "created_time": str(c.get("createdTime") or ""),
        }
        all_records.append(rec)
        if is_resolved:
            resolved_comments.append(rec)
        else:
            unresolved_comments.append(rec)

    returned = all_records if include_resolved else unresolved_comments
    return {
        "status": "success",
        "document_id": document_id,
        "total_comment_count": len(all_records),
        "unresolved_comment_count": len(unresolved_comments),
        "resolved_comment_count": len(resolved_comments),
        "unresolved_comments": unresolved_comments,
        "comments": returned,
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
    ``suggestion_id``, reconstructs structural Markdown from the Google Docs AST,
    and generates a standard unified diff.
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
        raw_doc=doc,
    )

    ast_recon = reconstruct_markdown_from_doc_ast(
        doc,
        view_mode="accepted",
        accept_suggestion_ids=accept_suggestion_ids,
        recover_italic_regex_wildcards=True,
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
        "accepted_markdown_body": ast_recon["markdown"],
        "headings_reconstructed_count": ast_recon["headings_reconstructed_count"],
        "list_items_reconstructed_count": ast_recon["list_items_reconstructed_count"],
        "tables_reconstructed_count": ast_recon["tables_reconstructed_count"],
        "italic_regex_wildcards_recovered_count": ast_recon[
            "italic_regex_wildcards_recovered_count"
        ],
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
    reconstruct_markdown_structure: bool = True,
    require_resolved_comments: bool = False,
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
       and structural AST Markdown reconstruction (:func:`reconstruct_markdown_from_doc_ast`
       when ``reconstruct_markdown_structure=True``), preserving ``#`` headings,
       ordered/unordered lists, Markdown tables, and recovered ``*`` regex wildcards.
    2. When ``skill_name`` (or ``skill_content_override``) is provided, checks
       whether the exported text begins with YAML frontmatter (``--- ... ---``).
       If Google Docs horizontal-rule conversion stripped the frontmatter
       delimiter lines, reconstructs the canonical YAML frontmatter header from
       the source skill so the exported Markdown remains a valid
       :class:`SkillRegistry` / :class:`DriveSkillRegistry` runbook.
    3. When ``require_resolved_comments=True``, queries Google Drive API v3
       ``files.comments`` via :func:`list_doc_comments` and blocks export/promotion
       with ``status="blocked_unresolved_comments"`` if any unresolved comment exists.
    4. Optionally writes the accepted Markdown to ``output_path`` and/or publishes
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

    if reconstruct_markdown_structure:
        source_body = str(
            inspected.get("accepted_markdown_body")
            or inspected.get("accepted_text")
            or ""
        )
        headings_reconstructed_count = int(
            inspected.get("headings_reconstructed_count", 0) or 0
        )
        list_items_reconstructed_count = int(
            inspected.get("list_items_reconstructed_count", 0) or 0
        )
        tables_reconstructed_count = int(
            inspected.get("tables_reconstructed_count", 0) or 0
        )
        italic_regex_wildcards_recovered_count = int(
            inspected.get("italic_regex_wildcards_recovered_count", 0) or 0
        )
    else:
        source_body = str(inspected.get("accepted_text") or "")
        headings_reconstructed_count = 0
        list_items_reconstructed_count = 0
        tables_reconstructed_count = 0
        italic_regex_wildcards_recovered_count = 0

    frontmatter_restored = False
    collapsed_fm_re = re.compile(
        r"^(?:#+\s*)?name:\s*(\S+)[^\n]*\bdescription:\s*[^\n]*\n+",
        re.IGNORECASE,
    )
    effective_skill_name = skill_name.strip()
    if not effective_skill_name:
        collapsed_match = collapsed_fm_re.match(source_body.lstrip())
        if collapsed_match:
            effective_skill_name = collapsed_match.group(1).strip()
        else:
            title_match = re.match(
                r"^Runbook_Redline_([A-Za-z0-9_-]+?)_Case_",
                str(inspected.get("title") or ""),
            )
            if title_match:
                effective_skill_name = title_match.group(1).strip()

    if _FRONTMATTER_BLOCK_RE.match(source_body.lstrip()):
        accepted_markdown = source_body.lstrip()
    elif effective_skill_name or skill_content_override:
        canonical_fm = _extract_canonical_frontmatter_header(
            effective_skill_name, skill_content_override=skill_content_override
        )
        cleaned_body = source_body.lstrip()
        # Strip collapsed single-line frontmatter artifact produced when Google Drive
        # converts YAML '---' delimiters into horizontalRule elements.
        cleaned_body = collapsed_fm_re.sub("", cleaned_body, count=1).lstrip()
        if canonical_fm:
            accepted_markdown = canonical_fm + cleaned_body
            frontmatter_restored = True
        else:
            accepted_markdown = cleaned_body
    else:
        accepted_markdown = source_body

    parsed_fm = parse_frontmatter(accepted_markdown)

    unresolved_comment_count = 0
    resolved_comment_count = 0
    unresolved_comments: list[dict[str, Any]] = []
    if require_resolved_comments:
        comments_res = list_doc_comments(
            document_id,
            include_resolved=True,
            tool_context=tool_context,
            token_source=token_source,
            quota_project=quota_project,
            transport=transport,
        )
        if comments_res.get("status") != "success":
            return comments_res
        unresolved_comment_count = int(
            comments_res.get("unresolved_comment_count", 0) or 0
        )
        resolved_comment_count = int(
            comments_res.get("resolved_comment_count", 0) or 0
        )
        unresolved_comments = list(
            comments_res.get("unresolved_comments") or []
        )
        if unresolved_comment_count > 0:
            return {
                "status": "blocked_unresolved_comments",
                "message": (
                    f"Export blocked by Unresolved Comment Governance Gate: Google Doc "
                    f"{document_id!r} has {unresolved_comment_count} unresolved review comment(s). "
                    "Resolve all review comments in Google Docs before promoting the runbook."
                ),
                "document_id": document_id,
                "title": inspected["title"],
                "skill_name": effective_skill_name,
                "suggestion_count": inspected["suggestion_count"],
                "accepted_suggestion_count": inspected["accepted_suggestion_count"],
                "suggestions": inspected["suggestions"],
                "unified_diff": inspected["unified_diff"],
                "unresolved_comment_count": unresolved_comment_count,
                "resolved_comment_count": resolved_comment_count,
                "unresolved_comments": unresolved_comments,
                "headings_reconstructed_count": headings_reconstructed_count,
                "list_items_reconstructed_count": list_items_reconstructed_count,
                "tables_reconstructed_count": tables_reconstructed_count,
                "italic_regex_wildcards_recovered_count": italic_regex_wildcards_recovered_count,
                "frontmatter_restored": frontmatter_restored,
                "frontmatter_valid": bool(parsed_fm.get("name")),
                "frontmatter": parsed_fm,
                "accepted_markdown": accepted_markdown,
                "markdown": accepted_markdown,
                "char_count": len(accepted_markdown),
                "output_path": None,
                "drive": None,
                "drive_error": None,
            }

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
            or (
                f"{effective_skill_name}.md"
                if effective_skill_name
                else f"{inspected['title']}.md"
            )
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
        "skill_name": effective_skill_name,
        "suggestion_count": inspected["suggestion_count"],
        "accepted_suggestion_count": inspected["accepted_suggestion_count"],
        "suggestions": inspected["suggestions"],
        "unified_diff": inspected["unified_diff"],
        "unresolved_comment_count": unresolved_comment_count,
        "resolved_comment_count": resolved_comment_count,
        "unresolved_comments": unresolved_comments,
        "headings_reconstructed_count": headings_reconstructed_count,
        "list_items_reconstructed_count": list_items_reconstructed_count,
        "tables_reconstructed_count": tables_reconstructed_count,
        "italic_regex_wildcards_recovered_count": italic_regex_wildcards_recovered_count,
        "frontmatter_restored": frontmatter_restored,
        "frontmatter_valid": bool(parsed_fm.get("name")),
        "frontmatter": parsed_fm,
        "accepted_markdown": accepted_markdown,
        "markdown": accepted_markdown,
        "char_count": len(accepted_markdown),
        "output_path": saved_path,
        "drive": drive_result,
        "drive_error": drive_error,
    }


# ---------------------------------------------------------------------------
# Cycle 15 (H13): Automated Leaked Credential Blast-Radius Triage, Safe JWT
# Claim Extraction & Emergency Revocation Playbook Stager in Google Docs
# ---------------------------------------------------------------------------

_SAFE_JWT_HEADER_KEYS: tuple[str, ...] = ("alg", "kid", "typ")
_SAFE_JWT_PAYLOAD_KEYS: tuple[str, ...] = (
    "sub",
    "email",
    "iss",
    "aud",
    "scope",
    "scp",
    "client_id",
    "azp",
    "hd",
    "exp",
    "iat",
    "nbf",
    "jti",
    "name",
    "service_account",
    "project_id",
)

_REDACTED_CREDENTIAL_TOKEN_RE = re.compile(
    r"<(REDACTED_GCP_TOKEN|REDACTED_JWT|REDACTED_AWS_KEY|REDACTED_PRIVATE_KEY)"
    r":(?:len=(\d+),)?sha256=([0-9a-fA-F]{6,64})>"
)
_REDACTED_LABEL_TO_CREDENTIAL_TYPE: dict[str, tuple[str, str, str]] = {
    "REDACTED_GCP_TOKEN": (
        "gcp_oauth_token",
        "T1528",
        "Google Cloud OAuth 2.0 ya29.* bearer access token",
    ),
    "REDACTED_JWT": (
        "jwt_bearer_token",
        "T1528",
        "JSON Web Token (JWT) bearer token",
    ),
    "REDACTED_AWS_KEY": (
        "aws_access_key_id",
        "T1552.001",
        "AWS IAM Access Key ID (AKIA*/ASIA*)",
    ),
    "REDACTED_PRIVATE_KEY": (
        "private_key_block",
        "T1552.004",
        "PEM/OpenSSH private key block",
    ),
}

_GCP_SA_EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._+-]+@[A-Za-z0-9.-]*gserviceaccount\.com)\b"
)
_GENERIC_EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)
_IPV4_CANDIDATE_RE = re.compile(
    r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b"
)
_GCP_PROJECT_PATH_RE = re.compile(r"\bprojects/([a-z][a-z0-9-]{3,29})\b")
_AWS_KEY_ID_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")

_DESTRUCTIVE_SA_DELETE_RE = re.compile(
    r"\bgcloud[ \t]+iam[ \t]+service-accounts[ \t]+delete[ \t]+"
    r"([A-Za-z0-9._+-]+@[A-Za-z0-9.-]*gserviceaccount\.com)"
    r"(?:[ \t]+--quiet|[ \t]+-q)?\b"
)
_LOCAL_GCLOUD_AUTH_REVOKE_RE = re.compile(
    r"\bgcloud[ \t]+auth[ \t]+revoke"
    r"(?:[ \t]+(--all|[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}))?\b"
)
_DESTRUCTIVE_GAM_USER_DELETE_RE = re.compile(
    r"\bgam[ \t]+user[ \t]+([A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})[ \t]+delete\b"
)
_DESTRUCTIVE_AWS_KEY_DELETE_RE = re.compile(
    r"\baws[ \t]+iam[ \t]+delete-access-key"
    r"(?:[ \t]+--user-name[ \t]+([A-Za-z0-9_+=,.@-]+))?"
    r"[ \t]+--access-key-id[ \t]+([A-Za-z0-9_<>{}:=-]+)"
    r"(?:[ \t]+--user-name[ \t]+([A-Za-z0-9_+=,.@-]+))?"
)
_AWS_IAM_KEY_CLI_SPAN_RE = re.compile(
    r"\baws[ \t]+iam[ \t]+(?:delete-access-key|update-access-key)\b[^\r\n`]*"
)


def _b64url_decode_json_object(segment: str) -> dict[str, Any]:
    """Deterministically base64url-decodes a JWT segment into a JSON dict if valid."""
    cleaned = str(segment or "").strip()
    if not cleaned or not re.fullmatch(r"[A-Za-z0-9_-]+", cleaned):
        return {}
    padded = cleaned + ("=" * ((4 - len(cleaned) % 4) % 4))
    try:
        raw_bytes = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded_str = raw_bytes.decode("utf-8", errors="strict")
        parsed = json.loads(decoded_str)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def decode_jwt_safe_claims(token: str) -> dict[str, Any]:
    """Deterministically decodes non-secret JWT header and payload claims in pure Python.

    Extracts only allowlisted non-secret header metadata (``alg``, ``kid``, ``typ``)
    and payload identity/scope claims (``sub``, ``email``, ``iss``, ``aud``,
    ``scope``, ``client_id``, ``azp``, ``hd``, ``exp``, ``iat``) while redacting
    and never returning the cryptographic signature segment or the raw JWT string.
    """
    cleaned = str(token or "").strip().strip("`'\"")
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    parts = cleaned.split(".")
    if len(parts) < 2 or not parts[0].startswith("eyJ"):
        return {
            "valid_jwt": False,
            "header": {},
            "payload": {},
            "signature_redacted": True,
        }

    raw_header = _b64url_decode_json_object(parts[0])
    raw_payload = _b64url_decode_json_object(parts[1])
    if not raw_header and not raw_payload:
        return {
            "valid_jwt": False,
            "header": {},
            "payload": {},
            "signature_redacted": True,
        }

    safe_header: dict[str, Any] = {}
    for k in _SAFE_JWT_HEADER_KEYS:
        if k in raw_header and raw_header[k] is not None:
            val = raw_header[k]
            safe_header[k] = (
                sanitize_telemetry_text(str(val))
                if isinstance(val, str)
                else val
            )

    safe_payload: dict[str, Any] = {}
    for k in _SAFE_JWT_PAYLOAD_KEYS:
        if k in raw_payload and raw_payload[k] is not None:
            val = raw_payload[k]
            if isinstance(val, str):
                safe_payload[k] = sanitize_telemetry_text(val)
            elif isinstance(val, (int, float, bool)):
                safe_payload[k] = val
            elif isinstance(val, list):
                safe_payload[k] = [
                    sanitize_telemetry_text(str(x)) for x in val[:10]
                ]

    email_candidate = ""
    for candidate_key in ("email", "service_account", "sub"):
        cand = str(safe_payload.get(candidate_key) or "").strip()
        if "@" in cand and _GENERIC_EMAIL_RE.fullmatch(cand):
            email_candidate = cand
            break

    sa_email = (
        email_candidate
        if email_candidate.endswith(".gserviceaccount.com")
        else ""
    )

    result: dict[str, Any] = {
        "valid_jwt": True,
        "header": safe_header,
        "payload": safe_payload,
        "signature_redacted": True,
        "alg": str(safe_header.get("alg") or ""),
        "kid": str(safe_header.get("kid") or ""),
        "typ": str(safe_header.get("typ") or ""),
        "sub": str(safe_payload.get("sub") or ""),
        "email": str(safe_payload.get("email") or ""),
        "iss": str(safe_payload.get("iss") or ""),
        "aud": safe_payload.get("aud") or "",
        "scope": str(safe_payload.get("scope") or safe_payload.get("scp") or ""),
        "client_id": str(
            safe_payload.get("client_id") or safe_payload.get("azp") or ""
        ),
        "exp": safe_payload.get("exp"),
        "principal_email": email_candidate,
        "service_account_email": sa_email,
    }
    return result


def _section_bounds_for_offset(plain_text: str, char_pos: int) -> tuple[int, int]:
    """Returns ``(section_start, section_end)`` bounded by Markdown ``#`` headings or converted Google Docs section headers."""
    lines = plain_text.splitlines(keepends=True)
    heading_offsets: list[int] = [0]
    cursor = 0
    converted_heading_re = re.compile(
        r"^\s*(?:#{1,6}\s+\S|(?:Scenario|Finding|Section|Phase|Part)\s+[A-Za-z0-9]+\b|\d+\.\s+[A-Z])"
    )
    for line in lines:
        if converted_heading_re.match(line):
            heading_offsets.append(cursor)
        cursor += len(line)
    heading_offsets.append(len(plain_text))
    heading_offsets = sorted(set(heading_offsets))

    sec_start = 0
    sec_end = len(plain_text)
    for idx in range(len(heading_offsets) - 1):
        h_s = heading_offsets[idx]
        h_e = heading_offsets[idx + 1]
        if h_s <= char_pos < h_e:
            sec_start, sec_end = h_s, h_e
            break
    return sec_start, sec_end


def _line_bounds_for_offset(plain_text: str, char_pos: int) -> tuple[int, int]:
    """Returns ``(line_start, line_end)`` for the line containing ``char_pos``."""
    line_start = plain_text.rfind("\n", 0, max(0, char_pos))
    line_start = 0 if line_start == -1 else line_start + 1
    line_end = plain_text.find("\n", max(0, char_pos))
    line_end = len(plain_text) if line_end == -1 else line_end
    return line_start, line_end


def _pick_closest_match(
    pattern: re.Pattern[str],
    text_slice: str,
    slice_offset: int,
    anchor_pos: int,
    *,
    group: int = 1,
    predicate: Any = None,
) -> str:
    """Returns the regex match group in ``text_slice`` closest to ``anchor_pos``."""
    best_val = ""
    best_dist: int | None = None
    for m in pattern.finditer(text_slice):
        val = str(m.group(group) or "").strip()
        if not val:
            continue
        if predicate is not None and not predicate(val):
            continue
        abs_mid = slice_offset + (m.start(group) + m.end(group)) // 2
        dist = abs(abs_mid - anchor_pos)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_val = val
    return best_val


def _is_routable_source_ip(ip_str: str) -> bool:
    """Returns True when ``ip_str`` is a valid IPv4 address excluding 0.0.0.0/127.0.0.1/169.254.169.254."""
    if ip_str in ("0.0.0.0", "127.0.0.1", "169.254.169.254", "255.255.255.255"):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return isinstance(ip_obj, ipaddress.IPv4Address) and not ip_obj.is_loopback
    except ValueError:
        return False


def _derive_project_from_sa_email(sa_email: str) -> str:
    """Derives ``projects/<project_id>`` from ``<name>@<project_id>.iam.gserviceaccount.com``."""
    m = re.search(r"@([a-z][a-z0-9-]{3,29})\.iam\.gserviceaccount\.com$", sa_email)
    if m:
        return f"projects/{m.group(1)}"
    return ""


def extract_leaked_credential_inventories(
    plain_text: str,
    index_map: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Extracts an inventory of raw and already-redacted leaked credentials from ``plain_text``.

    Scans for:
    - Unredacted cloud/API credentials (:data:`TELEMETRY_HAZARD_PATTERNS` with
      ``hazard_class == "leaked_credential"``: ``gcp_oauth_token`` ``ya29.*``,
      ``jwt_bearer_token`` ``eyJ*``, ``aws_access_key_id`` ``AKIA*``/``ASIA*``,
      and ``private_key_block``).
    - Already-redacted credential tokens (``<REDACTED_GCP_TOKEN:sha256=...>``,
      ``<REDACTED_JWT:sha256=...>``, ``<REDACTED_AWS_KEY:sha256=...>``,
      ``<REDACTED_PRIVATE_KEY:sha256=...>``).

    Correlates each credential with its surrounding line and Markdown section
    context (``principal_email``, ``service_account_email``,
    ``workspace_user_email``, ``source_ip``, ``gcp_project``,
    ``aws_key_id_masked``, decoded safe ``jwt_claims``, and the canonical
    non-destructive ``recommended_revocation_command``). Never exposes raw
    secret token strings or JWT cryptographic signatures in the returned records.
    """
    if not plain_text:
        return []

    aws_cli_spans = [
        (m.start(0), m.end(0))
        for m in _AWS_IAM_KEY_CLI_SPAN_RE.finditer(plain_text)
    ]

    raw_candidates: list[dict[str, Any]] = []
    for item in _iter_telemetry_hazard_matches(plain_text):
        if item.get("hazard_class") != "leaked_credential":
            continue
        c_start = int(item["char_start"])
        c_end = int(item["char_end"])
        if item.get("name") == "aws_access_key_id" and any(
            max(c_start, a_s) < min(c_end, a_e) for a_s, a_e in aws_cli_spans
        ):
            continue
        raw_candidates.append(
            {
                "credential_type": str(item["name"]),
                "token_label": str(item["token_label"]),
                "mitre_technique": str(item["mitre_technique"]),
                "description": str(item["description"]),
                "is_redacted": False,
                "char_start": c_start,
                "char_end": c_end,
                "raw_target": str(item["raw_target"]),
                "sha256_prefix": str(item["sha256_prefix"]),
                "redacted_token": str(item["replacement"]),
            }
        )

    for m in _REDACTED_CREDENTIAL_TOKEN_RE.finditer(plain_text):
        c_start, c_end = m.start(0), m.end(0)
        if any(max(c_start, a_s) < min(c_end, a_e) for a_s, a_e in aws_cli_spans):
            continue
        label = str(m.group(1))
        sha_prefix = str(m.group(3))
        cred_type, mitre_id, desc = _REDACTED_LABEL_TO_CREDENTIAL_TYPE[label]
        raw_candidates.append(
            {
                "credential_type": cred_type,
                "token_label": label,
                "mitre_technique": mitre_id,
                "description": desc,
                "is_redacted": True,
                "char_start": c_start,
                "char_end": c_end,
                "raw_target": "",
                "sha256_prefix": sha_prefix,
                "redacted_token": m.group(0),
            }
        )

    raw_candidates.sort(key=lambda r: int(r["char_start"]))

    inventories: list[dict[str, Any]] = []
    for cand in raw_candidates:
        c_start = int(cand["char_start"])
        c_end = int(cand["char_end"])
        if index_map and c_end - 1 < len(index_map):
            start_index = index_map[c_start]
            end_index = index_map[c_end - 1] + _utf16_code_unit_len(
                plain_text[c_end - 1]
            )
        else:
            start_index = c_start + 1
            end_index = c_end + 1

        cred_type = str(cand["credential_type"])
        is_redacted = bool(cand["is_redacted"])
        raw_target = str(cand["raw_target"])

        jwt_claims: dict[str, Any] = {}
        if cred_type == "jwt_bearer_token" and not is_redacted and raw_target:
            jwt_claims = decode_jwt_safe_claims(raw_target)

        line_s, line_e = _line_bounds_for_offset(plain_text, c_start)
        sec_s, sec_e = _section_bounds_for_offset(plain_text, c_start)
        near_s = max(sec_s, line_s - 240)
        near_e = min(sec_e, line_e + 240)

        line_slice = plain_text[line_s:line_e]
        near_slice = plain_text[near_s:near_e]
        sec_slice = plain_text[sec_s:sec_e]

        sa_email = str(jwt_claims.get("service_account_email") or "")
        if not sa_email:
            sa_email = (
                _pick_closest_match(
                    _GCP_SA_EMAIL_RE, line_slice, line_s, c_start
                )
                or _pick_closest_match(
                    _GCP_SA_EMAIL_RE, near_slice, near_s, c_start
                )
                or _pick_closest_match(
                    _GCP_SA_EMAIL_RE, sec_slice, sec_s, c_start
                )
            )

        workspace_email = ""
        jwt_principal = str(jwt_claims.get("principal_email") or "")
        if jwt_principal and not jwt_principal.endswith(".gserviceaccount.com"):
            workspace_email = jwt_principal
        if not workspace_email:
            non_sa_pred = lambda em: not em.lower().endswith(
                ".gserviceaccount.com"
            )
            workspace_email = (
                _pick_closest_match(
                    _GENERIC_EMAIL_RE,
                    line_slice,
                    line_s,
                    c_start,
                    predicate=non_sa_pred,
                )
                or _pick_closest_match(
                    _GENERIC_EMAIL_RE,
                    near_slice,
                    near_s,
                    c_start,
                    predicate=non_sa_pred,
                )
                or _pick_closest_match(
                    _GENERIC_EMAIL_RE,
                    sec_slice,
                    sec_s,
                    c_start,
                    predicate=non_sa_pred,
                )
            )

        principal_email = sa_email or workspace_email or jwt_principal

        source_ip = (
            _pick_closest_match(
                _IPV4_CANDIDATE_RE,
                line_slice,
                line_s,
                c_start,
                predicate=_is_routable_source_ip,
            )
            or _pick_closest_match(
                _IPV4_CANDIDATE_RE,
                near_slice,
                near_s,
                c_start,
                predicate=_is_routable_source_ip,
            )
            or _pick_closest_match(
                _IPV4_CANDIDATE_RE,
                sec_slice,
                sec_s,
                c_start,
                predicate=_is_routable_source_ip,
            )
        )

        proj_id = (
            _pick_closest_match(
                _GCP_PROJECT_PATH_RE, line_slice, line_s, c_start
            )
            or _pick_closest_match(
                _GCP_PROJECT_PATH_RE, near_slice, near_s, c_start
            )
            or _pick_closest_match(
                _GCP_PROJECT_PATH_RE, sec_slice, sec_s, c_start
            )
        )
        gcp_project = (
            f"projects/{proj_id}"
            if proj_id
            else _derive_project_from_sa_email(sa_email)
        )

        aws_key_id = ""
        aws_key_id_masked = ""
        if cred_type == "aws_access_key_id":
            if not is_redacted and raw_target:
                aws_key_id = raw_target
            else:
                aws_key_id = (
                    _pick_closest_match(
                        _AWS_KEY_ID_RE, line_slice, line_s, c_start
                    )
                    or _pick_closest_match(
                        _AWS_KEY_ID_RE, sec_slice, sec_s, c_start
                    )
                )
            if aws_key_id and len(aws_key_id) >= 12:
                aws_key_id_masked = f"{aws_key_id[:8]}...{aws_key_id[-4:]}"

        if cred_type == "aws_access_key_id":
            target_key_arg = aws_key_id or "<access-key-id>"
            recommended_cmd = (
                f"aws iam update-access-key --access-key-id {target_key_arg} --status Inactive"
            )
            ref_url = DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL
        elif sa_email:
            recommended_cmd = f"gcloud iam service-accounts disable {sa_email}"
            ref_url = (
                DEFAULT_GCP_SA_KEYS_DELETE_DOC_URL
                if cred_type == "private_key_block"
                else DEFAULT_GCP_SA_DISABLE_DOC_URL
            )
        elif workspace_email:
            recommended_cmd = f"gam user {workspace_email} suspend"
            ref_url = DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL
        else:
            recommended_cmd = (
                "gcloud iam service-accounts disable <service-account-email>"
            )
            ref_url = DEFAULT_GCP_SA_DISABLE_DOC_URL

        inventories.append(
            {
                "credential_type": cred_type,
                "token_label": str(cand["token_label"]),
                "mitre_technique": str(cand["mitre_technique"]),
                "description": str(cand["description"]),
                "is_redacted": is_redacted,
                "redacted_token": str(cand["redacted_token"]),
                "sha256_prefix": str(cand["sha256_prefix"]),
                "char_start": c_start,
                "char_end": c_end,
                "start_index": start_index,
                "end_index": end_index,
                "principal_email": principal_email,
                "service_account_email": sa_email,
                "workspace_user_email": workspace_email,
                "source_ip": source_ip,
                "gcp_project": gcp_project,
                "aws_key_id_masked": aws_key_id_masked,
                "jwt_claims": jwt_claims,
                "recommended_revocation_command": recommended_cmd,
                "reference_url": ref_url,
            }
        )

    return inventories


def _has_containment_command_for_credential(
    plain_text: str,
    cred: dict[str, Any],
) -> bool:
    """Returns True when ``plain_text`` already contains a revocation/containment command for ``cred``."""
    sec_s, sec_e = _section_bounds_for_offset(plain_text, int(cred["char_start"]))
    sec_text = plain_text[sec_s:sec_e]
    sa_email = str(cred.get("service_account_email") or "")
    ws_email = str(cred.get("workspace_user_email") or "")
    cred_type = str(cred.get("credential_type") or "")

    if cred_type == "aws_access_key_id":
        if re.search(
            r"\baws[ \t]+iam[ \t]+(?:update-access-key|delete-access-key)\b",
            plain_text,
        ):
            return True
        return False

    if sa_email:
        escaped_sa = re.escape(sa_email)
        if re.search(
            rf"\bgcloud[ \t]+iam[ \t]+service-accounts[ \t]+(?:disable|delete|keys[ \t]+delete)\b[^\r\n]*{escaped_sa}",
            plain_text,
        ):
            return True
        if re.search(
            rf"\bgcloud[ \t]+auth[ \t]+revoke\b[^\r\n]*{escaped_sa}",
            plain_text,
        ):
            return True
        for rev_m in _LOCAL_GCLOUD_AUTH_REVOKE_RE.finditer(sec_text):
            rev_arg = str(rev_m.group(1) or "").strip()
            if not rev_arg or rev_arg == "--all" or rev_arg == sa_email:
                return True
        return False

    if ws_email:
        escaped_ws = re.escape(ws_email)
        if re.search(
            rf"\bgam[ \t]+user[ \t]+{escaped_ws}[ \t]+(?:suspend|delete)\b",
            plain_text,
        ):
            return True
        return False

    if re.search(
        r"\bgcloud[ \t]+(?:iam[ \t]+service-accounts[ \t]+(?:disable|delete)|auth[ \t]+revoke)\b",
        sec_text,
    ):
        return True
    return False


def find_leaked_credential_containment_spans(
    plain_text: str,
    index_map: list[int],
    *,
    redact_unredacted_credentials: bool = True,
    synthesize_missing_revocation: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Detects leaked credentials and destructive/ineffective containment CLIs by 1-based UTF-16 span.

    Covers 6 deterministic defect categories:
    1. ``unredacted_leaked_credential``: Redacts raw ``ya29.*``, ``eyJ*`` JWT,
       ``AKIA*``/``ASIA*`` AWS key, and PEM private key spans to
       ``<REDACTED_...:sha256=...>``, enriching comments with decoded safe JWT
       claims (``sub``, ``email``, ``iss``, ``scope``) and principal-grounded
       emergency revocation CLI commands.
    2. ``destructive_service_account_delete``: Repairs
       ``gcloud iam service-accounts delete <sa_email>`` ->
       ``gcloud iam service-accounts disable <sa_email>``.
    3. ``local_only_gcloud_auth_revoke``: Repairs
       ``gcloud auth revoke [<account>]`` (local workstation CLI credential
       revocation) -> ``gcloud iam service-accounts disable <sa_email>``.
    4. ``destructive_workspace_user_delete``: Repairs
       ``gam user <email> delete`` -> ``gam user <email> suspend``.
    5. ``destructive_aws_access_key_delete``: Repairs
       ``aws iam delete-access-key --access-key-id <id>`` ->
       ``aws iam update-access-key --access-key-id <id> --status Inactive``.
    6. ``missing_credential_revocation_command``: When
       ``synthesize_missing_revocation=True`` and a leaked credential has no
       revocation/containment command in the document for its principal, stages
       a non-overlapping replacement appending
       ``[Emergency Revocation: `<canonical_cli_command>`]``.
    """
    if not plain_text or not index_map:
        return [], [], []

    inventories = extract_leaked_credential_inventories(plain_text, index_map)
    comments: list[dict[str, Any]] = []
    edits: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    claimed_char_spans: list[tuple[int, int]] = []

    def _to_utf16_span(c_start: int, c_end: int) -> tuple[int, int]:
        s_idx = index_map[c_start]
        e_idx = index_map[c_end - 1] + _utf16_code_unit_len(plain_text[c_end - 1])
        return s_idx, e_idx

    # 1. Credential token spans (unredacted redaction and/or missing revocation synthesis)
    for cred in inventories:
        c_start = int(cred["char_start"])
        c_end = int(cred["char_end"])
        start_index = int(cred["start_index"])
        end_index = int(cred["end_index"])
        is_redacted = bool(cred["is_redacted"])
        redacted_token = str(cred["redacted_token"])
        revocation_cmd = str(cred["recommended_revocation_command"])
        ref_url = str(cred["reference_url"])
        mitre_id = str(cred["mitre_technique"])
        mitre_url = mitre_technique_url(mitre_id)
        jwt_claims = cred.get("jwt_claims") or {}

        needs_redaction = (not is_redacted) and redact_unredacted_credentials
        needs_revocation = synthesize_missing_revocation and (
            not _has_containment_command_for_credential(plain_text, cred)
        )

        if not needs_redaction and not needs_revocation:
            continue

        claimed_char_spans.append((c_start, c_end))

        jwt_summary_parts: list[str] = []
        if isinstance(jwt_claims, dict) and jwt_claims.get("valid_jwt"):
            for claim_key in ("sub", "email", "iss", "aud", "scope", "kid"):
                claim_val = jwt_claims.get(claim_key)
                if claim_val:
                    jwt_summary_parts.append(f"{claim_key}={claim_val}")
        jwt_summary_str = (
            f" Decoded safe JWT claims (signature redacted): {', '.join(jwt_summary_parts)}."
            if jwt_summary_parts
            else ""
        )

        if needs_redaction and needs_revocation:
            replacement = (
                f"{redacted_token} [Emergency Revocation: `{revocation_cmd}`]"
            )
            defect_type = "unredacted_leaked_credential"
            comment_text = (
                f"Leaked Credential & Emergency Revocation Check ({cred['credential_type']} / "
                f"MITRE ATT&CK {mitre_id}: {mitre_url}): Unredacted {cred['description']} "
                f"detected with no corresponding containment command in document.{jwt_summary_str} "
                f"Redact secret to `{redacted_token}` (SHA-256 prefix `{cred['sha256_prefix']}`) "
                f"and stage non-destructive revocation `{revocation_cmd}` ({ref_url})."
            )
        elif needs_redaction:
            replacement = redacted_token
            defect_type = "unredacted_leaked_credential"
            comment_text = (
                f"Deterministic Telemetry & Credential Safety Check (leaked_credential / "
                f"{cred['credential_type']}): Unredacted {cred['description']} detected in "
                f"shared document.{jwt_summary_str} Redact sensitive payload/secret to "
                f"`{redacted_token}` (preserving SHA-256 prefix `{cred['sha256_prefix']}` "
                f"for forensic correlation; MITRE ATT&CK {mitre_id}: {mitre_url}). "
                f"Recommended non-destructive revocation: `{revocation_cmd}` ({ref_url})."
            )
        else:
            token_in_doc = plain_text[c_start:c_end]
            replacement = (
                f"{token_in_doc} [Emergency Revocation: `{revocation_cmd}`]"
            )
            defect_type = "missing_credential_revocation_command"
            comment_text = (
                f"Missing Emergency Credential Revocation Playbook Step "
                f"({cred['credential_type']} `{redacted_token}`): Leaked credential token is "
                f"logged in the incident timeline without a corresponding containment CLI "
                f"command for principal `{cred.get('principal_email') or 'unknown'}`. "
                f"Stage non-destructive revocation `{revocation_cmd}` ({ref_url})."
            )

        comments.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "replacement": replacement,
            }
        )
        finding_rec: dict[str, Any] = {
            "defect_type": defect_type,
            "credential_type": cred["credential_type"],
            "start_index": start_index,
            "end_index": end_index,
            "replacement": replacement,
            "recommended_revocation_command": revocation_cmd,
            "principal_email": cred.get("principal_email", ""),
            "service_account_email": cred.get("service_account_email", ""),
            "workspace_user_email": cred.get("workspace_user_email", ""),
            "source_ip": cred.get("source_ip", ""),
            "gcp_project": cred.get("gcp_project", ""),
            "jwt_claims": jwt_claims,
            "revocation_synthesized": bool(needs_revocation),
            "reference_url": ref_url,
            "rationale": comment_text,
        }
        findings.append(finding_rec)
        if needs_redaction and needs_revocation:
            findings.append(
                {
                    **finding_rec,
                    "defect_type": "missing_credential_revocation_command",
                }
            )

    # 2. Destructive GCP service account deletion: gcloud iam service-accounts delete <sa> -> disable <sa>
    for m in _DESTRUCTIVE_SA_DELETE_RE.finditer(plain_text):
        c_start, c_end = m.start(0), m.end(0)
        if any(max(c_start, cs) < min(c_end, ce) for cs, ce in claimed_char_spans):
            continue
        claimed_char_spans.append((c_start, c_end))
        sa_email = m.group(1)
        start_index, end_index = _to_utf16_span(c_start, c_end)
        replacement = f"gcloud iam service-accounts disable {sa_email}"
        comment_text = (
            f"Non-Destructive Cloud IAM Containment Repair (destructive_service_account_delete): "
            f"`{m.group(0)}` permanently deletes service account `{sa_email}` and its unique "
            f"UID, breaking dependent production workloads if the alert is a false positive. "
            f"Prefer reversible `{replacement}` during containment triage "
            f"({DEFAULT_GCP_SA_DISABLE_DOC_URL})."
        )
        comments.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "replacement": replacement,
            }
        )
        findings.append(
            {
                "defect_type": "destructive_service_account_delete",
                "original_command": m.group(0),
                "replacement": replacement,
                "principal_email": sa_email,
                "service_account_email": sa_email,
                "start_index": start_index,
                "end_index": end_index,
                "reference_url": DEFAULT_GCP_SA_DISABLE_DOC_URL,
                "rationale": comment_text,
            }
        )

    # 3. Local-only gcloud auth revoke -> gcloud iam service-accounts disable <sa>
    all_doc_sa_emails = [
        str(c["service_account_email"])
        for c in inventories
        if c.get("service_account_email")
    ]
    for m in _LOCAL_GCLOUD_AUTH_REVOKE_RE.finditer(plain_text):
        c_start, c_end = m.start(0), m.end(0)
        if any(max(c_start, cs) < min(c_end, ce) for cs, ce in claimed_char_spans):
            continue
        claimed_char_spans.append((c_start, c_end))
        arg_token = str(m.group(1) or "").strip()
        line_s, line_e = _line_bounds_for_offset(plain_text, c_start)
        sec_s, sec_e = _section_bounds_for_offset(plain_text, c_start)

        sa_email = ""
        if arg_token.endswith(".gserviceaccount.com"):
            sa_email = arg_token
        if not sa_email:
            sa_email = (
                _pick_closest_match(
                    _GCP_SA_EMAIL_RE,
                    plain_text[line_s:line_e],
                    line_s,
                    c_start,
                )
                or _pick_closest_match(
                    _GCP_SA_EMAIL_RE,
                    plain_text[sec_s:sec_e],
                    sec_s,
                    c_start,
                )
                or (all_doc_sa_emails[0] if all_doc_sa_emails else "")
                or _pick_closest_match(
                    _GCP_SA_EMAIL_RE, plain_text, 0, c_start
                )
            )
        target_sa = sa_email or "<service-account-email>"
        start_index, end_index = _to_utf16_span(c_start, c_end)
        replacement = f"gcloud iam service-accounts disable {target_sa}"
        comment_text = (
            f"Ineffective Cloud Containment Repair (local_only_gcloud_auth_revoke): "
            f"`{m.group(0)}` only revokes local gcloud CLI credentials cached on the "
            f"responder's workstation and does NOT disable the compromised cloud identity "
            f"or invalidate active bearer tokens in GCP. Use `{replacement}` to disable "
            f"the service account across Google Cloud ({DEFAULT_GCP_SA_DISABLE_DOC_URL})."
        )
        comments.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "replacement": replacement,
            }
        )
        findings.append(
            {
                "defect_type": "local_only_gcloud_auth_revoke",
                "original_command": m.group(0),
                "replacement": replacement,
                "principal_email": target_sa,
                "service_account_email": sa_email,
                "start_index": start_index,
                "end_index": end_index,
                "reference_url": DEFAULT_GCP_SA_DISABLE_DOC_URL,
                "rationale": comment_text,
            }
        )

    # 4. Destructive Workspace user deletion: gam user <email> delete -> gam user <email> suspend
    for m in _DESTRUCTIVE_GAM_USER_DELETE_RE.finditer(plain_text):
        c_start, c_end = m.start(0), m.end(0)
        if any(max(c_start, cs) < min(c_end, ce) for cs, ce in claimed_char_spans):
            continue
        claimed_char_spans.append((c_start, c_end))
        ws_email = m.group(1)
        start_index, end_index = _to_utf16_span(c_start, c_end)
        replacement = f"gam user {ws_email} suspend"
        comment_text = (
            f"Non-Destructive Workspace Containment Repair (destructive_workspace_user_delete): "
            f"`{m.group(0)}` permanently deletes Workspace user `{ws_email}`, orphaning "
            f"Google Drive files and destroying forensic audit state. Prefer reversible "
            f"`{replacement}` during incident containment ({DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL})."
        )
        comments.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "replacement": replacement,
            }
        )
        findings.append(
            {
                "defect_type": "destructive_workspace_user_delete",
                "original_command": m.group(0),
                "replacement": replacement,
                "principal_email": ws_email,
                "workspace_user_email": ws_email,
                "start_index": start_index,
                "end_index": end_index,
                "reference_url": DEFAULT_WORKSPACE_USER_SUSPEND_DOC_URL,
                "rationale": comment_text,
            }
        )

    # 5. Destructive AWS access key deletion: aws iam delete-access-key -> update-access-key --status Inactive
    for m in _DESTRUCTIVE_AWS_KEY_DELETE_RE.finditer(plain_text):
        c_start, c_end = m.start(0), m.end(0)
        if any(max(c_start, cs) < min(c_end, ce) for cs, ce in claimed_char_spans):
            continue
        claimed_char_spans.append((c_start, c_end))
        user_before = str(m.group(1) or "").strip()
        key_id_arg = str(m.group(2) or "").strip()
        user_after = str(m.group(3) or "").strip()
        user_arg = user_before or user_after
        start_index, end_index = _to_utf16_span(c_start, c_end)
        if user_arg:
            replacement = (
                f"aws iam update-access-key --access-key-id {key_id_arg} "
                f"--status Inactive --user-name {user_arg}"
            )
        else:
            replacement = (
                f"aws iam update-access-key --access-key-id {key_id_arg} --status Inactive"
            )
        comment_text = (
            f"Non-Destructive AWS IAM Containment Repair (destructive_aws_access_key_delete): "
            f"`aws iam delete-access-key` permanently destroys the IAM access key before "
            f"blast-radius triage confirms whether dependent automation requires cutover. "
            f"Prefer reversible deactivation `{replacement}` during initial containment "
            f"({DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL})."
        )
        comments.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "comment": comment_text,
            }
        )
        edits.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "replacement": replacement,
            }
        )
        findings.append(
            {
                "defect_type": "destructive_aws_access_key_delete",
                "original_command": sanitize_telemetry_text(m.group(0)),
                "replacement": replacement,
                "aws_access_key_id": key_id_arg,
                "start_index": start_index,
                "end_index": end_index,
                "reference_url": DEFAULT_AWS_ACCESS_KEY_ROTATE_DOC_URL,
                "rationale": comment_text,
            }
        )

    comments.sort(key=lambda item: int(item["start_index"]))
    edits.sort(key=lambda item: int(item["start_index"]))
    findings.sort(key=lambda item: int(item["start_index"]))
    return comments, edits, findings


def triage_leaked_credential_with_siem(
    credential_record: dict[str, Any],
    *,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 20,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Queries Chronicle SIEM (`GCP_CLOUDAUDIT`, `WORKSPACE_ACTIVITY`) to quantify the blast radius of a leaked credential.

    Builds targeted UDM queries from ``credential_record``'s correlated
    ``source_ip``, ``service_account_email`` / ``workspace_user_email`` /
    ``principal_email``, and ``gcp_project``, executes via
    :func:`verify_udm_query_with_siem`, and aggregates sanitized empirical
    ``observed_actions``, ``observed_principals``, ``observed_ips``, and
    ``target_resources``.
    """
    sa_email = str(credential_record.get("service_account_email") or "").strip()
    ws_email = str(credential_record.get("workspace_user_email") or "").strip()
    principal_email = str(
        credential_record.get("principal_email") or sa_email or ws_email
    ).strip()
    source_ip = str(credential_record.get("source_ip") or "").strip()
    gcp_project = str(credential_record.get("gcp_project") or "").strip()
    if gcp_project and not gcp_project.startswith("projects/"):
        gcp_project = f"projects/{gcp_project}"

    log_type = (
        "WORKSPACE_ACTIVITY"
        if (ws_email and not sa_email)
        else "GCP_CLOUDAUDIT"
    )

    candidate_queries: list[str] = []
    if source_ip and principal_email:
        candidate_queries.append(
            f'metadata.log_type = "{log_type}" AND principal.ip = "{source_ip}" '
            f'AND principal.user.email_addresses = "{principal_email}"'
        )
        candidate_queries.append(
            f'metadata.log_type = "{log_type}" AND principal.ip = "{source_ip}"'
        )
        candidate_queries.append(
            f'metadata.log_type = "{log_type}" AND '
            f'principal.user.email_addresses = "{principal_email}"'
        )
    elif source_ip:
        candidate_queries.append(
            f'metadata.log_type = "{log_type}" AND principal.ip = "{source_ip}"'
        )
        candidate_queries.append(f'principal.ip = "{source_ip}"')
    elif principal_email:
        candidate_queries.append(
            f'metadata.log_type = "{log_type}" AND '
            f'principal.user.email_addresses = "{principal_email}"'
        )
        if log_type == "GCP_CLOUDAUDIT":
            candidate_queries.append(
                f'metadata.log_type = "GCP_CLOUDAUDIT" AND '
                f'security_result.about.email = "{principal_email}"'
            )
    if gcp_project:
        candidate_queries.append(
            f'metadata.log_type = "GCP_CLOUDAUDIT" AND '
            f'target.resource.name = "{gcp_project}"'
        )

    if not candidate_queries:
        return {
            "status": "skipped",
            "siem_verified": False,
            "siem_query": "",
            "events_matched": 0,
            "observed_actions": [],
            "observed_principals": [],
            "observed_ips": [],
            "target_resources": [],
            "summary": (
                "[SIEM Credential Blast-Radius Triage: skipped (no correlated principal, "
                "source IP, or GCP project found in credential context)]"
            ),
        }

    chosen_res: dict[str, Any] | None = None
    chosen_query = candidate_queries[0]
    for q in candidate_queries:
        res = verify_udm_query_with_siem(
            q,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        if chosen_res is None:
            chosen_res = res
            chosen_query = q
        if res.get("status") == "success" and int(res.get("event_count", 0) or 0) > 0:
            chosen_res = res
            chosen_query = q
            break

    assert chosen_res is not None
    if chosen_res.get("status") != "success":
        err_msg = sanitize_telemetry_text(str(chosen_res.get("message") or "SIEM query failed"))
        return {
            "status": "error",
            "siem_verified": False,
            "siem_query": chosen_query,
            "events_matched": 0,
            "observed_actions": [],
            "observed_principals": [],
            "observed_ips": [],
            "target_resources": [],
            "summary": f"[SIEM Credential Blast-Radius Triage: error ({err_msg})]",
        }

    events = (
        chosen_res.get("siem_response", {}).get("events", [])
        if isinstance(chosen_res.get("siem_response"), dict)
        else []
    )
    events_matched = int(chosen_res.get("event_count", len(events)) or 0)

    observed_actions: list[str] = []
    observed_principals: list[str] = []
    observed_ips: list[str] = []
    target_resources: list[str] = []

    def _add_unique(bucket: list[str], values: list[str]) -> None:
        for val in values:
            cleaned_val = sanitize_telemetry_text(str(val).strip())
            if cleaned_val and cleaned_val not in bucket:
                bucket.append(cleaned_val)

    for ev in events if isinstance(events, list) else []:
        if not isinstance(ev, dict):
            continue
        flat = _extract_udm_event_field_values(ev)
        _add_unique(
            observed_actions,
            flat.get("metadata.product_event_type", [])
            + flat.get("security_result.action_details", [])
            + flat.get("metadata.event_type", []),
        )
        _add_unique(
            observed_principals,
            flat.get("principal.user.email_addresses", [])
            + flat.get("principal.user.userid", [])
            + flat.get("security_result.about.email", [])
            + flat.get("target.user.email_addresses", []),
        )
        _add_unique(
            observed_ips,
            flat.get("principal.ip", []) + flat.get("src.ip", []),
        )
        _add_unique(
            target_resources,
            flat.get("target.resource.name", [])
            + flat.get("target.application", []),
        )

    if events_matched > 0:
        actions_str = ", ".join(observed_actions[:5]) or "activity observed"
        principals_str = ", ".join(observed_principals[:4]) or principal_email or "n/a"
        ips_str = ", ".join(observed_ips[:3]) or source_ip or "n/a"
        targets_str = ", ".join(target_resources[:3]) or gcp_project or "n/a"
        summary = (
            f"[SIEM Credential Blast-Radius Triage: {events_matched} event(s) matched "
            f"via `{chosen_query}` | actions: {actions_str} | principals: {principals_str} "
            f"| source_ips: {ips_str} | target_resources: {targets_str}]"
        )
    else:
        summary = (
            f"[SIEM Credential Blast-Radius Triage: 0 events matched via `{chosen_query}` "
            f"in window {start_time}..{end_time}]"
        )

    return {
        "status": "success",
        "siem_verified": True,
        "siem_query": chosen_query,
        "events_matched": events_matched,
        "observed_actions": observed_actions,
        "observed_principals": observed_principals,
        "observed_ips": observed_ips,
        "target_resources": target_resources,
        "summary": sanitize_telemetry_text(summary),
    }


def triage_and_redline_leaked_credentials_in_doc(
    document_id: str,
    *,
    run_live_siem_check: bool = False,
    redact_unredacted_credentials: bool = True,
    synthesize_missing_revocation: bool = False,
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    siem_search_fn: Any = None,
    tool_context: Any = None,
    token_source: TokenSource | None = None,
    quota_project: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Triages leaked credentials in a Google Doc against Chronicle SIEM and stages non-destructive containment red-lines.

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 index map
       and ``pending_suggestion_spans``.
    2. Extracts the leaked credential inventory via
       :func:`extract_leaked_credential_inventories` (decoding safe pure-Python
       JWT header/payload claims while redacting signatures and raw secrets).
    3. Detects unredacted credentials, destructive/ineffective containment CLI
       commands, and missing emergency revocation playbook commands via
       :func:`find_leaked_credential_containment_spans`.
    4. When ``run_live_siem_check=True``, queries Chronicle SIEM
       (``GCP_CLOUDAUDIT``, ``WORKSPACE_ACTIVITY``) via
       :func:`triage_leaked_credential_with_siem` and appends
       ``[SIEM Credential Blast-Radius Triage: ...]`` badges to the anchored
       review comments.
    5. Skips any span overlapping an existing pending suggestion
       (``skipped_existing_suggestion_count``) for multi-pass idempotency.
    6. Anchors comments first (:func:`insert_doc_comments`) and stages
       Suggested Edits second (:func:`propose_doc_suggested_edits` sorted
       descending by ``startIndex`` under ``writeMode="SUGGEST"``).
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

    plain_text, index_map = _load_doc_index_state(
        document_id, tool_context=tool_context
    )
    if plain_text is None or index_map is None:
        return {
            "status": "error",
            "message": "Failed to load UTF-16 index map after read_google_doc.",
        }

    pending_spans = _load_doc_pending_suggestion_spans(
        document_id, tool_context=tool_context
    )

    credentials = extract_leaked_credential_inventories(plain_text, index_map)
    raw_comments, raw_edits, findings = find_leaked_credential_containment_spans(
        plain_text,
        index_map,
        redact_unredacted_credentials=redact_unredacted_credentials,
        synthesize_missing_revocation=synthesize_missing_revocation,
    )

    siem_triage_results: list[dict[str, Any]] = []
    if run_live_siem_check:
        siem_cache: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        span_to_badge: dict[tuple[int, int], str] = {}
        principal_to_badge: dict[str, str] = {}

        for cred in credentials:
            cache_key = (
                str(cred.get("service_account_email") or ""),
                str(cred.get("workspace_user_email") or ""),
                str(cred.get("source_ip") or ""),
                str(cred.get("gcp_project") or ""),
            )
            if cache_key not in siem_cache:
                siem_cache[cache_key] = triage_leaked_credential_with_siem(
                    cred,
                    start_time=start_time,
                    end_time=end_time,
                    siem_search_fn=siem_search_fn,
                )
            siem_res = siem_cache[cache_key]
            cred["siem_blast_radius"] = siem_res
            siem_triage_results.append(
                {
                    "credential_type": cred["credential_type"],
                    "redacted_token": cred["redacted_token"],
                    "principal_email": cred.get("principal_email", ""),
                    "source_ip": cred.get("source_ip", ""),
                    "gcp_project": cred.get("gcp_project", ""),
                    **siem_res,
                }
            )
            badge = str(siem_res.get("summary") or "")
            if badge:
                c_span = (int(cred["start_index"]), int(cred["end_index"]))
                span_to_badge[c_span] = badge
                p_email = str(cred.get("principal_email") or "")
                if p_email:
                    principal_to_badge[p_email] = badge

        for c_item, f_item in zip(raw_comments, findings):
            c_span = (int(c_item["start_index"]), int(c_item["end_index"]))
            p_email = str(f_item.get("principal_email") or "")
            badge = span_to_badge.get(c_span) or principal_to_badge.get(p_email) or ""
            if badge and badge not in c_item["comment"]:
                c_item["comment"] = f"{c_item['comment']} {badge}"
                f_item["rationale"] = c_item["comment"]

    filtered_comments: list[dict[str, Any]] = []
    for c_item in raw_comments:
        c_span = (int(c_item["start_index"]), int(c_item["end_index"]))
        if any(_spans_overlap(c_span, p_span) for p_span in pending_spans):
            continue
        filtered_comments.append(c_item)

    filtered_edits: list[dict[str, Any]] = []
    skipped_existing_suggestion_count = 0
    for e_item in raw_edits:
        e_span = (int(e_item["start_index"]), int(e_item["end_index"]))
        if any(_spans_overlap(e_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
        filtered_edits.append(e_item)

    active_findings = [
        f
        for f in findings
        if not any(
            _spans_overlap(
                (int(f["start_index"]), int(f["end_index"])), p_span
            )
            for p_span in pending_spans
        )
    ]

    comments_res: dict[str, Any] = {
        "status": "skipped",
        "inserted_count": 0,
        "comment_ids": [],
    }
    if filtered_comments:
        comments_res = insert_doc_comments(
            document_id,
            filtered_comments,
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
    if filtered_edits:
        edits_res = propose_doc_suggested_edits(
            document_id,
            filtered_edits,
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
        "credential_count": len(credentials),
        "credentials": credentials,
        "finding_count": len(active_findings),
        "findings": active_findings,
        "siem_triage_results": siem_triage_results,
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "comments": comments_res,
        "edits": edits_res,
    }
