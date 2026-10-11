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
    r"(re\.regex\(\s*\$[A-Za-z_][A-Za-z0-9_.]*\s*,\s*)/([^/\r\n]+)/(\s*nocase)?(\s*\))(\s*nocase)?",
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
    for match in _UDM_COMPARISON_RE.finditer(plain_text):
        c_start, c_end = match.start(0), match.end(0)
        if any(max(c_start, r_start) < min(c_end, r_end) for r_start, r_end in excluded_spans):
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
            kept_clauses.append(
                f"{c['canonical_field']}{c['operator_raw']}{c['rhs_raw']}"
            )
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
            out_parts.append(
                f"{c['canonical_field']}{c['operator_raw']}{c['rhs_raw']}"
            )
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

    raw_comments, raw_edits, raw_findings = find_udm_field_spans(
        plain_text, index_map, udm_doc_url=udm_doc_url
    )
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

        for re_match in _YARAL2_RE_REGEX_CALL_RE.finditer(sec_body):
            m_span = (re_match.start(), re_match.end())
            if any(_spans_overlap(m_span, c_span) for c_span in comment_spans):
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

        for cmp_match in _YARAL2_EVENT_COMPARISON_RE.finditer(sec_body):
            c_span = (cmp_match.start(), cmp_match.end())
            if any(_spans_overlap(c_span, r_span) for r_span in re_spans):
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


def extract_yaral2_multi_event_spec(
    rule_text: str,
    rule_char_start: int = 0,
    full_plain_text: str | None = None,
    index_map: list[int] | None = None,
) -> dict[str, Any]:
    """Parses multi-line and Drive-collapsed single-line YARA-L 2.0 (``YL2``) rules into
    per-event-stream UDM queries, cross-event join bindings, ``match:`` clauses, and
    ``condition:`` variable tokens with exact 1-based UTF-16 spans.
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
    condition_tokens: list[dict[str, Any]] = []
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

            for cm in _YARAL2_COND_VAR_RE.finditer(sec_body):
                c_span = (cm.start(), cm.end())
                if any(_spans_overlap(c_span, cs) for cs in comment_spans):
                    continue
                sigil = cm.group(1)
                v_name = cm.group(2)
                loc_s = b_start + cm.start(0)
                loc_e = b_start + cm.end(0)
                u_s, u_e = _to_utf16_span(loc_s, loc_e)
                condition_tokens.append(
                    {
                        "sigil": sigil,
                        "var_name": v_name,
                        "token_text": f"{sigil}{v_name}",
                        "local_start": loc_s,
                        "local_end": loc_e,
                        "start_index": u_s,
                        "end_index": u_e,
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

    return {
        "event_vars": event_vars,
        "event_var_names": event_var_names,
        "is_multi_event": len(event_vars) >= 2,
        "predicates": predicates,
        "per_event_predicates": per_event_predicates,
        "per_event_udm_queries": per_event_udm_queries,
        "join_bindings": join_bindings,
        "join_placeholders": join_placeholders,
        "match_clauses": match_clauses,
        "condition_tokens": condition_tokens,
        "condition_span": condition_span,
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


def find_yaral2_rule_spans(
    plain_text: str,
    index_map: list[int],
    *,
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Scans ``plain_text`` for single-event and multi-event YARA-L 2.0 (``YL2``) detection rules
    and computes 1-based UTF-16 spans.

    Detects deterministic YARA-L 2.0 defect classes without an LLM:
    1. Standard YARA (``strings:``) vs. Chronicle YARA-L 2.0 (``events:``) section confusion,
       explicitly distinguishing standard YARA (file/payload byte-pattern matching) from
       YARA-L 2.0 / YL2 (Chronicle SIEM UDM event detection rules).
    2. Event-variable-prefixed invalid UDM fields (``$<var>.<field_path>`` in comparisons,
       join bindings, or inside YARA-L 2.0 function calls such as ``re.regex($<var>.<field_path>, ...)``).
    3. Cross-event join semantic type contradictions (``cross_event_join_type_mismatch``) where
       two event streams bind the same join placeholder ``$<join_key>`` to incompatible UDM domains
       (e.g. ``$e1.principal.ip = $ip`` paired with ``$e2.principal.hostname = $ip``).
    4. ``match:`` section placeholder variable mismatches (``match_placeholder_mismatch``) and
       invalid ``match:`` time window syntax or verbose units (``invalid_match_window_syntax``,
       normalized to ``over <N><s|m|h|d>``).
    5. Single-event (``condition_variable_mismatch``) and multi-event
       (``multi_event_condition_mismatch``) condition variable binding errors.

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

        multi_spec = extract_yaral2_multi_event_spec(
            rule_text,
            rule_char_start=rule_char_start,
            full_plain_text=plain_text,
            index_map=index_map,
        )
        declared_event_vars: list[str] = list(multi_spec["event_var_names"])
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

        # (e) Condition event-variable checks (single-event and multi-event)
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
        elif len(declared_event_vars) >= 2:
            cond_tokens = multi_spec["condition_tokens"]
            cond_span = multi_spec["condition_span"]
            referenced_valid = {
                str(ct["var_name"])
                for ct in cond_tokens
                if str(ct["var_name"]) in declared_event_vars
            }
            missing_declared = [
                v for v in declared_event_vars if v not in referenced_valid
            ]
            undeclared_tokens = [
                ct
                for ct in cond_tokens
                if str(ct["var_name"]) not in declared_event_vars
                and str(ct["var_name"]) not in declared_placeholder_vars
            ]
            if undeclared_tokens:
                for ct in undeclared_tokens:
                    target_ev = (
                        missing_declared.pop(0)
                        if missing_declared
                        else declared_event_vars[-1]
                    )
                    sigil = str(ct["sigil"])
                    local_start = int(ct["local_start"])
                    local_end = int(ct["local_end"])
                    quote = str(ct["token_text"])
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
            elif missing_declared and cond_span is not None:
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
                    "is_multi_event": repaired_multi_spec["is_multi_event"],
                    "per_event_udm_queries": repaired_multi_spec[
                        "per_event_udm_queries"
                    ],
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


def _validate_yaral2_rule_with_compiler(
    candidate_rule_text: str,
    *,
    siem_validate_fn: Any = None,
) -> tuple[bool, str]:
    """Compiles a YARA-L 2.0 (``YL2``) rule via Chronicle's ``validate_rule`` endpoint."""
    try:
        if siem_validate_fn is not None:
            try:
                raw_val = siem_validate_fn(rule_text=candidate_rule_text)
            except TypeError:
                raw_val = siem_validate_fn(candidate_rule_text)
        else:
            from .tools import execute_mcp_tool

            raw_val = execute_mcp_tool(
                "secops-mcp_validate_rule",
                {"rule_text": candidate_rule_text},
            )
        parsed_val = _parse_siem_validate_output(raw_val)
        return bool(parsed_val["compiler_verified"]), str(
            parsed_val["compiler_output"]
        )
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
    and computes shared join-key values across correlated streams."""
    spec = extract_yaral2_multi_event_spec(rule_text)
    event_vars: list[str] = list(spec["event_vars"])
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
    shared_join_values: list[str] = []
    correlated_event_count = 0

    if join_placeholder is not None:
        ph_bindings = [
            b for b in join_bindings if str(b["placeholder_var"]) == join_placeholder
        ]
        for b in ph_bindings:
            ev = str(b["event_var"])
            c_field = str(b["canonical_field"])
            vals = per_event_field_values.get(ev, {}).get(c_field, [])
            per_event_join_values[ev] = list(vals)

        if len(ph_bindings) >= 2 and all(
            bool(per_event_join_values.get(str(b["event_var"]))) for b in ph_bindings
        ):
            first_ev = str(ph_bindings[0]["event_var"])
            first_vals = per_event_join_values.get(first_ev, [])
            other_sets = [
                {
                    v.lower()
                    for v in per_event_join_values.get(str(b["event_var"]), [])
                }
                for b in ph_bindings[1:]
            ]
            shared_join_values = [
                v for v in first_vals if all(v.lower() in s for s in other_sets)
            ]

        # If initial 20-event samples did not intersect because a broad stream hit the
        # sample pagination limit (>= sample_limit), push down candidate join values
        # from the selective stream into the truncated stream to check server-side intersection.
        sample_limit = max(max_events, 20)
        if not shared_join_values and len(ph_bindings) >= 2:
            selective_bindings = [
                b
                for b in ph_bindings
                if 1 <= len(per_event_join_values.get(str(b["event_var"]), [])) <= 5
            ]
            truncated_bindings = [
                b
                for b in ph_bindings
                if per_event_counts.get(str(b["event_var"]), 0) >= sample_limit
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
                for trunc_b in truncated_bindings:
                    trunc_ev = str(trunc_b["event_var"])
                    if trunc_ev == anchor_ev:
                        continue
                    trunc_q = per_event_queries.get(trunc_ev, "")
                    trunc_field = str(trunc_b["canonical_field"])
                    if not trunc_q or not trunc_field:
                        continue
                    for cand_val in anchor_vals[:3]:
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

                first_ev = str(ph_bindings[0]["event_var"])
                first_vals = per_event_join_values.get(first_ev, [])
                other_sets = [
                    {
                        v.lower()
                        for v in per_event_join_values.get(str(b["event_var"]), [])
                    }
                    for b in ph_bindings[1:]
                ]
                shared_join_values = [
                    v
                    for v in first_vals
                    if all(v.lower() in s for s in other_sets)
                ]

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
                            v.lower() in shared_lower for v in em.get(c_field, [])
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
        "siem_verified": siem_verified,
        "event_vars": event_vars,
        "per_event_queries": per_event_queries,
        "per_event_counts": per_event_counts,
        "per_event_join_values": per_event_join_values,
        "per_event_responses": per_event_responses,
        "per_event_field_values": per_event_field_values,
        "per_event_event_maps": per_event_event_maps,
        "join_placeholder": join_placeholder,
        "join_bindings": join_bindings,
        "shared_join_values": shared_join_values,
        "correlated_event_count": correlated_event_count,
        "summary_query": summary_query,
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
    """Diagnoses a zero-hit single-event or multi-event YARA-L 2.0 (``YL2``) detection rule
    against historical UDM telemetry and synthesizes a compiler-verified YARA-L 2.0 pivot.

    1. Repairs any static YARA-L 2.0 syntax/schema/correlation defects via
       :func:`find_yaral2_rule_spans`.
    2. For multi-event correlation rules (``is_multi_event=True``), executes per-stream UDM
       queries via :func:`_run_multi_event_siem_retrohunt`, detects
       ``cross_event_join_entity_role_swap`` when individual streams match events but share
       0 join-key values, pivots the swapped stream's join binding to the matching sibling
       entity role (e.g. ``$svc.target.hostname`` -> ``$svc.principal.hostname``), and
       verifies compilation via Chronicle's ``validate_rule`` API.
    3. For single-event rules, extracts ordered ``events:`` predicates via
       :func:`extract_yaral2_event_predicates`, invokes :func:`diagnose_zero_hit_udm_query`,
       maps ``failing_clause_index`` back to the corresponding YARA-L 2.0 predicate
       (``exact_match_on_command_line``, ``entity_role_swap``, ``value_format_mismatch``),
       and compiles ``pivoted_rule_text`` via Chronicle's ``validate_rule`` API.
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

        if initial_corr_count > 0 or not me_retro["siem_verified"]:
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

    if not retrohunt_udm_query or len(repaired_predicates) < 2:
        return {
            "status": "error" if not retrohunt_udm_query else "success",
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
    event_var = str(orig_pred["event_var"])
    recommended_field = str(
        udm_diag.get("recommended_field") or rep_pred["canonical_field"]
    )
    recommended_rhs = str(udm_diag.get("recommended_rhs") or rep_pred["rhs_raw"])
    recommended_clause = str(udm_diag.get("recommended_clause") or "")
    has_schema_defect = bool(
        orig_pred["field_token"] != orig_pred["canonical_field"]
    )

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
    udm_doc_url: str = DEFAULT_UDM_FIELD_LIST_URL,
    yaral2_doc_url: str = DEFAULT_YARAL2_DOC_URL,
) -> str:
    """Formats a grounded Google Docs review comment for a zero-hit YARA-L 2.0 (``YL2``) predicate pivot."""
    diag_class = str(
        diag_res.get("diagnosis_class")
        or diag_res.get("failure_reason")
        or "zero_hit"
    )
    failing_pred = diag_res.get("failing_predicate") or {}
    orig_pred_text = str(failing_pred.get("predicate_text") or "")
    orig_var_field = str(failing_pred.get("var_field_token") or "")
    orig_field = str(failing_pred.get("field_token") or "")
    canon_field = str(failing_pred.get("canonical_field") or "")
    event_var = str(failing_pred.get("event_var") or "$e")
    rec_field = str(diag_res.get("recommended_field") or canon_field)
    rec_pred = str(diag_res.get("recommended_yaral2_predicate") or "")
    rec_span_rep = str(diag_res.get("recommended_span_replacement") or rec_pred)
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
    if has_schema_defect:
        schema_prefix = (
            f"Deterministic YARA-L 2.0 (YL2) UDM Schema Check in rule '{rule_name}': "
            f"'{orig_var_field}' references non-canonical Chronicle UDM field '{orig_field}' "
            f"(canonical: '{event_var}.{canon_field}', {udm_doc_url}). "
        )

    if diag_class == "exact_match_on_command_line":
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
    start_time: str = "2026-02-07T00:00:00Z",
    end_time: str = "2026-02-08T00:00:00Z",
    max_events: int = 10,
    siem_validate_fn: Any = None,
    siem_search_fn: Any = None,
) -> dict[str, Any]:
    """Repairs a candidate single-event or multi-event YARA-L 2.0 (``YL2``) rule, compiles it
    via Chronicle ``validate_rule``, and dry-runs its ``events:`` predicates (or per-stream
    multi-event correlation queries) against historical Chronicle UDM telemetry.
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

        if (
            retrohunt_verified
            and retrohunt_event_count == 0
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
            max_events=max_events,
            siem_search_fn=siem_search_fn,
        )
        retrohunt_verified = bool(retrohunt_res.get("siem_verified"))
        retrohunt_event_count = int(retrohunt_res.get("event_count", 0) or 0)

        if (
            retrohunt_verified
            and retrohunt_event_count == 0
            and diagnose_zero_hit_retrohunt
            and len(retrohunt_clauses) >= 2
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
        "compiler_verified": compiler_verified,
        "compiler_output": compiler_output,
        "retrohunt_udm_query": retrohunt_udm_query,
        "retrohunt_verified": retrohunt_verified,
        "retrohunt_event_count": retrohunt_event_count,
        "retrohunt_response": retrohunt_res,
    }
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
    """Lints single-event and multi-event YARA-L 2.0 (``YL2``) rules in a Google Doc, optionally
    compiles and retrohunts them in Chronicle SIEM (including per-stream multi-event correlation,
    zero-hit predicate ablation, and cross-event join entity-role pivot red-lining), and stages
    non-destructive Suggested Edits (``writeMode="SUGGEST"``).

    1. Calls :func:`read_google_doc` to populate the 1-based UTF-16 character index map
       and ``pending_suggestion_spans``.
    2. Calls :func:`find_yaral2_rule_spans` and skips any span that overlaps an existing
       pending suggestion (guaranteeing multi-pass idempotency).
    3. When ``run_live_siem_check=True`` (or ``siem_validate_fn`` / ``siem_search_fn`` is
       provided), verifies every YARA-L 2.0 rule in the document via
       :func:`verify_yaral2_rule_with_siem` and :func:`diagnose_zero_hit_yaral2_rule`,
       upgrading combined static-schema + zero-hit value predicates in-place and staging
       compiler-verified ``writeMode="SUGGEST"`` pivots for syntactically valid zero-hit rules
       (including ``cross_event_join_entity_role_swap`` on multi-event correlation rules).
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

    static_rules_all: set[str] = set()
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
        if any(_spans_overlap(f_span, p_span) for p_span in pending_spans):
            skipped_existing_suggestion_count += 1
            continue
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
                    start_time=start_time,
                    end_time=end_time,
                    max_events=max_events,
                    siem_validate_fn=siem_validate_fn,
                    siem_search_fn=siem_search_fn,
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
                        doc_preds = extract_yaral2_event_predicates(
                            orig_rule,
                            rule_char_start=int(b_info["char_start"]),
                            full_plain_text=plain_text,
                            index_map=index_map,
                        )
                        f_pred_idx = zh_diag.get("failing_predicate_index")
                        if (
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
                                        "observed_values": zh_diag.get(
                                            "observed_values", []
                                        ),
                                    }
                                )
                                upgraded_finding_indices.add(existing_f_idx)
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
                if isinstance(me_info, dict) and me_info.get("is_multi_event"):
                    comments[idx]["comment"] = (
                        f"{comments[idx]['comment']} "
                        f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                        f"Multi-Event Retrohunt Correlation: "
                        f"shared_join_values={me_info.get('shared_join_values', [])}, "
                        f"events_matched={rule_check['retrohunt_event_count']}]"
                    )
                else:
                    comments[idx]["comment"] = (
                        f"{comments[idx]['comment']} "
                        f"[Chronicle YARA-L 2.0 Compiler Verified: PASSED | "
                        f"Retrohunt Dry-Run: query='{rule_check['retrohunt_udm_query']}', "
                        f"events_matched={rule_check['retrohunt_event_count']}]"
                    )

        if diagnose_zero_hit_retrohunt:
            for block in _iter_yaral2_rule_blocks(plain_text):
                r_name = str(block["rule_name"])
                if r_name in static_rules_all:
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
                if len(doc_preds) < 2 and not doc_multi_spec["is_multi_event"]:
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
                        comp_ok, comp_out = _validate_yaral2_rule_with_compiler(
                            normalized_rule, siem_validate_fn=siem_validate_fn
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
                                "compiler_verified": comp_ok,
                                "compiler_output": comp_out,
                                "retrohunt_udm_query": str(
                                    initial_me.get("summary_query") or ""
                                ),
                                "retrohunt_verified": True,
                                "retrohunt_event_count": initial_hits,
                                "retrohunt_response": initial_me,
                                "multi_event_retrohunt": initial_me,
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
                        max_events=max_events,
                        siem_search_fn=siem_search_fn,
                    )
                    if not initial_siem.get("siem_verified"):
                        continue
                    initial_hits = int(initial_siem.get("event_count", 0) or 0)
                    if initial_hits > 0:
                        comp_ok, comp_out = _validate_yaral2_rule_with_compiler(
                            normalized_rule, siem_validate_fn=siem_validate_fn
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
                            }
                        )
                        continue

                if any(
                    _spans_overlap(rule_span, p_span) for p_span in pending_spans
                ):
                    skipped_existing_suggestion_count += 1
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
                    continue

                zero_hit_yaral2_diagnoses.append(zh_diag)
                span_target = str(
                    zh_diag.get("recommended_span_target") or "predicate"
                )

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
        "zero_hit_yaral2_findings_count": zero_hit_yaral2_findings_count,
        "skipped_existing_suggestion_count": skipped_existing_suggestion_count,
        "findings": findings,
        "siem_rule_checks": siem_rule_checks,
        "zero_hit_yaral2_diagnoses": zero_hit_yaral2_diagnoses,
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
    2. Runs Stage A (:func:`find_telemetry_hazard_spans` when
       ``include_telemetry_hazard_stage_a=True``,
       :func:`find_deterministic_indicator_spans`,
       :func:`find_udm_field_spans` when ``include_udm_stage_a=True``,
       :func:`find_yaral2_rule_spans` when ``include_yaral2_stage_a=True``, and
       :func:`find_mitre_and_cve_spans` when ``include_mitre_cve_stage_a=True``)
       to locate unredacted telemetry payloads/secrets, live untrusted URLs,
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
        deduped_telemetry_comments
        + stage_a_comments
        + deduped_udm_comments
        + deduped_yaral2_comments
        + deduped_mitre_cve_comments
        + stage_b_comments
    )
    raw_all_edits = (
        deduped_telemetry_edits
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
        "stage_a_telemetry_hazard_count": stage_a_telemetry_hazard_count,
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
        "stage_a_telemetry_hazard_count": review_res.get("stage_a_telemetry_hazard_count", 0),
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


