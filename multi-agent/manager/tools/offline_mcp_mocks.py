"""Offline-resilient MCPToolset and canonical SIEM/SOAR/GTI FunctionTool specs."""

import inspect
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams

from .logstory_corpus import get_logstory_corpus
from .mcp_registry import (
    MCPToolMetadata,
    MCPToolRegistry,
    _extract_schema_from_callable,
)

logger = logging.getLogger(__name__)


class OfflineResilientMCPToolset(MCPToolset):
    """MCPToolset that uses offline FunctionTool declarations in test/offline environments.

    When `.env` is present in live execution, connects to the real MCP server.
    If `ADK_STRICT_MCP_CONNECT=1` is set, connection failures raise immediately;
    otherwise a warning is logged before falling back to local declarations.
    """

    def __init__(
        self,
        *,
        connection_params: StdioConnectionParams,
        tool_name_prefix: Optional[str] = None,
        env_file_path: Optional[Path] = None,
        offline_tools: Optional[list[BaseTool]] = None,
    ):
        super().__init__(
            connection_params=connection_params,
            tool_name_prefix=tool_name_prefix,
        )
        self._env_file_path = env_file_path
        self._offline_tools = list(offline_tools or [])

    async def get_tools(self, readonly_context: Any = None) -> list[BaseTool]:
        if (
            os.environ.get("PYTEST_CURRENT_TEST")
            or os.environ.get("ADK_OFFLINE_MCP_MOCKS") == "1"
            or (self._env_file_path is not None and not self._env_file_path.exists())
        ):
            return list(self._offline_tools)
        try:
            return await super().get_tools(readonly_context)
        except Exception as exc:
            if os.environ.get("ADK_STRICT_MCP_CONNECT") == "1":
                raise
            logger.warning(
                "MCP server connection failed for prefix=%s (%s: %s); falling back to offline tool declarations.",
                self.tool_name_prefix,
                type(exc).__name__,
                exc,
            )
            return list(self._offline_tools)


_URSNIF_COLLECTION_IDS = {
    "alienvault_63bbee81b55c8ba00724605a",
    "report--22-00022539",
    "report--252e33f9227d94e22ed03f78164d44ffb9af07b8ca3288d7cd057b53e1859404",
}

_URSNIF_C2_DOMAINS = {
    "superstarts.top",
    "superliner.top",
    "internetlined.com",
    "superlinez.top",
    "denterdrigx.com",
    "internetlines.in",
}

_URSNIF_Payload_SHA256 = "dfdfd0a339fe03549b2475811b106866d035954e9bc002f20b0f69e0f986838f"
_URSNIF_DLL_SHA256 = "8e570e32acb99abfd0daf62cff13a09eb694ebfa633a365d224aefc6449f97de"
_LOLBIN_RUNDLL32_SHA256 = "7d99c80a1249a1ec9af0f3047c855778b06ea57e11943a271071985afe09e6c2"
_BENIGN_NGINX_SHA256 = "38ffd143fb97ef7ce2fbbe39cbbe8ed1ebdc41eb53b2c68f20cb2be6381eb38e"

_URSNIF_UDM_EVENTS = [
    {
        "event_timestamp": "5_days_ago_120h",
        "metadata": {"event_type": "NETWORK_DNS"},
        "principal": {
            "hostname": "malwaretest-win",
            "ip": "10.128.0.2",
            "user": {"userid": "sandbox_user"},
        },
        "network": {"dns": {"questions": [{"name": "superstarts.top"}]}},
        "target": {"hostname": "superstarts.top", "ip": "193.106.191.163"},
        "summary": (
            "27 DNS queries from malwaretest-win (10.128.0.2) to Ursnif C2 domain "
            "superstarts.top resolving to 193.106.191.163 (correlated with CASE-2396)."
        ),
    },
    {
        "event_timestamp": "5_days_ago_120h",
        "metadata": {"event_type": "PROCESS_LAUNCH"},
        "principal": {
            "hostname": "malwaretest-win",
            "ip": "10.128.0.2",
            "user": {"userid": "sandbox_user"},
        },
        "target": {
            "process": {
                "command_line": (
                    "C:\\Windows\\System32\\wscript.exe //B "
                    "C:\\Users\\Public\\gift_unwrap.js hello cexe lldnur revreSretsigeRllD"
                ),
                "file": {"sha256": _URSNIF_Payload_SHA256},
            }
        },
        "summary": (
            "JScript dropper wscript.exe launched with reversed rundll32 "
            "DllRegisterServer string on malwaretest-win."
        ),
    },
    {
        "event_timestamp": "5_days_ago_120h",
        "metadata": {"event_type": "PROCESS_MODULE_LOAD"},
        "principal": {
            "hostname": "malwaretest-win",
            "ip": "10.128.0.2",
            "process": {
                "file": {
                    "full_path": "C:\\Users\\Public\\123.com",
                    "sha256": _LOLBIN_RUNDLL32_SHA256,
                    "note": "Renamed Microsoft-signed Windows rundll32.exe LOLBin",
                }
            },
        },
        "target": {
            "process": {
                "command_line": "C:\\Users\\Public\\123.com C:\\ProgramData\\itsIt.db,DllRegisterServer"
            },
            "file": {
                "full_path": "C:\\ProgramData\\itsIt.db",
                "sha256": _URSNIF_DLL_SHA256,
                "note": "Malicious Ursnif DLL payload loaded by rundll32.exe",
            },
        },
        "summary": (
            "Signed LOLBin 123.com (rundll32.exe, 7d99c80a...) loaded malicious "
            "Ursnif DLL C:\\ProgramData\\itsIt.db (8e570e32...) on malwaretest-win."
        ),
    },
]

_URSNIF_SOAR_CASE = {
    "case_id": "CASE-2396",
    "title": "Low-Priority Telemetry Note: Reversed String Script Execution on malwaretest-win",
    "priority": "MEDIUM",
    "stage": "TRIAGE",
    "status": "OPEN",
    "alerts_count": 0,
    "hostname": "malwaretest-win",
    "indicators": ["superstarts.top"],
    "comments": [
        (
            "5 days ago (120h lookback): Uncorrelated script execution observed on "
            "host malwaretest-win (10.128.0.2) running wscript.exe with reversed "
            "arguments 'hello cexe lldnur revreSretsigeRllD' and outbound DNS "
            "queries to superstarts.top. Zero SIEM alerts fired (detection gap)."
        )
    ],
}


def _is_ursnif_collection(collection_id: str) -> bool:
    cid = str(collection_id or "").strip().lower()
    return cid in _URSNIF_COLLECTION_IDS or "ursnif" in cid or "63bbee81b55c8ba00724605a" in cid


def _is_ursnif_query(text: str) -> bool:
    q = str(text or "").lower()
    tokens = (
        "superstarts.top",
        "superliner.top",
        "internetlined.com",
        "193.106.191.163",
        "malwaretest-win",
        "8e570e32",
        "7d99c80a",
        "dfdfd0a3",
        "itsit.db",
        "123.com",
        "revresretsigerlld",
        "ursnif",
        "63bbee81b55c8ba00724605a",
    )
    return any(tok in q for tok in tokens)


def _mock_search_security_events(
    text: str = "",
    query: str = "",
    hours_back: int = 168,
    max_events: int = 50,
) -> dict[str, Any]:
    effective_query = query or text
    try:
        hb = int(hours_back)
    except (TypeError, ValueError):
        hb = 168
    if _is_ursnif_query(effective_query):
        if hb < 168:
            return {
                "status": "success",
                "server": "siem",
                "query": effective_query,
                "hours_back": hb,
                "events_matched": 0,
                "events": [],
                "hint": (
                    f"0 events returned over hours_back={hb}. Historical campaign "
                    "telemetry may precede 72h; widen hours_back to 168 (7 days)."
                ),
            }
        return {
            "status": "success",
            "server": "siem",
            "query": effective_query,
            "hours_back": hb,
            "events_matched": len(_URSNIF_UDM_EVENTS),
            "events": list(_URSNIF_UDM_EVENTS)[: int(max_events or 50)],
        }

    corpus = get_logstory_corpus()
    if corpus.get_active_usecase_ids() is not None or corpus.has_corpus_match(effective_query):
        events = corpus.search_events(
            query=effective_query,
            hours_back=hb,
            max_events=int(max_events or 50),
        )
        return {
            "status": "success",
            "server": "siem",
            "query": effective_query,
            "hours_back": hb,
            "events_matched": len(events),
            "events": events,
        }

    return {
        "status": "success",
        "server": "siem",
        "events_matched": 1,
        "query": effective_query,
    }


def _mock_lookup_entity(
    entity_value: str = "",
    hours_back: int = 168,
) -> dict[str, Any]:
    val = str(entity_value or "").strip()
    val_lower = val.lower()
    try:
        hb = int(hours_back)
    except (TypeError, ValueError):
        hb = 168
    if val_lower in ("malwaretest-win", "10.128.0.2"):
        return {
            "status": "success",
            "server": "siem",
            "entity_value": val,
            "hostname": "malwaretest-win",
            "ip": "10.128.0.2",
            "os": "Windows 10 Enterprise LTSC",
            "criticality_tier": "HIGH",
            "active_user": "sandbox_user",
            "change_records": [],
            "related_soar_cases": ["CASE-2396"],
            "summary": (
                "Host malwaretest-win (10.128.0.2) executed wscript.exe -> renamed "
                "signed rundll32.exe (123.com, 7d99c80a...) -> itsIt.db (8e570e32...) "
                "and queried superstarts.top 120h ago. No authorized CHG-... maintenance."
            ),
        }
    if _is_ursnif_query(val_lower):
        if hb < 168:
            return {
                "status": "success",
                "server": "siem",
                "entity_value": val,
                "hours_back": hb,
                "events_matched": 0,
                "summary": (
                    f"0 SIEM hits for {val} in {hb}h window. Widen hours_back to 168 (7 days)."
                ),
            }
        return {
            "status": "success",
            "server": "siem",
            "entity_value": val,
            "hours_back": hb,
            "events_matched": 3,
            "involved_hosts": ["malwaretest-win"],
            "related_soar_cases": ["CASE-2396"],
            "summary": (
                f"Entity {val} observed on host malwaretest-win (10.128.0.2) 120h ago "
                "in DNS/PROCESS_LAUNCH/PROCESS_MODULE_LOAD telemetry (correlated with CASE-2396)."
            ),
        }

    corpus_ent = get_logstory_corpus().lookup_entity(val)
    if corpus_ent is not None:
        return corpus_ent

    return {
        "status": "success",
        "server": "siem",
        "entity_value": entity_value,
        "summary": f"Entity {entity_value} inspected in Chronicle SIEM.",
    }


def _mock_get_security_alerts(
    query: str = "",
    hours_back: int = 168,
    max_alerts: int = 25,
) -> dict[str, Any]:
    if _is_ursnif_query(query):
        return {
            "status": "success",
            "server": "siem",
            "query": query,
            "hours_back": hours_back,
            "alerts": [],
            "note": (
                "0 SIEM detection alerts fired on malwaretest-win. Activity was only "
                "logged as an unalerted telemetry note in SOAR CASE-2396 (detection gap)."
            ),
        }
    corpus = get_logstory_corpus()
    if corpus.get_active_usecase_ids() is not None or corpus.has_corpus_match(query):
        findings = corpus.list_scc_findings(query=query)[: int(max_alerts or 25)]
        return {
            "status": "success",
            "server": "siem",
            "query": query,
            "hours_back": hours_back,
            "alerts": findings,
        }
    return {
        "status": "success",
        "server": "siem",
        "alerts": [],
    }


def _mock_get_ioc_matches(
    hours_back: int = 72,
    max_matches: int = 25,
) -> dict[str, Any]:
    try:
        hb = int(hours_back)
    except (TypeError, ValueError):
        hb = 72
    corpus = get_logstory_corpus()
    active_ids = corpus.get_active_usecase_ids()
    if active_ids is not None:
        matches: list[dict[str, Any]] = []
        for uid in sorted(active_ids):
            uc = corpus.usecases.get(uid)
            if not uc or uc.is_baseline:
                continue
            for ev in uc.events:
                if ev.domain:
                    matches.append(
                        {
                            "ioc_value": ev.domain,
                            "ioc_type": "DOMAIN",
                            "hostname": ev.hostname,
                            "ip": ev.src_ip,
                            "event_timestamp": ev.timestamp,
                            "usecase_id": uid,
                        }
                    )
                if ev.file_sha256:
                    matches.append(
                        {
                            "ioc_value": ev.file_sha256,
                            "ioc_type": "FILE_SHA256",
                            "hostname": ev.hostname,
                            "ip": ev.src_ip,
                            "event_timestamp": ev.timestamp,
                            "usecase_id": uid,
                        }
                    )
        deduped: list[dict[str, Any]] = []
        seen_vals: set[str] = set()
        for m in matches:
            k = f"{m['ioc_type']}:{m['ioc_value']}"
            if k not in seen_vals:
                seen_vals.add(k)
                deduped.append(m)
        return {
            "status": "success",
            "server": "siem",
            "hours_back": hb,
            "total_matches": len(deduped),
            "ioc_matches": deduped[: int(max_matches or 25)],
        }
    if hb >= 168:
        matches = [
            {
                "ioc_value": "superstarts.top",
                "ioc_type": "DOMAIN",
                "hostname": "malwaretest-win",
                "ip": "10.128.0.2",
                "event_timestamp": "5_days_ago_120h",
                "event_type": "NETWORK_DNS",
                "related_case_id": "CASE-2396",
            },
            {
                "ioc_value": _URSNIF_Payload_SHA256,
                "ioc_type": "FILE_SHA256",
                "hostname": "malwaretest-win",
                "ip": "10.128.0.2",
                "event_timestamp": "5_days_ago_120h",
                "event_type": "PROCESS_LAUNCH",
                "related_case_id": "CASE-2396",
            },
        ]
        return {
            "status": "success",
            "server": "siem",
            "hours_back": hb,
            "total_matches": len(matches),
            "ioc_matches": matches[: int(max_matches or 25)],
        }
    return {
        "status": "success",
        "server": "siem",
        "hours_back": hb,
        "total_matches": 0,
        "ioc_matches": [],
        "hint": (
            f"Zero automated IOC matches in {hb}h. Widen hours_back to 168 (7 days) "
            "and search DNS, network, and PROCESS_MODULE_LOAD."
        ),
    }


def _mock_get_case_full_details(case_id: str = "") -> dict[str, Any]:
    cid = str(case_id or "").strip().upper()
    if cid in ("CASE-2396", "2396"):
        return {
            "status": "success",
            "server": "soar",
            **_URSNIF_SOAR_CASE,
        }
    corpus = get_logstory_corpus()
    if cid in corpus.usecases:
        built = corpus.build_soar_case(cid)
        if built:
            return {"status": "success", "server": "soar", **built}
    if cid.startswith("CASE-40"):
        try:
            idx = int(cid.split("-")[1]) - 4000
            keys = sorted(corpus.usecases.keys())
            if 0 <= idx < len(keys):
                built = corpus.build_soar_case(keys[idx])
                if built:
                    return {"status": "success", "server": "soar", **built}
        except ValueError:
            pass
    active_ids = corpus.get_active_usecase_ids()
    if active_ids:
        for uid in sorted(active_ids):
            uc = corpus.usecases.get(uid)
            if uc and not uc.is_baseline:
                built = corpus.build_soar_case(uid)
                if built:
                    return {"status": "success", "server": "soar", **built}
    return {
        "status": "success",
        "server": "soar",
        "case_id": case_id,
    }


def _mock_list_cases(limit: int = 25) -> dict[str, Any]:
    cases = [dict(_URSNIF_SOAR_CASE)]
    corpus = get_logstory_corpus()
    active_ids = corpus.get_active_usecase_ids()
    if active_ids:
        for uid in sorted(active_ids):
            built = corpus.build_soar_case(uid)
            if built:
                cases.append(built)
    return {
        "status": "success",
        "server": "soar",
        "cases": cases[: int(limit or 25)],
    }


def _mock_get_ip_address_report(ip_address: str = "") -> dict[str, Any]:
    ip = str(ip_address or "").strip()
    if ip == "193.106.191.163":
        return {
            "status": "success",
            "server": "gti",
            "ip_address": ip,
            "verdict": "malicious",
            "threat_family": "Ursnif / Gozi",
            "asn": "AS49505 (Selectel / Bulletproof Hosting)",
            "vt_positives": 62,
            "vt_total": 72,
            "reverse_dns": "superstarts.top",
        }
    corpus_rep = get_logstory_corpus().get_gti_indicator_report(ip, "IP")
    if corpus_rep is not None:
        return corpus_rep
    return {
        "status": "success",
        "server": "gti",
        "ip_address": ip_address,
        "verdict": "clean",
    }


def _mock_get_domain_report(domain: str = "") -> dict[str, Any]:
    dom = str(domain or "").strip().lower()
    if dom in _URSNIF_C2_DOMAINS:
        return {
            "status": "success",
            "server": "gti",
            "domain": dom,
            "verdict": "malicious",
            "category": "Command and Control (Ursnif / Gozi)",
            "threat_family": "Ursnif / Gozi IAP 2.0",
            "vt_positives": 64,
            "vt_total": 72,
            "resolutions": ["193.106.191.163"],
        }
    corpus_rep = get_logstory_corpus().get_gti_indicator_report(dom, "DOMAIN")
    if corpus_rep is not None:
        return corpus_rep
    return {
        "status": "success",
        "server": "gti",
        "domain": domain,
        "verdict": "clean",
    }


def _mock_get_file_report(hash: str = "", file_hash: str = "") -> dict[str, Any]:
    h = str(hash or file_hash or "").strip().lower()
    if h == _LOLBIN_RUNDLL32_SHA256:
        return {
            "status": "success",
            "server": "gti",
            "hash": h,
            "verdict": "benign",
            "filename": "123.com (Microsoft Windows rundll32.exe LOLBin)",
            "cert_status": "VALID_CERTIFICATE",
            "signer": "Microsoft Windows Production PCA",
            "vendor": "Microsoft Corporation",
            "threat_name": "None (Legitimate Signed Windows System Binary / LOLBin)",
            "vt_positives": 0,
            "vt_total": 72,
            "note": (
                "Legitimate Microsoft-signed Windows system binary (rundll32.exe LOLBin). "
                "Do NOT block this hash."
            ),
        }
    if h == _BENIGN_NGINX_SHA256:
        return {
            "status": "success",
            "server": "gti",
            "hash": h,
            "verdict": "benign",
            "filename": "index.html (Default Nginx welcome page)",
            "cert_status": "NONE",
            "vendor": "Nginx Inc.",
            "vt_positives": 0,
            "vt_total": 72,
            "note": "Benign default Nginx web server HTML page; do not block.",
        }
    if h == _URSNIF_DLL_SHA256:
        return {
            "status": "success",
            "server": "gti",
            "hash": h,
            "verdict": "malicious",
            "filename": "itsIt.db",
            "cert_status": "UNSIGNED",
            "threat_name": "TrojanSpy.Win32.Ursnif.DLL",
            "vt_positives": 51,
            "vt_total": 72,
        }
    if h == _URSNIF_Payload_SHA256:
        return {
            "status": "success",
            "server": "gti",
            "hash": h,
            "verdict": "malicious",
            "filename": "ursnif_stage1_loader.bin",
            "cert_status": "UNSIGNED",
            "threat_name": "Trojan.Win32.Ursnif.IAP",
            "vt_positives": 59,
            "vt_total": 72,
        }
    corpus_rep = get_logstory_corpus().get_gti_indicator_report(h, "FILE_SHA256")
    if corpus_rep is not None:
        return corpus_rep
    return {
        "status": "success",
        "server": "gti",
        "hash": hash or file_hash,
        "verdict": "malicious",
    }


def _mock_list_security_rules(query: str = "") -> dict[str, Any]:
    rules = get_logstory_corpus().list_rules(query=query)
    return {
        "status": "success",
        "server": "siem",
        "query": query,
        "rules_count": len(rules),
        "rules": rules[:50],
    }


def _mock_get_detection_rule(rule_id: str = "") -> dict[str, Any]:
    rule = get_logstory_corpus().get_rule(rule_id=rule_id)
    if rule is not None:
        return rule
    return {
        "status": "success",
        "server": "siem",
        "rule_id": rule_id,
    }


def _mock_validate_yaral2_rule(rule_text: str = "") -> dict[str, Any]:
    return get_logstory_corpus().validate_yaral2_rule(rule_text=rule_text)


def _mock_list_scc_findings(
    query: str = "",
    category: str = "",
    max_findings: int = 25,
) -> dict[str, Any]:
    findings = get_logstory_corpus().list_scc_findings(query=query, category=category)
    return {
        "status": "success",
        "server": "scc",
        "query": query,
        "category": category,
        "total_findings": len(findings),
        "findings": findings[: int(max_findings or 25)],
    }


def _mock_get_scc_finding(finding_id: str = "", category: str = "") -> dict[str, Any]:
    findings = get_logstory_corpus().list_scc_findings(query=finding_id, category=category)
    if findings:
        return {
            "status": "success",
            "server": "scc",
            "finding": findings[0],
        }
    return {
        "status": "not_found",
        "server": "scc",
        "finding_id": finding_id,
    }


def _mock_lookup_cloud_iam_principal(principal_email: str = "") -> dict[str, Any]:
    res = get_logstory_corpus().lookup_cloud_iam_principal(principal_email=principal_email)
    if res is not None:
        return res
    return {
        "status": "not_found",
        "server": "scc",
        "principal_email": principal_email,
    }


def _mock_get_collection_report(collection_id: str = "", id: str = "") -> dict[str, Any]:
    cid = str(collection_id or id or "").strip()
    if _is_ursnif_collection(cid):
        return {
            "status": "success",
            "server": "gti",
            "collection_id": cid,
            "name": "Unwrapping Ursnifs Gifts",
            "collection_type": "collection",
            "threat_family": "Ursnif / Gozi (IAP 2.0)",
            "summary": (
                "Ursnif (Gozi) banking trojan and initial access campaign using "
                "JScript droppers (wscript.exe) with reversed command-line arguments "
                "('hello cexe lldnur revreSretsigeRllD') to invoke signed Windows "
                "rundll32.exe LOLBins that load malicious Ursnif DLL payloads (itsIt.db) "
                "and beacon to .top/.com/.in C2 domains."
            ),
            "attack_techniques": [
                "T1218.011 - System Binary Proxy Execution: Rundll32",
                "T1059.007 - Command and Scripting Interpreter: JavaScript/JScript (wscript.exe)",
                "T1071.001 - Application Layer Protocol: Web/DNS C2",
            ],
            "indicator_counts": {
                "domains": 6,
                "files": 2,
                "ip_addresses": 1,
            },
        }
    return {
        "status": "success",
        "server": "gti",
        "collection_id": cid,
    }


def _mock_get_entities_related_to_a_collection(
    collection_id: str = "",
    relationship_name: str = "all",
    id: str = "",
) -> dict[str, Any]:
    cid = str(collection_id or id or "").strip()
    rel = str(relationship_name or "all").strip().lower()
    if _is_ursnif_collection(cid):
        domains = sorted(_URSNIF_C2_DOMAINS)
        files = [
            {
                "sha256": _URSNIF_Payload_SHA256,
                "filename": "ursnif_stage1_loader.bin",
                "note": "Primary campaign file indicator; verify with get_file_report.",
            },
            {
                "sha256": _LOLBIN_RUNDLL32_SHA256,
                "filename": "123.com (rundll32.exe)",
                "note": (
                    "Associated execution binary; MUST verify with get_file_report "
                    "to check if signed OS LOLBin before blocking."
                ),
            },
        ]
        ips = ["193.106.191.163"]
        techniques = ["T1218.011", "T1059.007", "T1071.001"]
        if rel == "domains":
            return {
                "status": "success",
                "server": "gti",
                "collection_id": cid,
                "relationship_name": rel,
                "entities": domains,
            }
        if rel == "files":
            return {
                "status": "success",
                "server": "gti",
                "collection_id": cid,
                "relationship_name": rel,
                "entities": files,
            }
        if rel in ("ip_addresses", "ips"):
            return {
                "status": "success",
                "server": "gti",
                "collection_id": cid,
                "relationship_name": rel,
                "entities": ips,
            }
        return {
            "status": "success",
            "server": "gti",
            "collection_id": cid,
            "relationship_name": rel or "all",
            "domains": domains,
            "files": files,
            "ip_addresses": ips,
            "attack_techniques": techniques,
            "entities": domains + ips + [f["sha256"] for f in files],
        }
    return {
        "status": "success",
        "server": "gti",
        "collection_id": cid,
        "entities": [],
    }


def _mock_get_entities_related_to_a_domain(
    domain: str = "",
    relationship_name: str = "communicating_files",
) -> dict[str, Any]:
    dom = str(domain or "").strip().lower()
    rel = str(relationship_name or "communicating_files").strip().lower()
    if dom in _URSNIF_C2_DOMAINS:
        if rel in ("resolutions", "ip_addresses"):
            return {
                "status": "success",
                "server": "gti",
                "domain": dom,
                "relationship_name": rel,
                "entities": ["193.106.191.163"],
            }
        files = [
            {
                "sha256": _URSNIF_DLL_SHA256,
                "filename": "itsIt.db",
                "file_type": "PE32 DLL (Ursnif Module)",
                "vt_positives": 51,
                "vt_total": 72,
                "note": (
                    "Second-hop DLL payload communicating with superstarts.top; "
                    "verify with get_file_report and search PROCESS_MODULE_LOAD."
                ),
            },
            {
                "sha256": _BENIGN_NGINX_SHA256,
                "filename": "index.html",
                "file_type": "HTML document (Default Nginx welcome page)",
                "vt_positives": 0,
                "vt_total": 72,
                "note": "Benign default Nginx web server HTML page; do not block.",
            },
        ]
        return {
            "status": "success",
            "server": "gti",
            "domain": dom,
            "relationship_name": rel,
            "communicating_files": files,
            "entities": files,
        }
    return {
        "status": "success",
        "server": "gti",
        "domain": domain,
        "entities": [],
    }


def build_canonical_mcp_tools(
    server: str,
    registry: MCPToolRegistry,
) -> list[BaseTool]:
    """Build lightweight FunctionTool representations of canonical SIEM, SOAR, and GTI MCP tools."""
    specs: dict[str, list[tuple[str, str, Callable[..., Any]]]] = {
        "siem": [
            (
                "search_security_events",
                "Search Chronicle SIEM UDM security events using natural language or UDM filter.",
                _mock_search_security_events,
            ),
            (
                "lookup_entity",
                "Look up an IP, domain, hash, or user entity in Chronicle SIEM.",
                _mock_lookup_entity,
            ),
            (
                "get_security_alerts",
                "Retrieve security alerts from Chronicle SIEM.",
                _mock_get_security_alerts,
            ),
            (
                "get_ioc_matches",
                "Fetch IOC matches from Chronicle SIEM.",
                _mock_get_ioc_matches,
            ),
            (
                "list_security_rules",
                "List YARA-L detection rules in Chronicle SIEM.",
                _mock_list_security_rules,
            ),
            (
                "get_detection_rule",
                "Retrieve a specific YARA-L detection rule by rule_id.",
                _mock_get_detection_rule,
            ),
            (
                "validate_yaral2_rule",
                "Validate YARA-L 2.0 detection rule syntax and Chronicle UDM field bindings.",
                _mock_validate_yaral2_rule,
            ),
            (
                "get_threat_intel",
                "Query SecOps threat intelligence context.",
                lambda query="": {
                    "status": "success",
                    "server": "siem",
                    "summary": f"Threat intel summary for {query}",
                },
            ),
        ],
        "scc": [
            (
                "list_scc_findings",
                "List Google Cloud Security Command Center (SCC) threat and vulnerability findings.",
                _mock_list_scc_findings,
            ),
            (
                "get_scc_finding",
                "Retrieve details for a specific Security Command Center (SCC) finding.",
                _mock_get_scc_finding,
            ),
            (
                "lookup_cloud_iam_principal",
                "Look up Cloud IAM roles, groups, and service account context for a principal.",
                _mock_lookup_cloud_iam_principal,
            ),
        ],
        "soar": [
            (
                "get_case_full_details",
                "Retrieve full details for a SOAR case including alerts and insights.",
                _mock_get_case_full_details,
            ),
            (
                "post_case_comment",
                "Post an investigative comment to a SOAR case wall.",
                lambda case_id="", comment="": {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "comment": comment,
                },
            ),
            (
                "update_case_comment",
                "Update or append an investigative comment on a SOAR case.",
                lambda case_id="", comment="": {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "comment": comment,
                },
            ),
            (
                "list_cases",
                "List active SOAR cases.",
                _mock_list_cases,
            ),
            (
                "isolate_host",
                "Isolate a compromised endpoint host via SOAR/EDR containment.",
                lambda hostname="", endpoint_id="", reason="", case_id="": {
                    "status": "success",
                    "server": "soar",
                    "action": "isolate_host",
                    "hostname": hostname or endpoint_id,
                    "isolated": True,
                    "reason": reason,
                    "case_id": case_id,
                },
            ),
            (
                "isolate_endpoint",
                "Isolate an endpoint host by hostname or endpoint_id.",
                lambda endpoint_id="", hostname="", confirm_isolation=True, case_id="": {
                    "status": "success",
                    "server": "soar",
                    "action": "isolate_endpoint",
                    "endpoint_id": endpoint_id or hostname,
                    "isolated": bool(confirm_isolation),
                    "case_id": case_id,
                },
            ),
            (
                "block_indicator",
                "Block a confirmed malicious domain, IP, or file hash indicator via SOAR.",
                lambda indicator_value="", indicator_type="", case_id="": {
                    "status": "success",
                    "server": "soar",
                    "action": "block_indicator",
                    "indicator_value": indicator_value,
                    "indicator_type": indicator_type,
                    "blocked": True,
                    "case_id": case_id,
                },
            ),
            (
                "block_ioc",
                "Block an IOC value across perimeter and EDR controls.",
                lambda ioc_value="", ioc_type="", case_id="": {
                    "status": "success",
                    "server": "soar",
                    "action": "block_ioc",
                    "ioc_value": ioc_value,
                    "ioc_type": ioc_type,
                    "blocked": True,
                    "case_id": case_id,
                },
            ),
            (
                "close_case",
                "Close a SOAR case with a resolution reason and root cause.",
                lambda case_id="", reason="Resolved", root_cause="Benign", comment="": {
                    "status": "closed",
                    "server": "soar",
                    "case_id": case_id,
                    "reason": reason,
                    "root_cause": root_cause,
                },
            ),
            (
                "list_alerts_by_case",
                "List alerts associated with a SOAR case.",
                lambda case_id="": {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "alerts": get_logstory_corpus().list_alerts_for_case(case_id),
                },
            ),
            (
                "list_events_by_alert",
                "List UDM events associated with a SOAR alert.",
                lambda case_id="", alert_id="": {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "alert_id": alert_id,
                    "events": get_logstory_corpus().list_events_for_alert(case_id, alert_id),
                },
            ),
            (
                "get_entities_by_alert_group_identifiers",
                "Retrieve entities linked to SOAR alert group identifiers.",
                lambda case_id="", alert_group_identifiers=None: {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "entities": [],
                },
            ),
            (
                "change_case_priority",
                "Update the priority of a SOAR case.",
                lambda case_id="", priority="High": {
                    "status": "success",
                    "server": "soar",
                    "case_id": case_id,
                    "priority": priority,
                },
            ),
            (
                "get_case_settings_root_causes",
                "Retrieve configured SOAR case closure root causes.",
                lambda: {
                    "status": "success",
                    "server": "soar",
                    "root_causes": ["Benign", "True Positive", "Duplicate"],
                },
            ),
            (
                "siemplify_close_case",
                "Close a SOAR case with a reason and root cause.",
                lambda case_id="", reason="Resolved", root_cause="Benign", comment="": {
                    "status": "closed",
                    "server": "soar",
                    "case_id": case_id,
                },
            ),
            (
                "siemplify_close_alert",
                "Close an individual SOAR alert inside a case.",
                lambda case_id="", alert_group_identifier="", reason="Resolved", root_cause="Benign": {
                    "status": "closed",
                    "server": "soar",
                    "case_id": case_id,
                },
            ),
            (
                "siemplify_get_similar_cases",
                "Find similar historical SOAR cases for deduplication and grouping.",
                lambda case_id="", days_back=7: {
                    "status": "success",
                    "server": "soar",
                    "similar_cases": [],
                },
            ),
            (
                "google_chronicle_get_rule_details",
                "Fetch Chronicle rule details via SOAR integration.",
                lambda case_id="", rule_id="": {
                    "status": "success",
                    "server": "soar",
                    "rule_id": rule_id,
                },
            ),
            (
                "google_chronicle_get_detection_details",
                "Fetch Chronicle detection details via SOAR integration.",
                lambda case_id="", detection_id="": {
                    "status": "success",
                    "server": "soar",
                    "detection_id": detection_id,
                },
            ),
            (
                "google_chronicle_list_events",
                "List Chronicle events via SOAR integration.",
                lambda case_id="": {
                    "status": "success",
                    "server": "soar",
                    "events": [],
                },
            ),
            (
                "google_chronicle_add_values_to_reference_list",
                "Add IOC values to a Chronicle Reference List for containment.",
                lambda case_id="", reference_list_name="", values="": {
                    "status": "success",
                    "server": "soar",
                    "reference_list_name": reference_list_name,
                },
            ),
        ],
        "gti": [
            (
                "get_ip_address_report",
                "Retrieve VirusTotal / GTI reputation report for an IP address.",
                _mock_get_ip_address_report,
            ),
            (
                "get_domain_report",
                "Retrieve VirusTotal / GTI reputation report for a domain.",
                _mock_get_domain_report,
            ),
            (
                "get_file_report",
                "Retrieve VirusTotal / GTI reputation report for a file hash.",
                _mock_get_file_report,
            ),
            (
                "get_file_behavior_summary",
                "Retrieve sandbox behavioral summary for a file hash from GTI.",
                lambda hash="": {
                    "status": "success",
                    "server": "gti",
                    "hash": hash,
                    "behaviors": [],
                },
            ),
            (
                "get_url_report",
                "Retrieve VirusTotal / GTI reputation report for a URL.",
                lambda url="": (
                    get_logstory_corpus().get_gti_indicator_report(url, "URL")
                    or {
                        "status": "success",
                        "server": "gti",
                        "url": url,
                        "verdict": "clean",
                    }
                ),
            ),
            (
                "get_collection_report",
                "Retrieve GTI threat intelligence collection report.",
                _mock_get_collection_report,
            ),
            (
                "get_collection_timeline_events",
                "Retrieve timeline events for a GTI collection.",
                lambda collection_id="": {
                    "status": "success",
                    "server": "gti",
                    "collection_id": collection_id,
                    "events": [],
                },
            ),
            (
                "get_collection_mitre_tree",
                "Retrieve MITRE ATT&CK TTP tree for a GTI collection.",
                lambda collection_id="": {
                    "status": "success",
                    "server": "gti",
                    "collection_id": collection_id,
                },
            ),
            (
                "get_entities_related_to_a_collection",
                "Retrieve IOC entities associated with a GTI collection.",
                _mock_get_entities_related_to_a_collection,
            ),
            (
                "get_entities_related_to_a_domain",
                "Retrieve entities related to a domain in GTI.",
                _mock_get_entities_related_to_a_domain,
            ),
            (
                "get_threat_intel",
                "Query GTI threat intelligence knowledge base.",
                lambda query="": {
                    "status": "success",
                    "server": "gti",
                    "query": query,
                },
            ),
            (
                "search_threats",
                "Search GTI for threats, campaigns, or malware families.",
                lambda query="": {
                    "status": "success",
                    "server": "gti",
                    "query": query,
                },
            ),
            (
                "search_threat_actors",
                "Search GTI for threat actor profiles.",
                lambda query="": {
                    "status": "success",
                    "server": "gti",
                    "query": query,
                },
            ),
            (
                "search_vulnerabilities",
                "Search GTI for CVE vulnerability intelligence.",
                lambda query="": {
                    "status": "success",
                    "server": "gti",
                    "query": query,
                },
            ),
        ],
    }

    prefix_map = {"siem": "secops-mcp", "soar": "soar-mcp", "gti": "gti-mcp", "scc": "scc-mcp"}
    prefix = prefix_map.get(server, server)
    tools: list[BaseTool] = []

    for short_name, desc, fn in specs.get(server, []):
        def _make_fn(f, s_name, d):
            def _wrapped(**kwargs):
                return f(**kwargs)
            _wrapped.__name__ = s_name
            _wrapped.__doc__ = d
            _wrapped.__signature__ = inspect.signature(f)  # type: ignore[attr-defined]
            return _wrapped

        fn_obj = _make_fn(fn, short_name, desc)
        ft = FunctionTool(func=fn_obj)
        tools.append(ft)

        prefixed_name = f"{prefix}_{short_name}"
        schema = _extract_schema_from_callable(fn)
        registry.register_tool(
            MCPToolMetadata(
                name=prefixed_name,
                server=server,
                description=desc,
                input_schema=schema,
                executor=fn_obj,
            )
        )
        registry.register_tool(
            MCPToolMetadata(
                name=short_name,
                server=server,
                description=desc,
                input_schema=schema,
                executor=fn_obj,
            )
        )

    return tools
