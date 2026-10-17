"""Corpus loader and replay index for the 43 Logstory usecases and 4 Cymbal baselines."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Optional
import yaml

DEFAULT_LOGSTORY_DIR = Path(
    "/usr/local/google/home/dandye/Projects/logstory_usecases__worktrees/main"
)

PAIRED_BASELINES_BY_USECASE: dict[str, list[str]] = {
    "AKIRA_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "ALPHV_BLACKCAT": ["CYMBAL_BASELINE_ENDPOINT"],
    "AVOSLOCKER_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "BLACKBASTA_EDR": ["CYMBAL_BASELINE_ENDPOINT"],
    "CARBONBLACK_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "CITRIXBLEED_LOCKBIT": ["CYMBAL_BASELINE_ENDPOINT"],
    "DEFENDER_MALWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "FIREEYE_HX_INTRUSION": ["CYMBAL_BASELINE_ENDPOINT"],
    "LIMACHARLIE_INTRUSION": ["CYMBAL_BASELINE_ENDPOINT"],
    "PLAY_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "RHYSIDA_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "ROYAL_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "SENTINELONE_INTRUSION": ["CYMBAL_BASELINE_ENDPOINT"],
    "SEP_MALWARE_OUTBREAK": ["CYMBAL_BASELINE_ENDPOINT"],
    "SNATCH_RANSOMWARE": ["CYMBAL_BASELINE_ENDPOINT"],
    "TANIUM_THREAT_HUNT": ["CYMBAL_BASELINE_ENDPOINT"],
    "TRUEBOT_INFECTION": ["CYMBAL_BASELINE_ENDPOINT"],
    "ZOHO_MANAGEENGINE": ["CYMBAL_BASELINE_ENDPOINT"],
    "DUO_MFA_BOMBING": ["CYMBAL_BASELINE_ENDPOINT", "CYMBAL_BASELINE_IDENTITY"],
    "QAKBOT_INFECTION": ["CYMBAL_BASELINE_ENDPOINT", "CYMBAL_BASELINE_NETWORK"],
    "SQUID_PROXY_C2": ["CYMBAL_BASELINE_ENDPOINT", "CYMBAL_BASELINE_NETWORK"],
    "MIDNIGHT_BLIZZARD": ["CYMBAL_BASELINE_IDENTITY"],
    "SCATTERED_SPIDER": [
        "CYMBAL_BASELINE_ENDPOINT",
        "CYMBAL_BASELINE_IDENTITY",
        "CYMBAL_BASELINE_CLOUD",
    ],
    "AWS_S3_DATA_THEFT": ["CYMBAL_BASELINE_CLOUD"],
    "AWS_WAF_WEBATTACK": ["CYMBAL_BASELINE_CLOUD"],
    "GCP_CRYPTOMINING": ["CYMBAL_BASELINE_CLOUD"],
    "GCP_HONEY_TOKENS": ["CYMBAL_BASELINE_CLOUD"],
    "GITHUB_SUPPLY_CHAIN": ["CYMBAL_BASELINE_CLOUD"],
    "CLOP_MOVEIT": ["CYMBAL_BASELINE_CLOUD", "CYMBAL_BASELINE_ENDPOINT"],
    "INSIDER_PRIVILEGE_ABUSE": [
        "CYMBAL_BASELINE_CLOUD",
        "CYMBAL_BASELINE_IDENTITY",
    ],
    "INSIDER_SABOTAGE": ["CYMBAL_BASELINE_CLOUD", "CYMBAL_BASELINE_ENDPOINT"],
    "INSIDER_SOURCE_THEFT": ["CYMBAL_BASELINE_CLOUD", "CYMBAL_BASELINE_NETWORK"],
    "WORKSPACE_INSIDER": ["CYMBAL_BASELINE_IDENTITY"],
    "NETWORK_BEACON_DETECT": ["CYMBAL_BASELINE_NETWORK"],
    "GCP_VPC_LATERAL": ["CYMBAL_BASELINE_NETWORK", "CYMBAL_BASELINE_CLOUD"],
    "DNS_TUNNELING_EXFIL": ["CYMBAL_BASELINE_NETWORK", "CYMBAL_BASELINE_CLOUD"],
    "VOLT_TYPHOON_LOTL": ["CYMBAL_BASELINE_NETWORK"],
    "ANDROXGH0ST": ["CYMBAL_BASELINE_NETWORK"],
    "BARRACUDA_ESG": ["CYMBAL_BASELINE_NETWORK"],
    "CITRIX_WEBSHELL": ["CYMBAL_BASELINE_NETWORK"],
    "COLDFUSION_EXPLOIT": ["CYMBAL_BASELINE_NETWORK"],
    "CONFLUENCE_EXPLOIT": ["CYMBAL_BASELINE_NETWORK"],
    "NIX_CRYPTOMINER": ["CYMBAL_BASELINE_NETWORK"],
}

_ACTIVE_USECASE_STATE: dict[str, Any] = {
    "usecase_id": None,
    "include_baselines": True,
}


@dataclass(frozen=True)
class LogstoryEvent:
    """Normalized security event parsed from any of the 36 Logstory log types."""

    usecase_id: str
    log_type: str
    timestamp: str
    hostname: str = ""
    principal_user: str = ""
    target_user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    method_or_action: str = ""
    resource_name: str = ""
    process_command_line: str = ""
    file_sha256: str = ""
    domain: str = ""
    url: str = ""
    status_or_result: str = ""
    severity: str = ""
    is_baseline: bool = False
    scc_finding: Optional[dict[str, Any]] = None
    raw_record: dict[str, Any] | str = field(default_factory=dict)

    def to_udm_like_dict(self) -> dict[str, Any]:
        """Convert to a compact Chronicle UDM-like dict for SIEM tool responses."""
        event_type = _infer_udm_event_type(self)
        payload: dict[str, Any] = {
            "usecase_id": self.usecase_id,
            "event_timestamp": self.timestamp,
            "metadata": {
                "log_type": self.log_type,
                "event_type": event_type,
                "product_event_type": self.method_or_action,
            },
            "principal": {
                "hostname": self.hostname,
                "ip": self.src_ip,
                "user": {"userid": self.principal_user},
            },
            "target": {
                "hostname": self.domain or self.hostname,
                "ip": self.dst_ip,
                "user": {"userid": self.target_user},
                "resource": {"name": self.resource_name},
                "url": self.url,
                "process": {
                    "command_line": self.process_command_line,
                    "file": {"sha256": self.file_sha256},
                },
            },
            "security_result": {
                "severity": self.severity or ("INFORMATIONAL" if self.is_baseline else "HIGH"),
                "action": self.status_or_result or "ALLOW",
            },
            "is_baseline_noise": self.is_baseline,
        }
        if self.domain:
            payload["network"] = {"dns": {"questions": [{"name": self.domain}]}}
        if self.scc_finding:
            payload["scc_finding"] = self.scc_finding
        return payload

    def matches_query(self, query: str) -> bool:
        """Return True when free-text or UDM-style query tokens match this event."""
        q = str(query or "").strip().lower()
        if not q or q == "*":
            return True
        haystack = " ".join(
            [
                self.usecase_id,
                self.log_type,
                self.timestamp,
                self.hostname,
                self.principal_user,
                self.target_user,
                self.src_ip,
                self.dst_ip,
                self.method_or_action,
                self.resource_name,
                self.process_command_line,
                self.file_sha256,
                self.domain,
                self.url,
                self.status_or_result,
                self.severity,
                json.dumps(self.scc_finding or {}, default=str),
                json.dumps(self.raw_record, default=str)
                if isinstance(self.raw_record, dict)
                else str(self.raw_record),
            ]
        ).lower()
        tokens = _extract_search_tokens(q)
        if not tokens:
            return q in haystack
        return any(tok in haystack for tok in tokens)


@dataclass(frozen=True)
class LogstoryEntity:
    """Normalized user, service account, or host entity from ENTITIES/*.log."""

    usecase_id: str
    entity_log_type: str
    identifier: str
    entity_type: str
    display_name: str = ""
    department: str = ""
    title: str = ""
    roles_or_groups: list[str] = field(default_factory=list)
    raw_record: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LogstoryRule:
    """Parsed YARA-L 2.0 detection rule from RULES/*.yl2."""

    usecase_id: str
    file_name: str
    rule_name: str
    meta: dict[str, str]
    mitre_techniques: list[str]
    events_predicates: list[str]
    has_match_section: bool
    has_outcome_section: bool
    has_condition_section: bool
    raw_text: str


@dataclass
class LogstoryUsecase:
    """Complete representation of one Logstory usecase or Cymbal baseline."""

    usecase_id: str
    title: str
    description: str
    tags: list[str]
    is_baseline: bool
    paired_baselines: list[str]
    events: list[LogstoryEvent]
    entities: list[LogstoryEntity]
    rules: list[LogstoryRule]
    narrative_markdown: str

    @property
    def scc_findings(self) -> list[dict[str, Any]]:
        return [ev.scc_finding for ev in self.events if ev.scc_finding]

    @property
    def unique_hosts(self) -> list[str]:
        return sorted({ev.hostname for ev in self.events if ev.hostname})

    @property
    def unique_users(self) -> list[str]:
        users = {ev.principal_user for ev in self.events if ev.principal_user}
        users.update(ev.target_user for ev in self.events if ev.target_user)
        return sorted(users)

    @property
    def unique_ips(self) -> list[str]:
        ips = {ev.src_ip for ev in self.events if ev.src_ip}
        ips.update(ev.dst_ip for ev in self.events if ev.dst_ip)
        return sorted(ips)

    @property
    def unique_hashes(self) -> list[str]:
        return sorted({ev.file_sha256 for ev in self.events if ev.file_sha256})

    @property
    def unique_domains(self) -> list[str]:
        return sorted({ev.domain for ev in self.events if ev.domain})


def _extract_search_tokens(query: str) -> list[str]:
    """Extract informative entity/IOC/field values from UDM or free-text queries."""
    quoted = [m.strip().lower() for m in re.findall(r'["\']([^"\']{2,})["\']', query)]
    regex_lits = [
        re.sub(r"\\(.)", r"\1", m).strip(".*^$").lower()
        for m in re.findall(r"/([^/]{3,})/", query)
    ]
    candidates = [t for t in (quoted + regex_lits) if len(t) >= 3]
    if candidates:
        return candidates
    stop_words = {
        "and",
        "or",
        "not",
        "nocase",
        "over",
        "metadata",
        "event_type",
        "principal",
        "target",
        "hostname",
        "user",
        "userid",
        "process",
        "command_line",
        "file",
        "sha256",
        "network",
        "dns",
        "ip",
        "email_addresses",
        "log_type",
        "security_result",
    }
    raw_words = re.findall(r"[a-zA-Z0-9_.@:\\/-]{3,}", query.lower())
    return [w for w in raw_words if w not in stop_words]


def _infer_udm_event_type(ev: LogstoryEvent) -> str:
    lt = ev.log_type.upper()
    method = ev.method_or_action.lower()
    if "DNS" in lt or ev.domain and not ev.process_command_line:
        return "NETWORK_DNS"
    if "VPC_FLOW" in lt or "FIREWALL" in lt or "CORELIGHT" in lt or "SURICATA" in lt:
        return "NETWORK_CONNECTION"
    if "WEBPROXY" in lt or "WAF" in lt:
        return "NETWORK_HTTP"
    if "SYSMON" in lt or "EDR" in lt or "AUDITD" in lt or "POWERSHELL" in lt or "TANIUM" in lt:
        if ev.process_command_line:
            return "PROCESS_LAUNCH"
    if "OKTA" in lt or "AZURE_AD" in lt or "DUO" in lt:
        return "USER_LOGIN"
    if "CLOUDAUDIT" in lt or "CLOUDTRAIL" in lt or "WORKSPACE" in lt or "OFFICE_365" in lt:
        if "login" in method or "authenticate" in method:
            return "USER_LOGIN"
        if "iam" in method or "role" in method or "permission" in method:
            return "USER_RESOURCE_UPDATE_PERMISSIONS"
        return "USER_RESOURCE_ACCESS"
    if "SECURITYCENTER" in lt or "GUARDDUTY" in lt or "DETECTS" in lt:
        return "ALERT"
    return "GENERIC_EVENT"


def _parse_frontmatter_and_body(md_path: Path) -> tuple[dict[str, Any], str]:
    if not md_path.exists():
        return {}, ""
    text = md_path.read_text(encoding="utf-8", errors="replace")
    if text.startswith("---\n"):
        parts = text.split("\n---\n", 1)
        if len(parts) == 2:
            try:
                fm = yaml.safe_load(parts[0][4:]) or {}
                if isinstance(fm, dict):
                    return fm, parts[1].strip()
            except Exception:
                pass
    return {}, text.strip()


def _extract_sha256_from_hashes(hashes_str: str) -> str:
    if not hashes_str:
        return ""
    m = re.search(r"SHA256=([0-9a-fA-F]{64})", str(hashes_str))
    if m:
        return m.group(1).lower()
    m_bare = re.search(r"\b([0-9a-fA-F]{64})\b", str(hashes_str))
    return m_bare.group(1).lower() if m_bare else ""


def _parse_json_event(
    usecase_id: str,
    log_type: str,
    obj: dict[str, Any],
    is_baseline: bool,
) -> LogstoryEvent:
    ts = str(
        obj.get("timestamp")
        or obj.get("EventTime")
        or obj.get("ts")
        or obj.get("time")
        or obj.get("published")
        or obj.get("isotimestamp")
        or obj.get("CreationTime")
        or obj.get("datetime")
        or obj.get("event_at")
        or obj.get("eventTimestamp")
        or obj.get("@timestamp")
        or ""
    )
    hostname = ""
    principal_user = ""
    target_user = ""
    src_ip = ""
    dst_ip = ""
    method_or_action = ""
    resource_name = ""
    cmd = ""
    sha256 = ""
    domain = ""
    url = ""
    status = ""
    severity = str(obj.get("severity") or obj.get("Severity") or "")
    scc_finding: Optional[dict[str, Any]] = None

    if "protoPayload" in obj and isinstance(obj["protoPayload"], dict):
        pp = obj["protoPayload"]
        auth = pp.get("authenticationInfo") or {}
        req_meta = pp.get("requestMetadata") or {}
        principal_user = str(auth.get("principalEmail") or "")
        src_ip = str(req_meta.get("callerIp") or "")
        method_or_action = str(pp.get("methodName") or "")
        resource_name = str(pp.get("resourceName") or "")
        st = pp.get("status")
        if isinstance(st, dict) and st.get("message"):
            status = str(st.get("message"))
        elif isinstance(pp.get("authorizationInfo"), list) and pp["authorizationInfo"]:
            granted = pp["authorizationInfo"][0].get("granted")
            status = "GRANTED" if granted else "PERMISSION_DENIED"
        res_labels = (obj.get("resource") or {}).get("labels") or {}
        hostname = str(res_labels.get("instance_id") or res_labels.get("project_id") or "")

    elif "finding" in obj and isinstance(obj["finding"], dict):
        f = obj["finding"]
        scc_finding = f
        ts = str(f.get("eventTime") or ts)
        severity = str(f.get("severity") or severity)
        method_or_action = str(f.get("category") or "")
        resource_name = str(f.get("resourceName") or "")
        sp = f.get("sourceProperties") or {}
        principal_user = str(sp.get("principalEmail") or "")
        src_ip = str(sp.get("callerIp") or "")
        status = str(sp.get("outcome") or f.get("state") or "")

    elif log_type in ("WINEVTLOG", "WINDOWS_SYSMON", "POWERSHELL"):
        hostname = str(obj.get("Hostname") or "").split(".")[0]
        principal_user = str(
            obj.get("SubjectUserName")
            or obj.get("User")
            or obj.get("AccountName")
            or ""
        )
        target_user = str(obj.get("TargetUserName") or "")
        src_ip = str(obj.get("IpAddress") or obj.get("SourceIp") or "")
        dst_ip = str(obj.get("DestinationIp") or "")
        method_or_action = str(
            obj.get("EventID") or obj.get("Task") or obj.get("EventType") or ""
        )
        cmd = str(
            obj.get("CommandLine")
            or obj.get("ScriptBlockText")
            or obj.get("ParentCommandLine")
            or obj.get("Message")
            or ""
        )
        sha256 = _extract_sha256_from_hashes(str(obj.get("Hashes") or obj.get("SHA256") or ""))
        domain = str(obj.get("QueryName") or obj.get("DestinationHostname") or "")
        resource_name = str(obj.get("TargetFilename") or obj.get("Image") or "")

    elif log_type == "AWS_CLOUDTRAIL":
        ui = obj.get("userIdentity") or {}
        principal_user = str(ui.get("arn") or ui.get("userName") or "")
        src_ip = str(obj.get("sourceIPAddress") or "")
        method_or_action = str(obj.get("eventName") or "")
        resource_name = str(obj.get("eventSource") or "")
        status = str(obj.get("errorCode") or "SUCCESS")

    elif log_type == "GUARDDUTY":
        method_or_action = str(obj.get("type") or "")
        severity = str(obj.get("severity") or "")
        resource_name = str(obj.get("arn") or "")
        res = obj.get("resource") or {}
        ak = res.get("accessKeyDetails") or {}
        principal_user = str(ak.get("userName") or ak.get("principalId") or "")

    elif log_type == "AWS_WAF":
        hr = obj.get("httpRequest") or {}
        src_ip = str(hr.get("clientIp") or "")
        url = str(hr.get("uri") or "")
        method_or_action = str(obj.get("action") or obj.get("terminatingRuleId") or "")

    elif log_type == "OKTA":
        actor = obj.get("actor") or {}
        client = obj.get("client") or {}
        principal_user = str(actor.get("alternateId") or actor.get("displayName") or "")
        src_ip = str(client.get("ipAddress") or "")
        method_or_action = str(obj.get("eventType") or "")
        outcome = obj.get("outcome") or {}
        status = str(outcome.get("result") or "")

    elif log_type == "AZURE_AD":
        props = obj.get("properties") or {}
        init_by = (props.get("initiatedBy") or {}).get("user") or {}
        principal_user = str(
            init_by.get("userPrincipalName")
            or props.get("userPrincipalName")
            or ""
        )
        src_ip = str(init_by.get("ipAddress") or props.get("ipAddress") or "")
        method_or_action = str(obj.get("operationName") or "")
        status = str(obj.get("resultType") or "")

    elif log_type == "OFFICE_365":
        principal_user = str(obj.get("UserId") or "")
        src_ip = str(obj.get("ClientIP") or "")
        method_or_action = str(obj.get("Operation") or "")
        resource_name = str(obj.get("MailboxOwnerUPN") or obj.get("ObjectId") or "")
        status = str(obj.get("ResultStatus") or "")

    elif log_type == "WORKSPACE_ACTIVITY":
        actor = obj.get("actor") or {}
        principal_user = str(actor.get("email") or "")
        src_ip = str(obj.get("ipAddress") or "")
        events_list = obj.get("events") or []
        if events_list and isinstance(events_list[0], dict):
            method_or_action = str(events_list[0].get("name") or "")

    elif log_type == "GMAIL_LOGS":
        msg_info = (obj.get("message_info") or [{}])[0]
        src = msg_info.get("source") or {}
        dsts = msg_info.get("destination") or [{}]
        principal_user = str(src.get("address") or "")
        target_user = str((dsts[0] if dsts else {}).get("address") or "")
        method_or_action = "GMAIL_MESSAGE"

    elif log_type == "CHROME_MANAGEMENT":
        dev = obj.get("device") or {}
        hostname = str(dev.get("hostname") or dev.get("deviceId") or "")
        principal_user = str(dev.get("userName") or "")
        ev = obj.get("event") or {}
        method_or_action = str(ev.get("type") or "")

    elif log_type == "GITHUB":
        principal_user = str(obj.get("actor") or obj.get("user") or "")
        src_ip = str(obj.get("actor_ip") or "")
        method_or_action = str(obj.get("action") or "")
        resource_name = str(obj.get("repo") or obj.get("org") or "")

    elif log_type in ("DUO_AUTH", "DUO_ADMIN"):
        usr = obj.get("user") if isinstance(obj.get("user"), dict) else {}
        principal_user = str(usr.get("name") or obj.get("username") or "")
        acc = obj.get("access_device") if isinstance(obj.get("access_device"), dict) else {}
        src_ip = str(acc.get("ip") or obj.get("ip") or "")
        method_or_action = str(obj.get("event_type") or obj.get("action") or "")
        status = str(obj.get("result") or obj.get("reason") or "")

    elif log_type in ("CS_EDR", "CS_DETECTS"):
        ev_body = obj.get("event") if isinstance(obj.get("event"), dict) else obj
        hostname = str(
            ev_body.get("ComputerName") or obj.get("ComputerName") or ""
        ).split(".")[0]
        principal_user = str(ev_body.get("UserName") or obj.get("UserName") or "")
        cmd = str(ev_body.get("CommandLine") or obj.get("CommandLine") or "")
        sha256 = str(
            ev_body.get("SHA256HashData")
            or obj.get("SHA256HashData")
            or ""
        ).lower()
        method_or_action = str(
            obj.get("event_simpleName")
            or ev_body.get("Technique")
            or ""
        )
        dst_ip = str(ev_body.get("RemoteAddressIP4") or obj.get("RemoteAddressIP4") or "")
        domain = str(ev_body.get("DomainName") or obj.get("DomainName") or "")

    elif log_type == "SENTINEL_EDR":
        hostname = str(obj.get("agentComputerName") or "")
        principal_user = str(obj.get("processUserName") or obj.get("user") or "")
        cmd = str(obj.get("processCmd") or obj.get("commandLine") or "")
        sha256 = str(obj.get("processSha256") or obj.get("sha256") or "").lower()
        method_or_action = str(obj.get("eventType") or "")
        dst_ip = str(obj.get("dstIp") or "")

    elif log_type == "MICROSOFT_DEFENDER_ENDPOINT":
        props = obj.get("properties") or obj
        hostname = str(props.get("DeviceName") or "").split(".")[0]
        principal_user = str(props.get("AccountName") or "")
        cmd = str(props.get("ProcessCommandLine") or "")
        sha256 = str(props.get("SHA256") or "").lower()
        method_or_action = str(props.get("ActionType") or obj.get("category") or "")
        dst_ip = str(props.get("RemoteIP") or "")
        domain = str(props.get("RemoteUrl") or "")

    elif log_type == "CB_EDR":
        hostname = str(obj.get("computer_name") or "")
        principal_user = str(obj.get("username") or "")
        cmd = str(obj.get("command_line") or "")
        sha256 = str(obj.get("sha256") or obj.get("md5") or "").lower()
        method_or_action = str(obj.get("type") or "")

    elif log_type == "LIMACHARLIE_EDR":
        routing = obj.get("routing") or {}
        ev = obj.get("event") or {}
        hostname = str(routing.get("hostname") or "")
        method_or_action = str(routing.get("event_type") or "")
        cmd = str(ev.get("COMMAND_LINE") or "")
        principal_user = str(ev.get("USER_NAME") or "")
        sha256 = str(ev.get("HASH") or "").lower()

    elif log_type == "FIREEYE_HX":
        hostname = str(obj.get("hostname") or "")
        principal_user = str(obj.get("user") or "")
        cmd = str(obj.get("process_cmdline") or obj.get("process") or "")
        sha256 = str(obj.get("sha256") or "").lower()
        method_or_action = str(obj.get("event_type") or "")

    elif log_type == "TANIUM_TH":
        hostname = str(obj.get("computerName") or "")
        src_ip = str(obj.get("computerIpAddress") or "")
        principal_user = str(obj.get("userName") or "")
        cmd = str(obj.get("processCommandLine") or obj.get("filePath") or "")
        sha256 = str(obj.get("sha256") or "").lower()
        method_or_action = str(obj.get("intelDocTitle") or obj.get("type") or "")

    elif log_type == "CORELIGHT":
        src_ip = str(obj.get("id.orig_h") or "")
        dst_ip = str(obj.get("id.resp_h") or "")
        method_or_action = str(obj.get("service") or obj.get("proto") or "")
        domain = str(obj.get("query") or obj.get("server_name") or "")

    elif log_type == "SURICATA_EVE":
        src_ip = str(obj.get("src_ip") or "")
        dst_ip = str(obj.get("dest_ip") or "")
        alert = obj.get("alert") or {}
        method_or_action = str(alert.get("signature") or obj.get("event_type") or "")
        severity = str(alert.get("severity") or severity)

    elif log_type == "ZSCALER_WEBPROXY":
        principal_user = str(obj.get("user") or "")
        url = str(obj.get("url") or "")
        domain = str(obj.get("host") or "")
        method_or_action = str(obj.get("action") or "")
        src_ip = str(obj.get("ClientIP") or "")

    elif log_type == "GCP_DNS":
        jp = obj.get("jsonPayload") or {}
        domain = str(jp.get("queryName") or "").rstrip(".")
        src_ip = str(jp.get("sourceIP") or "")
        method_or_action = str(jp.get("queryType") or "DNS_QUERY")

    elif log_type in ("GCP_FIREWALL", "GCP_VPC_FLOW"):
        jp = obj.get("jsonPayload") or {}
        conn = jp.get("connection") or {}
        src_ip = str(conn.get("src_ip") or "")
        dst_ip = str(conn.get("dest_ip") or "")
        method_or_action = str(jp.get("disposition") or log_type)
        inst = jp.get("instance") or {}
        hostname = str(inst.get("vm_name") or "")

    elif log_type == "NIX_SYSTEM":
        hostname = str(obj.get("hostname") or "")
        method_or_action = str(obj.get("process") or "")
        cmd = str(obj.get("message") or "")
        ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cmd)
        if ip_m:
            src_ip = ip_m.group(0)

    return LogstoryEvent(
        usecase_id=usecase_id,
        log_type=log_type,
        timestamp=ts,
        hostname=hostname,
        principal_user=principal_user,
        target_user=target_user,
        src_ip=src_ip,
        dst_ip=dst_ip,
        method_or_action=method_or_action,
        resource_name=resource_name,
        process_command_line=cmd,
        file_sha256=sha256,
        domain=domain,
        url=url,
        status_or_result=status,
        severity=severity,
        is_baseline=is_baseline,
        scc_finding=scc_finding,
        raw_record=obj,
    )


def _parse_event_line(
    usecase_id: str,
    log_type: str,
    line: str,
    is_baseline: bool,
) -> Optional[LogstoryEvent]:
    s = line.strip()
    if not s:
        return None

    # 1. Pure JSON
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return _parse_json_event(usecase_id, log_type, obj, is_baseline)
        except json.JSONDecodeError:
            pass

    # 2. Syslog-prefixed JSON (<pri>Mon DD HH:MM:SS host provider[pid]: {json})
    json_idx = s.find(": {")
    if json_idx != -1:
        candidate = s[json_idx + 2 :]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return _parse_json_event(usecase_id, log_type, obj, is_baseline)
        except json.JSONDecodeError:
            pass

    # 3. AUDITD key=value lines
    if log_type == "AUDITD":
        ts_m = re.search(r"audit\((\d+\.\d+):", s)
        type_m = re.search(r"type=([A-Z_]+)", s)
        exe_m = re.search(r'exe="([^"]+)"', s)
        args = re.findall(r'a\d+="([^"]+)"', s)
        cmd = " ".join(args) if args else (exe_m.group(1) if exe_m else s[:120])
        return LogstoryEvent(
            usecase_id=usecase_id,
            log_type=log_type,
            timestamp=ts_m.group(1) if ts_m else "",
            method_or_action=type_m.group(1) if type_m else "AUDITD",
            process_command_line=cmd,
            is_baseline=is_baseline,
            raw_record=s,
        )

    # 4. SQUID_WEBPROXY space-separated format
    if log_type == "SQUID_WEBPROXY":
        parts = s.split()
        if len(parts) >= 9:
            ts, _elapsed, client_ip, status_code, _bytes, method, url, user, peer = parts[:9]
            dst_ip = peer.split("/")[-1] if "/" in peer else ""
            dom_m = re.search(r"https?://([^/:]+)", url)
            return LogstoryEvent(
                usecase_id=usecase_id,
                log_type=log_type,
                timestamp=ts,
                principal_user="" if user == "-" else user,
                src_ip=client_ip,
                dst_ip="" if dst_ip == "-" else dst_ip,
                method_or_action=method,
                url=url,
                domain=dom_m.group(1) if dom_m else "",
                status_or_result=status_code,
                is_baseline=is_baseline,
                raw_record=s,
            )

    # 5. EXTRAHOP_DNS / SEP / generic syslog
    kv = dict(re.findall(r"(\w+)=([^\s]+)", s))
    hostname = kv.get("dvchost") or kv.get("shost") or ""
    src_ip = kv.get("client") or kv.get("src") or ""
    dst_ip = kv.get("answer") or kv.get("dst") or ""
    domain = kv.get("query") or ""
    return LogstoryEvent(
        usecase_id=usecase_id,
        log_type=log_type,
        timestamp=s[:32],
        hostname=hostname,
        src_ip=src_ip,
        dst_ip=dst_ip,
        domain=domain,
        method_or_action=log_type,
        process_command_line=s[:200],
        is_baseline=is_baseline,
        raw_record=s,
    )


def _parse_entity_line(
    usecase_id: str,
    entity_log_type: str,
    line: str,
) -> Optional[LogstoryEntity]:
    s = line.strip()
    if not s or not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None

    if entity_log_type == "GCP_IAM_CONTEXT":
        ident = str(obj.get("name") or "")
        etype = str(obj.get("principalType") or "USER")
        roles = list(obj.get("roles") or [])
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type=etype,
            display_name=ident,
            roles_or_groups=roles,
            raw_record=obj,
        )

    if entity_log_type == "WINDOWS_AD":
        if "DNSHostName" in obj or "OperatingSystem" in obj:
            ident = str(obj.get("Name") or obj.get("SamAccountName") or "").rstrip("$")
            return LogstoryEntity(
                usecase_id=usecase_id,
                entity_log_type=entity_log_type,
                identifier=ident,
                entity_type="HOST",
                display_name=str(obj.get("DNSHostName") or ident),
                title=str(obj.get("OperatingSystem") or ""),
                raw_record=obj,
            )
        ident = str(obj.get("UserPrincipalName") or obj.get("SamAccountName") or "")
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type="USER",
            display_name=str(obj.get("DisplayName") or obj.get("Name") or ident),
            department=str(obj.get("Department") or ""),
            title=str(obj.get("Title") or ""),
            roles_or_groups=list(obj.get("MemberOf") or []),
            raw_record=obj,
        )

    if entity_log_type == "AZURE_AD_CONTEXT":
        ident = str(obj.get("userPrincipalName") or obj.get("mail") or "")
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type="USER",
            display_name=str(obj.get("displayName") or ident),
            department=str(obj.get("department") or ""),
            title=str(obj.get("jobTitle") or ""),
            raw_record=obj,
        )

    if entity_log_type == "OKTA_USER_CONTEXT":
        prof = obj.get("profile") or {}
        ident = str(prof.get("login") or prof.get("email") or obj.get("id") or "")
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type="USER",
            display_name=f"{prof.get('firstName', '')} {prof.get('lastName', '')}".strip(),
            department=str(prof.get("department") or ""),
            title=str(prof.get("title") or ""),
            raw_record=obj,
        )

    if entity_log_type == "WORKSPACE_USERS":
        ident = str(obj.get("primaryEmail") or "")
        name_obj = obj.get("name") or {}
        roles = ["SUPER_ADMIN"] if obj.get("isAdmin") else []
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type="USER",
            display_name=str(name_obj.get("fullName") or ident),
            department=str(obj.get("orgUnitPath") or "").lstrip("/"),
            roles_or_groups=roles,
            raw_record=obj,
        )

    if entity_log_type == "AWS_IAM":
        ident = str(obj.get("Arn") or obj.get("UserName") or obj.get("RoleName") or "")
        etype = "SERVICE_ACCOUNT" if ":role/" in ident else "USER"
        return LogstoryEntity(
            usecase_id=usecase_id,
            entity_log_type=entity_log_type,
            identifier=ident,
            entity_type=etype,
            display_name=str(obj.get("UserName") or obj.get("RoleName") or ident),
            roles_or_groups=list(obj.get("AttachedManagedPolicies") or []),
            raw_record=obj,
        )

    return None


def _parse_yaral2_rule(usecase_id: str, yl2_path: Path) -> LogstoryRule:
    raw = yl2_path.read_text(encoding="utf-8", errors="replace")
    rule_m = re.search(r"\brule\s+([a-zA-Z0-9_]+)\s*\{", raw)
    rule_name = rule_m.group(1) if rule_m else yl2_path.stem

    meta: dict[str, str] = {}
    meta_block_m = re.search(
        r"\bmeta:\s*(.*?)(?=\b(?:events|match|outcome|condition):)",
        raw,
        re.DOTALL,
    )
    if meta_block_m:
        for k, v in re.findall(r'([a-zA-Z0-9_]+)\s*=\s*"([^"]*)"', meta_block_m.group(1)):
            meta[k] = v

    mitre_techs = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", raw)))

    events_preds: list[str] = []
    ev_block_m = re.search(
        r"\bevents:\s*(.*?)(?=\b(?:match|outcome|condition):|\Z)",
        raw,
        re.DOTALL,
    )
    if ev_block_m:
        for line in ev_block_m.group(1).splitlines():
            clean = line.strip()
            if clean and not clean.startswith("//"):
                events_preds.append(clean)

    return LogstoryRule(
        usecase_id=usecase_id,
        file_name=yl2_path.name,
        rule_name=rule_name,
        meta=meta,
        mitre_techniques=mitre_techs,
        events_predicates=events_preds,
        has_match_section=bool(re.search(r"^\s*match\s*:", raw, re.MULTILINE)),
        has_outcome_section=bool(re.search(r"^\s*outcome\s*:", raw, re.MULTILINE)),
        has_condition_section=bool(re.search(r"^\s*condition\s*:", raw, re.MULTILINE)),
        raw_text=raw,
    )


class LogstoryCorpus:
    """In-memory index of all 43 Logstory usecases and 4 Cymbal baselines."""

    def __init__(self, root_dir: Optional[Path] = None):
        env_dir = os.environ.get("LOGSTORY_USECASES_DIR")
        self.root_dir = Path(root_dir or env_dir or DEFAULT_LOGSTORY_DIR)
        self.usecases: dict[str, LogstoryUsecase] = {}
        if self.root_dir.is_dir():
            self._load_all()

    def _load_all(self) -> None:
        for d in sorted(p for p in self.root_dir.iterdir() if p.is_dir() and not p.name.startswith(".")):
            uid = d.name
            is_baseline = uid.startswith("CYMBAL_BASELINE_")
            md_path = d / f"{uid}.md"
            if not md_path.exists():
                continue

            fm, body = _parse_frontmatter_and_body(md_path)
            title = str(fm.get("title") or uid)
            description = str(fm.get("description") or "").strip()
            tags = [str(t) for t in (fm.get("tags") or [])]

            events: list[LogstoryEvent] = []
            ev_dir = d / "EVENTS"
            if ev_dir.is_dir():
                for ev_file in sorted(ev_dir.glob("*.log")):
                    log_type = ev_file.stem
                    for line in ev_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        parsed_ev = _parse_event_line(uid, log_type, line, is_baseline)
                        if parsed_ev is not None:
                            events.append(parsed_ev)

            entities: list[LogstoryEntity] = []
            en_dir = d / "ENTITIES"
            if en_dir.is_dir():
                for en_file in sorted(en_dir.glob("*.log")):
                    en_type = en_file.stem
                    for line in en_file.read_text(encoding="utf-8", errors="replace").splitlines():
                        parsed_en = _parse_entity_line(uid, en_type, line)
                        if parsed_en is not None:
                            entities.append(parsed_en)

            rules: list[LogstoryRule] = []
            ru_dir = d / "RULES"
            if ru_dir.is_dir():
                for yl2_file in sorted(ru_dir.glob("*.yl2")):
                    rules.append(_parse_yaral2_rule(uid, yl2_file))

            self.usecases[uid] = LogstoryUsecase(
                usecase_id=uid,
                title=title,
                description=description,
                tags=tags,
                is_baseline=is_baseline,
                paired_baselines=list(PAIRED_BASELINES_BY_USECASE.get(uid, [])),
                events=events,
                entities=entities,
                rules=rules,
                narrative_markdown=body,
            )

    def list_usecases(self, include_baselines: bool = False) -> list[str]:
        """Return sorted usecase IDs (excluding Cymbal baselines by default)."""
        return sorted(
            uid
            for uid, uc in self.usecases.items()
            if include_baselines or not uc.is_baseline
        )

    def list_baselines(self) -> list[str]:
        """Return sorted Cymbal baseline IDs."""
        return sorted(uid for uid, uc in self.usecases.items() if uc.is_baseline)

    def get_usecase(self, usecase_id: str) -> Optional[LogstoryUsecase]:
        """Return a LogstoryUsecase by ID."""
        return self.usecases.get(str(usecase_id or "").strip().upper())

    def get_active_usecase_ids(self) -> Optional[set[str]]:
        active = _ACTIVE_USECASE_STATE.get("usecase_id") or os.environ.get("LOGSTORY_ACTIVE_USECASE")
        if not active or active not in self.usecases:
            return None
        ids = {active}
        if _ACTIVE_USECASE_STATE.get("include_baselines", True):
            ids.update(self.usecases[active].paired_baselines)
        return ids

    def has_corpus_match(self, query: str) -> bool:
        """Return True if query tokens match any known Cymbal/Logstory entity, host, or usecase."""
        q_lower = str(query or "").strip().lower()
        if not q_lower:
            return False
        if any(
            marker in q_lower
            for marker in (
                "cymbal",
                "canary-",
                "cym-",
                "logstory",
            )
        ):
            return True
        tokens = [t for t in _extract_search_tokens(q_lower) if len(t) >= 4]
        if not tokens:
            return False
        for uid, uc in self.usecases.items():
            if uid.lower() in q_lower:
                return True
            for h in uc.unique_hosts:
                if len(h) >= 4 and h.lower() in q_lower:
                    return True
            for u in uc.unique_users:
                if len(u) >= 4 and u.lower() in q_lower:
                    return True
            for d in uc.unique_domains:
                if len(d) >= 4 and d.lower() in q_lower:
                    return True
            for sha in uc.unique_hashes:
                if len(sha) >= 8 and sha[:12].lower() in q_lower:
                    return True
        return False

    def search_events(
        self,
        query: str = "",
        hours_back: int = 168,
        max_events: int = 50,
        usecase_filter: Optional[set[str]] = None,
    ) -> list[dict[str, Any]]:
        target_ids = usecase_filter or self.get_active_usecase_ids()
        if target_ids is None:
            if not self.has_corpus_match(query):
                return []
            target_ids = set(self.usecases.keys())

        if int(hours_back or 168) < 24:
            return []

        matched: list[dict[str, Any]] = []
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for ev in uc.events:
                if ev.matches_query(query):
                    matched.append(ev.to_udm_like_dict())
                    if len(matched) >= max_events:
                        return matched
        return matched

    def lookup_entity(
        self,
        entity_value: str,
        usecase_filter: Optional[set[str]] = None,
    ) -> Optional[dict[str, Any]]:
        val = str(entity_value or "").strip().lower()
        if not val:
            return None

        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())
        matched_entities: list[LogstoryEntity] = []
        matched_events = 0
        malicious_events = 0
        baseline_events = 0
        seen_usecases: set[str] = set()

        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for ent in uc.entities:
                if val in ent.identifier.lower() or val in ent.display_name.lower():
                    matched_entities.append(ent)
            for ev in uc.events:
                if (
                    val in ev.hostname.lower()
                    or val in ev.principal_user.lower()
                    or val in ev.target_user.lower()
                    or val == ev.src_ip.lower()
                    or val == ev.dst_ip.lower()
                    or val == ev.file_sha256.lower()
                    or val in ev.domain.lower()
                ):
                    matched_events += 1
                    seen_usecases.add(uid)
                    if ev.is_baseline:
                        baseline_events += 1
                    else:
                        malicious_events += 1

        if not matched_entities and matched_events == 0:
            return None

        primary = matched_entities[0] if matched_entities else None
        is_canary = "canary-" in val
        return {
            "status": "success",
            "server": "siem",
            "entity": entity_value,
            "entity_type": primary.entity_type if primary else "ASSET_OR_IOC",
            "display_name": primary.display_name if primary else entity_value,
            "department": primary.department if primary else "",
            "title": primary.title if primary else "",
            "roles_or_groups": primary.roles_or_groups if primary else [],
            "is_canary_honeytoken": is_canary,
            "event_counts": {
                "total": matched_events,
                "attack_usecase_events": malicious_events,
                "baseline_noise_events": baseline_events,
            },
            "usecases_observed": sorted(seen_usecases),
        }

    def list_scc_findings(
        self,
        query: str = "",
        category: str = "",
        usecase_filter: Optional[set[str]] = None,
    ) -> list[dict[str, Any]]:
        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())
        q_lower = str(query or "").strip().lower()
        cat_lower = str(category or "").strip().lower()
        results: list[dict[str, Any]] = []
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for f in uc.scc_findings:
                f_str = json.dumps(f, default=str).lower()
                if q_lower and q_lower not in f_str:
                    continue
                if cat_lower and cat_lower not in str(f.get("category") or "").lower():
                    continue
                results.append({"usecase_id": uid, **f})
        return results

    def resolve_usecase_id_for_case(self, case_id: str = "") -> Optional[str]:
        cid = str(case_id or "").strip().upper()
        if cid in self.usecases:
            return cid
        if cid.startswith("CASE-40"):
            try:
                idx = int(cid.split("-")[1]) - 4000
                keys = sorted(self.usecases.keys())
                if 0 <= idx < len(keys):
                    return keys[idx]
            except ValueError:
                pass
        active_ids = self.get_active_usecase_ids()
        if active_ids:
            non_base = [uid for uid in sorted(active_ids) if uid in self.usecases and not self.usecases[uid].is_baseline]
            if non_base:
                return non_base[0]
            valid = [uid for uid in sorted(active_ids) if uid in self.usecases]
            if valid:
                return valid[0]
        return None

    def list_alerts_for_case(self, case_id: str = "") -> list[dict[str, Any]]:
        uid = self.resolve_usecase_id_for_case(case_id)
        if not uid or uid not in self.usecases:
            return []
        uc = self.usecases[uid]
        by_log_type: dict[str, list[LogstoryEvent]] = {}
        for ev in uc.events:
            by_log_type.setdefault(ev.log_type, []).append(ev)

        alerts: list[dict[str, Any]] = []
        if uc.rules:
            log_types = sorted(by_log_type.keys())
            for i, rule in enumerate(uc.rules, start=1):
                lt = log_types[(i - 1) % len(log_types)] if log_types else "GENERIC"
                ev_slice = by_log_type.get(lt, uc.events)[:15]
                alerts.append({
                    "alert_id": f"ALERT-{uid}-{i}",
                    "case_id": f"CASE-{4000 + sorted(self.usecases.keys()).index(uid)}",
                    "rule_id": rule.rule_name,
                    "rule_name": rule.rule_name,
                    "severity": rule.meta.get("severity") or ("LOW" if uc.is_baseline else "HIGH"),
                    "log_type": lt,
                    "event_count": len(ev_slice),
                    "hosts": sorted({e.hostname for e in ev_slice if e.hostname and e.hostname != "-"}),
                    "users": sorted({u for e in ev_slice for u in (e.principal_user, e.target_user) if u and u != "-"}),
                    "ips": sorted({ip for e in ev_slice for ip in (e.src_ip, e.dst_ip) if ip and ip != "-"}),
                    "domains": sorted({e.domain for e in ev_slice if e.domain and e.domain != "-"})[:10],
                    "urls": sorted({e.url for e in ev_slice if e.url and e.url != "-"})[:10],
                    "hashes": sorted({e.file_sha256 for e in ev_slice if e.file_sha256 and e.file_sha256 != "-"})[:10],
                })
        else:
            for i, (lt, ev_slice) in enumerate(sorted(by_log_type.items()), start=1):
                alerts.append({
                    "alert_id": f"ALERT-{uid}-{i}",
                    "case_id": f"CASE-{4000 + sorted(self.usecases.keys()).index(uid)}",
                    "rule_id": f"baseline_monitor_{lt.lower()}",
                    "rule_name": f"Baseline Telemetry Review ({lt})",
                    "severity": "LOW" if uc.is_baseline else "MEDIUM",
                    "log_type": lt,
                    "event_count": len(ev_slice),
                    "hosts": sorted({e.hostname for e in ev_slice if e.hostname and e.hostname != "-"}),
                    "users": sorted({u for e in ev_slice for u in (e.principal_user, e.target_user) if u and u != "-"}),
                    "ips": sorted({ip for e in ev_slice for ip in (e.src_ip, e.dst_ip) if ip and ip != "-"}),
                    "domains": sorted({e.domain for e in ev_slice if e.domain and e.domain != "-"})[:10],
                    "urls": sorted({e.url for e in ev_slice if e.url and e.url != "-"})[:10],
                    "hashes": sorted({e.file_sha256 for e in ev_slice if e.file_sha256 and e.file_sha256 != "-"})[:10],
                })
        return alerts

    def list_events_for_alert(
        self,
        case_id: str = "",
        alert_id: str = "",
        max_events: int = 25,
    ) -> list[dict[str, Any]]:
        uid = self.resolve_usecase_id_for_case(case_id)
        if not uid and alert_id:
            m = re.match(r"^ALERT-([A-Z0-9_]+)-\d+$", str(alert_id).strip().upper())
            if m and m.group(1) in self.usecases:
                uid = m.group(1)
        if not uid or uid not in self.usecases:
            return []
        uc = self.usecases[uid]
        alerts = self.list_alerts_for_case(uid)
        aid = str(alert_id or "").strip().upper()
        target_log_type = ""
        for a in alerts:
            if a["alert_id"].upper() == aid:
                target_log_type = str(a.get("log_type") or "")
                break
        matched: list[dict[str, Any]] = []
        for ev in uc.events:
            if target_log_type and ev.log_type != target_log_type:
                continue
            matched.append(ev.to_udm_like_dict())
            if len(matched) >= max_events:
                break
        if not matched:
            matched = [ev.to_udm_like_dict() for ev in uc.events[:max_events]]
        return matched

    def build_soar_case(self, usecase_id: str) -> Optional[dict[str, Any]]:
        uc = self.usecases.get(usecase_id)
        if not uc:
            return None
        case_num = 4000 + sorted(self.usecases.keys()).index(usecase_id)
        urls = sorted({ev.url for ev in uc.events if ev.url and ev.url != "-"})
        alerts = self.list_alerts_for_case(usecase_id)
        return {
            "case_id": f"CASE-{case_num}",
            "usecase_id": usecase_id,
            "title": f"Logstory Scenario: {uc.title}",
            "description": uc.description,
            "priority": "LOW" if uc.is_baseline else "HIGH",
            "stage": "TRIAGE",
            "status": "OPEN",
            "tags": uc.tags,
            "hosts": uc.unique_hosts[:10],
            "users": uc.unique_users[:10],
            "ips": uc.unique_ips[:10],
            "hashes": uc.unique_hashes[:10],
            "domains": uc.unique_domains[:10],
            "urls": urls[:10],
            "alerts": alerts,
            "scc_findings_count": len(uc.scc_findings),
            "rules_count": len(uc.rules),
        }

    def get_gti_indicator_report(
        self,
        indicator: str,
        indicator_type: str,
        usecase_filter: Optional[set[str]] = None,
    ) -> Optional[dict[str, Any]]:
        ind = str(indicator or "").strip().lower()
        if not ind:
            return None
        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())

        in_attack = False
        in_baseline = False
        attack_usecases: set[str] = set()
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for ev in uc.events:
                if ind in (
                    ev.src_ip.lower(),
                    ev.dst_ip.lower(),
                    ev.file_sha256.lower(),
                    ev.domain.lower(),
                    ev.url.lower(),
                ) or (ev.url and ind in ev.url.lower()):
                    if ev.is_baseline:
                        in_baseline = True
                    else:
                        in_attack = True
                        attack_usecases.add(uid)

        if not in_attack and not in_baseline:
            return None

        # Private RFC1918 IPs and baseline-only indicators are clean
        is_private_ip = ind.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))
        if is_private_ip or (in_baseline and not in_attack):
            return {
                "status": "success",
                "server": "gti",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "verdict": "clean",
                "reputation_score": 0,
                "is_private_or_internal": is_private_ip,
                "note": "Internal Cymbal IP or benign baseline traffic.",
            }

        return {
            "status": "success",
            "server": "gti",
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": "malicious",
            "reputation_score": 92,
            "associated_campaigns": sorted(attack_usecases),
            "note": f"Confirmed malicious {indicator_type} observed in {', '.join(sorted(attack_usecases))}.",
        }

    def lookup_cloud_iam_principal(
        self,
        principal_email: str,
        usecase_filter: Optional[set[str]] = None,
    ) -> Optional[dict[str, Any]]:
        """Look up GCP/AWS/Azure/Workspace IAM roles and context for a principal."""
        email = str(principal_email or "").strip().lower()
        if not email:
            return None
        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())
        matched: list[LogstoryEntity] = []
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for ent in uc.entities:
                if email in ent.identifier.lower() or email in ent.display_name.lower():
                    matched.append(ent)
        if not matched:
            return None
        primary = matched[0]
        all_roles: list[str] = []
        for ent in matched:
            for r in ent.roles_or_groups:
                if r not in all_roles:
                    all_roles.append(r)
        return {
            "status": "success",
            "server": "scc",
            "principal_email": principal_email,
            "identifier": primary.identifier,
            "entity_type": primary.entity_type,
            "display_name": primary.display_name,
            "department": primary.department,
            "title": primary.title,
            "roles_or_groups": all_roles,
            "is_canary_honeytoken": "canary-" in email,
            "usecases": sorted({ent.usecase_id for ent in matched}),
        }

    def list_rules(
        self,
        query: str = "",
        usecase_filter: Optional[set[str]] = None,
    ) -> list[dict[str, Any]]:
        """List YARA-L 2.0 rules across active or matching Logstory usecases."""
        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())
        q_lower = str(query or "").strip().lower()
        results: list[dict[str, Any]] = []
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for r in uc.rules:
                haystack = f"{r.usecase_id} {r.rule_name} {r.file_name} {' '.join(r.mitre_techniques)} {json.dumps(r.meta)}".lower()
                if q_lower and q_lower not in haystack:
                    continue
                results.append(
                    {
                        "usecase_id": r.usecase_id,
                        "rule_id": r.rule_name,
                        "file_name": r.file_name,
                        "meta": r.meta,
                        "mitre_techniques": r.mitre_techniques,
                        "has_match": r.has_match_section,
                        "has_outcome": r.has_outcome_section,
                    }
                )
        return results

    def get_rule(
        self,
        rule_id: str,
        usecase_filter: Optional[set[str]] = None,
    ) -> Optional[dict[str, Any]]:
        """Retrieve a specific YARA-L 2.0 rule by rule_name or file_name."""
        rid = str(rule_id or "").strip().lower()
        if not rid:
            return None
        target_ids = usecase_filter or self.get_active_usecase_ids() or set(self.usecases.keys())
        for uid in sorted(target_ids):
            uc = self.usecases.get(uid)
            if not uc:
                continue
            for r in uc.rules:
                if rid in (r.rule_name.lower(), r.file_name.lower(), f"{r.usecase_id.lower()}:{r.rule_name.lower()}"):
                    return {
                        "status": "success",
                        "server": "siem",
                        "usecase_id": r.usecase_id,
                        "rule_id": r.rule_name,
                        "file_name": r.file_name,
                        "meta": r.meta,
                        "mitre_techniques": r.mitre_techniques,
                        "rule_text": r.raw_text,
                    }
        return None

    def validate_yaral2_rule(self, rule_text: str) -> dict[str, Any]:
        """Validate YARA-L 2.0 rule syntax and Chronicle UDM schema constraints."""
        text = str(rule_text or "").strip()
        errors: list[str] = []
        warnings: list[str] = []

        rule_m = re.search(r"\brule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{", text)
        if not rule_m:
            errors.append("Missing valid `rule <rule_name> {` header.")
        rule_name = rule_m.group(1) if rule_m else ""

        for section in ("meta", "events", "condition"):
            if not re.search(rf"^\s*{section}\s*:", text, re.MULTILINE):
                errors.append(f"Missing required `{section}:` section.")

        event_vars = sorted(set(re.findall(r"(\$[a-zA-Z_][a-zA-Z0-9_]*)\.", text)))
        if not event_vars:
            errors.append("No event variable bindings (e.g., `$e.metadata.event_type`) found in `events:`.")

        cond_m = re.search(r"\bcondition\s*:\s*(.*?)(?:\}\s*\Z|\Z)", text, re.DOTALL)
        if cond_m:
            cond_body = cond_m.group(1)
            for v in event_vars:
                if v not in cond_body:
                    warnings.append(f"Event variable `{v}` bound in `events:` is not referenced in `condition:`.")

        # Chronicle YARA-L 2.0 gotcha 1: inline tuple `in (...)` is invalid syntax
        if re.search(r"\bin\s*\(", text, re.IGNORECASE):
            errors.append(
                "Invalid inline `in (...)` tuple syntax. Chronicle YARA-L 2.0 `in` only supports "
                "reference lists (`in %list`) or data tables (`in %table.col`); use parenthesized `or` groups instead."
            )

        # Chronicle YARA-L 2.0 gotcha 2: UDM search aliases ($e.ip, $e.hash, $e.domain, $e.user)
        for alias in ("ip", "hash", "domain", "user", "hostname", "email"):
            if re.search(rf"\$[a-zA-Z0-9_]+\.{alias}\s*=", text):
                errors.append(
                    f"UDM search alias `.{alias}` is not valid in YARA-L 2.0 rules; "
                    f"use explicit UDM field paths (e.g., `principal.{alias}` or `target.{alias}`)."
                )

        if text.count("{") != text.count("}"):
            errors.append("Unbalanced curly braces `{` and `}` in rule definition.")

        return {
            "status": "success" if not errors else "invalid",
            "valid": len(errors) == 0,
            "rule_name": rule_name,
            "event_variables": event_vars,
            "errors": errors,
            "warnings": warnings,
        }


_GLOBAL_CORPUS: Optional[LogstoryCorpus] = None


def get_logstory_corpus() -> LogstoryCorpus:
    """Return the singleton LogstoryCorpus instance."""
    global _GLOBAL_CORPUS
    if _GLOBAL_CORPUS is None:
        _GLOBAL_CORPUS = LogstoryCorpus()
    return _GLOBAL_CORPUS


@contextmanager
def active_logstory_usecase(
    usecase_id: str,
    include_baselines: bool = True,
) -> Iterator[LogstoryUsecase]:
    """Context manager pinning MCP replay tools to a specific Logstory usecase."""
    corpus = get_logstory_corpus()
    if usecase_id not in corpus.usecases:
        raise KeyError(f"Unknown Logstory usecase: {usecase_id}")
    prev_id = _ACTIVE_USECASE_STATE.get("usecase_id")
    prev_base = _ACTIVE_USECASE_STATE.get("include_baselines", True)
    _ACTIVE_USECASE_STATE["usecase_id"] = usecase_id
    _ACTIVE_USECASE_STATE["include_baselines"] = include_baselines
    try:
        yield corpus.usecases[usecase_id]
    finally:
        _ACTIVE_USECASE_STATE["usecase_id"] = prev_id
        _ACTIVE_USECASE_STATE["include_baselines"] = prev_base
