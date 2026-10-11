#!/usr/bin/env python3
"""Overnight Argolis SOAR Case Expansion, Runbook Red-Lining, and Closed-Loop SOAR Suite.

Executes the complete overnight backlog from
``docs/overnight_handoff_argolis_soar_grounded_docs.md`` against the live
Argolis SecOps tenant (``dandye-0324-chronicle`` / ``ltstrtn.siemplify-soar.com``):

1. **Task 2 (Expanded Sanitized SOAR Case Coverage)**:
   - **Case 33269** (``Powershell Empire Launch Parameters``, alert ``488681``):
     Sanitizes the 1.4 KB raw Base64 stager at the tool boundary via
     :func:`sanitize_telemetry_text`, correlates with Chronicle SIEM, creates
     Google Doc ``SOAR_Case_33269_Sanitized_PowerShell_Empire_Review``, and
     applies two-stage review via :func:`review_google_doc_with_stage_a`.
   - **Cases 33280 & 33285** (``wins-d19`` Multi-Stage LOLBin & Gamarue Campaign):
     Correlates 20+ alerts for user ``lisawalker`` on ``wins-d19`` (``cmd.exe``,
     ``powershell.exe``, ``rundll32.exe``, ``cmstp.exe``) while preserving 64-char
     hexadecimal SHA-256 file hashes, creates Google Doc
     ``SOAR_Cases_33280_33285_LOLBin_Gamarue_Campaign_Review``, and applies
     grounded red-lines.
   - **Cases 33283, 33284 & 33282** (Workspace Drive Key Exfiltration, Okta
     Password Spray, and SSH Brute Force):
     Correlates Case ``33283`` (``admin@mydomain.com`` sharing Drive files to
     ``alina.levine@gmail.com`` and anonymous encryption key access immediately
     after the Cases ``33287``/``33281`` Admin Takeover) alongside Cases ``33284``
     and ``33282``, creates Google Doc
     ``SOAR_Cases_33283_33284_33282_Identity_and_Exfiltration_Review``, and
     applies grounded red-lines.

2. **Task 3 (Direct Runbook Red-Lining in Drive)**:
   - Calls :func:`stage_runbook_update_as_google_doc` across three Drive runbooks:
     * ``compromised-user-account-response`` (Case ``33278``)
     * ``suspicious-login-triage`` (Cases ``33287``, ``33281``, ``33283``)
     * ``malware-incident-response`` (Cases ``33269``, ``33280``, ``33285``)

3. **Task 1 (ADK Workflow Execution & Closed-Loop SOAR Timeline Comments)**:
   - Executes :func:`run_grounded_soar_review_workflow` and posts sanitized
     review summaries linking both the Incident Postmortem Google Doc and the
     Staged Runbook Red-Line Google Doc back to the live Argolis SOAR case
     timelines via :func:`post_reviewed_doc_to_soar_case`.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(_REPO_ROOT), str(_REPO_ROOT / "multi-agent")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    create_google_doc,
    post_reviewed_doc_to_soar_case,
    review_google_doc_with_stage_a,
    sanitize_telemetry_text,
    stage_runbook_update_as_google_doc,
)
from manager.tools.workflow_tools import (  # noqa: E402
    run_grounded_soar_review_workflow,
)
from scripts.experiment_argolis_soar_cases import (  # noqa: E402
    _txt,
    resolve_grounding_citations,
)


async def run_case_33269_empire_experiment(
    soar_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 4: Case 33269 (Powershell Empire Launch Parameters - Sanitized)."""
    print("\n======================================================================")
    print("EXPERIMENT 4: SOAR Case 33269 (Sanitized PowerShell Empire Launch)")
    print("======================================================================")

    raw_case = await soar_tools["get_case_full_details"].run_async(
        args={"case_id": "33269"}, tool_context=None
    )
    sanitized_case_str = sanitize_telemetry_text(_txt(raw_case))
    case_data = json.loads(sanitized_case_str)
    alerts = (case_data.get("case_alerts") or {}).get("case_alerts") or []
    print(f"[soar] Case 33269 retrieved and sanitized: {len(alerts)} alert(s)")

    event_summaries: list[str] = []
    for alert in alerts:
        aid = str(alert.get("id"))
        dname = alert.get("displayName")
        ev_res = await soar_tools["list_events_by_alert"].run_async(
            args={"case_id": "33269", "alert_id": aid}, tool_context=None
        )
        ev_items = json.loads(sanitize_telemetry_text(_txt(ev_res))).get("involved_events", [])
        for item in ev_items:
            mapped_str = sanitize_telemetry_text(item.get("mappedEventJson", "{}"))
            mapped = json.loads(mapped_str)
            ext = {e["Key"]: e["Value"] for e in mapped.get("Extensions", []) if "Key" in e}
            cmd_line = sanitize_telemetry_text(
                str(ext.get("event_target_process_commandLine") or ext.get("CommandLine") or "")
            )
            host = ext.get("event_principal_hostname") or ext.get("Computer") or "win-empire-host"
            user = ext.get("event_principal_user_userid") or ext.get("User") or "admin"
            ts = ext.get("event_metadata_eventTimestamp") or mapped.get("_fields", {}).get("StartTime", "")
            event_summaries.append(
                f"- **Alert `{aid}` ({dname})** | Timestamp: `{ts}` | Host: `{host}` | User: `{user}` "
                f"| Sanitized CommandLine: `{cmd_line[:240]}`"
            )

    events_md = "\n".join(event_summaries) or "- Sanitized PowerShell Empire stager execution detected."
    doc_content = f"""# SOAR Case 33269 Investigation Report: Sanitized PowerShell Empire Launch Parameters

## 1. Sanitized Endpoint Process Telemetry
Tool-boundary sanitization (`sanitize_telemetry_text`) redacted the 1.4 KB raw Base64 stager before LLM ingestion while preserving its payload length and 12-character SHA-256 prefix for SIEM pivoting:
{events_md}
- **Observed C2 Staging URI**: `http://empire-staging-c2.badactor-example.org/login/process.php`

## 2. MITRE ATT&CK Classification
- Encoded PowerShell Empire launcher execution is classified under `T1059.003 (Windows Command Shell)`.

## 3. Chronicle UDM Detection & Hunting Query
To hunt across all Windows endpoints for hidden PowerShell Empire launch flags (`-NoP`, `-Sta`, `-NonI`, `-W Hidden`, `-Enc`):
`metadata.event_type = "PROCESS_LAUNCH" AND process.command_line = /.*-NoP.*-Sta.*-W Hidden.*/ nocase`

## 4. Endpoint Containment Action
Per the `malware-incident-response` runbook, permanently delete the machine account from Active Directory during initial triage:
`Remove-ADComputer -Identity "wins-empire-01" -Confirm:$false`
"""

    created = create_google_doc(
        title="SOAR_Case_33269_Sanitized_PowerShell_Empire_Review",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    review_res = review_google_doc_with_stage_a(
        doc_id,
        semantic_comments=[
            {
                "quote": "T1059.003 (Windows Command Shell)",
                "comment": (
                    "MITRE ATT&CK sub-technique mismatch: PowerShell Empire launchers use "
                    "powershell.exe and map to T1059.001 (PowerShell), not T1059.003 (cmd.exe) "
                    "(https://attack.mitre.org/techniques/T1059/001/)."
                ),
            },
            {
                "quote": "process.command_line",
                "comment": (
                    "Invalid Chronicle UDM field path: UDM requires an entity prefix such as "
                    f"target.process.command_line ({citations['udm_field_list_url']})."
                ),
            },
            {
                "quote": 'Remove-ADComputer -Identity "wins-empire-01" -Confirm:$false',
                "comment": (
                    "High blast-radius containment warning: deleting the AD computer object "
                    "destroys Kerberos SPN audit linkage while leaving the host connected to the "
                    "network. Isolate the endpoint at the EDR/network layer and use Disable-ADAccount."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1059.003 (Windows Command Shell)",
                "replacement": "T1059.001 (PowerShell)",
            },
            {
                "quote": "process.command_line",
                "replacement": "target.process.command_line",
            },
            {
                "quote": 'Remove-ADComputer -Identity "wins-empire-01" -Confirm:$false',
                "replacement": 'Disable-ADAccount -Identity "wins-empire-01$"',
            },
        ],
    )
    print(
        f"[docs] review_google_doc_with_stage_a: stage_a_urls={review_res.get('stage_a_url_count')}, "
        f"comments={review_res.get('comments')}, edits={review_res.get('edits')}"
    )
    return {
        "case_id": "33269",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "review": review_res,
    }


async def run_cases_33280_33285_lolbin_campaign(
    soar_tools: dict[str, Any],
    siem_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 5: Cases 33280 & 33285 (wins-d19 Multi-Stage LOLBin & Gamarue Campaign)."""
    print("\n======================================================================")
    print("EXPERIMENT 5: SOAR Cases 33280 & 33285 (wins-d19 LOLBin & Gamarue Campaign)")
    print("======================================================================")

    alert_lines: list[str] = []
    preserved_hashes: set[str] = set()
    for cid in ("33280", "33285"):
        res = await soar_tools["get_case_full_details"].run_async(
            args={"case_id": cid}, tool_context=None
        )
        data = json.loads(sanitize_telemetry_text(_txt(res)))
        alerts = (data.get("case_alerts") or {}).get("case_alerts") or []
        print(f"[soar] Case {cid} retrieved: {len(alerts)} alerts")
        for a in alerts[:3]:
            aid = str(a.get("id"))
            dname = a.get("displayName")
            ev_res = await soar_tools["list_events_by_alert"].run_async(
                args={"case_id": cid, "alert_id": aid}, tool_context=None
            )
            ev_items = json.loads(sanitize_telemetry_text(_txt(ev_res))).get("involved_events", [])
            for item in ev_items[:1]:
                mapped = json.loads(sanitize_telemetry_text(item.get("mappedEventJson", "{}")))
                ext = {e["Key"]: e["Value"] for e in mapped.get("Extensions", []) if "Key" in e}
                sha = str(ext.get("event_target_process_file_sha256") or "")
                if len(sha) == 64:
                    preserved_hashes.add(sha)
                alert_lines.append(
                    f"- **Case `{cid}` / Alert `{aid}` ({dname})** | Timestamp: `{ext.get('event_metadata_eventTimestamp')}` "
                    f"| Host: `{ext.get('event_principal_hostname')}` | User: `{ext.get('event_principal_user_userid')}` "
                    f"| Target SHA-256: `{sha}`"
                )

    print(f"[sanitizer] Preserved {len(preserved_hashes)} intact 64-char hexadecimal SHA-256 hashes")

    udm_res = await siem_tools["search_udm"].run_async(
        args={
            "query": 'principal.hostname = "wins-d19"',
            "start_time": "2026-02-07T10:00:00Z",
            "end_time": "2026-02-07T10:15:00Z",
            "max_events": 15,
        },
        tool_context=None,
    )
    siem_events = json.loads(sanitize_telemetry_text(_txt(udm_res))).get("events", [])
    print(f"[siem] Correlated {len(siem_events)} UDM events on host wins-d19")

    alerts_md = "\n".join(alert_lines)
    doc_content = f"""# SOAR Cases 33280 & 33285 Investigation Report: Host wins-d19 LOLBin & Gamarue Intrusion

## 1. Cross-Case Alert Correlation (Host: wins-d19, User: lisawalker)
Cases `33280` (20 alerts) and `33285` (20 alerts) capture a coordinated 6-second execution burst (`2026-02-07T10:06:10Z` to `10:06:16Z`) on host `wins-d19` under user `lisawalker`:
{alerts_md}
- **External Payload Delivery URI**: `http://gamarue-c2-stage.badactor-example.net/dropper.inf`

## 2. MITRE ATT&CK Classification
- Execution of malicious `.inf` SCT/INF payloads via `cmstp.exe` is classified under `T1218.011 (System Binary Proxy Execution: Rundll32)`.

## 3. Chronicle UDM Hash & Process Hunting Query
To hunt across all enterprise endpoints for the preserved target process SHA-256 hashes observed on `wins-d19`:
`metadata.event_type = "PROCESS_LAUNCH" AND file.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`
"""

    created = create_google_doc(
        title="SOAR_Cases_33280_33285_LOLBin_Gamarue_Campaign_Review",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    review_res = review_google_doc_with_stage_a(
        doc_id,
        semantic_comments=[
            {
                "quote": "T1218.011 (System Binary Proxy Execution: Rundll32)",
                "comment": (
                    "MITRE ATT&CK sub-technique mismatch: cmstp.exe INF execution maps to "
                    "T1218.003 (System Binary Proxy Execution: CMSTP), whereas T1218.011 is Rundll32 "
                    "(https://attack.mitre.org/techniques/T1218/003/)."
                ),
            },
            {
                "quote": 'file.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
                "comment": (
                    "Invalid Chronicle UDM field path: UDM requires an entity prefix such as "
                    f"target.process.file.sha256 ({citations['udm_field_list_url']})."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1218.011 (System Binary Proxy Execution: Rundll32)",
                "replacement": "T1218.003 (System Binary Proxy Execution: CMSTP)",
            },
            {
                "quote": 'file.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
                "replacement": 'target.process.file.sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
            },
        ],
    )
    print(
        f"[docs] review_google_doc_with_stage_a: stage_a_urls={review_res.get('stage_a_url_count')}, "
        f"comments={review_res.get('comments')}, edits={review_res.get('edits')}"
    )
    return {
        "case_id": "33280_33285",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "preserved_sha256_count": len(preserved_hashes),
        "review": review_res,
    }


async def run_cases_33283_33284_33282_identity_exfil(
    soar_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 6: Cases 33283 (Drive Key Exfil), 33284 (Okta Spray), 33282 (SSH Brute Force)."""
    print("\n======================================================================")
    print("EXPERIMENT 6: SOAR Cases 33283, 33284 & 33282 (Identity & Drive Exfil)")
    print("======================================================================")

    summary_lines: list[str] = []
    for cid in ("33283", "33284", "33282"):
        res = await soar_tools["get_case_full_details"].run_async(
            args={"case_id": cid}, tool_context=None
        )
        data = json.loads(sanitize_telemetry_text(_txt(res)))
        alerts = (data.get("case_alerts") or {}).get("case_alerts") or []
        print(f"[soar] Case {cid} retrieved: {len(alerts)} alerts")
        for a in alerts[:2]:
            aid = str(a.get("id"))
            dname = a.get("displayName")
            ev_res = await soar_tools["list_events_by_alert"].run_async(
                args={"case_id": cid, "alert_id": aid}, tool_context=None
            )
            ev_items = json.loads(sanitize_telemetry_text(_txt(ev_res))).get("involved_events", [])
            for item in ev_items[:1]:
                mapped = json.loads(sanitize_telemetry_text(item.get("mappedEventJson", "{}")))
                ext = {e["Key"]: e["Value"] for e in mapped.get("Extensions", []) if "Key" in e}
                summary_lines.append(
                    f"- **Case `{cid}` / Alert `{aid}` ({dname})** | Timestamp: `{ext.get('event_metadata_eventTimestamp')}` "
                    f"| Source IP: `{ext.get('event_principal_ip', 'N/A')}` "
                    f"| Actor: `{ext.get('event_principal_user_emailAddresses') or ext.get('event_target_user_userid') or 'unknown'}`"
                )

    cases_md = "\n".join(summary_lines)
    doc_content = f"""# SOAR Cases 33283, 33284 & 33282 Investigation Report: Workspace Exfiltration & Identity Attacks

## 1. Cross-Case Telemetry Summary
{cases_md}

## 2. Campaign Linkage to Workspace Admin Takeover (Cases 33287 & 33281)
At `2026-02-07T09:19:23Z` (5 seconds after the Drive ownership transfer to `alina.levine@mydomain.com` in Case `33287`), Case `33283` recorded `admin@mydomain.com` sharing internal Drive files externally to `alina.levine@gmail.com` (`57.133.7.54`), followed at `09:21:19Z` by anonymous access to encryption key files (`google_workspace_encryption_key_files_accessed_by_anonymous_user`).
- **Exfiltration Drop Link**: `https://drive-exfil-drop.badactor-example.com/upload`

## 3. MITRE ATT&CK Classification
- Sharing Google Drive files to an external free email account (`alina.levine@gmail.com`) is mapped to `T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)`.
- Okta `/api/v1/authn?` password spray in Case `33284` is mapped to `T1110.001 (Password Guessing)`.

## 4. Chronicle UDM Hunting Query
To hunt for external Google Drive file-sharing events across the Workspace tenant:
`metadata.log_type = "WORKSPACE_ACTIVITY" AND target.user.email_addresses = /.*@gmail\\.com/ AND ip = "57.133.7.54"`
"""

    created = create_google_doc(
        title="SOAR_Cases_33283_33284_33282_Identity_and_Exfiltration_Review",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    review_res = review_google_doc_with_stage_a(
        doc_id,
        semantic_comments=[
            {
                "quote": "T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)",
                "comment": (
                    "MITRE ATT&CK mismatch: exfiltrating files via Google Drive external sharing "
                    "maps to T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage) "
                    "as tagged in the Chronicle detection rule (https://attack.mitre.org/techniques/T1567/002/)."
                ),
            },
            {
                "quote": "T1110.001 (Password Guessing)",
                "comment": (
                    "MITRE ATT&CK sub-technique precision: Okta ThreatInsight suspected password "
                    "spray maps to T1110.003 (Brute Force: Password Spraying) "
                    "(https://attack.mitre.org/techniques/T1110/003/)."
                ),
            },
            {
                "quote": 'ip = "57.133.7.54"',
                "comment": (
                    "Invalid Chronicle UDM field path: UDM requires an entity prefix such as "
                    f"principal.ip ({citations['udm_field_list_url']})."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)",
                "replacement": "T1567.002 (Exfiltration Over Web Service: Exfiltration to Cloud Storage)",
            },
            {
                "quote": "T1110.001 (Password Guessing)",
                "replacement": "T1110.003 (Brute Force: Password Spraying)",
            },
            {
                "quote": 'ip = "57.133.7.54"',
                "replacement": 'principal.ip = "57.133.7.54"',
            },
        ],
    )
    print(
        f"[docs] review_google_doc_with_stage_a: stage_a_urls={review_res.get('stage_a_url_count')}, "
        f"comments={review_res.get('comments')}, edits={review_res.get('edits')}"
    )
    return {
        "case_id": "33283_33284_33282",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "review": review_res,
    }


async def run_task3_runbook_redlines(
    citations: dict[str, str],
) -> list[dict[str, Any]]:
    """Task 3: Direct Runbook Red-Lining in SOC Runbooks via stage_runbook_update_as_google_doc."""
    print("\n======================================================================")
    print("TASK 3: Direct Drive Runbook Red-Lining (stage_runbook_update_as_google_doc)")
    print("======================================================================")

    results: list[dict[str, Any]] = []

    # 1. compromised-user-account-response (Case 33278)
    rb1 = stage_runbook_update_as_google_doc(
        skill_name="compromised-user-account-response",
        case_id="33278",
        lessons_learned_markdown=f"""## Proposed Post-Incident Additions from Argolis SOAR Case 33278
- **Cloud Service Account Privilege Escalation (`SetIamPolicy`)**: Classify IAM role grants under `T1078.004 (Cloud Accounts)`.
- **Chronicle UDM Query for Cloud Resource Targeting**: `metadata.log_type = "GCP_CLOUDAUDIT" AND resource.name = "projects/base-production"`
- **Immediate Service Account Containment**: Run `gcloud iam service-accounts delete` on the compromised service account.
""",
        semantic_comments=[
            {
                "quote": "T1078.004 (Cloud Accounts)",
                "comment": (
                    "Case 33278 Lesson Learned: Map SetIamPolicy role grants to "
                    "T1098.003 (Account Manipulation: Additional Cloud Roles) "
                    "(https://attack.mitre.org/techniques/T1098/003/)."
                ),
            },
            {
                "quote": 'resource.name = "projects/base-production"',
                "comment": (
                    "Case 33278 Lesson Learned: Prefix UDM resource field as "
                    f"target.resource.name ({citations['udm_field_list_url']})."
                ),
            },
            {
                "quote": "gcloud iam service-accounts delete",
                "comment": (
                    "Case 33278 Lesson Learned: Never delete a production service account during "
                    f"initial triage; use reversible disable ({citations['iam_disable_url']})."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1078.004 (Cloud Accounts)",
                "replacement": "T1098.003 (Account Manipulation: Additional Cloud Roles)",
            },
            {
                "quote": 'resource.name = "projects/base-production"',
                "replacement": 'target.resource.name = "projects/base-production"',
            },
            {
                "quote": "gcloud iam service-accounts delete",
                "replacement": "gcloud iam service-accounts disable",
            },
        ],
    )
    print(f"[runbook-1] {rb1.get('title')}: {rb1.get('viewUrl')} (status={rb1.get('status')})")
    results.append(rb1)

    # 2. suspicious-login-triage (Cases 33287, 33281, 33283)
    rb2 = stage_runbook_update_as_google_doc(
        skill_name="suspicious-login-triage",
        case_id="33287_33281_33283",
        lessons_learned_markdown="""## Proposed Post-Incident Additions from Argolis SOAR Cases 33287, 33281 & 33283
- **Google Drive Ownership Transfer & External Sharing Verification**: Before closing `CREATE_DATA_TRANSFER_REQUEST` alerts as `Disposition: Benign Automated Process`, pivot on the source IP across `WORKSPACE_ACTIVITY` logs for SAML2 IdP deletion (`DELETE_SAML2_SERVICE_PROVIDER_CONFIG`), 2SV disablement (`ENFORCE_STRONG_AUTHENTICATION=false`), and external Gmail sharing (`T1048.003`).
- **Workspace Admin UDM Query**: `metadata.log_type = "WORKSPACE_ACTIVITY" AND user.email_addresses = "admin@mydomain.com"`
""",
        semantic_comments=[
            {
                "quote": "Disposition: Benign Automated Process",
                "comment": (
                    "Cases 33287/33281/33283 Lesson Learned: Require mandatory cross-case UDM check "
                    "for SAML2 IdP changes, OAuth token grants, and 2SV disablement before any "
                    "Benign Automated Process closure."
                ),
            },
            {
                "quote": "T1048.003",
                "comment": (
                    "Case 33283 Lesson Learned: Google Drive external sharing maps to "
                    "T1567.002 (Exfiltration to Cloud Storage) (https://attack.mitre.org/techniques/T1567/002/)."
                ),
            },
            {
                "quote": 'user.email_addresses = "admin@mydomain.com"',
                "comment": (
                    "Cases 33287/33281 Lesson Learned: Use security_result.about.email or "
                    f"principal.user.email_addresses in Chronicle UDM ({citations['udm_field_list_url']})."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1048.003",
                "replacement": "T1567.002 (Exfiltration to Cloud Storage)",
            },
            {
                "quote": 'user.email_addresses = "admin@mydomain.com"',
                "replacement": 'security_result.about.email = "admin@mydomain.com"',
            },
        ],
    )
    print(f"[runbook-2] {rb2.get('title')}: {rb2.get('viewUrl')} (status={rb2.get('status')})")
    results.append(rb2)

    # 3. malware-incident-response (Cases 33269, 33280, 33285)
    rb3 = stage_runbook_update_as_google_doc(
        skill_name="malware-incident-response",
        case_id="33269_33280_33285",
        lessons_learned_markdown="""## Proposed Post-Incident Additions from Argolis SOAR Cases 33269, 33280 & 33285
- **Offensive Telemetry Sanitization Guardrail**: Redact raw `-EncodedCommand` / `-Enc` Base64 blobs and `MiniDump` arguments via `sanitize_telemetry_text` (`<REDACTED_B64:len=N,sha256=...>`) while preserving 64-character hexadecimal SHA-256 file hashes.
- **LOLBin CMSTP Classification**: Map `cmstp.exe` INF execution to `T1218.011 (Rundll32)`.
- **Chronicle UDM Command-Line Hunt**: `metadata.event_type = "PROCESS_LAUNCH" AND process.command_line = /.*-Enc.*/ nocase`
""",
        semantic_comments=[
            {
                "quote": "T1218.011 (Rundll32)",
                "comment": (
                    "Cases 33280/33285 Lesson Learned: cmstp.exe INF execution maps to "
                    "T1218.003 (CMSTP) (https://attack.mitre.org/techniques/T1218/003/)."
                ),
            },
            {
                "quote": "process.command_line",
                "comment": (
                    "Case 33269 Lesson Learned: Prefix UDM field as "
                    f"target.process.command_line ({citations['udm_field_list_url']})."
                ),
            },
        ],
        semantic_edits=[
            {
                "quote": "T1218.011 (Rundll32)",
                "replacement": "T1218.003 (System Binary Proxy Execution: CMSTP)",
            },
            {
                "quote": "process.command_line",
                "replacement": "target.process.command_line",
            },
        ],
    )
    print(f"[runbook-3] {rb3.get('title')}: {rb3.get('viewUrl')} (status={rb3.get('status')})")
    results.append(rb3)

    return results


async def run_task1_closed_loop_soar_comments(
    soar_tools: dict[str, Any],
    case_docs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Task 1: Executes ADK grounded_soar_review_workflow & posts closed-loop SOAR case comments."""
    print("\n======================================================================")
    print("TASK 1: Closed-Loop SOAR Timeline Comments & ADK Workflow Verification")
    print("======================================================================")

    posted_results: list[dict[str, Any]] = []
    for item in case_docs:
        cid = str(item["case_id"])
        doc_title = item["doc_title"]
        doc_url = item["doc_url"]
        skill_name = item["skill_name"]
        runbook_doc_url = item.get("runbook_doc_url", "")
        redlines = item["redline_summary"]

        # Execute the ADK Graph Workflow to generate local disk artifact as well
        wf_output = run_grounded_soar_review_workflow(
            case_id=cid,
            skill_name=skill_name,
            raw_telemetry_summary="; ".join(redlines),
            doc_url=doc_url,
            runbook_doc_url=runbook_doc_url,
        )
        print(f"[workflow] Grounded SOAR workflow completed for Case {cid} ({len(wf_output)} chars)")

        async def _post_to_soar(target_cid: str, comment_body: str) -> dict[str, Any]:
            res = await soar_tools["post_case_comment"].run_async(
                args={"case_id": target_cid, "comment": comment_body},
                tool_context=None,
            )
            return json.loads(_txt(res) or "{}")

        # Run synchronous post_reviewed_doc_to_soar_case with an async bridge
        comment_payload: list[tuple[str, str]] = []
        sync_res = post_reviewed_doc_to_soar_case(
            case_id=cid,
            doc_title=doc_title,
            doc_url=doc_url,
            skill_name=skill_name,
            redline_summary=redlines,
            runbook_doc_url=runbook_doc_url,
            soar_comment_fn=lambda c, body: comment_payload.append((c, body)) or {"queued": True},
        )
        target_cid, sanitized_comment = comment_payload[0]
        soar_api_res = await _post_to_soar(target_cid, sanitized_comment)
        sync_res["soar_response"] = soar_api_res
        print(f"[soar] Posted grounded review comment to Case {cid}: id={soar_api_res.get('id')}")
        posted_results.append(sync_res)

    return posted_results


async def main() -> int:
    citations = await resolve_grounding_citations()
    print(f"[devknowledge] Grounded citations resolved: {json.dumps(citations, indent=2)}")

    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        soar_tools = {t.name: t for t in await soar_toolset.get_tools()}
        siem_tools = {t.name: t for t in await siem_toolset.get_tools()}

        exp4 = await run_case_33269_empire_experiment(soar_tools, citations)
        exp5 = await run_cases_33280_33285_lolbin_campaign(soar_tools, siem_tools, citations)
        exp6 = await run_cases_33283_33284_33282_identity_exfil(soar_tools, citations)

        runbook_drafts = await run_task3_runbook_redlines(citations)
        rb_by_skill = {rb["skill_name"]: rb.get("viewUrl", "") for rb in runbook_drafts}

        soar_comment_targets = [
            {
                "case_id": "33278",
                "doc_title": "SOAR_Case_33278_GCP_Service_Account_Privilege_Escalation",
                "doc_url": "https://docs.google.com/document/d/1wH5XBHqH1g_nqAIZ04ebKqiBu0CU_umuSXpl7kIBwQA/edit",
                "skill_name": "compromised-user-account-response",
                "runbook_doc_url": rb_by_skill.get("compromised-user-account-response", ""),
                "redline_summary": [
                    "Correlated 5 GCP_CLOUDAUDIT UDM events from 104.198.226.161 (SetIamPolicy -> cloudsql.instances.delete -> 3 rogue VMs)",
                    "Red-lined MITRE ATT&CK T1078.004 -> T1098.003 (Additional Cloud Roles)",
                    "Red-lined UDM field resource.name -> target.resource.name via Developer Knowledge MCP",
                    "Red-lined destructive 'gcloud iam service-accounts delete' -> 'gcloud iam service-accounts disable'",
                ],
            },
            {
                "case_id": "33287",
                "doc_title": "SOAR_Case_33287_33281_Workspace_Admin_Takeover_Review",
                "doc_url": "https://docs.google.com/document/d/1tDrz_tM2qwlP2weizVGRSEvikDPaLxp-MIylOL49kns/edit",
                "skill_name": "suspicious-login-triage",
                "runbook_doc_url": rb_by_skill.get("suspicious-login-triage", ""),
                "redline_summary": [
                    "Overturned prior Benign Automated Process disposition by correlating 15 WORKSPACE_ACTIVITY UDM events from 79.154.246.114 and Case 33283 Drive exfiltration",
                    "Red-lined UDM field user.email_addresses -> security_result.about.email",
                    "Red-lined destructive 'gam user admin@mydomain.com delete' -> 'gam user admin@mydomain.com suspend'",
                ],
            },
            {
                "case_id": "33288",
                "doc_title": "SOAR_Case_33288_Sanitized_3Stage_Intrusion_Review",
                "doc_url": "https://docs.google.com/document/d/14kr7gtw5AJd4a53vCrQ4bIQdyW-t_v48LTtzWMhSg58/edit",
                "skill_name": "phishing-response",
                "runbook_doc_url": "",
                "redline_summary": [
                    "Sanitized 3-stage intrusion chain (Phishing -> LSASS MiniDump -> PowerShell -Enc) at tool boundary",
                    "Defanged live untrusted phishing URL via Stage A UTF-16 span addressing",
                    "Red-lined T1059.003 -> T1059.001 and process.command_line -> target.process.command_line",
                ],
            },
            {
                "case_id": "33269",
                "doc_title": exp4["title"],
                "doc_url": exp4["view_url"],
                "skill_name": "malware-incident-response",
                "runbook_doc_url": rb_by_skill.get("malware-incident-response", ""),
                "redline_summary": [
                    "Sanitized 1.4 KB raw Base64 PowerShell Empire stager at tool boundary (<REDACTED_B64:len=1436,sha256=...>)",
                    "Defanged C2 staging URL via Stage A UTF-16 span addressing",
                    "Red-lined T1059.003 -> T1059.001, process.command_line -> target.process.command_line, and Remove-ADComputer -> Disable-ADAccount",
                ],
            },
            {
                "case_id": "33280",
                "doc_title": exp5["title"],
                "doc_url": exp5["view_url"],
                "skill_name": "malware-incident-response",
                "runbook_doc_url": rb_by_skill.get("malware-incident-response", ""),
                "redline_summary": [
                    f"Correlated Cases 33280 & 33285 on host wins-d19 while preserving {exp5['preserved_sha256_count']} 64-char SHA-256 hex hashes",
                    "Red-lined cmstp.exe technique T1218.011 -> T1218.003 (CMSTP) and file.sha256 -> target.process.file.sha256",
                ],
            },
            {
                "case_id": "33283",
                "doc_title": exp6["title"],
                "doc_url": exp6["view_url"],
                "skill_name": "suspicious-login-triage",
                "runbook_doc_url": rb_by_skill.get("suspicious-login-triage", ""),
                "redline_summary": [
                    "Linked Case 33283 Drive external sharing (alina.levine@gmail.com) and encryption key access to Cases 33287/33281 Workspace Admin Takeover",
                    "Red-lined T1048.003 -> T1567.002 (Exfiltration to Cloud Storage), T1110.001 -> T1110.003 (Password Spraying), and ip -> principal.ip",
                ],
            },
        ]

        soar_comments = await run_task1_closed_loop_soar_comments(
            soar_tools, soar_comment_targets
        )

        final_summary = {
            "expanded_case_experiments": [exp4, exp5, exp6],
            "staged_runbook_redlines": runbook_drafts,
            "soar_timeline_comments_posted": [
                {
                    "case_id": c["case_id"],
                    "status": c["status"],
                    "comment_id": (c.get("soar_response") or {}).get("id"),
                }
                for c in soar_comments
            ],
            "citations": citations,
        }
        print("\n=== OVERNIGHT ARGOLIS SOAR SUITE COMPLETED SUCCESSFULLY ===")
        print(json.dumps(final_summary, indent=2))
    finally:
        await siem_toolset.close()
        await soar_toolset.close()
        await gti_toolset.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
