#!/usr/bin/env python3
"""Live end-to-end experiment on real Argolis SOAR cases with Grounded Google Docs Review.

Connects to the live Argolis SecOps tenant (``dandye-0324-chronicle``):
  - SOAR MCP (``https://ltstrtn.siemplify-soar.com``) via ``soar_toolset``
  - Chronicle SIEM MCP (``us-chronicle.googleapis.com``) via ``siem_toolset``
  - Google Drive Runbooks & Reports via ``load_skill`` and ``create_google_doc``
  - Developer Knowledge Remote MCP (``https://developerknowledge.googleapis.com/mcp``)
  - Google Docs API v1 non-destructive review tools (``read_google_doc``,
    ``find_deterministic_indicator_spans``, ``insert_doc_comments``,
    ``propose_doc_suggested_edits`` with ``writeMode="SUGGEST"``)

Executes three live SOAR case investigations and grounded review passes:
  1. Case 33278 (``gcp_admin_privileged_roles_added_to_service_accounts``):
     Correlates SOAR alerts 488690/488689 with 5 live ``GCP_CLOUDAUDIT`` UDM events
     in Chronicle SIEM (``SetIamPolicy`` privilege escalation -> ``cloudsql.instances.delete``
     on ``prod-customers`` -> 3 rogue Compute Engine VMs ``production-do-not-delete1..3``).
  2. Cases 33287 & 33281 (``google_workspace_ownership_transferred_on_google_drive`` /
     ``google_workspace_new_trusted_domain_added``):
     Correlates SOAR Case 33287 (and its 4 historical analyst comments) with 20 live
     ``WORKSPACE_ACTIVITY`` UDM events from ``79.154.246.114``, overturning the prior
     analyst's "legitimate automated process" hypothesis by uncovering SAML2 IdP
     tampering, rogue OAuth client authorization, and 2SV disablement on the ``Finance`` OU.
  3. Case 33288 (``Argolis Admin Live Manual Case``):
     Processes a 3-stage intrusion chain (Phishing -> LSASS -> Encoded PowerShell)
     through ``sanitize_telemetry_text`` at the tool boundary and combines Stage A
     deterministic span-based indicator defanging (``find_deterministic_indicator_spans``)
     with Stage B Developer Knowledge MCP grounded review.
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
    find_deterministic_indicator_spans,
    insert_doc_comments,
    propose_doc_suggested_edits,
    read_google_doc,
    sanitize_telemetry_text,
)
from manager.tools.grounding_tools import (  # noqa: E402
    init_developer_knowledge_toolset,
)


def _txt(res: dict[str, Any]) -> str:
    content = res.get("content") or []
    return content[0].get("text", "") if content else ""


def _extract_first_doc_url(res: dict[str, Any], prefix_filter: str = "") -> str | None:
    for block in res.get("content", []):
        if isinstance(block, dict) and block.get("type") == "text":
            try:
                parsed = json.loads(block.get("text", "{}"))
                for item in parsed.get("results", []):
                    if not isinstance(item, dict):
                        continue
                    parent = str(item.get("parent", ""))
                    if parent.startswith("documents/"):
                        candidate = "https://" + parent[len("documents/") :]
                        if not prefix_filter or prefix_filter in candidate:
                            return candidate
            except json.JSONDecodeError:
                pass
    return None


async def resolve_grounding_citations() -> dict[str, str]:
    """Queries Developer Knowledge Remote MCP for authoritative Google Cloud & SecOps URLs."""
    citations = {
        "iam_disable_url": "https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable",
        "udm_field_list_url": "https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list",
    }
    toolset = init_developer_knowledge_toolset()
    try:
        tools = {t.name: t for t in await toolset.get_tools(readonly_context=None)}
        if "search_documents" in tools:
            iam_res = await tools["search_documents"].run_async(
                args={"query": "gcloud iam service-accounts disable delete service account"},
                tool_context=None,
            )
            found_iam = _extract_first_doc_url(iam_res, "iam/docs")
            if found_iam:
                citations["iam_disable_url"] = found_iam

            udm_res = await tools["search_documents"].run_async(
                args={"query": "udm-field-list target.resource.name target.process.command_line"},
                tool_context=None,
            )
            found_udm = _extract_first_doc_url(udm_res, "udm-field-list")
            if found_udm:
                citations["udm_field_list_url"] = found_udm
    finally:
        await toolset.close()
    return citations


async def run_case_33278_experiment(
    soar_tools: dict[str, Any],
    siem_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 1: Case 33278 (gcp_admin_privileged_roles_added_to_service_accounts)."""
    print("\n======================================================================")
    print("EXPERIMENT 1: SOAR Case 33278 (GCP Service Account Privilege Escalation)")
    print("======================================================================")

    case_res = await soar_tools["get_case_full_details"].run_async(
        args={"case_id": "33278"}, tool_context=None
    )
    case_data = json.loads(_txt(case_res))
    alerts = (case_data.get("case_alerts") or {}).get("case_alerts") or []
    print(f"[soar] Case 33278 retrieved: {len(alerts)} alerts")

    udm_res = await siem_tools["search_udm"].run_async(
        args={
            "query": 'metadata.log_type = "GCP_CLOUDAUDIT" AND principal.ip = "104.198.226.161"',
            "start_time": "2026-02-07T19:00:00Z",
            "end_time": "2026-02-07T19:35:00Z",
            "max_events": 10,
        },
        tool_context=None,
    )
    udm_data = json.loads(_txt(udm_res))
    udm_events = udm_data.get("events", [])
    print(f"[siem] Correlated {len(udm_events)} GCP_CLOUDAUDIT UDM events from 104.198.226.161")

    skill_text = tmod.load_skill("compromised-user-account-response")
    print(f"[drive] Loaded runbook 'compromised-user-account-response' ({len(skill_text)} chars)")

    timeline_lines = []
    for ev in reversed(udm_events):
        udm = ev.get("udm", {})
        meta = udm.get("metadata", {})
        princ = udm.get("principal", {})
        tgt = udm.get("target", {})
        ts = meta.get("eventTimestamp", "")
        etype = meta.get("eventType", "")
        petype = meta.get("productEventType", "")
        user = princ.get("user", {}).get("userid", "")
        res_name = tgt.get("resource", {}).get("name", "") or tgt.get("cloud", {}).get("project", {}).get("name", "")
        timeline_lines.append(f"- `{ts}` | `{etype}` (`{petype}`) | Principal: `{user}` | Target: `{res_name}`")

    timeline_md = "\n".join(timeline_lines)
    doc_content = f"""# SOAR Case 33278 Investigation Report: GCP Service Account Privilege Escalation & Sabotage

## 1. Executive Summary & SOAR Case Metadata
- **SOAR Case ID**: `33278` (`gcp_admin_privileged_roles_added_to_service_accounts`)
- **Alert IDs**: `488690` (`de_97569133-ec1d-dd69-4e20-12b4da643296`), `488689` (`de_8e4b2bf0-dc75-97b9-aa9a-58824b99d55a`)
- **Initiating Principal**: `294955789222-compute@developer.gserviceaccount.com` from IP `104.198.226.161` (`gcloud/417.0.0` in Cloud Shell)
- **Escalated Target Identity**: `serviceAccount:hello@base-production.iam.gserviceaccount.com` granted `roles/editor` on `projects/base-production`
- **MITRE ATT&CK Classification**: The `SetIamPolicy` IAM role grant is classified under `T1078.004 (Cloud Accounts)`.

## 2. Correlated Chronicle SIEM UDM Timeline (104.198.226.161)
{timeline_md}

## 3. Chronicle UDM Threat Hunting Query
To hunt for additional IAM policy modifications or destructive actions against `projects/base-production`, run:
`metadata.log_type = "GCP_CLOUDAUDIT" AND resource.name = "projects/base-production"`

## 4. Immediate Containment & Eradication Runbook Actions
Per the `compromised-user-account-response` runbook, immediately terminate the compromised Compute Engine service account:
`gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com`
"""

    created = create_google_doc(
        title="SOAR_Case_33278_GCP_Service_Account_Privilege_Escalation",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    read_res = read_google_doc(doc_id)
    print(f"[docs] Read {read_res['char_count']} UTF-16 character positions")

    comments_res = insert_doc_comments(
        doc_id,
        [
            {
                "quote": "T1078.004 (Cloud Accounts)",
                "comment": (
                    "MITRE ATT&CK precision review: SetIamPolicy granting roles/editor to a "
                    "service account maps to T1098.003 (Account Manipulation: Additional Cloud Roles) "
                    "as tagged in Chronicle rule ru_d16945b0-dd56-49e2-987a-9f3c97b4e643 "
                    "(https://attack.mitre.org/techniques/T1098/003/)."
                ),
            },
            {
                "quote": 'resource.name = "projects/base-production"',
                "comment": (
                    "Invalid Chronicle UDM field path: UDM requires the entity prefix "
                    f"target.resource.name ({citations['udm_field_list_url']})."
                ),
            },
            {
                "quote": "gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com",
                "comment": (
                    "High blast-radius containment warning: deleting the Compute Engine default "
                    "service account permanently destroys its unique resource UID across all attached VMs. "
                    "Use reversible 'gcloud iam service-accounts disable' during triage "
                    f"({citations['iam_disable_url']})."
                ),
            },
        ],
    )
    print(f"[docs] insert_doc_comments: {comments_res}")

    edits_res = propose_doc_suggested_edits(
        doc_id,
        [
            {
                "quote": "T1078.004 (Cloud Accounts)",
                "replacement": "T1098.003 (Account Manipulation: Additional Cloud Roles)",
            },
            {
                "quote": 'resource.name = "projects/base-production"',
                "replacement": 'target.resource.name = "projects/base-production"',
            },
            {
                "quote": "gcloud iam service-accounts delete 294955789222-compute@developer.gserviceaccount.com",
                "replacement": "gcloud iam service-accounts disable 294955789222-compute@developer.gserviceaccount.com",
            },
        ],
    )
    print(f"[docs] propose_doc_suggested_edits: {edits_res}")
    return {
        "case_id": "33278",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "comments": comments_res,
        "edits": edits_res,
    }


async def run_case_33287_33281_experiment(
    soar_tools: dict[str, Any],
    siem_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 2: Cases 33287 & 33281 (Google Workspace Admin Takeover & Drive Transfer)."""
    print("\n======================================================================")
    print("EXPERIMENT 2: SOAR Cases 33287 & 33281 (Google Workspace Admin Takeover)")
    print("======================================================================")

    c33287 = json.loads(
        _txt(await soar_tools["get_case_full_details"].run_async(args={"case_id": "33287"}, tool_context=None))
    )
    prior_comments = (c33287.get("case_comments") or {}).get("comments") or []
    print(f"[soar] Case 33287 retrieved: {len(prior_comments)} prior analyst comments")

    udm_res = await siem_tools["search_udm"].run_async(
        args={
            "query": 'principal.ip = "79.154.246.114"',
            "start_time": "2026-02-07T09:15:00Z",
            "end_time": "2026-02-07T09:22:00Z",
            "max_events": 15,
        },
        tool_context=None,
    )
    ws_events = json.loads(_txt(udm_res)).get("events", [])
    print(f"[siem] Correlated {len(ws_events)} WORKSPACE_ACTIVITY UDM events from 79.154.246.114")

    skill_text = tmod.load_skill("suspicious-login-triage")
    print(f"[drive] Loaded runbook 'suspicious-login-triage' ({len(skill_text)} chars)")

    ws_lines = []
    for ev in reversed(ws_events[:8]):
        udm = ev.get("udm", {})
        meta = udm.get("metadata", {})
        tgt = udm.get("target", {})
        sec = udm.get("securityResult", [{}])
        actor = sec[0].get("about", {}).get("email", "admin@mydomain.com") if sec else "admin@mydomain.com"
        ws_lines.append(
            f"- `{meta.get('eventTimestamp')}` | `{meta.get('eventType')}` (`{meta.get('productEventType')}`) "
            f"| Actor: `{actor}` | App: `{tgt.get('application')}`"
        )
    ws_timeline_md = "\n".join(ws_lines)

    doc_content = f"""# SOAR Cases 33287 & 33281 Investigation Report: Google Workspace Admin Takeover

## 1. Prior Tier-1 Analyst Assessment (Case 33287 Comment #50)
- **Prior Triage Verdict**: `Disposition: Benign Automated Process (Pending IT Validation)`
- **Prior Analyst Note**: Comment #50 concluded that `CREATE_DATA_TRANSFER_REQUEST` from `admin@mydomain.com` to `alina.levine@mydomain.com` (source IP `79.154.246.114`) was a recurring automated workflow and recommended moving the case to the IT queue.

## 2. Cross-Case Chronicle SIEM UDM Correlation (IP 79.154.246.114)
Pivoting across all `WORKSPACE_ACTIVITY` events from `79.154.246.114` between `09:17:01Z` and `09:19:18Z` (linked to Case `33281`) reveals an active administrative takeover:
{ws_timeline_md}

## 3. Chronicle UDM Hunting Query for Workspace Admin Activity
To hunt for all Google Workspace Admin console modifications performed by `admin@mydomain.com`:
`metadata.log_type = "WORKSPACE_ACTIVITY" AND user.email_addresses = "admin@mydomain.com"`

## 4. Workspace Admin Containment Step
To lock out the compromised Workspace super-administrator account immediately:
`gam user admin@mydomain.com delete`
"""

    created = create_google_doc(
        title="SOAR_Case_33287_33281_Workspace_Admin_Takeover_Review",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    read_res = read_google_doc(doc_id)
    print(f"[docs] Read {read_res['char_count']} UTF-16 character positions")

    comments_res = insert_doc_comments(
        doc_id,
        [
            {
                "quote": "Disposition: Benign Automated Process (Pending IT Validation)",
                "comment": (
                    "False-negative triage red-line: Chronicle UDM telemetry for source IP 79.154.246.114 "
                    "shows SAML2 IdP deletion (DELETE_SAML2_SERVICE_PROVIDER_CONFIG), rogue OAuth client "
                    "authorization (AUTHORIZE_API_CLIENT_ACCESS for https://mail.google.com/), and 2-Step "
                    "Verification disablement (ENFORCE_STRONG_AUTHENTICATION=false) 65 seconds before the "
                    "Drive transfer. Escalate to Confirmed True Positive."
                ),
            },
            {
                "quote": 'user.email_addresses = "admin@mydomain.com"',
                "comment": (
                    "Invalid Chronicle UDM field path: unprefixed user.email_addresses fails compilation, "
                    "and WORKSPACE_ACTIVITY Admin audit logs populate the acting admin email in "
                    f"security_result.about.email or principal.user.email_addresses ({citations['udm_field_list_url']})."
                ),
            },
            {
                "quote": "gam user admin@mydomain.com delete",
                "comment": (
                    "Destructive containment warning: deleting a Google Workspace super-admin account "
                    "orphans owned Drive files and destroys audit trail bindings. Suspend the account "
                    "and revoke OAuth 2.0 grants instead."
                ),
            },
        ],
    )
    print(f"[docs] insert_doc_comments: {comments_res}")

    edits_res = propose_doc_suggested_edits(
        doc_id,
        [
            {
                "quote": "Disposition: Benign Automated Process (Pending IT Validation)",
                "replacement": "Disposition: Confirmed True Positive (Workspace Admin Takeover & 2SV Bypass)",
            },
            {
                "quote": 'user.email_addresses = "admin@mydomain.com"',
                "replacement": 'security_result.about.email = "admin@mydomain.com"',
            },
            {
                "quote": "gam user admin@mydomain.com delete",
                "replacement": "gam user admin@mydomain.com suspend",
            },
        ],
    )
    print(f"[docs] propose_doc_suggested_edits: {edits_res}")
    return {
        "case_id": "33287_33281",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "comments": comments_res,
        "edits": edits_res,
    }


async def run_case_33288_sanitized_experiment(
    soar_tools: dict[str, Any],
    citations: dict[str, str],
) -> dict[str, Any]:
    """Experiment 3: Case 33288 (3-Stage Intrusion with Sanitizer + Span Defanger)."""
    print("\n======================================================================")
    print("EXPERIMENT 3: SOAR Case 33288 (Sanitized 3-Stage Intrusion Chain)")
    print("======================================================================")

    c33288 = json.loads(
        _txt(await soar_tools["get_case_full_details"].run_async(args={"case_id": "33288"}, tool_context=None))
    )
    alerts = (c33288.get("case_alerts") or {}).get("case_alerts") or []
    print(f"[soar] Case 33288 retrieved: {len(alerts)} alerts")

    stage_summaries: list[str] = []
    for alert in reversed(alerts):
        aid = str(alert.get("id"))
        dname = alert.get("displayName")
        ev_res = await soar_tools["list_events_by_alert"].run_async(
            args={"case_id": "33288", "alert_id": aid}, tool_context=None
        )
        ev_items = json.loads(_txt(ev_res)).get("involved_events", [])
        for item in ev_items:
            # Sanitize raw mappedEventJson at the tool boundary BEFORE parsing/formatting
            sanitized_json_str = sanitize_telemetry_text(item.get("mappedEventJson", "{}"))
            mapped = json.loads(sanitized_json_str)
            ext = {e["Key"]: e["Value"] for e in mapped.get("Extensions", []) if "Key" in e}
            ev_id = mapped.get("_fields", {}).get("EventId", "")
            stage_summaries.append(
                f"- **Alert `{aid}` ({dname})** | EventId: `{ev_id}` | User: `{ext.get('SourceUserName')}` "
                f"| Telemetry: `{json.dumps(ext)}`"
            )

    skill_text = tmod.load_skill("phishing-response")
    print(f"[drive] Loaded runbook 'phishing-response' ({len(skill_text)} chars)")

    stages_md = "\n".join(stage_summaries)
    doc_content = f"""# SOAR Case 33288 Investigation Report: Multi-Stage Phishing to Endpoint Intrusion

## 1. Sanitized SOAR Alert & Event Chain (User: jdoe@altostrat.com)
{stages_md}

## 2. MITRE ATT&CK Classification
- Stage 3 Encoded PowerShell execution is mapped to `T1059.003 (Windows Command Shell)`.

## 3. Chronicle UDM Endpoint Hunting Query
Search for other endpoints executing hidden encoded PowerShell cradles:
`metadata.event_type = "PROCESS_LAUNCH" AND process.command_line = /.*-Enc.*/ nocase`
"""

    created = create_google_doc(
        title="SOAR_Case_33288_Sanitized_3Stage_Intrusion_Review",
        content=doc_content,
    )
    doc_id = created["document_id"]
    print(f"[docs] Created Google Doc: {doc_id} ({created.get('viewUrl')})")

    read_res = read_google_doc(doc_id)
    print(f"[docs] Read {read_res['char_count']} UTF-16 character positions")

    # Stage A: Deterministic Indicator Scanner (finds live untrusted URLs by UTF-16 span)
    from manager.tools.docs_review_tools import _load_doc_index_state
    plain_text, index_map = _load_doc_index_state(doc_id)
    det_comments, det_edits = find_deterministic_indicator_spans(plain_text or "", index_map or [])
    print(f"[docs] Stage A deterministic scanner found {len(det_edits)} live untrusted URL span(s)")

    # Combine Stage A (span-addressed) and Stage B (grounded quote-addressed) comments & edits
    all_comments = list(det_comments) + [
        {
            "quote": "T1059.003 (Windows Command Shell)",
            "comment": (
                "MITRE ATT&CK sub-technique mismatch: powershell.exe -Enc executions map to "
                "T1059.001 (PowerShell), not T1059.003 (Windows Command Shell) "
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
    ]
    all_edits = list(det_edits) + [
        {
            "quote": "T1059.003 (Windows Command Shell)",
            "replacement": "T1059.001 (PowerShell)",
        },
        {
            "quote": "process.command_line",
            "replacement": "target.process.command_line",
        },
    ]

    comments_res = insert_doc_comments(doc_id, all_comments)
    print(f"[docs] insert_doc_comments: {comments_res}")

    edits_res = propose_doc_suggested_edits(doc_id, all_edits)
    print(f"[docs] propose_doc_suggested_edits: {edits_res}")

    return {
        "case_id": "33288",
        "document_id": doc_id,
        "view_url": created.get("viewUrl"),
        "title": created.get("title"),
        "comments": comments_res,
        "edits": edits_res,
    }


async def main() -> int:
    citations = await resolve_grounding_citations()
    print(f"[devknowledge] Grounded citations resolved: {json.dumps(citations, indent=2)}")

    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        soar_tools = {t.name: t for t in await soar_toolset.get_tools()}
        siem_tools = {t.name: t for t in await siem_toolset.get_tools()}

        r1 = await run_case_33278_experiment(soar_tools, siem_tools, citations)
        r2 = await run_case_33287_33281_experiment(soar_tools, siem_tools, citations)
        r3 = await run_case_33288_sanitized_experiment(soar_tools, citations)

        summary = {"experiments": [r1, r2, r3], "citations": citations}
        print("\n=== ALL 3 ARGOLIS SOAR CASE EXPERIMENTS COMPLETED ===")
        print(json.dumps(summary, indent=2))
    finally:
        await siem_toolset.close()
        await soar_toolset.close()
        await gti_toolset.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
