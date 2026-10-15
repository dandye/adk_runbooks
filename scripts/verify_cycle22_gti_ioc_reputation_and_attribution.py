#!/usr/bin/env python3
"""Cycle 22 (H23) Live Validation: Automated GTI / VirusTotal Live IoC Reputation
Enrichment & Unverified Threat Attribution Red-Liner in Google Docs.

Reuses and resets the existing Google Doc in ``SOC Reports``
(``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``) in place via Drive API v3
media upload (``0`` new Google Docs created) and validates:
1. Quantitative benchmark evaluation via ``evaluate_infosec_doc_reviewer`` on
   ``BENCH-09-GTI-IOC-REPUTATION-AND-ATTRIBUTION`` and ``all_with_night2``
   (9 scenarios, 48 seeded defects, 19 negative controls, F1 = 1.0000,
   HDA_Error = 0.0000, 0 Google Drive write calls).
2. Live ``gti-mcp`` (``get_ip_address_report``, ``get_domain_report``,
   ``get_file_report``) and ``secops-mcp`` (``lookup_entity``, ``search_udm``)
   enrichment on ``104.198.226.161``, ``79.154.246.114``, ``8.8.8.8``, and
   ``e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855``.
3. In-place reset of Google Doc ``1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE``
   with ``BENCH-09`` seeded postmortem + Chronicle SIEM YARA-L 2.0 (``YL2``)
   rules, followed by Pass 1 live execution of
   ``verify_google_doc_ioc_reputation_and_attribution`` (red-lining all 5 ``H23``
   defect classes in descending character offset order and appending the
   ``[VERIFIED GTI IOC REPUTATION & THREAT ATTRIBUTION MATRIX (H23)]`` appendix).
4. Read-back verification via ``inspect_doc_suggestions`` and Pass 2 idempotency
   check confirming ``0`` remaining defects and ``0`` additional writes.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import httpx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = PROJECT_ROOT / "multi-agent"
for p in (PROJECT_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(PROJECT_ROOT / "external" / "mcp-security" / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    EMPTY_FILE_SHA256,
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    clear_doc_index_cache,
    evaluate_infosec_doc_reviewer,
    inspect_doc_suggestions,
    resolve_docs_token,
    verify_google_doc_ioc_reputation_and_attribution,
)
from skills.drive_registry import AdcTokenSource  # noqa: E402

EXISTING_VALIDATION_DOC_ID = "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"
DOC_TITLE = "Cycle22_H23_Live_GTI_IoC_Reputation_and_Threat_Attribution_Validation"


def _reset_google_doc_in_place(
    doc_id: str,
    title: str,
    markdown_body: str,
    token: str,
    quota_project: str,
) -> dict[str, Any]:
    """Replaces the body of an existing Google Doc in place via Drive API v3 media upload and clears prior comments."""
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": quota_project,
    }
    with httpx.Client(timeout=30.0) as client:
        comments_resp = client.get(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments",
            params={"fields": "comments(id,deleted)", "pageSize": 100},
            headers=headers,
        )
        comments_resp.raise_for_status()
        deleted_comments = 0
        for c in comments_resp.json().get("comments", []) or []:
            if c.get("deleted"):
                continue
            cid = c.get("id")
            if cid:
                del_resp = client.delete(
                    f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments/{cid}",
                    headers=headers,
                )
                if del_resp.status_code in (200, 204):
                    deleted_comments += 1

        meta_resp = client.patch(
            f"https://www.googleapis.com/drive/v3/files/{doc_id}",
            params={"fields": "id,name"},
            headers={**headers, "Content-Type": "application/json"},
            json={"name": title},
        )
        meta_resp.raise_for_status()

        upload_resp = client.patch(
            f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}",
            params={"uploadType": "media", "fields": "id,name,mimeType"},
            headers={**headers, "Content-Type": "text/markdown; charset=utf-8"},
            content=markdown_body.encode("utf-8"),
        )
        upload_resp.raise_for_status()
        return {
            "document_id": doc_id,
            "deleted_prior_comments": deleted_comments,
            "upload_status": upload_resp.status_code,
        }


def _parse_mcp_payload(raw_res: Any) -> dict[str, Any]:
    """Extracts JSON or structured summary from an MCP tool response."""
    if isinstance(raw_res, dict):
        if "content" in raw_res and isinstance(raw_res["content"], list):
            texts = []
            for item in raw_res["content"]:
                if isinstance(item, dict) and "text" in item:
                    texts.append(str(item["text"]))
            joined = "\n".join(texts).strip()
            try:
                parsed = json.loads(joined)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                return {"raw_text": joined[:600]}
        return raw_res
    if hasattr(raw_res, "content") and isinstance(raw_res.content, list):
        texts = [
            getattr(item, "text", str(item))
            for item in raw_res.content
        ]
        joined = "\n".join(texts).strip()
        try:
            parsed = json.loads(joined)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {"raw_text": joined[:600]}
    return {"raw_text": str(raw_res)[:600]}


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Step 1: Run local zero-quota 9-scenario benchmark (BENCH-01..BENCH-09)
    bench09_eval = evaluate_infosec_doc_reviewer(
        scenario_set="BENCH-09-GTI-IOC-REPUTATION-AND-ATTRIBUTION",
        include_hda_ablation=True,
    )
    all_night2_eval = evaluate_infosec_doc_reviewer(
        scenario_set="all_with_night2",
        include_hda_ablation=True,
    )
    assert bench09_eval["status"] == "success"
    assert bench09_eval["overall_f1"] == 1.0
    assert bench09_eval["overall_hda_error"] == 0.0
    assert all_night2_eval["status"] == "success"
    assert all_night2_eval["scenario_count"] == 9
    assert all_night2_eval["total_expected_defects"] == 48
    assert all_night2_eval["true_positive_edits"] == 48
    assert all_night2_eval["false_positive_edits"] == 0
    assert all_night2_eval["false_negative_defects"] == 0
    assert all_night2_eval["total_negative_controls"] == 19
    assert all_night2_eval["negative_controls_preserved"] == 19
    assert all_night2_eval["overall_f1"] == 1.0
    assert all_night2_eval["overall_hda_error"] == 0.0
    assert all_night2_eval["google_drive_write_calls"] == 0

    quota_project = (
        os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
        or os.environ.get("GOOGLE_CLOUD_PROJECT")
        or os.environ.get("GCP_PROJECT_ID")
        or "dandye-0324-chronicle"
    )
    token_source = AdcTokenSource()
    token = resolve_docs_token(None, token_source=token_source)

    bench09_scenario = next(
        s
        for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
        if s["scenario_id"] == "BENCH-09-GTI-IOC-REPUTATION-AND-ATTRIBUTION"
    )
    doc_markdown = (
        bench09_scenario["seeded_doc_text"]
        .replace("```yaral\n", "")
        .replace("```\n", "")
    )

    # Step 2: Live GTI + Chronicle SIEM enrichment via MCP toolsets
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    live_gti_reports: dict[str, dict[str, Any]] = {}
    live_siem_lookups: dict[str, dict[str, Any]] = {}
    gti_probe_summary: dict[str, Any] = {}
    siem_probe_summary: dict[str, Any] = {}

    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(
                siem_toolset.get_tools(readonly_context=None)
            )
        }
        gti_tools = {
            t.name: t
            for t in loop.run_until_complete(
                gti_toolset.get_tools(readonly_context=None)
            )
        }

        # Live GTI queries for key indicators
        if "get_ip_address_report" in gti_tools:
            for ip_ind in ("104.198.226.161", "79.154.246.114", "8.8.8.8"):
                try:
                    raw_ip = loop.run_until_complete(
                        gti_tools["get_ip_address_report"].run_async(
                            args={"ip_address": ip_ind},
                            tool_context=None,
                        )
                    )
                    parsed_ip = _parse_mcp_payload(raw_ip)
                    stats = (
                        parsed_ip.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                        if isinstance(parsed_ip.get("data"), dict)
                        else {}
                    )
                    mal_cnt = int(stats.get("malicious", 0) or 0)
                    susp_cnt = int(stats.get("suspicious", 0) or 0)
                    live_gti_reports[ip_ind] = {
                        "indicator": ip_ind,
                        "source": "gti-mcp:get_ip_address_report",
                        "malicious_count": mal_cnt,
                        "suspicious_count": susp_cnt,
                        "last_analysis_stats": stats,
                    }
                    gti_probe_summary[ip_ind] = live_gti_reports[ip_ind]
                except Exception as exc:
                    gti_probe_summary[ip_ind] = {"error": str(exc)}

        if "get_file_report" in gti_tools:
            try:
                raw_file = loop.run_until_complete(
                    gti_tools["get_file_report"].run_async(
                        args={"hash": EMPTY_FILE_SHA256},
                        tool_context=None,
                    )
                )
                parsed_file = _parse_mcp_payload(raw_file)
                stats = (
                    parsed_file.get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                    if isinstance(parsed_file.get("data"), dict)
                    else {}
                )
                live_gti_reports[EMPTY_FILE_SHA256] = {
                    "indicator": EMPTY_FILE_SHA256,
                    "source": "gti-mcp:get_file_report",
                    "malicious_count": int(stats.get("malicious", 0) or 0),
                    "suspicious_count": int(stats.get("suspicious", 0) or 0),
                    "last_analysis_stats": stats,
                }
                gti_probe_summary[EMPTY_FILE_SHA256] = live_gti_reports[
                    EMPTY_FILE_SHA256
                ]
            except Exception as exc:
                gti_probe_summary[EMPTY_FILE_SHA256] = {"error": str(exc)}

        # Live Chronicle SIEM UDM / entity lookups for campaign IPs
        if "search_udm" in siem_tools:
            for ip_ind, start_t, end_t in (
                ("104.198.226.161", "2026-02-07T00:00:00Z", "2026-02-08T00:00:00Z"),
                ("79.154.246.114", "2026-02-06T00:00:00Z", "2026-02-08T00:00:00Z"),
            ):
                try:
                    raw_udm = loop.run_until_complete(
                        siem_tools["search_udm"].run_async(
                            args={
                                "query": f'principal.ip = "{ip_ind}"',
                                "start_time": start_t,
                                "end_time": end_t,
                                "max_events": 10,
                            },
                            tool_context=None,
                        )
                    )
                    raw_str = str(raw_udm)
                    event_hits = raw_str.count("metadata")
                    live_siem_lookups[ip_ind] = {
                        "indicator": ip_ind,
                        "source": "secops-mcp:search_udm",
                        "udm_event_count": event_hits,
                        "verdict": (
                            "MALICIOUS_CAMPAIGN_IOC"
                            if event_hits > 0
                            else "NO_RECENT_UDM_HITS"
                        ),
                    }
                    siem_probe_summary[ip_ind] = live_siem_lookups[ip_ind]
                except Exception as exc:
                    siem_probe_summary[ip_ind] = {"error": str(exc)}

        # Step 3: Reset existing Google Doc in place (0 new docs created) and run Pass 1
        reset_info = _reset_google_doc_in_place(
            doc_id=EXISTING_VALIDATION_DOC_ID,
            title=DOC_TITLE,
            markdown_body=doc_markdown,
            token=token,
            quota_project=quota_project,
        )
        clear_doc_index_cache()

        pass1_res = verify_google_doc_ioc_reputation_and_attribution(
            doc_id=EXISTING_VALIDATION_DOC_ID,
            apply_redlines=True,
            append_executive_matrix=True,
            live_gti_reports=live_gti_reports,
            live_siem_lookups=live_siem_lookups,
            token=token,
            quota_project=quota_project,
        )
        assert pass1_res["status"] == "success", f"Pass 1 failed: {pass1_res}"
        assert pass1_res["defect_count"] == 5, (
            f"Expected 5 H23 defects in Pass 1, got {pass1_res['defect_count']}"
        )
        assert pass1_res["applied_redline_count"] == 5, (
            f"Expected 5 applied redlines in Pass 1, got {pass1_res['applied_redline_count']}"
        )
        assert pass1_res["appended_matrix"] is True

        # Step 4: Inspect document state & run Pass 2 idempotency check
        clear_doc_index_cache()
        inspect_after_pass1 = inspect_doc_suggestions(
            document_id=EXISTING_VALIDATION_DOC_ID,
            token_source=token_source,
            quota_project=quota_project,
        )
        pass2_res = verify_google_doc_ioc_reputation_and_attribution(
            doc_id=EXISTING_VALIDATION_DOC_ID,
            apply_redlines=True,
            append_executive_matrix=True,
            live_gti_reports=live_gti_reports,
            live_siem_lookups=live_siem_lookups,
            token=token,
            quota_project=quota_project,
        )
        assert pass2_res["status"] == "success"
        assert pass2_res["defect_count"] == 0, (
            f"Expected 0 defects on Pass 2 idempotency check, got {pass2_res['defect_count']}"
        )
        assert pass2_res["applied_redline_count"] == 0
        assert pass2_res["appended_matrix"] is False

        summary = {
            "cycle": 22,
            "horizon_id": "H23",
            "status": "SUCCESS",
            "new_docs_created": 0,
            "validation_document_id": EXISTING_VALIDATION_DOC_ID,
            "reset_info": reset_info,
            "benchmark_bench09": {
                "scenario_count": bench09_eval["scenario_count"],
                "total_expected_defects": bench09_eval["total_expected_defects"],
                "true_positive_edits": bench09_eval["true_positive_edits"],
                "false_positive_edits": bench09_eval["false_positive_edits"],
                "false_negative_defects": bench09_eval["false_negative_defects"],
                "overall_precision": bench09_eval["overall_precision"],
                "overall_recall": bench09_eval["overall_recall"],
                "overall_f1": bench09_eval["overall_f1"],
                "overall_negative_control_pass_rate": bench09_eval[
                    "overall_negative_control_pass_rate"
                ],
                "overall_hda_error": bench09_eval["overall_hda_error"],
                "google_drive_write_calls": bench09_eval[
                    "google_drive_write_calls"
                ],
            },
            "benchmark_all_with_night2": {
                "scenario_count": all_night2_eval["scenario_count"],
                "total_expected_defects": all_night2_eval[
                    "total_expected_defects"
                ],
                "true_positive_edits": all_night2_eval["true_positive_edits"],
                "false_positive_edits": all_night2_eval["false_positive_edits"],
                "false_negative_defects": all_night2_eval[
                    "false_negative_defects"
                ],
                "total_negative_controls": all_night2_eval[
                    "total_negative_controls"
                ],
                "negative_controls_preserved": all_night2_eval[
                    "negative_controls_preserved"
                ],
                "overall_precision": all_night2_eval["overall_precision"],
                "overall_recall": all_night2_eval["overall_recall"],
                "overall_f1": all_night2_eval["overall_f1"],
                "overall_negative_control_pass_rate": all_night2_eval[
                    "overall_negative_control_pass_rate"
                ],
                "overall_hda_error": all_night2_eval["overall_hda_error"],
                "google_drive_write_calls": all_night2_eval[
                    "google_drive_write_calls"
                ],
            },
            "live_gti_enrichment_summary": gti_probe_summary,
            "live_siem_enrichment_summary": siem_probe_summary,
            "pass1_live_google_doc": {
                "defect_count": pass1_res["defect_count"],
                "defect_counts_by_type": pass1_res["defect_counts_by_type"],
                "applied_redline_count": pass1_res["applied_redline_count"],
                "appended_matrix": pass1_res["appended_matrix"],
                "doc_length_after_pass1": inspect_after_pass1.get(
                    "total_text_length"
                ),
            },
            "pass2_idempotency": {
                "defect_count": pass2_res["defect_count"],
                "applied_redline_count": pass2_res["applied_redline_count"],
                "appended_matrix": pass2_res["appended_matrix"],
            },
        }
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            try:
                loop.run_until_complete(ts.close())
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
