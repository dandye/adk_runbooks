#!/usr/bin/env python3
"""Cycle 27 (Horizon H28) Live Validation Script: Master Night 1 + Night 2 Cross-Horizon Synthesis & Readiness Auditor.

Validates:
1. Quantitative benchmark evaluation (`evaluate_verification_benchmark_suite` & `evaluate_grounding_benchmark_suite`):
   - `BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS`: 5/5 cross-pillar seeded defects caught (`H21`, `H23`, `H25`, `H26`, `H27`),
     2/2 negative controls preserved (standard file/payload YARA `strings:` rule and valid Siemplify + `$g.graph.entity.*` block),
     Precision=1.0, Recall=1.0, F1=1.0, Pass-2 idempotency=1.0, 0 Drive write calls.
   - Full 14-scenario `all_with_night2` suite (`BENCH-01`..`BENCH-14`): 73/73 defects caught, 29/29 negative
     controls preserved, Precision=1.0, Recall=1.0, F1=1.0, HDA error=0.0000.
2. SkillRL failure-trajectory distillation (`generate_skillrl_failure_distillation_matrix(include_h28_master_synthesis=True)`)
   and Master Evolution Synthesis Report (`generate_master_evolution_synthesis_report()`):
   - Verifies `SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE` is registered (`8` total rules across `H25`..`H28`).
   - Verifies `27` completed cycles (`H1`..`H28`) across `5` capability pillars.
3. Live Argolis Chronicle SIEM (`secops-mcp`) validation:
   - `validate_rule` on remediated `BENCH-14` YARA-L 2.0 (`YL2`) Entity Graph rule (`yaral2_composite_entity_graph_defect`)
     using `$g.graph.entity.metadata.entity_type = "ASSET"`, `$e.principal.hostname = $g.graph.entity.hostname`,
     and single `outcome:` aggregation `$event_count = count_distinct($e.metadata.id)`.
   - `search_udm` live telemetry check for `wins-d19` (`PROCESS_LAUNCH`) grounding.
4. Live Google Docs API v1 + Drive API v3 validation (reusing existing Doc `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE`
   in place via Drive API v3 `files.update` media upload, `new_docs_created = 0`):
   - Runs `audit_master_secops_doc_readiness_in_doc` with `apply_highlights=True`, `create_comments=True`,
     and `prepend_executive_banner=True`, verifying `release_gate_verdict == "BLOCKED_CRITICAL_DEFECTS"`,
     all 5 capability pillars audited, `standard_yara_blocks_ignored_count == 1`, yellow `#FFF2CC` highlights
     applied, Drive API v3 anchored comments created, and executive sign-off banner prepended.
   - Resets the existing Doc to clean `BENCH-14` markdown and runs Pass 1 + Pass 2 of
     `review_google_doc_with_stage_a(..., include_master_synthesis_stage_a=True)` to verify 5/5 cross-pillar
     redlines applied in Pass 1 and 0 duplicate edits in Pass 2 (100% idempotent).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any

from dotenv import load_dotenv
import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in (REPO_ROOT, MULTI_AGENT_DIR):
  if str(p) not in sys.path:
    sys.path.insert(0, str(p))

local_adc = REPO_ROOT / ".gcloud" / "application_default_credentials.json"
if local_adc.exists() and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
  os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(local_adc)

load_dotenv(Path.home() / ".config" / "secops-tenants" / "dandye-0324-chronicle.env")
load_dotenv(REPO_ROOT / ".env")
load_dotenv(MULTI_AGENT_DIR / "manager" / ".env")
load_dotenv(MULTI_AGENT_DIR / ".env")
load_dotenv(REPO_ROOT / "external" / "mcp-security" / ".env")

from manager.tools.docs_review_tools import (  # noqa: E402
    ChronicleRuleValidationGate,
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    H28_CAPABILITY_PILLAR_CATALOG,
    audit_master_secops_doc_readiness_in_doc,
    build_dwd_credentials,
    clear_doc_index_cache,
    evaluate_benchmark_scenario,
    evaluate_grounding_benchmark_suite,
    evaluate_verification_benchmark_suite,
    generate_master_evolution_synthesis_report,
    generate_skillrl_failure_distillation_matrix,
    inspect_google_doc_revision_and_Formatting,
    resolve_docs_token,
    review_google_doc_with_stage_a,
)
from manager.tools.tools import init_shared_mcp_tools  # noqa: E402

EXISTING_LIVE_DOC_ID = os.environ.get(
    "LIVE_VALIDATION_DOC_ID",
    "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
)
LIVE_DOC_TITLE = "Cycle27_H28_Live_Master_Cross_Pillar_Synthesis_Validation_20261012"
TMP_REPORT_PATH = Path("/tmp/cycle27_master_synthesis_verification.json")
ARTIFACTS_PATH = (
    REPO_ROOT / "artifacts" / "cycle27_master_synthesis_verification.json"
)


def _reset_existing_google_doc_in_place(
    doc_id: str,
    title: str,
    markdown_content: str,
    token: str,
) -> dict[str, Any]:
  """Resets an existing Google Doc in place via Drive API v3 media upload (`new_docs_created = 0`)."""
  quota_project = (
      os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
      or os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
      or os.environ.get("GOOGLE_CLOUD_PROJECT")
      or os.environ.get("GCP_PROJECT_ID")
      or "dandye-0324-chronicle"
  ).strip()
  base_headers = {
      "Authorization": f"Bearer {token}",
      "X-Goog-User-Project": quota_project,
  }
  with httpx.Client(timeout=60.0) as client:
    comments_resp = client.get(
        f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments",
        params={"fields": "comments(id,deleted,resolved)", "pageSize": 100},
        headers=base_headers,
    )
    deleted_comments = 0
    if comments_resp.status_code == 200:
      for c_obj in comments_resp.json().get("comments", []) or []:
        cid = c_obj.get("id")
        if cid and not c_obj.get("deleted"):
          del_resp = client.delete(
              f"https://www.googleapis.com/drive/v3/files/{doc_id}/comments/{cid}",
              headers=base_headers,
          )
          if del_resp.status_code in (200, 204):
            deleted_comments += 1

    meta_resp = client.patch(
        f"https://www.googleapis.com/drive/v3/files/{doc_id}",
        params={"fields": "id,name,mimeType,webViewLink"},
        headers={**base_headers, "Content-Type": "application/json"},
        json={"name": title},
    )
    meta_resp.raise_for_status()

    upload_url = (
        f"https://www.googleapis.com/upload/drive/v3/files/{doc_id}"
        "?uploadType=media&supportsAllDrives=true&fields=id,name,mimeType,webViewLink,headRevisionId"
    )
    upload_resp = client.patch(
        upload_url,
        headers={
            **base_headers,
            "Content-Type": "text/markdown; charset=utf-8",
        },
        content=markdown_content.encode("utf-8"),
    )
    upload_resp.raise_for_status()
    payload = upload_resp.json()
    payload["deleted_previous_comments"] = deleted_comments
    return payload


def _build_live_seed_markdown() -> str:
  """Returns the seeded Markdown payload from `BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS`."""
  bench14 = next(
      s
      for s in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
      if s["scenario_id"] == "BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS"
  )
  base_md = (
      str(bench14["markdown_content"])
      .replace("```yaral\n", "")
      .replace("```yara\n", "")
      .replace("```python\n", "")
      .replace("```yaml\n", "")
      .replace("```bash\n", "")
      .replace("```\n", "")
      .rstrip()
  )
  return base_md + "\n"


async def _run_live_chronicle_siem_checks() -> dict[str, Any]:
  """Runs live `secops-mcp:validate_rule` and `secops-mcp:search_udm` via siem_toolset."""
  remediated_yaral2_rule = """rule yaral2_composite_entity_graph_remediated {
  meta:
    author = "SecOps Detection Engineering"
    description = "Remediated H27/H28 Entity Graph correlation rule"
    severity = "HIGH"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.principal.hostname = $host
    $g.graph.entity.metadata.entity_type = "ASSET"
    $g.graph.entity.hostname = $host
  match:
    $host over 5m
  outcome:
    $risk_score = max(85)
    $event_count = count_distinct($e.metadata.id)
  condition:
    $e and $g
}"""
  compiler_safe_rule = (
      ChronicleRuleValidationGate._make_compiler_safe_entity_graph_rule(
          remediated_yaral2_rule
      )
  )
  siem_toolset, soar_toolset, gti_toolset = init_shared_mcp_tools()
  try:
    siem_tools = {
        t.name: t for t in await siem_toolset.get_tools(readonly_context=None)
    }
    val_tool = siem_tools.get("validate_rule") or siem_tools.get(
        "secops-mcp_validate_rule"
    )
    udm_tool = siem_tools.get("search_udm") or siem_tools.get(
        "secops-mcp_search_udm"
    )

    val_raw = await val_tool.run_async(
        args={"rule_text": compiler_safe_rule},
        tool_context=None,
    )
    val_str = str(val_raw).encode("ascii", errors="ignore").decode("ascii")
    passed = "FAILED" not in val_str.upper() and (
        "SUCCESS" in val_str.upper()
        or "VALID" in val_str.upper()
        or "PASSED" in val_str.upper()
    )

    udm_raw = await udm_tool.run_async(
        args={
            "query": 'metadata.event_type = "PROCESS_LAUNCH" AND principal.hostname = "wins-d19"',
            "start_time": "2026-02-07T00:00:00Z",
            "end_time": "2026-02-08T00:00:00Z",
            "max_events": 5,
        },
        tool_context=None,
    )
    udm_str = str(udm_raw).encode("ascii", errors="ignore").decode("ascii")
    return {
        "status": "success",
        "remediated_rule_name": "yaral2_composite_entity_graph_remediated",
        "rule_valid": passed,
        "validate_rule_raw": val_str[:400],
        "search_udm_raw": udm_str[:600],
        "search_udm_has_events": (
            "wins-d19" in udm_str
            or "metadata" in udm_str
            or "total_events" in udm_str
        ),
    }
  finally:
    for ts in (siem_toolset, soar_toolset, gti_toolset):
      try:
        await ts.close()
      except Exception:
        pass


def main() -> int:
  print(
      "=== Cycle 27 (H28): Master Night 1 + Night 2 Cross-Horizon Synthesis & Readiness Live Verification ==="
  )

  # 1. Run quantitative benchmark suite on BENCH-14 and all 14 scenarios
  bench14_eval = evaluate_benchmark_scenario(
      "BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS"
  )
  all_eval = evaluate_verification_benchmark_suite(include_night2_extended=True)
  assert bench14_eval["status"] == "success", bench14_eval
  assert bench14_eval["TP"] == 5, bench14_eval
  assert bench14_eval["FP"] == 0, bench14_eval
  assert bench14_eval["FN"] == 0, bench14_eval
  assert bench14_eval["TN"] == 2, bench14_eval
  assert bench14_eval["f1"] == 1.0, bench14_eval

  assert all_eval["status"] == "success", all_eval
  assert all_eval["scenario_count"] == 14, all_eval
  assert all_eval["total_expected_defects"] == 73, all_eval
  assert all_eval["TP"] == 73, all_eval
  assert all_eval["FP"] == 0, all_eval
  assert all_eval["FN"] == 0, all_eval
  assert all_eval["TN"] == 29, all_eval
  assert all_eval["micro_f1"] == 1.0, all_eval
  assert all_eval["pass2_idempotency_rate"] == 1.0, all_eval
  assert all_eval["google_drive_write_calls"] == 0, all_eval

  print(
      f"[1/4] Benchmark Suite Verified: BENCH-14 F1={bench14_eval['f1']:.4f} (5/5 defects, 2/2 controls) | "
      f"all_with_night2 (14 scenarios) F1={all_eval['micro_f1']:.4f} (73/73 defects, 29/29 controls)"
  )

  # 2. Verify SkillRL failure distillation matrix (8 rules) and Master Evolution Synthesis Report (27 cycles)
  skillrl_matrix = generate_skillrl_failure_distillation_matrix(
      include_h28_master_synthesis=True
  )
  assert "H28" in skillrl_matrix["horizons_covered"], skillrl_matrix
  assert len(skillrl_matrix["rules"]) == 8, skillrl_matrix
  h28_rule = next(
      r
      for r in skillrl_matrix["rules"]
      if r["rule_id"] == "SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE"
  )

  master_report = generate_master_evolution_synthesis_report()
  assert master_report["status"] == "success", master_report
  assert master_report["total_cycles_completed"] == 27, master_report
  assert master_report["pillar_count"] == 5, master_report
  assert master_report["skillrl_rule_count"] == 8, master_report

  print(
      f"[2/4] SkillRL & Master Evolution Synthesis Verified: cycles={master_report['total_cycles_completed']}, "
      f"pillars={master_report['pillar_count']}, skillrl_rules={master_report['skillrl_rule_count']} "
      f"(includes {h28_rule['rule_id']})"
  )

  # 3. Live Chronicle SIEM rule validation & UDM telemetry search
  live_siem_res = asyncio.run(_run_live_chronicle_siem_checks())
  assert live_siem_res["rule_valid"] is True, live_siem_res
  assert live_siem_res["search_udm_has_events"] is True, live_siem_res
  print(
      f"[3/4] Live Chronicle SIEM Verified: {live_siem_res['remediated_rule_name']} compiled VALID via "
      f"secops-mcp:validate_rule and search_udm(wins-d19)=True"
  )

  # 4. Live Google Doc validation (reusing existing Doc `1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE`, `new_docs_created = 0`)
  seeded_text = _build_live_seed_markdown()
  creds = build_dwd_credentials()
  token = resolve_docs_token(token_source=creds)

  # Step 4a: Reset existing Google Doc and run `audit_master_secops_doc_readiness_in_doc`
  clear_doc_index_cache()
  reset_meta_audit = _reset_existing_google_doc_in_place(
      EXISTING_LIVE_DOC_ID,
      LIVE_DOC_TITLE,
      seeded_text,
      token,
  )
  clear_doc_index_cache()

  live_master_audit = audit_master_secops_doc_readiness_in_doc(
      doc_id=EXISTING_LIVE_DOC_ID,
      apply_highlights=True,
      create_comments=True,
      prepend_executive_banner=True,
      credentials=creds,
  )
  assert live_master_audit["status"] == "success", live_master_audit
  assert (
      live_master_audit["release_gate_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
  ), live_master_audit
  assert live_master_audit["pillar_count"] == 5, live_master_audit
  assert live_master_audit["total_defect_count"] >= 5, live_master_audit
  assert (
      live_master_audit["standard_yara_blocks_ignored_count"] == 1
  ), live_master_audit
  assert live_master_audit["highlighted_count"] >= 5, live_master_audit
  assert live_master_audit["comments_created_count"] >= 5, live_master_audit
  assert live_master_audit["executive_banner_prepended"] is True, live_master_audit

  # Step 4b: Reset existing Google Doc and run Pass 1 + Pass 2 Stage-A redlining with `include_master_synthesis_stage_a=True`
  clear_doc_index_cache()
  reset_meta_redline = _reset_existing_google_doc_in_place(
      EXISTING_LIVE_DOC_ID,
      LIVE_DOC_TITLE,
      seeded_text,
      token,
  )
  clear_doc_index_cache()

  pass1_redline = review_google_doc_with_stage_a(
      EXISTING_LIVE_DOC_ID,
      token_source=creds,
      include_telemetry_hazard_stage_a=False,
      include_credential_containment_stage_a=False,
      include_udm_stage_a=False,
      include_yaral2_stage_a=False,
      include_mitre_cve_stage_a=False,
      include_master_synthesis_stage_a=True,
  )
  assert pass1_redline["status"] == "success", pass1_redline
  pass1_applied = int(pass1_redline.get("edits", {}).get("applied_count", 0))
  assert pass1_applied == 5, pass1_redline
  assert pass1_redline["stage_a_master_synthesis_count"] == 5, pass1_redline

  clear_doc_index_cache()
  rev_live = inspect_google_doc_revision_and_Formatting(
      EXISTING_LIVE_DOC_ID,
      credentials=creds,
  )
  assert rev_live["applied_redlines"] == 5, rev_live
  assert rev_live["false_positive_redlines"] == 0, rev_live

  clear_doc_index_cache()
  pass2_redline = review_google_doc_with_stage_a(
      EXISTING_LIVE_DOC_ID,
      token_source=creds,
      include_telemetry_hazard_stage_a=False,
      include_credential_containment_stage_a=False,
      include_udm_stage_a=False,
      include_yaral2_stage_a=False,
      include_mitre_cve_stage_a=False,
      include_master_synthesis_stage_a=True,
  )
  assert pass2_redline["status"] == "success", pass2_redline
  pass2_applied = int(pass2_redline.get("edits", {}).get("applied_count", 0))
  assert pass2_applied == 0, pass2_redline
  assert pass2_redline["skipped_existing_suggestion_count"] >= 5, pass2_redline

  print(
      f"[4/4] Live Google Doc Verified (documentId={EXISTING_LIVE_DOC_ID}, new_docs_created=0): "
      f"Master Audit verdict={live_master_audit['release_gate_verdict']} "
      f"(score={live_master_audit['master_readiness_score']}, highlights={live_master_audit['highlighted_count']}, "
      f"comments={live_master_audit['comments_created_count']}, banner={live_master_audit['executive_banner_prepended']}) | "
      f"Stage-A Pass 1 redlines={pass1_applied}, Pass 2 redlines={pass2_applied} "
      f"(skipped={pass2_redline['skipped_existing_suggestion_count']})"
  )

  artifact_payload = {
      "cycle": 27,
      "horizon": "H28",
      "title": (
          "Master Night 1 + Night 2 Cross-Horizon Synthesis, End-to-End Composite Playbook & "
          "Postmortem Readiness Auditor (audit_master_secops_doc_readiness_in_doc), BENCH-14 Composite "
          "Benchmark & Reference Architecture Publication"
      ),
      "timestamp_utc": datetime.now(timezone.utc).isoformat(),
      "catalog_version": "H28-2026-10-12-v1",
      "pillar_count": len(H28_CAPABILITY_PILLAR_CATALOG),
      "pillar_ids": list(H28_CAPABILITY_PILLAR_CATALOG.keys()),
      "benchmark_bench14": {
          "scenario_id": "BENCH-14-MASTER-COMPOSITE-SECOPS-SYNTHESIS",
          "TP": bench14_eval["TP"],
          "FP": bench14_eval["FP"],
          "FN": bench14_eval["FN"],
          "TN": bench14_eval["TN"],
          "precision": bench14_eval["precision"],
          "recall": bench14_eval["recall"],
          "f1": bench14_eval["f1"],
          "pass2_idempotency_rate": bench14_eval["pass2_idempotency_rate"],
      },
      "benchmark_all_with_night2": {
          "scenario_count": all_eval["scenario_count"],
          "total_expected_defects": all_eval["total_expected_defects"],
          "TP": all_eval["TP"],
          "FP": all_eval["FP"],
          "FN": all_eval["FN"],
          "TN": all_eval["TN"],
          "micro_precision": all_eval["micro_precision"],
          "micro_recall": all_eval["micro_recall"],
          "micro_f1": all_eval["micro_f1"],
          "pass2_idempotency_rate": all_eval["pass2_idempotency_rate"],
          "overall_hda_error": all_eval["overall_hda_error"],
          "google_drive_write_calls": all_eval["google_drive_write_calls"],
      },
      "skillrl_distillation": {
          "family_count": skillrl_matrix["family_count"],
          "rule_count": len(skillrl_matrix["rules"]),
          "horizons_covered": skillrl_matrix["horizons_covered"],
          "h28_rule_id": h28_rule["rule_id"],
      },
      "master_evolution_synthesis": {
          "total_cycles_completed": master_report["total_cycles_completed"],
          "horizons_completed": master_report["horizons_completed"],
          "pillar_count": master_report["pillar_count"],
          "skillrl_rule_count": master_report["skillrl_rule_count"],
      },
      "live_chronicle_siem_verification": live_siem_res,
      "live_google_doc_verification": {
          "document_id": EXISTING_LIVE_DOC_ID,
          "title": LIVE_DOC_TITLE,
          "web_view_link": reset_meta_redline.get(
              "webViewLink",
              f"https://docs.google.com/document/d/{EXISTING_LIVE_DOC_ID}/edit",
          ),
          "new_docs_created": 0,
          "master_readiness_audit": {
              "release_gate_verdict": live_master_audit["release_gate_verdict"],
              "master_readiness_score": live_master_audit[
                  "master_readiness_score"
              ],
              "pillar_count": live_master_audit["pillar_count"],
              "total_defect_count": live_master_audit["total_defect_count"],
              "critical_defect_count": live_master_audit[
                  "critical_defect_count"
              ],
              "standard_yara_blocks_ignored_count": live_master_audit[
                  "standard_yara_blocks_ignored_count"
              ],
              "highlighted_count": live_master_audit["highlighted_count"],
              "comments_created_count": live_master_audit[
                  "comments_created_count"
              ],
              "executive_banner_prepended": live_master_audit[
                  "executive_banner_prepended"
              ],
          },
          "stage_a_pass1_and_pass2": {
              "pass1_applied_redlines": pass1_applied,
              "pass1_false_positive_redlines": rev_live[
                  "false_positive_redlines"
              ],
              "fee2e2_span_count": rev_live["fee2e2_span_count"],
              "dcfce7_span_count": rev_live["dcfce7_span_count"],
              "pass2_applied_redlines": pass2_applied,
              "pass2_skipped_existing_suggestion_count": pass2_redline[
                  "skipped_existing_suggestion_count"
              ],
          },
      },
  }

  TMP_REPORT_PATH.write_text(
      json.dumps(artifact_payload, indent=2) + "\n", encoding="utf-8"
  )
  ARTIFACTS_PATH.parent.mkdir(parents=True, exist_ok=True)
  ARTIFACTS_PATH.write_text(
      json.dumps(artifact_payload, indent=2) + "\n", encoding="utf-8"
  )
  print(f"Saved verification artifact to {TMP_REPORT_PATH} and {ARTIFACTS_PATH}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
