#!/usr/bin/env python3
"""Cycle 29 (Horizon H30) Capstone Live Validation Script.

Validates:
1. Quantitative Benchmark Evaluation for `BENCH-16-CAPSTONE-KEV-DASHBOARD-SOAR-HILLCLIMB-OTEL`
   (`5/5` TP, `0` FP, `0` FN, `2/2` TN, `F1 = 1.0000`) and full 16-scenario Night-2 suite
   (`BENCH-01` through `BENCH-16`, `83/83` seeded defects, `0` FP, `0` FN, `33/33` negative
   controls preserved, `micro_f1 = 1.0000`, `pass2_idempotency_rate = 1.0000`).
2. SkillRL 10-Rule Failure Distillation Matrix (`SKILLRL-01` through `SKILLRL-10`) and
   29-Cycle Master Evolution Synthesis Report (`30` horizons `H1` through `H30`, `5` capability pillars).
3. Live Google Docs API v1 + Drive API v3 in-place validation on existing document
   `DOC_ID="1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE"` (`0` new Google Docs created)
   for Live Siemplify Case `CASE_ID="4097"`, verifying
   `audit_capstone_production_governance_and_kev_exposure_in_doc` (`mode="APPLY"`),
   Pass-2 idempotency (`0` duplicate suggestions), `verify_post_accept_secops_doc_readiness`
   (`BLOCKED_CRITICAL_DEFECTS` -> `APPROVED_FOR_SOC_EXECUTION`, `post_accept_readiness_status="CERTIFIED_READY"`),
   and `run_grounded_soar_review_workflow`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any

from dotenv import load_dotenv
import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
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
    EXTENDED_NIGHT2_BENCHMARK_SCENARIOS,
    H30_CAPSTONE_PRODUCTION_GOVERNANCE_AND_KEV_EXPOSURE_CATALOG,
    audit_capstone_production_governance_and_kev_exposure,
    audit_capstone_production_governance_and_kev_exposure_in_doc,
    build_dwd_credentials,
    clear_doc_index_cache,
    evaluate_benchmark_scenario,
    generate_master_evolution_synthesis_report,
    generate_skillrl_failure_distillation_matrix,
    inspect_doc_suggestions,
    resolve_docs_token,
    run_night2_grounded_secops_benchmark,
    verify_post_accept_secops_doc_readiness,
)
from manager.tools.workflow_tools import run_grounded_soar_review_workflow  # noqa: E402

DOC_ID = os.environ.get(
    "DOC_ID",
    os.environ.get(
        "LIVE_VALIDATION_DOC_ID",
        "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
    ),
)
CASE_ID = os.environ.get("CASE_ID", "4097")
LIVE_DOC_TITLE = (
    "Cycle29_H30_Live_Capstone_Governance_and_KEV_Exposure_Validation_20261012"
)
QUOTA_PROJECT = (
    os.environ.get("DRIVE_MCP_QUOTA_PROJECT")
    or os.environ.get("GOOGLE_CLOUD_QUOTA_PROJECT")
    or os.environ.get("GOOGLE_CLOUD_PROJECT")
    or os.environ.get("GCP_PROJECT_ID")
    or "dandye-0324-chronicle"
).strip()
REPORT_PATH = (
    REPO_ROOT
    / "docs"
    / "cycle29_h30_capstone_governance_verification_report.json"
)


def _reset_existing_google_doc_in_place(
    document_id: str,
    markdown_body: str,
    token: str,
) -> dict[str, Any]:
  """Resets an existing Google Doc in place via Drive API v3 media upload without creating any new Drive files."""
  base_headers = {
      "Authorization": f"Bearer {token}",
      "X-Goog-User-Project": QUOTA_PROJECT,
  }
  with httpx.Client(timeout=45.0) as client:
    comments_url = (
        f"https://www.googleapis.com/drive/v3/files/{document_id}/comments"
    )
    r_comments = client.get(
        comments_url,
        params={
            "fields": "comments(id,deleted)",
            "pageSize": 100,
        },
        headers=base_headers,
    )
    deleted_prior = 0
    if r_comments.status_code == 200:
      for c_item in r_comments.json().get("comments", []) or []:
        if not c_item.get("deleted") and c_item.get("id"):
          cid = c_item["id"]
          client.delete(
              f"{comments_url}/{cid}",
              headers=base_headers,
          )
          deleted_prior += 1

    client.patch(
        f"https://www.googleapis.com/drive/v3/files/{document_id}",
        params={"fields": "id,name"},
        headers={**base_headers, "Content-Type": "application/json"},
        json={"name": LIVE_DOC_TITLE},
    )

    upload_url = (
        f"https://www.googleapis.com/upload/drive/v3/files/{document_id}"
        "?uploadType=media&supportsAllDrives=true&fields=id,name,mimeType"
    )
    r_upd = client.patch(
        upload_url,
        headers={
            **base_headers,
            "Content-Type": "text/markdown; charset=utf-8",
        },
        content=markdown_body.encode("utf-8"),
    )
    r_upd.raise_for_status()

    return {
        "status": "success",
        "document_id": document_id,
        "inserted_chars": len(markdown_body),
        "deleted_prior_comments": deleted_prior,
        "new_docs_created": 0,
    }


def main() -> int:
  t0 = time.time()
  print("=== Cycle 29 (Horizon H30) Capstone Live Validation Starting ===")

  # 1. Evaluate BENCH-16 and full 16-scenario Night-2 benchmark suite
  print(
      "[1/4] Evaluating BENCH-16 and 16-scenario benchmark suite (BENCH-01..16)..."
  )
  bench16_eval = evaluate_benchmark_scenario(
      "BENCH-16-CAPSTONE-KEV-DASHBOARD-SOAR-HILLCLIMB-OTEL"
  )
  assert bench16_eval["status"] == "success", f"BENCH-16 failed: {bench16_eval}"
  assert bench16_eval["TP"] == 5, f"Expected TP=5, got {bench16_eval['TP']}"
  assert bench16_eval["FP"] == 0, f"Expected FP=0, got {bench16_eval['FP']}"
  assert bench16_eval["FN"] == 0, f"Expected FN=0, got {bench16_eval['FN']}"
  assert bench16_eval["TN"] == 2, f"Expected TN=2, got {bench16_eval['TN']}"
  assert bench16_eval["f1"] == 1.0, f"Expected f1=1.0, got {bench16_eval['f1']}"
  assert bench16_eval["pass2_idempotent"] is True

  suite_eval = run_night2_grounded_secops_benchmark()
  assert suite_eval["status"] == "success"
  assert suite_eval["scenario_count"] == 16
  assert suite_eval["total_seeded_defects"] == 83
  assert suite_eval["true_positives"] == 83
  assert suite_eval["false_positives"] == 0
  assert suite_eval["false_negatives"] == 0
  assert suite_eval["total_negative_controls"] == 33
  assert suite_eval["true_negatives"] == 33
  assert suite_eval["micro_f1"] == 1.0
  assert suite_eval["pass2_idempotency_rate"] == 1.0
  print(
      f"    -> BENCH-16: TP={bench16_eval['TP']}, FP={bench16_eval['FP']}, "
      f"FN={bench16_eval['FN']}, TN={bench16_eval['TN']}, F1={bench16_eval['f1']}"
  )
  print(
      f"    -> Full Suite (16 scenarios): TP={suite_eval['true_positives']}/83, "
      f"FP={suite_eval['false_positives']}, FN={suite_eval['false_negatives']}, "
      f"TN={suite_eval['true_negatives']}/33, Micro-F1={suite_eval['micro_f1']}"
  )

  # 2. Verify SkillRL 10-Rule Matrix & 29-Cycle (30-Horizon) Master Evolution Synthesis Report
  print(
      "[2/4] Verifying SkillRL 10-Rule Matrix & 29-Cycle (30-Horizon) Synthesis..."
  )
  skillrl_matrix = generate_skillrl_failure_distillation_matrix()
  assert skillrl_matrix["rule_count"] == 10
  assert (
      "SKILLRL-10-CAPSTONE-PRODUCTION-GOVERNANCE-GATE"
      in skillrl_matrix["rule_ids"]
  )
  evo_report = generate_master_evolution_synthesis_report()
  assert evo_report["total_cycles_completed"] == 29
  assert evo_report["total_horizons_completed"] == 30
  assert evo_report["total_horizons_delivered"] == 30
  assert evo_report["pillar_count"] == 5
  print(
      f"    -> SkillRL Rules: {skillrl_matrix['rule_count']} "
      f"(horizons={skillrl_matrix['horizons_covered']})"
  )
  print(
      f"    -> Evolution Synthesis: {evo_report['total_cycles_completed']} cycles, "
      f"{evo_report['total_horizons_delivered']} horizons (H1..H30)"
  )

  # 3. Live Google Docs API v1 + Drive API v3 in-place validation on existing doc
  print(
      f"[3/4] Resetting existing live Google Doc {DOC_ID} in place for Case {CASE_ID} (0 new docs)..."
  )
  bench16_spec = next(
      sc
      for sc in EXTENDED_NIGHT2_BENCHMARK_SCENARIOS
      if sc["scenario_id"]
      == "BENCH-16-CAPSTONE-KEV-DASHBOARD-SOAR-HILLCLIMB-OTEL"
  )
  audit_text_res = audit_capstone_production_governance_and_kev_exposure(
      bench16_spec["markdown_content"]
  )
  assert len(audit_text_res["defects"]) == 5

  creds = build_dwd_credentials()
  token = resolve_docs_token(token_source=creds)
  clear_doc_index_cache()
  reset_res = _reset_existing_google_doc_in_place(
      DOC_ID,
      bench16_spec["markdown_content"],
      token,
  )
  assert reset_res["new_docs_created"] == 0
  clear_doc_index_cache()

  live_pass1 = audit_capstone_production_governance_and_kev_exposure_in_doc(
      document_id=DOC_ID,
      mode="APPLY",
      token_source=creds,
      quota_project=QUOTA_PROJECT,
  )
  assert live_pass1["status"] == "success", f"live_pass1 failed: {live_pass1}"
  assert live_pass1["defect_count"] == 5, f"live_pass1 defect_count: {live_pass1}"
  assert live_pass1["comments_inserted"] == 5, f"live_pass1 comments: {live_pass1}"
  assert live_pass1["edits_staged"] == 5, f"live_pass1 edits: {live_pass1}"

  # Pass 2 idempotency on live Google Doc
  live_pass2 = audit_capstone_production_governance_and_kev_exposure_in_doc(
      document_id=DOC_ID,
      mode="APPLY",
      token_source=creds,
      quota_project=QUOTA_PROJECT,
  )
  assert live_pass2["status"] == "success"
  assert live_pass2["edits_staged"] == 0
  assert live_pass2["skipped_existing_suggestion_count"] >= 5

  live_suggestions = inspect_doc_suggestions(
      DOC_ID,
      token_source=creds,
      quota_project=QUOTA_PROJECT,
  )
  post_accept_res = verify_post_accept_secops_doc_readiness(
      document_id=DOC_ID,
      doc_text=bench16_spec["markdown_content"],
      token_source=creds,
      quota_project=QUOTA_PROJECT,
  )
  assert post_accept_res["pre_accept_verdict"] == "BLOCKED_CRITICAL_DEFECTS"
  assert post_accept_res["post_accept_verdict"] == "APPROVED_FOR_SOC_EXECUTION"
  assert post_accept_res["post_accept_readiness_status"] == "CERTIFIED_READY"
  assert post_accept_res["post_accept_readiness_score"] == 100.0
  assert post_accept_res["residual_defect_count"] == 0
  assert post_accept_res["convergence_rate"] == 1.0
  assert post_accept_res["is_converged"] is True

  print(
      f"    -> Live Doc Pass 1: defects={live_pass1['defect_count']}, "
      f"comments={live_pass1['comments_inserted']}, edits={live_pass1['edits_staged']}"
  )
  print(
      f"    -> Live Doc Pass 2 (Idempotency): edits_staged={live_pass2['edits_staged']}, "
      f"skipped_existing={live_pass2['skipped_existing_suggestion_count']}"
  )
  print(
      f"    -> Counterfactual Post-Accept Readiness: "
      f"{post_accept_res['pre_accept_verdict']} ({post_accept_res['pre_accept_readiness_score']}) -> "
      f"{post_accept_res['post_accept_verdict']} ({post_accept_res['post_accept_readiness_score']}), "
      f"status={post_accept_res['post_accept_readiness_status']}, "
      f"resolved={post_accept_res['resolved_defect_count']}, residual={post_accept_res['residual_defect_count']}"
  )

  # 4. Execute Grounded SOAR Review Workflow for Live Siemplify Case 4097
  print(
      f"[4/4] Executing Grounded SOAR Review Workflow for Case {CASE_ID}..."
  )
  workflow_output = run_grounded_soar_review_workflow(
      case_id=CASE_ID,
      skill_name="malware-incident-response",
      doc_url=f"https://docs.google.com/document/d/{DOC_ID}/edit",
      doc_text=bench16_spec["markdown_content"],
      verify_post_accept_readiness=True,
  )
  assert "BLOCKED_CRITICAL_DEFECTS" in workflow_output
  assert "APPROVED_FOR_SOC_EXECUTION" in workflow_output
  assert "CERTIFIED_READY" in workflow_output

  # Clean up any temporary workflow report written to multi-agent/reports/
  reports_dir = REPO_ROOT / "multi-agent" / "reports"
  if reports_dir.exists():
    for rpt_file in reports_dir.glob("Grounded_SOAR_Review_Case_*.md"):
      rpt_file.unlink(missing_ok=True)

  elapsed_s = round(time.time() - t0, 2)
  report_payload = {
      "cycle": 29,
      "horizon_id": "H30",
      "title": (
          "Epistemic Inventory-First CISA KEV Exposure Gate, Chronicle Native Dashboards "
          "RULE_DETECTIONS Verifier, Disciplined Hillclimber Anti-Memorization Guard & "
          "9-Hour Capstone Certification (BENCH-16)"
      ),
      "timestamp_epoch": int(time.time()),
      "elapsed_seconds": elapsed_s,
      "new_google_docs_created": 0,
      "reused_google_doc_id": DOC_ID,
      "case_id": CASE_ID,
      "catalog_version": H30_CAPSTONE_PRODUCTION_GOVERNANCE_AND_KEV_EXPOSURE_CATALOG[
          "catalog_version"
      ],
      "bench16_evaluation": {
          "scenario_id": bench16_eval["scenario_id"],
          "TP": bench16_eval["TP"],
          "FP": bench16_eval["FP"],
          "FN": bench16_eval["FN"],
          "TN": bench16_eval["TN"],
          "precision": bench16_eval["precision"],
          "recall": bench16_eval["recall"],
          "f1": bench16_eval["f1"],
          "pass2_idempotent": bench16_eval["pass2_idempotent"],
      },
      "full_benchmark_suite": {
          "scenario_count": suite_eval["scenario_count"],
          "total_seeded_defects": suite_eval["total_seeded_defects"],
          "TP": suite_eval["true_positives"],
          "FP": suite_eval["false_positives"],
          "FN": suite_eval["false_negatives"],
          "total_negative_controls": suite_eval["total_negative_controls"],
          "TN": suite_eval["true_negatives"],
          "micro_precision": suite_eval["micro_precision"],
          "micro_recall": suite_eval["micro_recall"],
          "micro_f1": suite_eval["micro_f1"],
          "pass2_idempotency_rate": suite_eval["pass2_idempotency_rate"],
      },
      "skillrl_distillation_matrix": {
          "rule_count": skillrl_matrix["rule_count"],
          "horizons_covered": skillrl_matrix["horizons_covered"],
          "rule_ids": skillrl_matrix["rule_ids"],
      },
      "master_evolution_synthesis": {
          "total_cycles_completed": evo_report["total_cycles_completed"],
          "total_horizons_delivered": evo_report["total_horizons_delivered"],
          "pillar_count": evo_report["pillar_count"],
      },
      "live_google_doc_validation": {
          "document_id": DOC_ID,
          "new_docs_created": 0,
          "pass1_defect_count": live_pass1["defect_count"],
          "pass1_defect_counts_by_type": live_pass1["defect_counts_by_type"],
          "pass1_comments_inserted": live_pass1["comments_inserted"],
          "pass1_edits_staged": live_pass1["edits_staged"],
          "pass1_negative_controls_preserved": live_pass1[
              "negative_controls_preserved"
          ],
          "pass1_standard_yara_ignored": live_pass1[
              "standard_yara_blocks_ignored_count"
          ],
          "pass2_edits_staged": live_pass2["edits_staged"],
          "pass2_skipped_existing_suggestions": live_pass2[
              "skipped_existing_suggestion_count"
          ],
          "live_suggestion_count": live_suggestions.get("suggestion_count", 0),
      },
      "counterfactual_post_accept_readiness": {
          "pre_accept_verdict": post_accept_res["pre_accept_verdict"],
          "post_accept_verdict": post_accept_res["post_accept_verdict"],
          "post_accept_readiness_status": post_accept_res[
              "post_accept_readiness_status"
          ],
          "pre_accept_readiness_score": post_accept_res[
              "pre_accept_readiness_score"
          ],
          "post_accept_readiness_score": post_accept_res[
              "post_accept_readiness_score"
          ],
          "readiness_score_delta": post_accept_res["readiness_score_delta"],
          "resolved_defect_count": post_accept_res["resolved_defect_count"],
          "residual_defect_count": post_accept_res["residual_defect_count"],
          "convergence_rate": post_accept_res["convergence_rate"],
          "is_converged": post_accept_res["is_converged"],
          "signoff_gate_passed": post_accept_res["signoff_gate_passed"],
          "signoff_badge_markdown": post_accept_res["signoff_badge_markdown"],
      },
  }
  REPORT_PATH.write_text(
      json.dumps(report_payload, indent=2) + "\n", encoding="utf-8"
  )
  print(
      f"=== Cycle 29 (H30) Validation Succeeded in {elapsed_s}s -> {REPORT_PATH} ==="
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
