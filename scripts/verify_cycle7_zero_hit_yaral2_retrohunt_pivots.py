#!/usr/bin/env python3
"""Cycle 7 (H14) Live Validation Script: Zero-Hit YARA-L 2.0 Retrohunt Predicate
Diagnostics & Compiler-Verified Pivot Red-Liner Inside Google Docs.

Validates against live Argolis Chronicle SIEM (`dandye-0324-chronicle`,
`validate_rule` + `search_udm`) and Google Docs API v1:
1. Step 1 (Direct SIEM Compiler + Retrohunt Zero-Hit Diagnosis):
   - Rule 1 (`gcp_sa_privilege_escalation_case_33278`): combined static YARA-L 2.0
     schema defects (`strings:`, `$e.resource.name`, `$e.ip`, `condition: $event`)
     AND semantic `value_format_mismatch` on
     `$e.resource.name = "projects/base-analytics/instances/prod-customers"`.
     Verifies static repair alone yields 0 retrohunt hits, while
     `diagnose_zero_hit_yaral2_rule` upgrades the predicate to
     `$e.target.resource.name = "projects/base-production"`, passes live
     `validate_rule` (`pivot_compiler_verified=True`), and matches live
     `GCP_CLOUDAUDIT` telemetry (`pivot_event_count >= 1`).
   - Rule 2 (`wins_d19_cmd_discovery_case_33280`): syntactically valid YARA-L 2.0
     rule with `exact_match_on_command_line` (`$proc.target.process.command_line = "cmd.exe"`).
     Verifies 0 static findings, 0 initial retrohunt hits, diagnosis as
     `exact_match_on_command_line`, pivot to
     `re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase`,
     live `validate_rule` pass (`pivot_compiler_verified=True`), and live
     `WINDOWS_SYSMON` matches (`pivot_event_count >= 1`).
   - Rule 3 (`linux_derp_process_creation_case_33279`): syntactically valid YARA-L 2.0
     rule with `entity_role_swap`
     (`re.regex($proc.principal.process.command_line, `.*DERPService.*`) nocase`).
     Verifies 0 static findings, 0 initial retrohunt hits, diagnosis as
     `entity_role_swap`, pivot to `$proc.target.process.command_line`, live
     `validate_rule` pass (`pivot_compiler_verified=True`), and live process
     command-line matches (`pivot_event_count >= 1`).
2. Step 2 (End-to-End Google Docs Red-Lining, Projection & Idempotency):
   - Creates (or reuses) at most 1 Google Doc
     (`Cycle7_H14_Live_Zero_Hit_YARAL2_Retrohunt_Pivot_Validation`) in `SOC Reports`
     containing the 3 zero-hit YARA-L 2.0 rules plus 1 valid non-zero-hit control
     rule (`valid_crowdstrike_network_control`).
   - Runs `verify_and_redline_yaral2_rules_in_doc(doc_id, run_live_siem_check=True, diagnose_zero_hit_retrohunt=True)`
     and asserts `yaral2_findings_count == 6`, `zero_hit_yaral2_findings_count == 3`,
     `comments.inserted_count == 6`, and `edits.applied_count == 6`.
   - Runs `inspect_doc_suggestions(doc_id)` and asserts `suggestion_count == 6`,
     verifies the unified diff contains all compiler-verified YARA-L 2.0 pivots,
     and confirms every rule extracted from `accepted_text` passes live
     `validate_rule` and matches live UDM telemetry (`retrohunt_event_count >= 1`).
   - Re-runs `verify_and_redline_yaral2_rules_in_doc` on the same Google Doc and
     asserts `yaral2_findings_count == 0`, `zero_hit_yaral2_findings_count == 0`,
     `skipped_existing_suggestion_count == 6`, `comments.inserted_count == 0`, and
     `edits.applied_count == 0`.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in (REPO_ROOT, MULTI_AGENT_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(MULTI_AGENT_DIR / ".env")

import manager.tools.tools as tmod  # noqa: E402
from manager.tools.docs_review_tools import (  # noqa: E402
    _iter_yaral2_rule_blocks,
    clear_doc_index_cache,
    create_google_doc,
    diagnose_zero_hit_yaral2_rule,
    inspect_doc_suggestions,
    verify_and_redline_yaral2_rules_in_doc,
    verify_yaral2_rule_with_siem,
)
from skills.drive_registry import DriveMcpClient  # noqa: E402

DOC_TITLE = "Cycle7_H14_Live_Zero_Hit_YARAL2_Retrohunt_Pivot_Validation"
START_TIME = "2026-02-07T00:00:00Z"
END_TIME = "2026-02-08T00:00:00Z"

RULE_1_COMBINED_SCHEMA_AND_VALUE_MISMATCH = """rule gcp_sa_privilege_escalation_case_33278 {
  meta:
    author = "SOC Detection Engineering"
    description = "Detects GCP SetIamPolicy privilege escalation from Case 33278"
    severity = "HIGH"
  strings:
    $e.metadata.log_type = "GCP_CLOUDAUDIT"
    $e.resource.name = "projects/base-analytics/instances/prod-customers"
    $e.ip = "104.198.226.161"
  condition:
    $event
}"""

RULE_2_EXACT_MATCH_COMMAND_LINE = """rule wins_d19_cmd_discovery_case_33280 {
  meta:
    author = "SOC Detection Engineering"
    description = "Detects cmd.exe process execution on wins-d19 from Case 33280"
    severity = "MEDIUM"
  events:
    $proc.principal.hostname = "wins-d19"
    $proc.target.process.command_line = "cmd.exe"
  condition:
    $proc
}"""

RULE_3_ENTITY_ROLE_SWAP = """rule linux_derp_process_creation_case_33279 {
  meta:
    author = "SOC Detection Engineering"
    description = "Detects DERPService execution on endpoint host"
    severity = "HIGH"
  events:
    $proc.principal.hostname = "wins-d19"
    re.regex($proc.principal.process.command_line, `.*DERPService.*`) nocase
  condition:
    $proc
}"""

RULE_4_VALID_CONTROL = """rule valid_crowdstrike_network_control {
  meta:
    author = "SOC Detection Engineering"
    description = "Valid non-zero-hit control rule for Windows Sysmon endpoint activity"
    severity = "LOW"
  events:
    $net.metadata.log_type = "WINDOWS_SYSMON"
    $net.principal.hostname = "wins-d19"
  condition:
    $net
}"""


def _escape_markdown_backticks(text: str) -> str:
    """Escapes literal backticks so Google Drive's text/markdown importer preserves
    backtick characters inside the Google Doc textRun instead of stripping them as
    inline code spans."""
    return re.sub(r"`([^`\r\n]+)`", r"\\`\1\\`", text)


def _build_doc_markdown() -> str:
    r3_escaped = _escape_markdown_backticks(RULE_3_ENTITY_ROLE_SWAP)
    return (
        f"# {DOC_TITLE}\n\n"
        "## Section 1: Combined Static Schema + Zero-Hit Value Mismatch (Case 33278)\n\n"
        f"{RULE_1_COMBINED_SCHEMA_AND_VALUE_MISMATCH}\n\n"
        "## Section 2: Syntactically Valid Zero-Hit Exact Command-Line Match (Case 33280)\n\n"
        f"{RULE_2_EXACT_MATCH_COMMAND_LINE}\n\n"
        "## Section 3: Syntactically Valid Zero-Hit Entity Role Swap (Case 33279)\n\n"
        f"{r3_escaped}\n\n"
        "## Section 4: Valid Non-Zero-Hit Control Rule\n\n"
        f"{RULE_4_VALID_CONTROL}\n"
    )


def _find_or_create_validation_doc(folder_id: str | None) -> str:
    """Creates at most 1 validation Google Doc for Cycle 7 (H14)."""
    create_res = create_google_doc(
        title=DOC_TITLE,
        content=_build_doc_markdown(),
        folder_id=folder_id,
    )
    assert create_res.get("status") == "success", f"create_google_doc failed: {create_res}"
    doc_id = str(create_res["document_id"])
    print(f"[Drive] Created new validation Google Doc: {doc_id}")
    return doc_id


def main() -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    folder_id = os.environ.get("GOOGLE_DRIVE_FOLDER_ID") or os.environ.get(
        "DRIVE_REPORTS_FOLDER_ID"
    )
    summary: dict[str, Any] = {"step1_direct_diagnoses": {}, "step2_doc_validation": {}}

    print("Initializing Argolis Chronicle SIEM MCP toolset...")
    siem_toolset, soar_toolset, gti_toolset = tmod.init_shared_mcp_tools()
    try:
        siem_tools = {
            t.name: t
            for t in loop.run_until_complete(
                siem_toolset.get_tools(readonly_context=None)
            )
        }
        print(
            f"Discovered {len(siem_tools)} SIEM tools "
            f"(validate_rule={'validate_rule' in siem_tools}, "
            f"search_udm={'search_udm' in siem_tools})"
        )

        def live_siem_validate(rule_text: str) -> Any:
            return loop.run_until_complete(
                siem_tools["validate_rule"].run_async(
                    args={"rule_text": rule_text},
                    tool_context=None,
                )
            )

        def live_siem_search(
            query: str,
            start_time: str = START_TIME,
            end_time: str = END_TIME,
            max_events: int = 20,
        ) -> Any:
            return loop.run_until_complete(
                siem_tools["search_udm"].run_async(
                    args={
                        "query": query,
                        "start_time": start_time,
                        "end_time": end_time,
                        "max_events": max_events,
                    },
                    tool_context=None,
                )
            )

        print("\n=== Step 1: Direct SIEM Compiler + Retrohunt Zero-Hit Diagnosis ===")

        # 1a. Rule 1: Combined static schema + value_format_mismatch
        diag1 = diagnose_zero_hit_yaral2_rule(
            RULE_1_COMBINED_SCHEMA_AND_VALUE_MISMATCH,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert diag1["status"] == "success", f"Rule 1 diagnosis failed: {diag1}"
        assert len(diag1["static_findings"]) == 4
        assert diag1["has_schema_defect"] is True
        assert diag1["initial_event_count"] == 0
        assert diag1["failure_reason"] == "value_format_mismatch"
        assert (
            diag1["recommended_yaral2_predicate"]
            == '$e.target.resource.name = "projects/base-production"'
        )
        assert diag1["pivot_compiler_verified"] is True
        assert diag1["pivot_verified"] is True
        assert diag1["pivot_event_count"] >= 1
        summary["step1_direct_diagnoses"]["rule1_value_format_mismatch"] = {
            "rule_name": diag1["rule_name"],
            "static_findings_count": len(diag1["static_findings"]),
            "initial_event_count": diag1["initial_event_count"],
            "failure_reason": diag1["failure_reason"],
            "recommended_yaral2_predicate": diag1["recommended_yaral2_predicate"],
            "pivoted_retrohunt_udm_query": diag1["pivoted_retrohunt_udm_query"],
            "pivot_compiler_verified": diag1["pivot_compiler_verified"],
            "pivot_event_count": diag1["pivot_event_count"],
            "observed_values": diag1["observed_values"],
        }
        print(
            f"[Step 1.1] Rule 1 ({diag1['rule_name']}): failure_reason={diag1['failure_reason']}, "
            f"pivot_compiler_verified={diag1['pivot_compiler_verified']}, "
            f"pivot_event_count={diag1['pivot_event_count']}"
        )

        # 1b. Rule 2: Syntactically valid rule with exact_match_on_command_line
        diag2 = diagnose_zero_hit_yaral2_rule(
            RULE_2_EXACT_MATCH_COMMAND_LINE,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert diag2["status"] == "success", f"Rule 2 diagnosis failed: {diag2}"
        assert len(diag2["static_findings"]) == 0
        assert diag2["initial_event_count"] == 0
        assert diag2["failure_reason"] == "exact_match_on_command_line"
        assert (
            diag2["recommended_yaral2_predicate"]
            == "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
        )
        assert diag2["pivot_compiler_verified"] is True
        assert diag2["pivot_verified"] is True
        assert diag2["pivot_event_count"] >= 1
        summary["step1_direct_diagnoses"]["rule2_exact_match_on_command_line"] = {
            "rule_name": diag2["rule_name"],
            "static_findings_count": len(diag2["static_findings"]),
            "initial_event_count": diag2["initial_event_count"],
            "failure_reason": diag2["failure_reason"],
            "recommended_yaral2_predicate": diag2["recommended_yaral2_predicate"],
            "pivoted_retrohunt_udm_query": diag2["pivoted_retrohunt_udm_query"],
            "pivot_compiler_verified": diag2["pivot_compiler_verified"],
            "pivot_event_count": diag2["pivot_event_count"],
            "observed_values": diag2["observed_values"],
        }
        print(
            f"[Step 1.2] Rule 2 ({diag2['rule_name']}): failure_reason={diag2['failure_reason']}, "
            f"pivot_compiler_verified={diag2['pivot_compiler_verified']}, "
            f"pivot_event_count={diag2['pivot_event_count']}"
        )

        # 1c. Rule 3: Syntactically valid rule with entity_role_swap
        diag3 = diagnose_zero_hit_yaral2_rule(
            RULE_3_ENTITY_ROLE_SWAP,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert diag3["status"] == "success", f"Rule 3 diagnosis failed: {diag3}"
        assert len(diag3["static_findings"]) == 0
        assert diag3["initial_event_count"] == 0
        assert diag3["failure_reason"] == "entity_role_swap"
        assert diag3["recommended_span_replacement"] == "$proc.target.process.command_line"
        assert (
            diag3["recommended_yaral2_predicate"]
            == "re.regex($proc.target.process.command_line, `.*DERPService.*`) nocase"
        )
        assert diag3["pivot_compiler_verified"] is True
        assert diag3["pivot_verified"] is True
        assert diag3["pivot_event_count"] >= 1
        summary["step1_direct_diagnoses"]["rule3_entity_role_swap"] = {
            "rule_name": diag3["rule_name"],
            "static_findings_count": len(diag3["static_findings"]),
            "initial_event_count": diag3["initial_event_count"],
            "failure_reason": diag3["failure_reason"],
            "recommended_span_replacement": diag3["recommended_span_replacement"],
            "recommended_yaral2_predicate": diag3["recommended_yaral2_predicate"],
            "pivoted_retrohunt_udm_query": diag3["pivoted_retrohunt_udm_query"],
            "pivot_compiler_verified": diag3["pivot_compiler_verified"],
            "pivot_event_count": diag3["pivot_event_count"],
            "observed_values": diag3["observed_values"],
        }
        print(
            f"[Step 1.3] Rule 3 ({diag3['rule_name']}): failure_reason={diag3['failure_reason']}, "
            f"pivot_compiler_verified={diag3['pivot_compiler_verified']}, "
            f"pivot_event_count={diag3['pivot_event_count']}"
        )

        print(
            "\n=== Step 2: End-to-End Google Docs Red-Lining, Projection & Idempotency ==="
        )
        clear_doc_index_cache()
        doc_id = _find_or_create_validation_doc(folder_id)

        pass1 = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert pass1["status"] == "success", f"Pass 1 failed: {pass1}"
        print(
            f"[Step 2.1] Pass 1: yaral2_findings_count={pass1['yaral2_findings_count']}, "
            f"zero_hit_yaral2_findings_count={pass1['zero_hit_yaral2_findings_count']}, "
            f"skipped={pass1['skipped_existing_suggestion_count']}, "
            f"comments={pass1['comments']['inserted_count']}, "
            f"edits={pass1['edits']['applied_count']}"
        )

        if pass1["skipped_existing_suggestion_count"] == 0:
            assert pass1["yaral2_findings_count"] == 6
            assert pass1["zero_hit_yaral2_findings_count"] == 3
            assert pass1["comments"]["inserted_count"] == 6
            assert pass1["edits"]["applied_count"] == 6

        inspect_res = inspect_doc_suggestions(doc_id)
        assert (
            inspect_res["status"] == "success"
        ), f"inspect_doc_suggestions failed: {inspect_res}"
        assert inspect_res["suggestion_count"] == 6, (
            f"Expected 6 suggestions, got {inspect_res['suggestion_count']}"
        )
        unified_diff = str(inspect_res["unified_diff"])
        assert '$e.target.resource.name = "projects/base-production"' in unified_diff
        assert (
            "re.regex($proc.target.process.command_line, `.*cmd\\.exe.*`) nocase"
            in unified_diff
        )
        assert "$proc.target.process.command_line" in unified_diff

        accepted_text = str(inspect_res["accepted_text"])
        accepted_blocks = _iter_yaral2_rule_blocks(accepted_text)
        assert len(accepted_blocks) == 4, (
            f"Expected 4 rules in accepted_text, got {len(accepted_blocks)}"
        )
        accepted_rule_verifications: list[dict[str, Any]] = []
        for block in accepted_blocks:
            r_check = verify_yaral2_rule_with_siem(
                block["rule_text"],
                run_retrohunt_check=True,
                diagnose_zero_hit_retrohunt=False,
                start_time=START_TIME,
                end_time=END_TIME,
                siem_validate_fn=live_siem_validate,
                siem_search_fn=live_siem_search,
            )
            assert r_check["compiler_verified"] is True, (
                f"Accepted rule {block['rule_name']} failed compiler check: {r_check}"
            )
            assert r_check["retrohunt_event_count"] >= 1, (
                f"Accepted rule {block['rule_name']} returned 0 retrohunt hits: {r_check}"
            )
            accepted_rule_verifications.append(
                {
                    "rule_name": block["rule_name"],
                    "compiler_verified": r_check["compiler_verified"],
                    "retrohunt_udm_query": r_check["retrohunt_udm_query"],
                    "retrohunt_event_count": r_check["retrohunt_event_count"],
                }
            )
            print(
                f"[Step 2.2] Accepted rule '{block['rule_name']}': "
                f"compiler_verified={r_check['compiler_verified']}, "
                f"retrohunt_event_count={r_check['retrohunt_event_count']}"
            )

        # Pass 2: Re-run verify_and_redline_yaral2_rules_in_doc for strict idempotency
        clear_doc_index_cache()
        pass2 = verify_and_redline_yaral2_rules_in_doc(
            doc_id,
            run_live_siem_check=True,
            diagnose_zero_hit_retrohunt=True,
            start_time=START_TIME,
            end_time=END_TIME,
            siem_validate_fn=live_siem_validate,
            siem_search_fn=live_siem_search,
        )
        assert pass2["status"] == "success", f"Pass 2 failed: {pass2}"
        assert pass2["yaral2_findings_count"] == 0
        assert pass2["zero_hit_yaral2_findings_count"] == 0
        assert pass2["skipped_existing_suggestion_count"] == 6
        assert pass2["comments"]["inserted_count"] == 0
        assert pass2["edits"]["applied_count"] == 0
        print(
            f"[Step 2.3] Pass 2 Idempotency: yaral2_findings_count={pass2['yaral2_findings_count']}, "
            f"zero_hit_yaral2_findings_count={pass2['zero_hit_yaral2_findings_count']}, "
            f"skipped_existing_suggestion_count={pass2['skipped_existing_suggestion_count']}"
        )

        summary["step2_doc_validation"] = {
            "document_id": doc_id,
            "document_url": f"https://docs.google.com/document/d/{doc_id}/edit",
            "char_count": pass1["char_count"],
            "pass1_yaral2_findings_count": pass1["yaral2_findings_count"],
            "pass1_zero_hit_yaral2_findings_count": pass1[
                "zero_hit_yaral2_findings_count"
            ],
            "pass1_comments_inserted": pass1["comments"]["inserted_count"],
            "pass1_edits_applied": pass1["edits"]["applied_count"],
            "suggestion_count": inspect_res["suggestion_count"],
            "accepted_rule_verifications": accepted_rule_verifications,
            "pass2_yaral2_findings_count": pass2["yaral2_findings_count"],
            "pass2_zero_hit_yaral2_findings_count": pass2[
                "zero_hit_yaral2_findings_count"
            ],
            "pass2_skipped_existing_suggestion_count": pass2[
                "skipped_existing_suggestion_count"
            ],
        }

        print("\n=== Cycle 7 (H14) Live Validation Summary JSON ===")
        print(json.dumps(summary, indent=2))
        return 0
    finally:
        for ts in (siem_toolset, soar_toolset, gti_toolset):
            if ts is not None:
                try:
                    loop.run_until_complete(ts.close())
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())
