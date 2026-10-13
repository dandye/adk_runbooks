"""
Outer-to-Inner Loop Trace Promotion Bridge (Phase 5).

Converts AQuA outer-loop systemic insights (from aqua_insights.db) or individual
ADK production session traces (from session.db) into declarative regression test
cases in evals/datasets/production_regressions.json.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in [str(REPO_ROOT), str(MULTI_AGENT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from evals.aqua_outer_loop import DEFAULT_AQUA_DB, AquaDatabase, analyze_session_trace
from evals.datasets import load_dataset
from evals.registry import WORKFLOW_REGISTRY, get_workflow_definition
from evals.telemetry_bridge import DEFAULT_SESSION_DB, load_session_trace

DEFAULT_REGRESSIONS_OUTPUT = REPO_ROOT / "evals" / "datasets" / "production_regressions.json"

WORKFLOW_ALIASES: Dict[str, str] = {
    "suspicious_login_triage_workflow": "suspicious_login_workflow",
    "run_suspicious_login_triage_workflow": "suspicious_login_workflow",
}


def _resolve_canonical_workflow_name(raw_name: str) -> str:
    cleaned = raw_name.strip().removeprefix("run_")
    if cleaned in WORKFLOW_ALIASES:
        return WORKFLOW_ALIASES[cleaned]
    if raw_name in WORKFLOW_ALIASES:
        return WORKFLOW_ALIASES[raw_name]
    if cleaned in WORKFLOW_REGISTRY:
        return cleaned
    return "suspicious_login_workflow"


def _get_template_by_workflow() -> Dict[str, Dict[str, Any]]:
    try:
        all_cases = load_dataset("all_36_workflows")
        return {c["workflow_name"]: c for c in all_cases if "workflow_name" in c}
    except Exception:
        return {}


def _merge_and_write_regressions(
    target_out: Path,
    new_cases: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge new regression cases into target_out by test_id without clobbering prior cases."""
    existing: List[Dict[str, Any]] = []
    if target_out.exists():
        raw_text = target_out.read_text(encoding="utf-8").strip()
        if raw_text:
            try:
                parsed = json.loads(raw_text)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Existing regression dataset '{target_out}' contains invalid JSON: {exc}"
                ) from exc
            if not isinstance(parsed, list):
                raise ValueError(
                    f"Existing regression dataset '{target_out}' must be a JSON list."
                )
            existing = parsed

    index_by_id = {
        c.get("test_id"): idx
        for idx, c in enumerate(existing)
        if isinstance(c, dict) and c.get("test_id")
    }
    for case in new_cases:
        tid = case.get("test_id")
        if tid in index_by_id:
            existing[index_by_id[tid]] = case
        else:
            index_by_id[tid] = len(existing)
            existing.append(case)

    target_out.parent.mkdir(parents=True, exist_ok=True)
    target_out.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return existing


def promote_from_aqua_db(
    db_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    insight_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Promote systemic AQuA insights from SQLite into declarative regression test cases.
    Merges with existing entries in output_path by test_id.
    """
    db = AquaDatabase(db_path or DEFAULT_AQUA_DB)
    templates = _get_template_by_workflow()

    if insight_id:
        ins = db.get_insight(insight_id)
        insights = [ins] if ins else []
    else:
        insights = db.list_insights()

    promoted_cases: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()

    for ins in insights:
        if not ins:
            continue
        affected = ins.get("affected_workflows") or ["suspicious_login_workflow"]
        for raw_wf in affected:
            wf_name = _resolve_canonical_workflow_name(raw_wf)
            wf_def = get_workflow_definition(wf_name)
            if wf_def is None:
                continue

            test_id = f"REG-{ins['insight_id']}-{wf_name.upper()}"
            if test_id in seen_ids:
                continue
            seen_ids.add(test_id)

            tpl = templates.get(wf_name, {})
            input_payload = dict(tpl.get("input", {"case_id": "33279"}))
            expected_payload = dict(
                tpl.get(
                    "expected",
                    {
                        "required_output_fields": ["action_taken", "soar_comment"],
                    },
                )
            )
            expected_payload["categorical_verdicts"] = {
                "ProgressiveDisclosureCompliance": "HONORED",
                "McpSchemaHygiene": "SCHEMA_VERIFIED",
                "SoarTriagingIntegrity": "GROUNDED_DISPOSITION",
            }

            case_record = {
                "test_id": test_id,
                "workflow_name": wf_name,
                "description": (
                    f"[Promoted from {ins['insight_id']} ({ins['category']})] "
                    f"{ins['description']}"
                ),
                "source_insight_id": ins["insight_id"],
                "failure_category": ins["category"],
                "root_cause_hypothesis": ins["root_cause_hypothesis"],
                "remediation_proposal": ins["remediation_proposal"],
                "runbook_reference": wf_def.runbook_path,
                "skill_reference": wf_def.skill_path,
                "rubric_type": wf_def.rubric_type,
                "disclosure_mode": "dual_progressive",
                "input": input_payload,
                "expected": expected_payload,
                "min_passing_score": 80.0,
            }
            promoted_cases.append(case_record)

    target_out = Path(output_path) if output_path else DEFAULT_REGRESSIONS_OUTPUT
    _merge_and_write_regressions(target_out, promoted_cases)
    return promoted_cases


def promote_session_to_dataset(
    session_id: str,
    db_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Promote a single ADK SQLite session trace into a regression test case."""
    trace = load_session_trace(session_id, db_path=db_path or DEFAULT_SESSION_DB)
    report = analyze_session_trace(trace, source="session-db")
    templates = _get_template_by_workflow()

    wf_name = _resolve_canonical_workflow_name(trace.workflow_name)
    wf_def = get_workflow_definition(wf_name)
    tpl = templates.get(wf_name, {})

    case_record = {
        "test_id": f"REG-SESSION-{session_id[:8].upper()}",
        "workflow_name": wf_name,
        "description": f"Promoted from ADK session {session_id}: {report['summary']}",
        "source_session_id": session_id,
        "failure_category": (
            report["detected_issues"][0]["category"]
            if report["detected_issues"]
            else "PRODUCTION_TRACE_REGRESSION"
        ),
        "runbook_reference": wf_def.runbook_path if wf_def else "",
        "skill_reference": wf_def.skill_path if wf_def else "",
        "rubric_type": wf_def.rubric_type if wf_def else "TRIAGE_IRP",
        "disclosure_mode": "dual_progressive",
        "input": dict(tpl.get("input", {"case_id": "33279"})),
        "expected": {
            **dict(tpl.get("expected", {"required_output_fields": ["action_taken"]})),
            "categorical_verdicts": {
                "ProgressiveDisclosureCompliance": "HONORED",
                "McpSchemaHygiene": "SCHEMA_VERIFIED",
                "SoarTriagingIntegrity": "GROUNDED_DISPOSITION",
            },
        },
        "min_passing_score": 80.0,
    }

    target_out = Path(output_path) if output_path else DEFAULT_REGRESSIONS_OUTPUT
    _merge_and_write_regressions(target_out, [case_record])
    return case_record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Promote AQuA outer-loop insights or ADK sessions to regression dataset JSON"
    )
    parser.add_argument(
        "--from-aqua-db",
        type=str,
        default=str(DEFAULT_AQUA_DB),
        help="Path to aqua_insights.db (default: evals/results/aqua_insights.db)",
    )
    parser.add_argument(
        "--insight-id",
        type=str,
        default=None,
        help="Optional specific insight ID to promote",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Optional specific ADK session ID to promote from session.db",
    )
    parser.add_argument(
        "--session-db",
        type=str,
        default=str(DEFAULT_SESSION_DB),
        help="Path to ADK session.db when --session-id is used",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_REGRESSIONS_OUTPUT),
        help="Output regression dataset JSON path (default: evals/datasets/production_regressions.json)",
    )

    args = parser.parse_args()
    out_path = Path(args.output)

    if args.session_id:
        case = promote_session_to_dataset(
            args.session_id,
            db_path=Path(args.session_db),
            output_path=out_path,
        )
        print(f"Promoted session '{args.session_id}' -> {case['test_id']} in {out_path}")
        return 0

    cases = promote_from_aqua_db(
        db_path=Path(args.from_aqua_db),
        output_path=out_path,
        insight_id=args.insight_id,
    )
    print(f"=== Outer-to-Inner Loop Promotion Complete ===")
    print(f"Promoted {len(cases)} regression test case(s) to {out_path}:")
    for c in cases:
        print(f"  * {c['test_id']} -> {c['workflow_name']} ({c['failure_category']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
