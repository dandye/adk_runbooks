"""Run a Harness2 Propose-Probe-Compose loop or dataset sweep on ADK Runbooks scenarios.

Examples:
  python -m evals.run_harness2_loop --task-id TEST-CORE-SUSP-LOGIN-002 --k 1 --mode parallel
  python -m evals.run_harness2_loop --sweep --k 1 --mode parallel
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from harness2.core import judge as harness_judge
from harness2.core import library as harness_library
from harness2.core import schedule as harness_schedule
from harness2.core import tree as harness_tree

from evals.harness2_adapter import REPO_ROOT, AdkGeminiProposer, AdkRunbooksAdapter


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Harness2 Propose-Probe-Compose loop or sweep on ADK Runbooks."
    )
    parser.add_argument(
        "--task-id",
        default="TEST-CORE-SUSP-LOGIN-002",
        help="Scenario test_id from the dataset (default: TEST-CORE-SUSP-LOGIN-002).",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="Run all scenarios in the dataset in continual-learning stream order across domains.",
    )
    parser.add_argument(
        "--max-tasks",
        type=int,
        default=None,
        help="Optional cap on tasks per domain during a sweep.",
    )
    parser.add_argument(
        "--domain-parallel",
        type=int,
        default=1,
        help="Number of domains to run concurrently during a sweep (default: 1).",
    )
    parser.add_argument(
        "--only-domains",
        default="",
        help="Comma-separated domain names to include during a sweep.",
    )
    parser.add_argument(
        "--dataset",
        default="core_workflows",
        help="Dataset name under evals/datasets/ (default: core_workflows).",
    )
    parser.add_argument(
        "--k",
        type=int,
        default=1,
        help="Recursion budget k; runs 4k solver rollouts and 3k improver stages (default: 1).",
    )
    parser.add_argument(
        "--mode",
        choices=("parallel", "sequential", "agg", "seq"),
        default="parallel",
        help="Recursion schedule: parallel (agg) or sequential (seq) (default: parallel).",
    )
    parser.add_argument(
        "--solver-model",
        default="gemini-3-flash-preview",
        help="Model ID for ADK solver rollouts (default: gemini-3-flash-preview).",
    )
    parser.add_argument(
        "--improver-model",
        default="gemini-3-flash-preview",
        help="Model ID for Harness2 improver/reflection calls (default: gemini-3-flash-preview).",
    )
    parser.add_argument(
        "--runs-dir",
        default=str(REPO_ROOT / "evals" / "results" / "harness2_runs"),
        help="Directory for Harness2 runs, audit logs, and experience library.",
    )
    parser.add_argument(
        "--tag",
        default="",
        help="Optional run namespace tag.",
    )
    return parser.parse_args(argv)


def _format_score(scored: harness_judge.Scored | None) -> str:
    if scored is None:
        return "not-scored"
    if scored.error:
        return f"error ({scored.error})"
    raw = scored.raw or {}
    rubric = raw.get("rubric_score")
    gates = raw.get("gates_passed")
    tokens = raw.get("total_tokens")
    calls = raw.get("tool_calls_count")
    return (
        f"score={rubric}/{scored.n_criteria} "
        f"all_pass={scored.all_pass} "
        f"gates_passed={gates} "
        f"tool_calls={calls} "
        f"tokens={tokens}"
    )


def _score_task_dir(
    *,
    adapter: AdkRunbooksAdapter,
    task_id: str,
    mode_tok: str,
    k: int,
    runs_root: Path,
    tag: str,
) -> dict[str, Any]:
    ns_obj = harness_schedule.Namespace(
        adapter.spec.name, adapter.substrate.name, mode_tok, k, None, tag
    )
    task_dir = ns_obj.task_dir(runs_root, task_id)
    summary_path = task_dir / "summary.json"
    summary = (
        json.loads(summary_path.read_text(encoding="utf-8"))
        if summary_path.is_file()
        else {}
    )
    base_list = summary.get("base") or []
    base_scored: harness_judge.Scored | None = None
    if base_list:
        b0 = base_list[0]
        base_scored = harness_judge.judge_one(
            adapter,
            task_id,
            mode_tok,
            k,
            str(b0["label"]),
            str(b0["run_id"]),
            Path(str(b0["run_dir"])),
            chosen_is_base=True,
        )

    sels = summary.get("selections") or {}
    sel = sels.get(mode_tok) or {}
    final_scored: harness_judge.Scored | None = None
    if sel.get("ok") and sel.get("chosen_run_dir"):
        judged = harness_judge.judge_selections(adapter, [sel], parallel=1)
        final_scored = judged[0] if judged else None

    surface = adapter.substrate.surface()
    base_tree = harness_tree.read_tree(surface, adapter.base_harness())
    chosen_label = str(sel.get("chosen_label") or "")
    chosen_harness_dir = task_dir / "harnesses" / chosen_label
    chosen_tree = (
        harness_tree.read_tree(surface, chosen_harness_dir)
        if chosen_label and chosen_harness_dir.is_dir()
        else base_tree
    )
    diff = harness_tree.diff_summary(surface, base_tree, chosen_tree)

    scores_payload = {
        "task_id": task_id,
        "domain": adapter.domain_of(task_id),
        "mode": mode_tok,
        "k": k,
        "status": summary.get("status", "unknown"),
        "chosen_label": chosen_label,
        "diff_from_base": diff,
        "base1": (base_scored.__dict__ if base_scored else None),
        "chosen": (final_scored.__dict__ if final_scored else None),
    }
    scores_path = task_dir / "scores.json"
    if task_dir.is_dir():
        scores_path.write_text(
            json.dumps(scores_payload, indent=2, default=str), encoding="utf-8"
        )
    return {
        "task_dir": task_dir,
        "summary": summary,
        "sel": sel,
        "diff": diff,
        "base_scored": base_scored,
        "final_scored": final_scored,
        "scores_path": scores_path,
    }


def run_single_task(
    *,
    task_id: str,
    dataset_name: str,
    k: int,
    mode: str,
    solver_model: str,
    improver_model: str,
    runs_dir: Path,
    tag: str = "",
) -> dict[str, Any]:
    runs_root = Path(runs_dir).resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    mode_tok = harness_schedule.mode_token(mode)

    adapter = AdkRunbooksAdapter(
        runs_root,
        dataset_name=dataset_name,
        task_ids=[task_id],
        solver_model=solver_model,
        improver_model=improver_model,
    )
    proposer = AdkGeminiProposer(
        adapter.spec.channels["proposer"],
        audit_dir=runs_root / "proposer_audit",
    )
    domain = adapter.domain_of(task_id)
    surface = adapter.substrate.surface()
    lib = harness_library.Library(
        root=runs_root / "library" / mode_tok,
        domain=domain,
        surface=surface,
    )

    print(
        f"[harness2] Starting task={task_id} domain={domain} mode={mode_tok} k={k} "
        f"solver={solver_model} improver={improver_model}",
        flush=True,
    )
    res = harness_schedule.run_task(
        task_id,
        k,
        adapter=adapter,
        prop=proposer,
        runs_root=runs_root,
        modes=(mode_tok,),
        tag=tag,
        library=lib,
    )

    scored_info = _score_task_dir(
        adapter=adapter,
        task_id=task_id,
        mode_tok=mode_tok,
        k=k,
        runs_root=runs_root,
        tag=tag,
    )
    task_dir = scored_info["task_dir"]
    sel = scored_info["sel"]
    diff = scored_info["diff"]
    base_scored = scored_info["base_scored"]
    final_scored = scored_info["final_scored"]
    chosen_label = str(sel.get("chosen_label") or "")

    mode_rec = res.modes.get(mode_tok) or {}
    stages = mode_rec.get("stages") or []
    exp = sel.get("experience") or {}
    exp_path = lib.entry_dir(task_id) / "EXPERIENCE.md"

    print(f"\n=== Harness2 Run Complete: {task_id} (status={res.status}) ===", flush=True)
    print(f"Task directory: {task_dir}", flush=True)
    for st in stages:
        st_lbl = st.get("label")
        st_dim = st.get("dim")
        st_fb = st.get("fell_back")
        st_kb = st.get("kept_base")
        st_notes = " ".join(str(st.get("notes") or st.get("error") or "").split())[:180]
        print(
            f"  Stage {st_lbl} ({st_dim}): fell_back={st_fb} kept_base={st_kb} :: {st_notes}",
            flush=True,
        )
    print(f"Chosen candidate: {chosen_label} (trivial={sel.get('trivial')})", flush=True)
    print(
        f"Harness edits vs base: added={diff['added']} modified={diff['modified']} removed={diff['removed']}",
        flush=True,
    )
    if exp.get("lesson"):
        print(f"Experience cue: {exp.get('cue')}", flush=True)
        print(f"Experience lesson: {exp.get('lesson')}", flush=True)
        if exp_path.is_file():
            print(f"Experience file: {exp_path}", flush=True)
    print(f"Judge base1 : {_format_score(base_scored)}", flush=True)
    print(f"Judge {chosen_label or 'final':<6}: {_format_score(final_scored)}", flush=True)
    if res.errors:
        print(f"Errors: {res.errors}", flush=True)

    return {
        "result": res.to_dict(),
        "task_dir": str(task_dir),
        "scores_path": str(scored_info["scores_path"]),
        "experience_path": str(exp_path) if exp_path.is_file() else "",
        "diff": diff,
        "base_scored": base_scored.__dict__ if base_scored else None,
        "final_scored": final_scored.__dict__ if final_scored else None,
    }


def run_dataset_sweep(
    *,
    dataset_name: str,
    k: int,
    mode: str,
    solver_model: str,
    improver_model: str,
    runs_dir: Path,
    tag: str = "",
    max_tasks: int | None = None,
    domain_parallel: int = 1,
    only_domains: Sequence[str] = (),
) -> dict[str, Any]:
    runs_root = Path(runs_dir).resolve()
    runs_root.mkdir(parents=True, exist_ok=True)
    mode_tok = harness_schedule.mode_token(mode)

    adapter = AdkRunbooksAdapter(
        runs_root,
        dataset_name=dataset_name,
        task_ids=None,
        solver_model=solver_model,
        improver_model=improver_model,
    )
    proposer = AdkGeminiProposer(
        adapter.spec.channels["proposer"],
        audit_dir=runs_root / "proposer_audit",
    )

    print(
        f"[harness2] Starting sweep dataset={dataset_name} mode={mode_tok} k={k} "
        f"domains={adapter.reference_domain_order()} max_tasks={max_tasks} "
        f"solver={solver_model} improver={improver_model}",
        flush=True,
    )
    sweep_rec = harness_schedule.run_sweep(
        k,
        adapter=adapter,
        prop=proposer,
        runs_root=runs_root,
        library_root=runs_root / "library",
        modes=(mode_tok,),
        tag=tag,
        domain_parallel=domain_parallel,
        only_domains=only_domains,
        max_tasks=max_tasks,
    )

    task_rows: list[dict[str, Any]] = []
    base_scores: list[float] = []
    final_scores: list[float] = []
    base_passes = 0
    final_passes = 0

    for dom_rec in sweep_rec.get("domains") or []:
        dom_name = str(dom_rec.get("domain") or "")
        for t_entry in dom_rec.get("tasks") or []:
            tid = str(t_entry.get("task") or "")
            if not tid:
                continue
            scored_info = _score_task_dir(
                adapter=adapter,
                task_id=tid,
                mode_tok=mode_tok,
                k=k,
                runs_root=runs_root,
                tag=tag,
            )
            bs = scored_info["base_scored"]
            fs = scored_info["final_scored"]
            diff = scored_info["diff"]
            lib_before = (t_entry.get("library_entries_before") or {}).get(mode_tok, 0)

            b_val = float(bs.raw.get("rubric_score", 0.0)) if (bs and bs.raw) else None
            f_val = float(fs.raw.get("rubric_score", 0.0)) if (fs and fs.raw) else None
            b_pass = bool(bs.all_pass) if bs else False
            f_pass = bool(fs.all_pass) if fs else False

            if b_val is not None:
                base_scores.append(b_val)
            if f_val is not None:
                final_scores.append(f_val)
            if b_pass:
                base_passes += 1
            if f_pass:
                final_passes += 1

            task_rows.append(
                {
                    "task_id": tid,
                    "domain": dom_name,
                    "status": t_entry.get("status"),
                    "library_entries_before": lib_before,
                    "base_score": b_val,
                    "base_all_pass": b_pass,
                    "final_label": scored_info["sel"].get("chosen_label"),
                    "final_score": f_val,
                    "final_all_pass": f_pass,
                    "diff_added": diff["added"],
                    "diff_modified": diff["modified"],
                    "diff_removed": diff["removed"],
                }
            )

    n_tasks = len(task_rows)
    agg_summary = {
        "dataset": dataset_name,
        "mode": mode_tok,
        "k": k,
        "tag": tag,
        "n_tasks": n_tasks,
        "base_pass_count": base_passes,
        "final_pass_count": final_passes,
        "base_mean_score": round(sum(base_scores) / len(base_scores), 2) if base_scores else None,
        "final_mean_score": round(sum(final_scores) / len(final_scores), 2) if final_scores else None,
        "sweep": sweep_rec,
        "tasks": task_rows,
    }
    tag_suffix = f"_{tag}" if tag else ""
    sweep_scores_path = runs_root / f"sweep_{mode_tok}{k}{tag_suffix}_scores.json"
    sweep_scores_path.write_text(
        json.dumps(agg_summary, indent=2, default=str), encoding="utf-8"
    )

    print(
        f"\n=== Harness2 Sweep Complete: {dataset_name} ({n_tasks} tasks, mode={mode_tok}, k={k}) ===",
        flush=True,
    )
    print(
        f"{'Task ID':<30} {'Domain':<22} {'Status':<8} {'Lib':<4} {'Base1':<12} {'Final':<12} {'Changed'}",
        flush=True,
    )
    print("-" * 110, flush=True)
    for row in task_rows:
        b_str = f"{row['base_score']}/100 ({'P' if row['base_all_pass'] else 'F'})" if row["base_score"] is not None else "n/a"
        f_str = f"{row['final_score']}/100 ({'P' if row['final_all_pass'] else 'F'})" if row["final_score"] is not None else "n/a"
        n_chg = len(row["diff_added"]) + len(row["diff_modified"]) + len(row["diff_removed"])
        print(
            f"{row['task_id']:<30} {row['domain']:<22} {str(row['status']):<8} "
            f"{row['library_entries_before']:<4} {b_str:<12} {f_str:<12} {n_chg} files",
            flush=True,
        )
    print("-" * 110, flush=True)
    print(
        f"Aggregate Base1 : {base_passes}/{n_tasks} passed, mean score={agg_summary['base_mean_score']}",
        flush=True,
    )
    print(
        f"Aggregate Final : {final_passes}/{n_tasks} passed, mean score={agg_summary['final_mean_score']}",
        flush=True,
    )
    print(f"Sweep report    : {sweep_scores_path}", flush=True)
    return agg_summary


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.sweep:
        only_domains = [d.strip() for d in args.only_domains.split(",") if d.strip()]
        out = run_dataset_sweep(
            dataset_name=args.dataset,
            k=args.k,
            mode=args.mode,
            solver_model=args.solver_model,
            improver_model=args.improver_model,
            runs_dir=Path(args.runs_dir),
            tag=args.tag,
            max_tasks=args.max_tasks,
            domain_parallel=args.domain_parallel,
            only_domains=only_domains,
        )
        failed = sum(
            int(d.get("failed") or 0) + (1 if d.get("error") else 0)
            for d in (out["sweep"].get("domains") or [])
        )
        return 0 if failed == 0 else 1

    out = run_single_task(
        task_id=args.task_id,
        dataset_name=args.dataset,
        k=args.k,
        mode=args.mode,
        solver_model=args.solver_model,
        improver_model=args.improver_model,
        runs_dir=Path(args.runs_dir),
        tag=args.tag,
    )
    status = out["result"].get("status")
    return 0 if status in ("ok", "skipped") else 1


if __name__ == "__main__":
    raise SystemExit(main())
