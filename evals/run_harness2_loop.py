"""Run a Harness2 Propose-Probe-Compose loop or dataset sweep on ADK Runbooks scenarios.

Examples:
  python -m evals.run_harness2_loop --task-id TEST-CORE-SUSP-LOGIN-002 --k 1 --mode parallel
  python -m evals.run_harness2_loop --sweep --k 1 --mode parallel
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        "--evaluate-only",
        action="store_true",
        help="Evaluate dataset scenarios on a frozen harness (k=0) without proposer calls.",
    )
    parser.add_argument(
        "--harness-dir",
        default="",
        help="Frozen harness directory for --evaluate-only (defaults to adapter base_harness).",
    )
    parser.add_argument(
        "--compare-harness-dir",
        default="",
        help="Optional second frozen harness directory to compare side-by-side in --evaluate-only mode.",
    )
    parser.add_argument(
        "--eval-parallel",
        type=int,
        default=1,
        help="Number of tasks to evaluate concurrently in --evaluate-only mode (default: 1).",
    )
    parser.add_argument(
        "--max-tasks",
        type=int,
        default=None,
        help="Optional cap on tasks per domain during a sweep or frozen evaluation.",
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
    evolved_export = export_merged_evolved_harness(
        adapter=adapter,
        sweep_rec=sweep_rec,
        mode_tok=mode_tok,
        k=k,
        runs_root=runs_root,
        tag=tag,
    )
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
        "evolved_harness_dir": evolved_export["evolved_harness_dir"],
        "evolved_manifest_path": evolved_export["manifest_path"],
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
    print(f"Evolved harness : {evolved_export['evolved_harness_dir']}", flush=True)
    print(f"Sweep report    : {sweep_scores_path}", flush=True)
    return agg_summary


def export_merged_evolved_harness(
    *,
    adapter: AdkRunbooksAdapter,
    sweep_rec: dict[str, Any],
    mode_tok: str,
    k: int,
    runs_root: Path,
    tag: str = "",
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Merge non-regressing evolved artifacts across all domain tasks into one valid harness tree."""
    surface = adapter.substrate.surface()
    base_tree = harness_tree.read_tree(surface, adapter.base_harness())
    merged_tree = dict(base_tree)

    ns_obj = harness_schedule.Namespace(
        adapter.spec.name, adapter.substrate.name, mode_tok, k, None, tag
    )

    merged_skills: dict[str, str] = {}
    merged_scripts: dict[str, str] = {}
    guardrail_seen = {
        line.strip()
        for line in base_tree.get("guardrails.md", "").splitlines()
        if line.strip()
    }
    guardrail_added: list[str] = []
    tool_guidance_seen = {
        line.strip()
        for line in base_tree.get("tool_descriptions/tool_guidance.md", "").splitlines()
        if line.strip()
    }
    tool_guidance_added: list[str] = []
    seen_cues: set[str] = set()
    memory_entries: list[str] = []

    for dom_rec in sweep_rec.get("domains") or []:
        dom_name = str(dom_rec.get("domain") or "")
        for t_entry in dom_rec.get("tasks") or []:
            tid = str(t_entry.get("task") or "")
            if not tid:
                continue
            task_dir = ns_obj.task_dir(runs_root, tid)
            summary_path = task_dir / "summary.json"
            if not summary_path.is_file():
                continue
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            sel = (summary.get("selections") or {}).get(mode_tok) or {}
            chosen_label = str(sel.get("chosen_label") or "")
            if not sel.get("ok") or not chosen_label or chosen_label.startswith("base"):
                continue

            scores_path = task_dir / "scores.json"
            if scores_path.is_file():
                scores = json.loads(scores_path.read_text(encoding="utf-8"))
                b_raw = ((scores.get("base1") or {}).get("raw") or {})
                c_raw = ((scores.get("chosen") or {}).get("raw") or {})
                b_pass = bool((scores.get("base1") or {}).get("all_pass"))
                c_pass = bool((scores.get("chosen") or {}).get("all_pass"))
                b_rubric = float(b_raw.get("rubric_score", 0.0) or 0.0)
                c_rubric = float(c_raw.get("rubric_score", 0.0) or 0.0)
                if (b_pass and not c_pass) or (c_rubric < b_rubric):
                    continue

            chosen_dir = task_dir / "harnesses" / chosen_label
            if not chosen_dir.is_dir():
                continue
            chosen_tree = harness_tree.read_tree(surface, chosen_dir)
            if not chosen_tree:
                continue

            for rel, content in chosen_tree.items():
                if rel.startswith("skills/") and rel.endswith("/SKILL.md"):
                    if content != base_tree.get(rel):
                        candidate = dict(merged_tree)
                        candidate[rel] = content
                        try:
                            harness_tree.autotrigger(surface, candidate)
                            harness_tree.validate(surface, candidate, allow_subagents=False)
                            adapter.validate_tree(candidate)
                            merged_tree = candidate
                            merged_skills[rel] = f"{dom_name}/{tid}"
                        except Exception:
                            pass
                elif rel.startswith("scripts/") and rel.endswith(".py"):
                    if content != base_tree.get(rel):
                        candidate = dict(merged_tree)
                        candidate[rel] = content
                        try:
                            harness_tree.autotrigger(surface, candidate)
                            harness_tree.validate(surface, candidate, allow_subagents=False)
                            adapter.validate_tree(candidate)
                            merged_tree = candidate
                            merged_scripts[rel] = f"{dom_name}/{tid}"
                        except Exception:
                            pass
                elif rel == "guardrails.md":
                    for line in content.splitlines():
                        s = line.strip()
                        if (
                            s.startswith("- ")
                            and not s.startswith("- Load `")
                            and s not in guardrail_seen
                            and tid not in s
                            and "CASE-" not in s
                            and "ALERT-" not in s
                        ):
                            guardrail_seen.add(s)
                            guardrail_added.append(s)
                elif rel == "tool_descriptions/tool_guidance.md":
                    for line in content.splitlines():
                        s = line.strip()
                        if s.startswith("- ") and s not in tool_guidance_seen and tid not in s:
                            tool_guidance_seen.add(s)
                            tool_guidance_added.append(s)

            exp = sel.get("experience") or {}
            cue = str(exp.get("cue") or "").strip()
            lesson = str(exp.get("lesson") or "").strip()
            if cue and lesson and cue not in seen_cues:
                seen_cues.add(cue)
                memory_entries.append(f"- **{cue}** ({dom_name}): {lesson}")

    harness_tree.autotrigger(surface, merged_tree)
    max_always_on = int(surface.always_on_max) - 400

    def _append_bounded_section(
        file_rel: str, heading: str, items: list[str], budget_share: int
    ) -> int:
        if not items:
            return 0
        current = merged_tree.get(file_rel, "").rstrip()
        header_block = f"\n\n{heading}\n"
        if len(harness_tree.always_on_text(surface, merged_tree)) + len(header_block) > max_always_on:
            return 0
        accepted: list[str] = []
        used_chars = 0
        for item in items:
            if used_chars + len(item) + 1 > budget_share:
                break
            candidate = dict(merged_tree)
            candidate[file_rel] = current + header_block + "\n".join([*accepted, item]) + "\n"
            if len(harness_tree.always_on_text(surface, candidate)) > max_always_on:
                break
            try:
                adapter.validate_tree(candidate)
                merged_tree[file_rel] = candidate[file_rel]
                accepted.append(item)
                used_chars += len(item) + 1
            except Exception:
                continue
        return len(accepted)

    rem_budget = max(0, max_always_on - len(harness_tree.always_on_text(surface, merged_tree)))
    n_guard = _append_bounded_section(
        "guardrails.md", "## Evolved Guardrails", guardrail_added, max(1200, rem_budget // 3)
    )
    rem_budget = max(0, max_always_on - len(harness_tree.always_on_text(surface, merged_tree)))
    n_tool = _append_bounded_section(
        "tool_descriptions/tool_guidance.md",
        "## Evolved Tool Notes",
        tool_guidance_added,
        max(1200, rem_budget // 2),
    )
    rem_budget = max(0, max_always_on - len(harness_tree.always_on_text(surface, merged_tree)))
    n_mem = _append_bounded_section(
        "LongTermMEMORY.md", "## Learned Domain Cues", memory_entries, rem_budget
    )

    harness_tree.autotrigger(surface, merged_tree)
    harness_tree.validate(surface, merged_tree, allow_subagents=False)
    adapter.validate_tree(merged_tree)

    tag_suffix = f"_{tag}" if tag else ""
    target_dir = Path(out_dir) if out_dir else (runs_root / f"evolved_harness_{mode_tok}{k}{tag_suffix}")
    harness_tree.write_tree(surface, merged_tree, target_dir, stubs=False)

    diff = harness_tree.diff_summary(surface, base_tree, merged_tree)
    manifest = {
        "mode": mode_tok,
        "k": k,
        "tag": tag,
        "evolved_harness_dir": str(target_dir),
        "diff_from_base": diff,
        "merged_skills": merged_skills,
        "merged_scripts": merged_scripts,
        "guardrail_rules_added": n_guard,
        "tool_notes_added": n_tool,
        "memory_cues_added": n_mem,
    }
    manifest_path = target_dir.parent / f"{target_dir.name}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest


def _adapt_compare_harness_for_dataset(
    *,
    adapter: AdkRunbooksAdapter,
    compare_dir: Path,
    runs_root: Path,
    dataset_name: str,
    tag: str = "",
) -> Path:
    """Overlay evolved harness components onto the target dataset's base harness.

    Keeps the skill catalog matched to the target dataset (plus any newly invented
    skills not in REPO_ROOT/skills) so zero-shot transfer comparisons stay fair.
    """
    surface = adapter.substrate.surface()
    target_base = harness_tree.read_tree(surface, adapter.base_harness())
    source_evolved = harness_tree.read_tree(surface, compare_dir)

    known_repo_skills = {
        p.parent.name for p in (REPO_ROOT / "skills").rglob("SKILL.md")
    }
    adapted = dict(target_base)
    for rel, content in source_evolved.items():
        if rel == "guardrails.md":
            target_guard = target_base.get("guardrails.md", "").rstrip()
            if "## Evolved Guardrails" in content:
                evolved_sec = content.split("## Evolved Guardrails", 1)[1]
                adapted["guardrails.md"] = (
                    target_guard + "\n\n## Evolved Guardrails" + evolved_sec
                )
            else:
                target_lines = {ln.strip() for ln in target_guard.splitlines() if ln.strip()}
                extra = [
                    ln.strip()
                    for ln in content.splitlines()
                    if ln.strip().startswith("- ")
                    and not ln.strip().startswith("- Load `")
                    and ln.strip() not in target_lines
                ]
                if extra:
                    adapted["guardrails.md"] = (
                        target_guard + "\n\n## Evolved Guardrails\n" + "\n".join(extra) + "\n"
                    )
        elif rel in target_base:
            adapted[rel] = content
        elif rel.startswith("scripts/") and rel.endswith(".py"):
            adapted[rel] = content
        elif rel.startswith("skills/") and rel.endswith("/SKILL.md"):
            parts = Path(rel).parts
            skill_name = parts[1] if len(parts) >= 3 else ""
            if skill_name and skill_name not in known_repo_skills:
                adapted[rel] = content

    harness_tree.autotrigger(surface, adapted)
    tag_suffix = f"_{tag}" if tag else ""
    dest = runs_root / f"adapted_evolved_harness_{dataset_name}{tag_suffix}"
    harness_tree.write_tree(surface, adapted, dest, stubs=False)
    return dest


def run_frozen_transfer_eval(
    *,
    dataset_name: str,
    runs_dir: Path,
    harness_dir: Path | None = None,
    compare_harness_dir: Path | None = None,
    solver_model: str = "gemini-3-flash-preview",
    eval_parallel: int = 1,
    max_tasks: int | None = None,
    tag: str = "",
) -> dict[str, Any]:
    """Evaluate dataset tasks zero-shot (k=0) on one or two frozen harnesses without proposer calls."""
    runs_root = Path(runs_dir).resolve()
    runs_root.mkdir(parents=True, exist_ok=True)

    adapter = AdkRunbooksAdapter(
        runs_root,
        dataset_name=dataset_name,
        task_ids=None,
        solver_model=solver_model,
    )
    all_tasks = adapter.tasks("all")
    if max_tasks is not None and max_tasks > 0:
        all_tasks = all_tasks[:max_tasks]

    primary_dir = Path(harness_dir).resolve() if harness_dir else None
    raw_compare_dir = Path(compare_harness_dir).resolve() if compare_harness_dir else None
    compare_dir = (
        _adapt_compare_harness_for_dataset(
            adapter=adapter,
            compare_dir=raw_compare_dir,
            runs_root=runs_root,
            dataset_name=dataset_name,
            tag=tag,
        )
        if raw_compare_dir is not None
        else None
    )
    primary_label = "base" if primary_dir is None else "primary"
    compare_label = "evolved"

    print(
        f"[harness2] Starting frozen transfer eval dataset={dataset_name} tasks={len(all_tasks)} "
        f"primary={primary_dir or 'adapter.base_harness'} "
        f"compare={compare_dir or 'none'} parallel={eval_parallel}",
        flush=True,
    )

    def _eval_one(task_id: str, label: str, h_dir: Path | None) -> dict[str, Any]:
        tag_part = f"_{tag}" if tag else ""
        run_id = f"transfer_{dataset_name}_{label}_{task_id}{tag_part}"
        run_dir = adapter.execute(task_id, h_dir, run_id)
        scored = adapter.score(run_dir, task_id)
        return {
            "task_id": task_id,
            "domain": adapter.domain_of(task_id),
            "label": label,
            "run_dir": str(run_dir),
            "delivered": adapter.delivered(run_dir),
            "scored": scored,
        }

    jobs: list[tuple[str, str, Path | None]] = []
    for tid in all_tasks:
        jobs.append((tid, primary_label, primary_dir))
        if compare_dir is not None:
            jobs.append((tid, compare_label, compare_dir))

    results_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max(1, int(eval_parallel))) as pool:
        futs = {
            pool.submit(_eval_one, tid, lbl, h_dir): (tid, lbl)
            for tid, lbl, h_dir in jobs
        }
        for fut in as_completed(futs):
            tid, lbl = futs[fut]
            res = fut.result()
            results_by_key[(tid, lbl)] = res
            sc = res.get("scored") or {}
            print(
                f"  [transfer:{lbl:<7}] {tid:<32} score={sc.get('rubric_score')} "
                f"all_pass={sc.get('all_pass')} calls={sc.get('tool_calls_count')}",
                flush=True,
            )

    rows: list[dict[str, Any]] = []
    p_scores: list[float] = []
    c_scores: list[float] = []
    p_calls: list[int] = []
    c_calls: list[int] = []
    p_passes = 0
    c_passes = 0

    for tid in all_tasks:
        p_res = results_by_key[(tid, primary_label)]
        p_sc = p_res.get("scored") or {}
        p_val = float(p_sc.get("rubric_score", 0.0)) if p_sc else None
        p_pass = bool(p_sc.get("all_pass")) if p_sc else False
        p_tc = int(p_sc.get("tool_calls_count", 0)) if p_sc else None
        if p_val is not None:
            p_scores.append(p_val)
        if p_tc is not None:
            p_calls.append(p_tc)
        if p_pass:
            p_passes += 1

        row: dict[str, Any] = {
            "task_id": tid,
            "domain": adapter.domain_of(tid),
            "primary_label": primary_label,
            "primary_score": p_val,
            "primary_all_pass": p_pass,
            "primary_tool_calls": p_tc,
            "primary_tokens": p_sc.get("total_tokens") if p_sc else None,
        }

        if compare_dir is not None:
            c_res = results_by_key[(tid, compare_label)]
            c_sc = c_res.get("scored") or {}
            c_val = float(c_sc.get("rubric_score", 0.0)) if c_sc else None
            c_pass = bool(c_sc.get("all_pass")) if c_sc else False
            c_tc = int(c_sc.get("tool_calls_count", 0)) if c_sc else None
            if c_val is not None:
                c_scores.append(c_val)
            if c_tc is not None:
                c_calls.append(c_tc)
            if c_pass:
                c_passes += 1

            row.update(
                {
                    "compare_label": compare_label,
                    "compare_score": c_val,
                    "compare_all_pass": c_pass,
                    "compare_tool_calls": c_tc,
                    "compare_tokens": c_sc.get("total_tokens") if c_sc else None,
                    "score_delta": (
                        round(c_val - p_val, 2)
                        if (c_val is not None and p_val is not None)
                        else None
                    ),
                    "tool_calls_delta": (
                        (c_tc - p_tc) if (c_tc is not None and p_tc is not None) else None
                    ),
                }
            )
        rows.append(row)

    n_tasks = len(rows)
    summary: dict[str, Any] = {
        "dataset": dataset_name,
        "tag": tag,
        "n_tasks": n_tasks,
        "primary_harness": str(primary_dir) if primary_dir else "base_harness",
        "compare_harness": str(compare_dir) if compare_dir else None,
        "primary_pass_count": p_passes,
        "primary_mean_score": round(sum(p_scores) / len(p_scores), 2) if p_scores else None,
        "primary_mean_tool_calls": round(sum(p_calls) / len(p_calls), 2) if p_calls else None,
        "compare_pass_count": c_passes if compare_dir else None,
        "compare_mean_score": round(sum(c_scores) / len(c_scores), 2) if c_scores else None,
        "compare_mean_tool_calls": round(sum(c_calls) / len(c_calls), 2) if c_calls else None,
        "tasks": rows,
    }
    tag_suffix = f"_{tag}" if tag else ""
    out_path = runs_root / f"transfer_{dataset_name}{tag_suffix}_scores.json"
    out_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    print(
        f"\n=== Frozen Transfer Complete: {dataset_name} ({n_tasks} tasks) ===",
        flush=True,
    )
    print(
        f"Primary ({primary_label}): {p_passes}/{n_tasks} passed, "
        f"mean score={summary['primary_mean_score']}, mean calls={summary['primary_mean_tool_calls']}",
        flush=True,
    )
    if compare_dir is not None:
        print(
            f"Compare ({compare_label}): {c_passes}/{n_tasks} passed, "
            f"mean score={summary['compare_mean_score']}, mean calls={summary['compare_mean_tool_calls']}",
            flush=True,
        )
    print(f"Transfer report : {out_path}", flush=True)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.evaluate_only:
        run_frozen_transfer_eval(
            dataset_name=args.dataset,
            runs_dir=Path(args.runs_dir),
            harness_dir=Path(args.harness_dir) if args.harness_dir else None,
            compare_harness_dir=(
                Path(args.compare_harness_dir) if args.compare_harness_dir else None
            ),
            solver_model=args.solver_model,
            eval_parallel=args.eval_parallel,
            max_tasks=args.max_tasks,
            tag=args.tag,
        )
        return 0

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
