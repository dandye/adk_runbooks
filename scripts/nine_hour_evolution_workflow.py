# 9-Hour Continuous Evolutionary Workflow for Grounded Google Docs & InfoSec Runbooks
# Executed via Jetski `run_workflow` tool.
import asyncio
import time

WORKTREE_DIR = "/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/drive-mcp-runbooks__grounded-docs"
ARTIFACT_DIR = "/usr/local/google/home/dandye/.gemini/jetski/brain/0494c8f8-6d6d-4717-af77-56f8618c1994"
LEDGER_REPO_PATH = f"{WORKTREE_DIR}/docs/evolution_ledger.md"
LEDGER_ARTIFACT_PATH = f"{ARTIFACT_DIR}/evolution_ledger.md"
BLOG_REPO_PATH = f"{WORKTREE_DIR}/docs/blog_grounded_google_docs_runbooks.md"

DURATION_SECONDS = 9 * 3600  # 9 straight hours (32,400 seconds)
COOLDOWN_SECONDS = 90        # Brief API quota cooldown between cycles
MAX_CYCLES = 40              # Upper bound safety cap across 9 hours

start_time = time.time()
deadline = start_time + DURATION_SECONDS

CRITIC_SCHEMA = {
    "type": "object",
    "properties": {
        "cycle": {"type": "integer"},
        "horizon_id": {"type": "string"},
        "title": {"type": "string"},
        "practitioner_problem": {"type": "string"},
        "why_most_useful_and_interesting_now": {"type": "string"},
        "rubric_scores": {
            "type": "object",
            "properties": {
                "operational_friction_removed": {"type": "integer"},
                "grounding_rigor": {"type": "integer"},
                "safety_and_trust": {"type": "integer"},
                "live_testability": {"type": "integer"},
                "total": {"type": "integer"},
            },
            "required": [
                "operational_friction_removed",
                "grounding_rigor",
                "safety_and_trust",
                "live_testability",
                "total",
            ],
        },
        "target_files": {"type": "array", "items": {"type": "string"}},
        "implementation_plan": {"type": "string"},
        "unit_test_plan": {"type": "string"},
        "live_validation_plan": {"type": "string"},
    },
    "required": [
        "cycle",
        "horizon_id",
        "title",
        "practitioner_problem",
        "why_most_useful_and_interesting_now",
        "rubric_scores",
        "target_files",
        "implementation_plan",
        "unit_test_plan",
        "live_validation_plan",
    ],
}

BUILDER_SCHEMA = {
    "type": "object",
    "properties": {
        "cycle": {"type": "integer"},
        "horizon_id": {"type": "string"},
        "status": {"type": "string"},
        "files_modified_or_created": {"type": "array", "items": {"type": "string"}},
        "pytest_passed_count": {"type": "integer"},
        "live_validation_summary": {"type": "string"},
        "commit_sha": {"type": "string"},
        "new_questions_or_horizons_unlocked": {"type": "string"},
    },
    "required": [
        "cycle",
        "horizon_id",
        "status",
        "files_modified_or_created",
        "pytest_passed_count",
        "live_validation_summary",
        "commit_sha",
        "new_questions_or_horizons_unlocked",
    ],
}

VERIFIER_SCHEMA = {
    "type": "object",
    "properties": {
        "cycle": {"type": "integer"},
        "git_clean": {"type": "boolean"},
        "pytest_green": {"type": "boolean"},
        "ledger_synced": {"type": "boolean"},
        "zero_emojis_verified": {"type": "boolean"},
        "commit_sha": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": [
        "cycle",
        "git_clean",
        "pytest_green",
        "ledger_synced",
        "zero_emojis_verified",
        "commit_sha",
        "summary",
    ],
}


async def run_evolution_cycle(cycle_num: int):
    elapsed_hours = (time.time() - start_time) / 3600.0
    remaining_hours = max(0.0, (deadline - time.time()) / 3600.0)
    log(
        f"Starting Cycle {cycle_num} | Elapsed: {elapsed_hours:.2f}h | Remaining: {remaining_hours:.2f}h"
    )

    # Phase 1: InfoSec Critic Re-Evaluation
    phase(f"Cycle {cycle_num}: InfoSec Critic Re-Evaluation")
    critic_prompt = f"""Cycle {cycle_num} InfoSec Practitioner Critic.
You are operating in the repository worktree:
`{WORKTREE_DIR}` (branch `drive-mcp-runbooks__grounded-docs`).
Elapsed time in the 9-hour continuous run: {elapsed_hours:.2f} hours ({remaining_hours:.2f} hours remaining).

Your job:
1. Read `{LEDGER_REPO_PATH}` to see all completed cycles, the Seed Horizon Backlog (`H1` through `H8`), and any new findings or horizons unlocked by the most recent cycle.
2. Inspect recent commits (`git log -n 5 --oneline` in `{WORKTREE_DIR}`) and the current code in `multi-agent/manager/tools/docs_review_tools.py`, `multi-agent/manager/tools/tools.py`, `multi-agent/manager/workflows/grounded_soar_review_workflow.py`, and `tests/test_docs_review_tools.py`.
3. Ask the core evolutionary question:
   "Given everything we have built and empirically verified so far, what is the single most useful, novel, and interesting capability we should build next to evolve this project for InfoSec practitioners (SOC analysts, incident commanders, detection engineers, and threat hunters)?"
4. You may select the highest-scoring `PENDING` horizon from `H1`..`H8` OR formulate a brand-new horizon (`H9`, `H10`, ...) if the previous cycle revealed a compelling opportunity.
5. Score your chosen evolution on the 4-part rubric (1-5 each, total out of 20):
   - `operational_friction_removed`
   - `grounding_rigor`
   - `safety_and_trust`
   - `live_testability`
6. Design a concrete, surgical implementation plan, unit test plan, and live validation plan that can be completed cleanly in this cycle.
   - IMPORTANT: Keep new Google Docs creation in `SOC Reports` to at most 1 doc per cycle (or reuse/inspect existing reviewed Google Docs from `docs/evolution_ledger.md` / `docs/overnight_handoff_argolis_soar_grounded_docs.md`) to conserve Drive API quota over the 9-hour run.
   - NEVER use emojis anywhere.

Call `finish` with a JSON object matching the required schema."""

    try:
        decision = await agent(
            critic_prompt,
            schema=CRITIC_SCHEMA,
            role=f"Cycle {cycle_num} InfoSec Critic",
        )
    except Exception as err:
        log(f"Cycle {cycle_num} Critic raised exception: {err}")
        return None

    log(
        f"Cycle {cycle_num} Critic selected [{decision.get('horizon_id')}] {decision.get('title')} "
        f"(Score: {decision.get('rubric_scores', {}).get('total')}/20)"
    )

    # Phase 2: Builder & Live SecOps Validator
    phase(f"Cycle {cycle_num}: Build, Test & Live Validation ({decision.get('horizon_id')})")
    builder_prompt = f"""Cycle {cycle_num} InfoSec Builder & Live Validator.
Worktree: `{WORKTREE_DIR}` (branch `drive-mcp-runbooks__grounded-docs`).

The Cycle {cycle_num} InfoSec Critic selected the following evolution to build and validate:
- Horizon ID: {decision.get('horizon_id')}
- Title: {decision.get('title')}
- Practitioner Problem: {decision.get('practitioner_problem')}
- Why Most Useful Now: {decision.get('why_most_useful_and_interesting_now')}
- Rubric Scores: {decision.get('rubric_scores')}
- Target Files: {decision.get('target_files')}
- Implementation Plan: {decision.get('implementation_plan')}
- Unit Test Plan: {decision.get('unit_test_plan')}
- Live Validation Plan: {decision.get('live_validation_plan')}

Execute these steps with high engineering rigor:
1. Implement the capability in `{WORKTREE_DIR}`. Follow Google Python conventions, preserve existing functionality, and NEVER use emojis anywhere in code, comments, docs, or commit messages.
2. Add comprehensive unit tests in `{WORKTREE_DIR}/tests/test_docs_review_tools.py` (or a new test file under `{WORKTREE_DIR}/tests/`) and run the full test suite using:
   ```bash
   WORKTREE_DIR="{WORKTREE_DIR}"
   direnv exec "$WORKTREE_DIR" env RUNBOOK_SOURCE=local "$WORKTREE_DIR/.venv/bin/pytest" "$WORKTREE_DIR/tests" -q
   ```
   Fix any issues until 100% of unit tests pass.
3. Run the live validation plan (against existing reviewed Google Docs, Argolis Chronicle SIEM/SOAR, Developer Knowledge MCP, or a targeted script in `{WORKTREE_DIR}/scripts/`). Cap new Google Doc creation to at most 1 doc per cycle (prefer inspecting/validating against our existing 9 Argolis Google Docs or creating at most 1 focused doc when needed).
4. Update `{LEDGER_REPO_PATH}`:
   - Mark `{decision.get('horizon_id')}` as `COMPLETED (Cycle {cycle_num})` in the Seed Horizon Backlog table (or add it to the table if it is a new Horizon ID).
   - If your work unlocked a new high-value follow-up idea for InfoSec practitioners, add it as a new `PENDING` row (`H9`, `H10`, ...) in the Seed Horizon Backlog table so the next cycle's Critic can evaluate it!
   - Append a detailed `### Cycle {cycle_num}: [{decision.get('horizon_id')}] {decision.get('title')}` section at the bottom of `{LEDGER_REPO_PATH}` documenting:
     - Critic rubric score and rationale
     - Functions/tools added or updated
     - Unit test results (`N passed`)
     - Live validation empirical results
     - Reflection: what new practitioner question or capability this unlocks next.
5. Copy `{LEDGER_REPO_PATH}` to `{LEDGER_ARTIFACT_PATH}` so the user's live artifact view stays up to date.
6. Update `{BLOG_REPO_PATH}` with a concise subsection or table row capturing the new capability and empirical finding from Cycle {cycle_num}.
7. Clean any temporary untracked test report files (`rm -f {WORKTREE_DIR}/multi-agent/reports/Grounded_SOAR_Review_Case_*.md`), inspect `git status -s`, stage ONLY explicit file paths (`git add <file1> <file2>`, NEVER `git add .`, `git add -A`, or `git add --all`), and commit to `drive-mcp-runbooks__grounded-docs`.

Call `finish` with the required JSON build report."""

    try:
        build_report = await agent(
            builder_prompt,
            schema=BUILDER_SCHEMA,
            role=f"Cycle {cycle_num} Builder ({decision.get('horizon_id')})",
        )
    except Exception as err:
        log(f"Cycle {cycle_num} Builder raised exception: {err}")
        build_report = {
            "cycle": cycle_num,
            "horizon_id": decision.get("horizon_id", "UNKNOWN"),
            "status": f"ERROR: {err}",
            "files_modified_or_created": [],
            "pytest_passed_count": 0,
            "live_validation_summary": f"Interrupted: {err}",
            "commit_sha": "NONE",
            "new_questions_or_horizons_unlocked": "Recover in Verifier",
        }

    log(
        f"Cycle {cycle_num} Builder finished: status={build_report.get('status')}, "
        f"pytest={build_report.get('pytest_passed_count')}, commit={build_report.get('commit_sha')}"
    )

    # Phase 3: Independent Verifier & Hygiene Gate
    phase(f"Cycle {cycle_num}: Independent Verification")
    verifier_prompt = f"""Cycle {cycle_num} Independent Verifier.
Worktree: `{WORKTREE_DIR}` (branch `drive-mcp-runbooks__grounded-docs`).

Builder report for Cycle {cycle_num} ({decision.get('horizon_id')} - {decision.get('title')}):
{build_report}

Verify and enforce all quality gates:
1. Run the unit test suite:
   ```bash
   WORKTREE_DIR="{WORKTREE_DIR}"
   direnv exec "$WORKTREE_DIR" env RUNBOOK_SOURCE=local "$WORKTREE_DIR/.venv/bin/pytest" "$WORKTREE_DIR/tests" -q
   ```
   Ensure 100% pass rate.
2. Check `git status -s` in `{WORKTREE_DIR}`. Remove any stray untracked scratch files (such as `multi-agent/reports/Grounded_SOAR_Review_Case_*.md`). If the Builder left any legitimate modified code/test/doc files uncommitted, stage them by explicit path (`git add <file>`) and commit them.
3. Verify `{LEDGER_REPO_PATH}` contains the `### Cycle {cycle_num}` entry and copy `{LEDGER_REPO_PATH}` to `{LEDGER_ARTIFACT_PATH}` if they differ.
4. Check `git log -n 1 --oneline` to record the latest `commit_sha`.

Call `finish` with the required verification JSON."""

    try:
        verification = await agent(
            verifier_prompt,
            schema=VERIFIER_SCHEMA,
            role=f"Cycle {cycle_num} Verifier",
        )
        log(
            f"Cycle {cycle_num} Verified: commit={verification.get('commit_sha')} | "
            f"clean={verification.get('git_clean')} | pytest_green={verification.get('pytest_green')} | "
            f"{verification.get('summary')}"
        )
    except Exception as err:
        log(f"Cycle {cycle_num} Verifier raised exception: {err}")
        verification = None

    # Check if the Critic's prompt should know about H1-H28
    return {
        "cycle": cycle_num,
        "decision": decision,
        "build_report": build_report,
        "verification": verification,
    }


def _detect_next_cycle_num() -> int:
    import re
    from pathlib import Path

    try:
        text = Path(LEDGER_REPO_PATH).read_text(encoding="utf-8")
        matches = [int(m) for m in re.findall(r"^### Cycle (\d+)\b", text, flags=re.M)]
        if matches:
            return max(matches) + 1
    except Exception:
        pass
    return 19


cycle_num = _detect_next_cycle_num()
completed_cycles = []

while time.time() < deadline and cycle_num <= MAX_CYCLES:
    result = await run_evolution_cycle(cycle_num)
    if result is not None:
        completed_cycles.append(result)
    cycle_num = max(cycle_num + 1, _detect_next_cycle_num())
    if time.time() + COOLDOWN_SECONDS < deadline:
        await asyncio.sleep(COOLDOWN_SECONDS)

phase("Final 9-Hour Synthesis")
final_summary = await agent(
    f"""The 9-hour continuous evolutionary loop in `{WORKTREE_DIR}` has completed {len(completed_cycles)} cycles.
1. Inspect `{LEDGER_REPO_PATH}`, `{BLOG_REPO_PATH}`, and `git log --oneline -n 25`.
2. Add or update the top-level Executive Summary of all completed evolutionary cycles in `{LEDGER_REPO_PATH}` and sync it to `{LEDGER_ARTIFACT_PATH}`.
3. Ensure `git status -s` is completely clean (commit any final doc updates using explicit file paths).
4. Return a concise summary of the 9-hour run via `finish`.""",
    schema={"type": "string"},
    role="9-Hour Run Final Synthesizer",
)
log("9-Hour Evolutionary Loop Complete:", final_summary)

