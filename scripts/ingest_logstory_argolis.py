#!/usr/bin/env python3
"""Ingest all 47 Logstory usecases and Cymbal baselines into Argolis Chronicle via logstory CLI."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "multi-agent"))

from manager.tools.logstory_corpus import get_logstory_corpus  # noqa: E402

DEFAULT_LOGSTORY_BIN = Path(
    "/usr/local/google/home/dandye/Projects/logstory__worktrees/main/.venv/bin/logstory"
)
DEFAULT_USECASES_BUCKET = (
    "file:///usr/local/google/home/dandye/Projects/logstory_usecases__worktrees/main"
)
DEFAULT_REST_CREDS = Path(
    "/usr/local/google/home/dandye/.ssh/dandye-0324-chronicle-1eb3f78499b3.json"
)
DEFAULT_LEGACY_CREDS = Path(
    "/usr/local/google/home/dandye/.ssh/"
    "project_dandye-0324-chronicle_customer_7e977ce4-f45d-43b2-aea0-52f8b66acd80.json"
)
DEFAULT_PROJECT_ID = "dandye-0324-chronicle"
DEFAULT_CUSTOMER_ID = "7e977ce4-f45d-43b2-aea0-52f8b66acd80"
DEFAULT_REGION = "US"


def _run_logstory_cmd(
    *,
    logstory_bin: Path,
    usecase_id: str,
    entities: bool,
    api_type: str,
    creds_path: Path,
    project_id: str,
    customer_id: str,
    region: str,
    timestamp_delta: str,
    usecases_bucket: str,
) -> tuple[bool, str, float]:
    """Execute one logstory replay command and return (ok, output_snippet, elapsed_sec)."""
    cmd = [
        str(logstory_bin),
        "replay",
        "usecase",
        usecase_id,
        "--timestamp-delta",
        timestamp_delta,
        "--api-type",
        api_type,
        "--credentials-path",
        str(creds_path),
        "--customer-id",
        customer_id,
        "--region",
        region,
    ]
    if api_type == "rest":
        cmd.extend(["--project-id", project_id])
    if entities:
        cmd.append("--entities")

    env = dict(os.environ)
    env["LOGSTORY_USECASES_BUCKETS"] = usecases_bucket
    env["LOGSTORY_AUTO_GET"] = "true"

    t0 = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=str(logstory_bin.parents[2]),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    elapsed = round(time.monotonic() - t0, 2)
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    ok = proc.returncode == 0
    return ok, combined.strip()[-600:], elapsed


def ingest_usecase(
    *,
    usecase_id: str,
    has_entities: bool,
    logstory_bin: Path,
    rest_creds: Path,
    legacy_creds: Path,
    project_id: str,
    customer_id: str,
    region: str,
    timestamp_delta: str,
    usecases_bucket: str,
) -> dict[str, Any]:
    """Ingest events (and entities if present) for one usecase with REST/Legacy fallback."""
    record: dict[str, Any] = {
        "usecase_id": usecase_id,
        "events_ok": False,
        "events_api": None,
        "events_elapsed_sec": 0.0,
        "entities_attempted": has_entities,
        "entities_ok": not has_entities,
        "entities_api": None,
        "entities_elapsed_sec": 0.0,
        "errors": [],
    }

    # 1. Events: try REST first, fallback to Legacy
    for api_type, creds in (("rest", rest_creds), ("legacy", legacy_creds)):
        if not creds.exists():
            continue
        ok, snippet, elapsed = _run_logstory_cmd(
            logstory_bin=logstory_bin,
            usecase_id=usecase_id,
            entities=False,
            api_type=api_type,
            creds_path=creds,
            project_id=project_id,
            customer_id=customer_id,
            region=region,
            timestamp_delta=timestamp_delta,
            usecases_bucket=usecases_bucket,
        )
        if ok:
            record["events_ok"] = True
            record["events_api"] = api_type
            record["events_elapsed_sec"] = elapsed
            break
        record["errors"].append(f"events/{api_type}: {snippet}")

    # 2. Entities: try Legacy first (native Malachite entities API), fallback to REST
    if has_entities:
        for api_type, creds in (("legacy", legacy_creds), ("rest", rest_creds)):
            if not creds.exists():
                continue
            ok, snippet, elapsed = _run_logstory_cmd(
                logstory_bin=logstory_bin,
                usecase_id=usecase_id,
                entities=True,
                api_type=api_type,
                creds_path=creds,
                project_id=project_id,
                customer_id=customer_id,
                region=region,
                timestamp_delta=timestamp_delta,
                usecases_bucket=usecases_bucket,
            )
            if ok:
                record["entities_ok"] = True
                record["entities_api"] = api_type
                record["entities_elapsed_sec"] = elapsed
                break
            record["errors"].append(f"entities/{api_type}: {snippet}")

    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--usecase",
        action="append",
        help="Specific usecase ID(s) to ingest. Defaults to all 47.",
    )
    parser.add_argument(
        "--skip-usecase",
        action="append",
        default=[],
        help="Usecase ID(s) to skip (e.g. already ingested).",
    )
    parser.add_argument(
        "--timestamp-delta",
        default="1d",
        help="Timestamp delta passed to logstory replay (default: 1d).",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "evals" / "results" / "argolis_logstory_ingestion_manifest.json"),
        help="Path to write JSON ingestion manifest.",
    )
    args = parser.parse_args()

    corpus = get_logstory_corpus()
    target_ids = sorted(args.usecase) if args.usecase else sorted(corpus.usecases.keys())
    skip_set = {u.strip().upper() for u in args.skip_usecase}
    target_ids = [uid for uid in target_ids if uid not in skip_set]

    print(
        f"Starting Argolis ingestion for {len(target_ids)} usecases "
        f"(project={DEFAULT_PROJECT_ID}, customer={DEFAULT_CUSTOMER_ID})..."
    )

    results: list[dict[str, Any]] = []
    t_start = time.monotonic()

    for idx, uid in enumerate(target_ids, start=1):
        uc = corpus.usecases[uid]
        has_entities = len(uc.entities) > 0
        rec = ingest_usecase(
            usecase_id=uid,
            has_entities=has_entities,
            logstory_bin=DEFAULT_LOGSTORY_BIN,
            rest_creds=DEFAULT_REST_CREDS,
            legacy_creds=DEFAULT_LEGACY_CREDS,
            project_id=DEFAULT_PROJECT_ID,
            customer_id=DEFAULT_CUSTOMER_ID,
            region=DEFAULT_REGION,
            timestamp_delta=args.timestamp_delta,
            usecases_bucket=DEFAULT_USECASES_BUCKET,
        )
        results.append(rec)
        status_str = "OK" if (rec["events_ok"] and rec["entities_ok"]) else "PARTIAL_OR_ERR"
        print(
            f"[{idx:02d}/{len(target_ids):02d}] {uid}: {status_str} "
            f"(events={rec['events_api']}/{rec['events_elapsed_sec']}s, "
            f"entities={rec['entities_api'] if has_entities else 'n/a'})",
            flush=True,
        )

    total_elapsed = round(time.monotonic() - t_start, 2)
    events_ok_count = sum(1 for r in results if r["events_ok"])
    entities_attempted = sum(1 for r in results if r["entities_attempted"])
    entities_ok_count = sum(1 for r in results if r["entities_attempted"] and r["entities_ok"])

    manifest = {
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "project_id": DEFAULT_PROJECT_ID,
        "customer_id": DEFAULT_CUSTOMER_ID,
        "region": DEFAULT_REGION,
        "timestamp_delta": args.timestamp_delta,
        "total_usecases_targeted": len(target_ids),
        "events_succeeded": events_ok_count,
        "entities_attempted": entities_attempted,
        "entities_succeeded": entities_ok_count,
        "total_elapsed_sec": total_elapsed,
        "results": results,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"Completed ingestion in {total_elapsed}s: "
        f"events={events_ok_count}/{len(target_ids)}, "
        f"entities={entities_ok_count}/{entities_attempted}. "
        f"Manifest saved to {out_path}"
    )
    return 0 if events_ok_count == len(target_ids) else 1


if __name__ == "__main__":
    raise SystemExit(main())
