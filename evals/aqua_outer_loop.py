"""AQuA Outer-Loop Production Trace Analyzer & Longitudinal Clustering Engine (Phase 4).

Implements a two-stage outer-loop diagnostic pipeline:
- Stage 1 (Single-Trace Analysis): Evaluates individual ADK session traces or
  historical execution_metrics.jsonl / otel_traces.jsonl records using categorical
  rubrics and root-cause heuristics.
- Stage 2 (Longitudinal Clustering): Aggregates TraceReport findings into
  recurring systemic Insight clusters persisted in SQLite (evals/results/aqua_insights.db)
  with optional BigQuery export.
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import UTC
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for p in [str(REPO_ROOT), str(MULTI_AGENT_DIR)]:
  if p not in sys.path:
    sys.path.insert(0, p)

from evals.evaluators.base import WorkflowTrace
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite
from evals.telemetry_bridge import DEFAULT_METRICS_JSONL
from evals.telemetry_bridge import DEFAULT_OTEL_JSONL
from evals.telemetry_bridge import DEFAULT_SESSION_DB
from evals.telemetry_bridge import load_all_session_traces
from evals.telemetry_bridge import load_traces_from_metrics_jsonl
from evals.telemetry_bridge import load_traces_from_otel_jsonl

DEFAULT_AQUA_DB = REPO_ROOT / "evals" / "results" / "aqua_insights.db"


class AquaDatabase:
  """SQLite persistence store for AQuA outer-loop insights, occurrences, and traces."""

  def __init__(self, db_path: Path | None = None):
    self.db_path = Path(db_path) if db_path else DEFAULT_AQUA_DB
    self.db_path.parent.mkdir(parents=True, exist_ok=True)
    self._init_schema()

  def _init_schema(self) -> None:
    conn = sqlite3.connect(self.db_path)
    try:
      conn.execute("""
                CREATE TABLE IF NOT EXISTS insights (
                    insight_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    root_cause_hypothesis TEXT NOT NULL,
                    remediation_proposal TEXT NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1,
                    affected_workflows TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                )
                """)
      conn.execute("""
                CREATE TABLE IF NOT EXISTS occurrences (
                    occurrence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    insight_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    workflow_name TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                )
                """)
      conn.execute("""
                CREATE TABLE IF NOT EXISTS traces (
                    trace_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    report_json TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL
                )
                """)
      conn.commit()
    finally:
      conn.close()

  def save_trace_report(self, report: dict[str, Any]) -> None:
    conn = sqlite3.connect(self.db_path)
    try:
      conn.execute(
          """
                INSERT OR REPLACE INTO traces
                (trace_id, session_id, source, summary, report_json, analyzed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
          (
              report["trace_id"],
              report.get("session_id", "unknown"),
              report.get("source", "unknown"),
              report.get("summary", ""),
              json.dumps(report, default=str),
              datetime.now(UTC).isoformat(),
          ),
      )
      conn.commit()
    finally:
      conn.close()

  def upsert_insight(
      self,
      insight: dict[str, Any],
      occurrences: list[dict[str, Any]],
  ) -> dict[str, Any]:
    conn = sqlite3.connect(self.db_path)
    conn.row_factory = sqlite3.Row
    try:
      existing_row = conn.execute(
          "SELECT * FROM insights WHERE insight_id = ?",
          (insight["insight_id"],),
      ).fetchone()

      existing_workflows: set[str] = set()
      existing_description = ""
      created_at = insight.get("created_at") or datetime.now(UTC).isoformat()
      if existing_row is not None:
        existing_workflows.update(
            json.loads(existing_row["affected_workflows"] or "[]")
        )
        existing_description = existing_row["description"] or ""
        created_at = existing_row["created_at"] or created_at

      existing_occ_rows = conn.execute(
          "SELECT trace_id, session_id, workflow_name, tool_name, evidence_json "
          "FROM occurrences WHERE insight_id = ? ORDER BY occurrence_id ASC",
          (insight["insight_id"],),
      ).fetchall()

      seen_keys: set[tuple[str, str, str, str, str]] = set()
      merged_occs: list[tuple[str, str, str, str, str]] = []
      for r in existing_occ_rows:
        key = (
            str(r["trace_id"]),
            str(r["session_id"]),
            str(r["workflow_name"]),
            str(r["tool_name"]),
            str(r["evidence_json"]),
        )
        if key not in seen_keys:
          seen_keys.add(key)
          merged_occs.append(key)

      new_occ_added = 0
      for occ in occurrences:
        ev_str = json.dumps(
            occ.get("evidence", {}), sort_keys=True, default=str
        )
        key = (
            str(occ.get("trace_id", "")),
            str(occ.get("session_id", "")),
            str(occ.get("workflow_name", "")),
            str(occ.get("tool_name", "")),
            ev_str,
        )
        if key not in seen_keys:
          seen_keys.add(key)
          merged_occs.append(key)
          new_occ_added += 1
          conn.execute(
              """
                        INSERT INTO occurrences
                        (insight_id, trace_id, session_id, workflow_name, tool_name, evidence_json)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
              (
                  insight["insight_id"],
                  key[0],
                  key[1],
                  key[2],
                  key[3],
                  key[4],
              ),
          )

      merged_workflows = sorted(
          existing_workflows | set(insight.get("affected_workflows", []))
      )
      description = existing_description or insight["description"]
      for part in str(insight["description"]).split(" | "):
        part_clean = part.strip()
        if part_clean and part_clean not in description:
          description = (
              f"{description} | {part_clean}" if description else part_clean
          )

      if existing_row is not None:
        prior_count = int(existing_row["occurrence_count"] or 0)
        total_count = max(
            len(merged_occs),
            prior_count + new_occ_added if occurrences else prior_count,
        )
      else:
        total_count = max(
            len(merged_occs), int(insight.get("occurrence_count", 1))
        )

      conn.execute(
          """
                INSERT OR REPLACE INTO insights
                (insight_id, category, severity, title, description,
                 root_cause_hypothesis, remediation_proposal,
                 occurrence_count, affected_workflows, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
          (
              insight["insight_id"],
              insight["category"],
              insight["severity"],
              insight["title"],
              description,
              insight["root_cause_hypothesis"],
              insight["remediation_proposal"],
              total_count,
              json.dumps(merged_workflows),
              created_at,
          ),
      )
      conn.commit()
      result = dict(insight)
      result["description"] = description
      result["affected_workflows"] = merged_workflows
      result["occurrence_count"] = total_count
      result["created_at"] = created_at
      return result
    finally:
      conn.close()

  def list_insights(self) -> list[dict[str, Any]]:
    conn = sqlite3.connect(self.db_path)
    conn.row_factory = sqlite3.Row
    try:
      rows = conn.execute(
          "SELECT * FROM insights ORDER BY occurrence_count DESC, insight_id ASC"
      ).fetchall()
      results = []
      for r in rows:
        d = dict(r)
        d["affected_workflows"] = json.loads(
            d.get("affected_workflows") or "[]"
        )
        results.append(d)
      return results
    finally:
      conn.close()

  def get_insight(self, insight_id: str) -> dict[str, Any] | None:
    conn = sqlite3.connect(self.db_path)
    conn.row_factory = sqlite3.Row
    try:
      row = conn.execute(
          "SELECT * FROM insights WHERE insight_id = ?", (insight_id,)
      ).fetchone()
      if not row:
        return None
      d = dict(row)
      d["affected_workflows"] = json.loads(d.get("affected_workflows") or "[]")
      d["occurrences"] = self.get_insight_traces(insight_id)
      return d
    finally:
      conn.close()

  def get_insight_traces(self, insight_id: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(self.db_path)
    conn.row_factory = sqlite3.Row
    try:
      rows = conn.execute(
          "SELECT * FROM occurrences WHERE insight_id = ? ORDER BY occurrence_id ASC",
          (insight_id,),
      ).fetchall()
      out = []
      for r in rows:
        d = dict(r)
        d["evidence"] = json.loads(d.pop("evidence_json", "{}") or "{}")
        out.append(d)
      return out
    finally:
      conn.close()


def analyze_session_trace(
    trace: WorkflowTrace, source: str = "session-db"
) -> dict[str, Any]:
  """Stage 1: Single-Trace Analyzer.
  Evaluates a WorkflowTrace against categorical rubrics and extracts failure modes.
  """
  verdicts = CategoricalRubricSuite.evaluate_all(
      trace, trace.raw_output if isinstance(trace.raw_output, dict) else None
  )
  detected_issues: list[dict[str, Any]] = []

  workflow_calls = [
      tc
      for tc in trace.tool_calls
      if (
          tc.tool_name.startswith("run_") and tc.tool_name.endswith("_workflow")
      )
      or (
          tc.tool_name == "execute_mcp_tool"
          and str(tc.args.get("tool_name", "")).startswith("run_")
      )
  ]
  load_skill_calls = [
      tc for tc in trace.tool_calls if tc.tool_name == "load_skill"
  ]
  schema_calls = [
      tc
      for tc in trace.tool_calls
      if tc.tool_name in ("get_mcp_tool_schema", "search_mcp_tools")
  ]
  error_calls = [tc for tc in trace.tool_calls if tc.status == "error"]

  pd_verdict = verdicts["ProgressiveDisclosureCompliance"]
  if pd_verdict.category in ("FULL_BYPASS", "PARTIAL_BYPASS") or (
      len(workflow_calls) > len(load_skill_calls) and len(schema_calls) == 0
  ):
    bypassed_tools = [
        tc.args.get("tool_name", tc.tool_name)
        for tc in workflow_calls
        if not (tc.disclosure_skill_loaded and tc.mcp_schema_inspected)
    ]
    detected_issues.append(
        {
            "category": "PROGRESSIVE_DISCLOSURE_BYPASS",
            "severity": "HIGH",
            "summary": (
                f"Detected {len(workflow_calls)} workflow executions with only "
                f"{len(load_skill_calls)} load_skill call(s) and {len(schema_calls)} "
                f"search_mcp_tools/get_mcp_tool_schema call(s)."
            ),
            "root_cause_hypothesis": (
                "All 36 WORKFLOW_TOOLS were statically bound on root_agent alongside "
                "load_skill and execute_mcp_tool, allowing the LLM to invoke run_*_workflow "
                "directly on Turn 1 without progressive skill or schema discovery."
            ),
            "remediation_proposal": (
                "Set default disclosure_mode='dual_progressive' (or 'skill_toolset') in "
                "get_agent_tools() so only the 9 meta-discovery tools are bound at Turn 0 "
                "and all 36 workflow tools are registered in global_mcp_registry."
            ),
            "affected_tools": sorted({str(t) for t in bypassed_tools}),
            "occurrence_count": max(1, len(workflow_calls)),
            "occurrences": [
                {
                    "trace_id": trace.trace_id or "unknown",
                    "session_id": trace.session_id or "unknown",
                    "workflow_name": str(
                        tc.args.get("tool_name", tc.tool_name)
                    ).removeprefix("run_"),
                    "tool_name": str(tc.args.get("tool_name", tc.tool_name)),
                    "evidence": {
                        "turn_index": tc.turn_index,
                        "disclosure_skill_loaded": tc.disclosure_skill_loaded,
                        "mcp_schema_inspected": tc.mcp_schema_inspected,
                        "args": tc.args,
                    },
                }
                for tc in (workflow_calls or trace.tool_calls)
            ],
        }
    )

  if error_calls:
    failed_names = [
        str(tc.args.get("tool_name", tc.tool_name)) for tc in error_calls
    ]
    detected_issues.append(
        {
            "category": "TOOL_EXECUTION_FAILURE",
            "severity": "HIGH",
            "summary": (
                f"Detected {len(error_calls)} failed tool execution(s) across: "
                f"{', '.join(sorted(set(failed_names)))}."
            ),
            "root_cause_hypothesis": (
                "Direct tool execution occurred without prior schema validation "
                "(get_mcp_tool_schema) or failed due to missing/invalid input arguments."
            ),
            "remediation_proposal": (
                "Require get_mcp_tool_schema inspection prior to execute_mcp_tool and "
                "promote failing workflow invocations into evals/datasets/production_regressions.json."
            ),
            "affected_tools": sorted(set(failed_names)),
            "occurrence_count": len(error_calls),
            "occurrences": [
                {
                    "trace_id": trace.trace_id or "unknown",
                    "session_id": trace.session_id or "unknown",
                    "workflow_name": str(
                        tc.args.get("tool_name", tc.tool_name)
                    ).removeprefix("run_"),
                    "tool_name": str(tc.args.get("tool_name", tc.tool_name)),
                    "evidence": {
                        "turn_index": tc.turn_index,
                        "status": tc.status,
                        "error_message": tc.error_message,
                        "args": tc.args,
                    },
                }
                for tc in error_calls
            ],
        }
    )

  soar_verdict = verdicts["SoarTriagingIntegrity"]
  if soar_verdict.category == "UNVERIFIED_CONTAINMENT":
    detected_issues.append(
        {
            "category": "UNVERIFIED_CONTAINMENT",
            "severity": "CRITICAL",
            "summary": soar_verdict.reason,
            "root_cause_hypothesis": (
                "Agent executed destructive host or account containment before "
                "correlating SIEM events or GTI threat intelligence."
            ),
            "remediation_proposal": (
                "Enforce SoarTriagingIntegrityRubric == GROUNDED_DISPOSITION gate "
                "and require SIEM/GTI enrichment steps in triage skills."
            ),
            "affected_tools": soar_verdict.evidence.get(
                "containment_tools", []
            ),
            "occurrence_count": 1,
            "occurrences": [
                {
                    "trace_id": trace.trace_id or "unknown",
                    "session_id": trace.session_id or "unknown",
                    "workflow_name": trace.workflow_name,
                    "tool_name": "containment_action",
                    "evidence": soar_verdict.evidence,
                }
            ],
        }
    )

  return {
      "trace_id": trace.trace_id or f"trace-{trace.session_id or 'anon'}",
      "session_id": trace.session_id or "unknown",
      "workflow_name": trace.workflow_name,
      "source": source,
      "summary": (
          f"Analyzed {len(trace.tool_calls)} tool calls "
          f"({len(workflow_calls)} workflow calls, {len(load_skill_calls)} skill loads, "
          f"{len(schema_calls)} schema lookups, {len(error_calls)} errors)."
      ),
      "categorical_verdicts": {
          k: {
              "category": v.category,
              "passed": v.passed,
              "reason": v.reason,
          }
          for k, v in verdicts.items()
      },
      "detected_issues": detected_issues,
  }


def analyze_metrics_jsonl(
    metrics_path: Path | None = None,
) -> list[dict[str, Any]]:
  """Analyze execution_metrics.jsonl and return Stage 1 TraceReport dictionaries."""
  traces = load_traces_from_metrics_jsonl(metrics_path=metrics_path)
  return [analyze_session_trace(t, source="metrics-jsonl") for t in traces]


def cluster_trace_reports(
    reports: list[dict[str, Any]],
    db_path: Path | None = None,
    bq_dataset: str | None = None,
) -> list[dict[str, Any]]:
  """Stage 2: Longitudinal Cross-Trace Clustering.
  Groups Stage 1 TraceReports by issue category and persists systemic Insights to SQLite.
  """
  db = AquaDatabase(db_path=db_path)

  clusters: dict[str, dict[str, Any]] = {}
  cluster_occurrences: dict[str, list[dict[str, Any]]] = {}

  for rep in reports:
    db.save_trace_report(rep)
    for issue in rep.get("detected_issues", []):
      cat = issue["category"]
      digest = hashlib.sha256(cat.encode()).hexdigest()[:6].upper()
      insight_id = f"INS-{cat[:12]}-{digest}"

      if cat not in clusters:
        clusters[cat] = {
            "insight_id": insight_id,
            "category": cat,
            "severity": issue.get("severity", "HIGH"),
            "title": f"{cat.replace('_', ' ').title()} Systemic Pattern",
            "description": issue["summary"],
            "root_cause_hypothesis": issue["root_cause_hypothesis"],
            "remediation_proposal": issue["remediation_proposal"],
            "occurrence_count": 0,
            "affected_workflows": set(),
            "created_at": datetime.now(UTC).isoformat(),
        }
        cluster_occurrences[cat] = []

      clusters[cat]["occurrence_count"] += int(issue.get("occurrence_count", 1))
      for tool_name in issue.get("affected_tools", []):
        wf_clean = str(tool_name).removeprefix("run_")
        clusters[cat]["affected_workflows"].add(wf_clean)
      if issue["summary"] not in clusters[cat]["description"]:
        clusters[cat]["description"] += f" | {issue['summary']}"

      cluster_occurrences[cat].extend(issue.get("occurrences", []))

  persisted_insights: list[dict[str, Any]] = []
  for cat, ins in clusters.items():
    ins_dict = dict(ins)
    ins_dict["affected_workflows"] = sorted(ins["affected_workflows"])
    occs = cluster_occurrences.get(cat, [])
    merged_ins = db.upsert_insight(ins_dict, occs)
    persisted_insights.append(merged_ins)

  if bq_dataset:
    _export_insights_to_bigquery(persisted_insights, bq_dataset)

  return persisted_insights


def _export_insights_to_bigquery(
    insights: list[dict[str, Any]], bq_dataset: str
) -> None:
  """Optional BigQuery export when --bq-dataset is specified."""
  try:
    from google.cloud import bigquery  # type: ignore

    client = bigquery.Client()
    table_id = f"{bq_dataset}.aqua_insights"
    errors = client.insert_rows_json(table_id, insights)
    if errors:
      print(
          f"Warning: BigQuery export encountered errors: {errors}",
          file=sys.stderr,
      )
  except Exception as exc:
    print(f"Warning: Skipping BigQuery export ({exc})", file=sys.stderr)


def main() -> int:
  parser = argparse.ArgumentParser(
      description="AQuA Outer-Loop Production Trace Analyzer & Clustering CLI"
  )
  subparsers = parser.add_subparsers(dest="command", required=True)

  # analyze subcommand
  analyze_parser = subparsers.add_parser(
      "analyze",
      help="Run Stage 1 & Stage 2 AQuA analysis over telemetry traces",
  )
  analyze_parser.add_argument(
      "--source",
      choices=["session-db", "metrics-jsonl", "otel-jsonl"],
      default="metrics-jsonl",
      help="Telemetry source to analyze",
  )
  analyze_parser.add_argument(
      "--input",
      type=str,
      default=None,
      help="Path to input file (session.db, execution_metrics.jsonl, or otel_traces.jsonl)",
  )
  analyze_parser.add_argument(
      "--db-path",
      type=str,
      default=str(DEFAULT_AQUA_DB),
      help="Path to SQLite insights database (default: evals/results/aqua_insights.db)",
  )
  analyze_parser.add_argument(
      "--bq-dataset",
      type=str,
      default=None,
      help="Optional BigQuery dataset ID for exporting clustered insights",
  )

  # insights subcommand
  insights_parser = subparsers.add_parser(
      "insights", help="Query clustered systemic insights from aqua_insights.db"
  )
  insights_sub = insights_parser.add_subparsers(
      dest="insights_cmd", required=True
  )

  list_p = insights_sub.add_parser("list", help="List all clustered insights")
  list_p.add_argument("--db-path", type=str, default=str(DEFAULT_AQUA_DB))

  get_p = insights_sub.add_parser(
      "get", help="Get details for a specific insight ID"
  )
  get_p.add_argument("insight_id", type=str)
  get_p.add_argument("--db-path", type=str, default=str(DEFAULT_AQUA_DB))

  traces_p = insights_sub.add_parser(
      "traces", help="List affected traces/occurrences for an insight ID"
  )
  traces_p.add_argument("insight_id", type=str)
  traces_p.add_argument("--db-path", type=str, default=str(DEFAULT_AQUA_DB))

  args = parser.parse_args()

  if args.command == "analyze":
    inp_path = Path(args.input) if args.input else None
    if args.source == "metrics-jsonl":
      reports = analyze_metrics_jsonl(inp_path or DEFAULT_METRICS_JSONL)
    elif args.source == "session-db":
      traces = load_all_session_traces(inp_path or DEFAULT_SESSION_DB)
      reports = [analyze_session_trace(t, source="session-db") for t in traces]
    else:
      traces = load_traces_from_otel_jsonl(inp_path or DEFAULT_OTEL_JSONL)
      reports = [analyze_session_trace(t, source="otel-jsonl") for t in traces]

    insights = cluster_trace_reports(
        reports, db_path=Path(args.db_path), bq_dataset=args.bq_dataset
    )
    print(f"=== AQuA Outer-Loop Analysis Complete (source={args.source}) ===")
    print(
        f"Analyzed {len(reports)} trace cohort(s) -> Discovered {len(insights)} systemic insight cluster(s):"
    )
    for ins in insights:
      print(
          f"  * [{ins['insight_id']}] {ins['category']} ({ins['severity']}) "
          f"— {ins['occurrence_count']} occurrence(s): {ins['description']}"
      )
    return 0

  if args.command == "insights":
    db = AquaDatabase(Path(args.db_path))
    if args.insights_cmd == "list":
      insights = db.list_insights()
      if not insights:
        print("No insights found in database.")
        return 0
      print(f"=== AQuA Systemic Insights ({len(insights)} total) ===")
      for ins in insights:
        print(
            f"[{ins['insight_id']}] {ins['category']} | Severity: {ins['severity']} | "
            f"Occurrences: {ins['occurrence_count']}"
        )
        print(f"  Summary:     {ins['description']}")
        print(f"  Root Cause:  {ins['root_cause_hypothesis']}")
        print(f"  Remediation: {ins['remediation_proposal']}")
        print(f"  Workflows:   {', '.join(ins['affected_workflows'])}")
        print("-" * 75)
      return 0
    elif args.insights_cmd == "get":
      ins = db.get_insight(args.insight_id)
      if not ins:
        print(f"Insight '{args.insight_id}' not found.")
        return 1
      print(json.dumps(ins, indent=2))
      return 0
    elif args.insights_cmd == "traces":
      occs = db.get_insight_traces(args.insight_id)
      print(json.dumps(occs, indent=2))
      return 0

  return 0


if __name__ == "__main__":
  sys.exit(main())
