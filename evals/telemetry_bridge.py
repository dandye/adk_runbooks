"""Telemetry Bridge connecting ADK SQLite session.db, execution_metrics.jsonl,
and OpenTelemetry GenAI traces (otel_traces.jsonl) to WorkflowTrace objects.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any

from evals.evaluators.base import ToolCallRecord
from evals.evaluators.base import WorkflowTrace

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SESSION_DB = (
    REPO_ROOT / "multi-agent" / "manager" / ".adk" / "session.db"
)
DEFAULT_METRICS_JSONL = (
    REPO_ROOT / "multi-agent" / "reports" / "execution_metrics.jsonl"
)
DEFAULT_OTEL_JSONL = REPO_ROOT / "multi-agent" / "reports" / "otel_traces.jsonl"


def _is_tool_schema_inspected(
    tool_name: str, inspected_schemas: list[str]
) -> bool:
  """Return True if tool_name (or a matching discovery query/token) was inspected prior to execution."""
  if not tool_name or not inspected_schemas:
    return False
  norm_tool = tool_name.lower().strip()
  unprefixed = (
      norm_tool.split("_", 1)[-1]
      if "-" in norm_tool.split("_", 1)[0]
      else norm_tool
  )
  stop_words = {
      "run",
      "mcp",
      "get",
      "list",
      "the",
      "for",
      "by",
      "tool",
      "workflow",
  }
  tool_tokens = {
      tok
      for tok in unprefixed.replace("-", "_").split("_")
      if len(tok) >= 3 and tok not in stop_words
  }
  for item in inspected_schemas:
    norm_item = str(item).lower().strip()
    if not norm_item:
      continue
    if norm_item == norm_tool or norm_item == unprefixed:
      return True
    if norm_item in norm_tool or unprefixed in norm_item:
      return True
    item_tokens = {
        tok
        for tok in norm_item.replace("-", "_").replace(" ", "_").split("_")
        if len(tok) >= 3 and tok not in stop_words
    }
    if tool_tokens and item_tokens and (tool_tokens & item_tokens):
      return True
  return False


def load_session_trace(
    session_id: str = "latest",
    db_path: Path | None = None,
    disclosure_mode: str = "dual_progressive",
) -> WorkflowTrace:
  """Load an ADK session from SQLite session.db into a structured WorkflowTrace."""
  target_db = Path(db_path) if db_path else DEFAULT_SESSION_DB
  if not target_db.exists():
    raise FileNotFoundError(f"ADK session database not found at {target_db}")

  conn = sqlite3.connect(target_db)
  cursor = conn.cursor()

  try:
    if session_id == "latest":
      cursor.execute(
          "SELECT id FROM sessions ORDER BY update_time DESC LIMIT 1"
      )
      row = cursor.fetchone()
      if not row:
        raise ValueError("No sessions found in database.")
      session_id = row[0]

    cursor.execute(
        "SELECT id, timestamp, event_data FROM events WHERE session_id = ? ORDER BY timestamp ASC, id ASC",
        (session_id,),
    )
    rows = cursor.fetchall()
  finally:
    conn.close()

  prompt_tokens = 0
  candidates_tokens = 0
  total_tokens = 0
  has_usage_metadata = False

  activated_skills: list[str] = []
  inspected_schemas: list[str] = []
  agent_delegations: list[str] = []
  tool_calls: list[ToolCallRecord] = []
  executed_nodes: list[str] = []
  timestamps: list[float] = []
  output_texts: list[str] = []
  workflow_name = "adk_session"
  route: str | None = None
  trace_status = "success"
  trace_error: str | None = None

  turn_idx = 0
  for _ev_id, ts, data_str in rows:
    turn_idx += 1
    if ts is not None:
      try:
        timestamps.append(float(ts))
      except (TypeError, ValueError):
        pass

    try:
      data = json.loads(data_str)
    except json.JSONDecodeError:
      continue

    author = data.get("author", "unknown")
    if author not in ("user", "unknown") and author not in agent_delegations:
      agent_delegations.append(author)
      if route is None and author != "manager":
        route = author

    usage = data.get("usage_metadata") or data.get("metadata", {}).get(
        "usage_metadata"
    )
    if usage:
      has_usage_metadata = True
      p_tok = int(usage.get("prompt_token_count", 0) or 0)
      c_tok = int(usage.get("candidates_token_count", 0) or 0)
      t_tok = int(
          usage.get("total_token_count", p_tok + c_tok) or (p_tok + c_tok)
      )
      prompt_tokens += p_tok
      candidates_tokens += c_tok
      total_tokens += t_tok

    content = data.get("content") or {}
    for part in content.get("parts") or []:
      if "text" in part and author != "user":
        output_texts.append(part["text"])

      if "function_call" in part:
        fc = part["function_call"]
        t_name = fc.get("name", "")
        t_args = fc.get("args", {}) or {}
        if not isinstance(t_args, dict):
          t_args = {"raw_args": t_args}

        if t_name == "load_skill":
          skill_name = t_args.get("skill_name") or t_args.get("name") or ""
          if skill_name and skill_name not in activated_skills:
            activated_skills.append(str(skill_name))
          disclosure_loaded = True
          schema_inspected = False
        elif t_name in ("get_mcp_tool_schema", "search_mcp_tools"):
          inspected = t_args.get("tool_name") or t_args.get("query") or ""
          if inspected and str(inspected) not in inspected_schemas:
            inspected_schemas.append(str(inspected))
          disclosure_loaded = len(activated_skills) > 0
          schema_inspected = True
        elif t_name == "execute_mcp_tool":
          inner_tool = str(t_args.get("tool_name", ""))
          disclosure_loaded = len(activated_skills) > 0
          schema_inspected = _is_tool_schema_inspected(
              inner_tool, inspected_schemas
          )
          if inner_tool.startswith("run_") and inner_tool.endswith("_workflow"):
            workflow_name = inner_tool.removeprefix("run_")
        else:
          disclosure_loaded = len(activated_skills) > 0
          schema_inspected = _is_tool_schema_inspected(
              t_name, inspected_schemas
          )
          if t_name.startswith("run_") and t_name.endswith("_workflow"):
            workflow_name = t_name.removeprefix("run_")

        record = ToolCallRecord(
            turn_index=turn_idx,
            agent_name=author,
            tool_name=t_name,
            args=t_args,
            status="success",
            disclosure_skill_loaded=disclosure_loaded,
            mcp_schema_inspected=schema_inspected,
        )
        tool_calls.append(record)
        executed_nodes.append(t_name)

      if "function_response" in part:
        fr = part["function_response"]
        resp_name = fr.get("name", "")
        resp_payload = fr.get("response", {})
        resp_str = (
            json.dumps(resp_payload)
            if isinstance(resp_payload, dict)
            else str(resp_payload)
        )
        # Match most recent tool call for this tool
        for tc in reversed(tool_calls):
          if tc.tool_name == resp_name and tc.result_summary is None:
            tc.result_summary = resp_str[:500]
            if isinstance(resp_payload, dict) and resp_payload.get("error"):
              tc.status = "error"
              tc.error_message = str(resp_payload.get("error"))
            break

  duration_sec = (
      (max(timestamps) - min(timestamps)) if len(timestamps) >= 2 else 0.0
  )

  return WorkflowTrace(
      workflow_name=workflow_name,
      executed_nodes=executed_nodes,
      route=route or (agent_delegations[0] if agent_delegations else None),
      duration_seconds=round(duration_sec, 4),
      estimated_tokens_in=prompt_tokens,
      estimated_tokens_out=candidates_tokens,
      total_tokens=total_tokens,
      status=trace_status,
      raw_output="\n".join(output_texts) if output_texts else None,
      error=trace_error,
      session_id=session_id,
      trace_id=f"adk-session-{session_id}",
      token_source="usage_metadata" if has_usage_metadata else "heuristic",
      disclosure_mode=disclosure_mode,
      tool_calls=tool_calls,
      activated_skills=activated_skills,
      inspected_schemas=inspected_schemas,
      agent_delegations=agent_delegations,
  )


def load_all_session_traces(
    db_path: Path | None = None,
    disclosure_mode: str = "dual_progressive",
) -> list[WorkflowTrace]:
  """Load all sessions from ADK SQLite session.db."""
  target_db = Path(db_path) if db_path else DEFAULT_SESSION_DB
  if not target_db.exists():
    return []
  conn = sqlite3.connect(target_db)
  try:
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM sessions ORDER BY update_time ASC")
    session_ids = [r[0] for r in cursor.fetchall()]
  finally:
    conn.close()

  traces: list[WorkflowTrace] = []
  for sid in session_ids:
    try:
      traces.append(
          load_session_trace(
              sid, db_path=target_db, disclosure_mode=disclosure_mode
          )
      )
    except Exception:
      continue
  return traces


def load_traces_from_metrics_jsonl(
    metrics_path: Path | None = None,
    disclosure_mode: str = "dual_progressive",
) -> list[WorkflowTrace]:
  """Parse execution_metrics.jsonl into session-grouped WorkflowTrace objects.
  If entries lack session_id (legacy entries), group by session_id or treat the
  legacy stream as a longitudinal cohort trace + per-window session traces.
  """
  target_path = Path(metrics_path) if metrics_path else DEFAULT_METRICS_JSONL
  if not target_path.exists():
    return []

  raw_entries: list[dict[str, Any]] = []
  for idx, line in enumerate(
      target_path.read_text(encoding="utf-8").splitlines(), start=1
  ):
    if not line.strip():
      continue
    try:
      item = json.loads(line)
      item["_line_number"] = idx
      raw_entries.append(item)
    except json.JSONDecodeError:
      continue

  if not raw_entries:
    return []

  # Group by explicit session_id if present, else build a single longitudinal trace
  grouped: dict[str, list[dict[str, Any]]] = {}
  for entry in raw_entries:
    sid = entry.get("session_id") or "legacy-metrics-cohort"
    grouped.setdefault(sid, []).append(entry)

  traces: list[WorkflowTrace] = []
  for sid, entries in grouped.items():
    activated_skills: list[str] = []
    inspected_schemas: list[str] = []
    tool_calls: list[ToolCallRecord] = []
    executed_nodes: list[str] = []
    tokens_in = 0
    tokens_out = 0
    total_tokens = 0
    total_duration = 0.0
    has_error = False
    error_messages: list[str] = []

    for turn_i, item in enumerate(entries, start=1):
      t_name = item.get("tool_name", "unknown")
      status = item.get("status", "success")
      dur = float(item.get("duration_seconds", 0.0) or 0.0)
      t_in = int(item.get("estimated_tokens_in", 0) or 0)
      t_out = int(item.get("estimated_tokens_out", 0) or 0)
      t_tot = int(
          item.get("total_estimated_tokens", t_in + t_out) or (t_in + t_out)
      )

      tokens_in += t_in
      tokens_out += t_out
      total_tokens += t_tot
      total_duration += dur

      if t_name == "load_skill":
        activated_skills.append(item.get("skill_name", "loaded_skill"))
        skill_loaded = True
        schema_inspected = False
      elif t_name in ("get_mcp_tool_schema", "search_mcp_tools"):
        inspected_schemas.append(item.get("target_tool", t_name))
        skill_loaded = len(activated_skills) > 0
        schema_inspected = True
      else:
        skill_loaded = bool(
            item.get("adk.disclosure_skill_loaded", len(activated_skills) > 0)
        )
        schema_inspected = bool(
            item.get("adk.mcp_schema_inspected", len(inspected_schemas) > 0)
        )

      err_msg = item.get("error_message")
      if status == "error":
        has_error = True
        err_msg = (
            err_msg
            or f"Tool '{t_name}' failed at line {item.get('_line_number')}"
        )
        error_messages.append(err_msg)

      tc = ToolCallRecord(
          turn_index=turn_i,
          agent_name=item.get("agent_name", "manager"),
          tool_name=t_name,
          args=item.get(
              "args",
              {
                  "_line": item.get("_line_number"),
                  "timestamp": item.get("timestamp"),
              },
          ),
          status=status,
          duration_seconds=dur,
          error_message=err_msg,
          disclosure_skill_loaded=skill_loaded,
          mcp_schema_inspected=schema_inspected,
      )
      tool_calls.append(tc)
      executed_nodes.append(t_name)

    traces.append(
        WorkflowTrace(
            workflow_name="execution_metrics_cohort"
            if sid == "legacy-metrics-cohort"
            else sid,
            executed_nodes=executed_nodes,
            duration_seconds=round(total_duration, 4),
            estimated_tokens_in=tokens_in,
            estimated_tokens_out=tokens_out,
            total_tokens=total_tokens,
            status="error" if has_error else "success",
            error="; ".join(error_messages) if error_messages else None,
            session_id=sid,
            trace_id=f"metrics-{sid}",
            token_source="heuristic",
            disclosure_mode=disclosure_mode,
            tool_calls=tool_calls,
            activated_skills=activated_skills,
            inspected_schemas=inspected_schemas,
        )
    )

  return traces


def load_traces_from_otel_jsonl(
    otel_path: Path | None = None,
) -> list[WorkflowTrace]:
  """Load OpenTelemetry GenAI spans from otel_traces.jsonl into WorkflowTrace objects."""
  target_path = Path(otel_path) if otel_path else DEFAULT_OTEL_JSONL
  if not target_path.exists():
    return []

  grouped: dict[str, list[dict[str, Any]]] = {}
  for line in target_path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
      continue
    try:
      span = json.loads(line)
    except json.JSONDecodeError:
      continue
    sid = span.get("session_id") or "otel-default-session"
    grouped.setdefault(sid, []).append(span)

  traces: list[WorkflowTrace] = []
  for sid, spans in grouped.items():
    activated_skills: list[str] = []
    inspected_schemas: list[str] = []
    tool_calls: list[ToolCallRecord] = []
    executed_nodes: list[str] = []
    tokens_in = 0
    tokens_out = 0
    total_tokens = 0
    total_duration = 0.0
    disclosure_mode = "dual_progressive"
    trace_id = f"otel-{sid}"
    has_error = False
    errors: list[str] = []

    for idx, sp in enumerate(spans, start=1):
      t_name = sp.get("gen_ai.tool.name", "unknown")
      agent_name = sp.get("gen_ai.agent.name", "manager")
      status = sp.get("status", "success")
      dur = float(sp.get("duration_seconds", 0.0) or 0.0)
      t_in = int(sp.get("estimated_tokens_in", 0) or 0)
      t_out = int(sp.get("estimated_tokens_out", 0) or 0)
      tokens_in += t_in
      tokens_out += t_out
      total_tokens += t_in + t_out
      total_duration += dur
      disclosure_mode = sp.get("adk.disclosure_mode", disclosure_mode)
      trace_id = sp.get("trace_id", trace_id)

      for sk in sp.get("adk.activated_skills") or []:
        if sk not in activated_skills:
          activated_skills.append(sk)
      for sc in sp.get("adk.inspected_schemas") or []:
        if sc not in inspected_schemas:
          inspected_schemas.append(sc)

      err_msg = sp.get("error.message")
      if status == "error":
        has_error = True
        if err_msg:
          errors.append(err_msg)

      tool_calls.append(
          ToolCallRecord(
              turn_index=sp.get("turn_index", idx),
              agent_name=agent_name,
              tool_name=t_name,
              args=sp.get("gen_ai.tool.call.arguments_redacted", {}),
              status=status,
              duration_seconds=dur,
              error_message=err_msg,
              result_summary=sp.get("gen_ai.tool.call.result_summary"),
              disclosure_skill_loaded=bool(
                  sp.get("adk.disclosure_skill_loaded", False)
              ),
              mcp_schema_inspected=bool(
                  sp.get("adk.mcp_schema_inspected", False)
              ),
          )
      )
      executed_nodes.append(t_name)

    traces.append(
        WorkflowTrace(
            workflow_name=sid,
            executed_nodes=executed_nodes,
            duration_seconds=round(total_duration, 4),
            estimated_tokens_in=tokens_in,
            estimated_tokens_out=tokens_out,
            total_tokens=total_tokens,
            status="error" if has_error else "success",
            error="; ".join(errors) if errors else None,
            session_id=sid,
            trace_id=trace_id,
            token_source="otel_span",
            disclosure_mode=disclosure_mode,
            tool_calls=tool_calls,
            activated_skills=activated_skills,
            inspected_schemas=inspected_schemas,
        )
    )

  return traces
