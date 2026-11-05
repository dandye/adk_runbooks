from contextlib import contextmanager
import contextvars
from datetime import datetime, timezone
import functools
import inspect
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Iterator
import uuid

# Configure logging for instrumentation
logger = logging.getLogger("tool_instrumentation")
logger.setLevel(logging.INFO)

# Backward-compatible global metrics list
RUN_METRICS: list[dict[str, Any]] = []

# Context variables for session-scoped OpenTelemetry GenAI tracing
current_session_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_session_id", default="default-session"
)
current_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_trace_id", default="trace-default"
)
current_parent_span_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "current_parent_span_id", default=None
)
current_agent_name: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_agent_name", default="manager"
)
current_turn_index: contextvars.ContextVar[int] = contextvars.ContextVar(
    "current_turn_index", default=0
)
current_disclosure_mode: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_disclosure_mode",
    default=os.environ.get("ADK_DISCLOSURE_MODE", "dual_progressive"),
)
current_otel_log_path: contextvars.ContextVar[Path | None] = contextvars.ContextVar(
    "current_otel_log_path", default=None
)

_SENSITIVE_KEY_SUBSTRINGS = (
    "api_key",
    "apikey",
    "password",
    "passwd",
    "token",
    "app_key",
    "secret",
    "authorization",
    "credential",
    "private_key",
)

_META_DISCOVERY_TOOLS = {
    "load_skill",
    "list_available_skills",
    "list_skills",
    "search_mcp_tools",
    "get_mcp_tool_schema",
    "get_current_time",
    "get_execution_metrics",
    "read_file_content",
    "write_report",
}


def estimate_tokens(text: str) -> int:
    """Rough token estimation using ~4 characters per token."""
    if not text:
        return 0
    return len(str(text)) // 4


def redact_sensitive_args(data: Any) -> Any:
    """Recursively redact sensitive keys from tool call arguments."""
    if isinstance(data, dict):
        redacted: dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(sub in key_lower for sub in _SENSITIVE_KEY_SUBSTRINGS):
                redacted[k] = "[REDACTED]"
            else:
                redacted[k] = redact_sensitive_args(v)
        return redacted
    if isinstance(data, (list, tuple)):
        return [redact_sensitive_args(item) for item in data]
    return data


def _normalize_identifier(name: str) -> str:
    norm = name.strip().lower().replace("-", "_")
    for prefix in (
        "secops_mcp_",
        "soar_mcp_",
        "gti_mcp_",
        "secops_soar_",
        "secops_",
        "soar_",
        "gti_",
    ):
        if norm.startswith(prefix):
            return norm[len(prefix) :]
    return norm


class AgentTelemetryRecorder:
    """Session-scoped OpenTelemetry GenAI span and progressive disclosure state recorder."""

    def __init__(self) -> None:
        self._activated_skills: dict[str, list[str]] = {}
        self._inspected_schemas: dict[str, list[str]] = {}
        self._session_spans: dict[str, list[dict[str, Any]]] = {}

    def reset_session(self, session_id: str | None = None) -> None:
        if session_id is None:
            self._activated_skills.clear()
            self._inspected_schemas.clear()
            self._session_spans.clear()
        else:
            self._activated_skills.pop(session_id, None)
            self._inspected_schemas.pop(session_id, None)
            self._session_spans.pop(session_id, None)

    def get_activated_skills(self, session_id: str | None = None) -> list[str]:
        sid = session_id or current_session_id.get()
        return list(self._activated_skills.get(sid, []))

    def get_inspected_schemas(self, session_id: str | None = None) -> list[str]:
        sid = session_id or current_session_id.get()
        return list(self._inspected_schemas.get(sid, []))

    def record_skill_activation(
        self, skill_name: str, session_id: str | None = None
    ) -> None:
        if not skill_name:
            return
        sid = session_id or current_session_id.get()
        skills = self._activated_skills.setdefault(sid, [])
        if skill_name not in skills:
            skills.append(skill_name)

    def record_schema_inspection(
        self, tool_name: str, session_id: str | None = None
    ) -> None:
        if not tool_name:
            return
        sid = session_id or current_session_id.get()
        schemas = self._inspected_schemas.setdefault(sid, [])
        if tool_name not in schemas:
            schemas.append(tool_name)

    def is_schema_inspected(
        self, tool_name: str, session_id: str | None = None
    ) -> bool:
        if not tool_name:
            return False
        sid = session_id or current_session_id.get()
        norm_target = _normalize_identifier(tool_name)
        for s in self._inspected_schemas.get(sid, []):
            if _normalize_identifier(s) == norm_target:
                return True
        return False

    def record_span(self, span: dict[str, Any]) -> None:
        sid = span.get("session_id", current_session_id.get())
        self._session_spans.setdefault(sid, []).append(span)
        RUN_METRICS.append(span)

        otel_path = current_otel_log_path.get()
        if otel_path is None:
            env_otel = os.environ.get("ADK_OTEL_TRACES_PATH")
            if env_otel:
                otel_path = Path(env_otel)
            else:
                otel_path = (
                    Path(__file__).resolve().parent.parent.parent
                    / "reports"
                    / "otel_traces.jsonl"
                )

        try:
            otel_path.parent.mkdir(parents=True, exist_ok=True)
            with open(otel_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(span, default=str) + "\n")
        except Exception as log_err:
            logger.error("Failed to write OTel span: %s", log_err)

        if os.environ.get("ADK_APPEND_LEGACY_METRICS") == "1":
            try:
                log_dir = Path(__file__).resolve().parent.parent.parent / "reports"
                log_dir.mkdir(parents=True, exist_ok=True)
                legacy_file = log_dir / "execution_metrics.jsonl"
                legacy_metric = {
                    "timestamp": span["timestamp"],
                    "tool_name": span["tool_name"],
                    "duration_seconds": span["duration_seconds"],
                    "status": span["status"],
                    "estimated_tokens_in": span["estimated_tokens_in"],
                    "estimated_tokens_out": span["estimated_tokens_out"],
                    "total_estimated_tokens": span["total_estimated_tokens"],
                }
                with open(legacy_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(legacy_metric) + "\n")
            except Exception as log_err:
                logger.error("Failed to write legacy metric: %s", log_err)

    def get_session_spans(self, session_id: str | None = None) -> list[dict[str, Any]]:
        sid = session_id or current_session_id.get()
        return list(self._session_spans.get(sid, []))


TELEMETRY_RECORDER = AgentTelemetryRecorder()


def record_skill_activation(skill_name: str, session_id: str | None = None) -> None:
    TELEMETRY_RECORDER.record_skill_activation(skill_name, session_id=session_id)


def record_schema_inspection(tool_name: str, session_id: str | None = None) -> None:
    TELEMETRY_RECORDER.record_schema_inspection(tool_name, session_id=session_id)


def get_session_spans(session_id: str | None = None) -> list[dict[str, Any]]:
    return TELEMETRY_RECORDER.get_session_spans(session_id=session_id)


def reset_telemetry_session(session_id: str | None = None) -> None:
    TELEMETRY_RECORDER.reset_session(session_id=session_id)


@contextmanager
def telemetry_session_scope(
    session_id: str,
    trace_id: str | None = None,
    agent_name: str = "manager",
    disclosure_mode: str = "dual_progressive",
    turn_index: int = 0,
    otel_log_path: Path | str | None = None,
    reset_existing: bool = True,
) -> Iterator[AgentTelemetryRecorder]:
    """Context manager scoping OpenTelemetry GenAI attributes to an execution session."""
    if reset_existing:
        TELEMETRY_RECORDER.reset_session(session_id)

    eff_trace_id = trace_id or f"trace-{uuid.uuid4().hex[:16]}"
    eff_otel_path = Path(otel_log_path) if otel_log_path else None

    tok_sess = current_session_id.set(session_id)
    tok_trace = current_trace_id.set(eff_trace_id)
    tok_agent = current_agent_name.set(agent_name)
    tok_mode = current_disclosure_mode.set(disclosure_mode)
    tok_turn = current_turn_index.set(turn_index)
    tok_path = current_otel_log_path.set(eff_otel_path)
    try:
        yield TELEMETRY_RECORDER
    finally:
        current_session_id.reset(tok_sess)
        current_trace_id.reset(tok_trace)
        current_agent_name.reset(tok_agent)
        current_disclosure_mode.reset(tok_mode)
        current_turn_index.reset(tok_turn)
        current_otel_log_path.reset(tok_path)


def _extract_bound_arguments(tool_func: Any, args: tuple, kwargs: dict) -> dict[str, Any]:
    try:
        sig = inspect.signature(tool_func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except Exception:
        res = dict(kwargs)
        if args:
            res["_positional_args"] = list(args)
        return res


def _finalize_span(
    tool_func: Any,
    bound_args: dict[str, Any],
    result: Any,
    status: str,
    start_dt: datetime,
    duration: float,
    prior_skills: list[str],
    prior_schemas: list[str],
) -> None:
    session_id = current_session_id.get()
    trace_id = current_trace_id.get()
    parent_span_id = current_parent_span_id.get()
    agent_name = current_agent_name.get()
    disclosure_mode = current_disclosure_mode.get()
    turn_idx = current_turn_index.get() + 1
    current_turn_index.set(turn_idx)

    wrapper_name = getattr(tool_func, "__name__", str(tool_func))
    effective_tool_name = wrapper_name
    if wrapper_name == "execute_mcp_tool" and isinstance(bound_args.get("tool_name"), str):
        effective_tool_name = bound_args["tool_name"]

    disclosure_skill_loaded = len(prior_skills) > 0
    if disclosure_mode == "skill_toolset" and disclosure_skill_loaded:
        mcp_schema_inspected = True
    elif wrapper_name == "execute_mcp_tool":
        target_name = str(bound_args.get("tool_name", ""))
        mcp_schema_inspected = TELEMETRY_RECORDER.is_schema_inspected(
            target_name, session_id=session_id
        )
    elif wrapper_name not in _META_DISCOVERY_TOOLS:
        mcp_schema_inspected = TELEMETRY_RECORDER.is_schema_inspected(
            wrapper_name, session_id=session_id
        )
    else:
        mcp_schema_inspected = True

    # Update session state if this call activated a skill or inspected a schema
    res_str = str(result) if result is not None else ""
    if status == "success" and not res_str.startswith("Error:"):
        if wrapper_name == "load_skill":
            sk_name = str(bound_args.get("skill_name", "")).strip()
            if sk_name:
                TELEMETRY_RECORDER.record_skill_activation(sk_name, session_id=session_id)
        elif wrapper_name == "get_mcp_tool_schema":
            t_name = str(bound_args.get("tool_name", "")).strip()
            if t_name:
                TELEMETRY_RECORDER.record_schema_inspection(t_name, session_id=session_id)

    redacted_args = redact_sensitive_args(bound_args)
    input_str = json.dumps(redacted_args, default=str)
    output_str = res_str
    tokens_in = estimate_tokens(input_str)
    tokens_out = estimate_tokens(output_str)

    span = {
        "trace_id": trace_id,
        "span_id": f"span-{uuid.uuid4().hex[:12]}",
        "parent_span_id": parent_span_id,
        "session_id": session_id,
        "timestamp": start_dt.isoformat(),
        "tool_name": wrapper_name,
        "effective_tool_name": effective_tool_name,
        "duration_seconds": round(duration, 4),
        "status": status,
        "estimated_tokens_in": tokens_in,
        "estimated_tokens_out": tokens_out,
        "total_estimated_tokens": tokens_in + tokens_out,
        "gen_ai.system": "google_adk",
        "gen_ai.agent.name": agent_name,
        "gen_ai.tool.name": effective_tool_name,
        "gen_ai.tool.wrapper_name": wrapper_name,
        "gen_ai.tool.call.arguments_redacted": redacted_args,
        "gen_ai.tool.call.result_summary": output_str[:500],
        "gen_ai.usage.input_tokens": tokens_in,
        "gen_ai.usage.output_tokens": tokens_out,
        "adk.turn_index": turn_idx,
        "adk.disclosure_mode": disclosure_mode,
        "adk.activated_skills": list(TELEMETRY_RECORDER.get_activated_skills(session_id)),
        "adk.inspected_schemas": list(TELEMETRY_RECORDER.get_inspected_schemas(session_id)),
        "adk.disclosure_skill_loaded": disclosure_skill_loaded,
        "adk.mcp_schema_inspected": mcp_schema_inspected,
    }
    TELEMETRY_RECORDER.record_span(span)


def instrument_tool(tool_func: Any) -> Any:
    """Wraps a synchronous or asynchronous tool with OpenTelemetry GenAI span recording."""
    if getattr(tool_func, "_is_adk_instrumented", False):
        return tool_func

    if inspect.iscoroutinefunction(tool_func):
        @functools.wraps(tool_func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            start_dt = datetime.now(timezone.utc)
            status = "success"
            result = None
            sid = current_session_id.get()
            prior_skills = TELEMETRY_RECORDER.get_activated_skills(sid)
            prior_schemas = TELEMETRY_RECORDER.get_inspected_schemas(sid)
            bound_args = _extract_bound_arguments(tool_func, args, kwargs)
            try:
                result = await tool_func(*args, **kwargs)
                if isinstance(result, str) and result.startswith("Error executing tool"):
                    status = "error"
                return result
            except Exception as e:
                status = "error"
                result = str(e)
                raise
            finally:
                duration = time.perf_counter() - start_time
                _finalize_span(
                    tool_func,
                    bound_args,
                    result,
                    status,
                    start_dt,
                    duration,
                    prior_skills,
                    prior_schemas,
                )

        async_wrapper._is_adk_instrumented = True  # type: ignore[attr-defined]
        return async_wrapper

    @functools.wraps(tool_func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        start_dt = datetime.now(timezone.utc)
        status = "success"
        result = None
        sid = current_session_id.get()
        prior_skills = TELEMETRY_RECORDER.get_activated_skills(sid)
        prior_schemas = TELEMETRY_RECORDER.get_inspected_schemas(sid)
        bound_args = _extract_bound_arguments(tool_func, args, kwargs)
        try:
            result = tool_func(*args, **kwargs)
            if isinstance(result, str) and result.startswith("Error executing tool"):
                status = "error"
            return result
        except Exception as e:
            status = "error"
            result = str(e)
            raise
        finally:
            duration = time.perf_counter() - start_time
            _finalize_span(
                tool_func,
                bound_args,
                result,
                status,
                start_dt,
                duration,
                prior_skills,
                prior_schemas,
            )

    sync_wrapper._is_adk_instrumented = True  # type: ignore[attr-defined]
    return sync_wrapper


def get_run_metrics() -> str:
    """Returns a summary of the execution metrics for the current session."""
    sid = current_session_id.get()
    session_spans = TELEMETRY_RECORDER.get_session_spans(sid)
    spans = (
        session_spans
        if session_spans or sid != "default-session"
        else RUN_METRICS[-50:]
    )
    compact_spans = [
        {
            "timestamp": s.get("timestamp"),
            "tool_name": s.get("effective_tool_name") or s.get("tool_name"),
            "duration_seconds": s.get("duration_seconds"),
            "status": s.get("status"),
            "estimated_tokens_in": s.get("estimated_tokens_in"),
            "estimated_tokens_out": s.get("estimated_tokens_out"),
            "total_estimated_tokens": s.get("total_estimated_tokens"),
        }
        for s in spans[-50:]
    ]
    return json.dumps(compact_spans, indent=2, default=str)
