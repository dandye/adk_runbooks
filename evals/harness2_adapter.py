"""Harness2 BenchmarkAdapter and Vertex Gemini Proposer for ADK Runbooks.

Wraps the ADK Runbooks evaluation scenarios behind the `harness2` BenchmarkAdapter
interface so `harness2`'s Propose-Probe-Compose recursion and domain experience
library can evolve the agent's always-on prompts and on-demand skills.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

import yaml
from google import genai
from google.adk.agents import Agent
from google.adk.evaluation._retry_options_utils import EnsureRetryOptionsPlugin
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types as genai_types
from harness2.core import tree as harness_tree
from harness2.core.proposer import Proposer, ProposerError, Reply, _call_fingerprint, _drop_workspace
from harness2.core.spec import BenchPrompts, BenchSpec, ChannelSpec
from harness2.substrate.opencode import OPENCODE_SURFACE

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for _p in (str(REPO_ROOT), str(MULTI_AGENT_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from evals.datasets import load_dataset  # noqa: E402
from evals.evaluators.base import ToolCallRecord, WorkflowTrace  # noqa: E402
from evals.evaluators.rubric_evaluator import RubricEvaluator  # noqa: E402
from evals.registry import WORKFLOW_REGISTRY  # noqa: E402
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite  # noqa: E402
from manager.tools.mcp_registry import MCPToolRegistry  # noqa: E402
from manager.tools.offline_mcp_mocks import build_canonical_mcp_tools  # noqa: E402
from manager.tools.workflow_tools import get_all_workflow_tools  # noqa: E402
from skills.registry import SkillRegistry  # noqa: E402

COMMON_SUPPORTING_SKILLS = (
    "enrich-ioc",
    "find-relevant-soar-case",
    "document-in-soar",
    "generate-report-file",
    "report-writing-guidelines",
)

DEFAULT_SYSTEM_PROMPT = """You are a Security Operations Center (SOC) Analyst agent investigating security alerts and cases.
Your job is to gather grounded telemetry from SIEM, SOAR, and Threat Intelligence tools, reach a clear disposition, and produce a complete Markdown triage report.

Follow this operating procedure on every task:
1. Check the available skills and call `load_skill(skill_name)` first for the workflow that matches the request.
2. Before invoking any SIEM, SOAR, GTI, or workflow action via `execute_mcp_tool`, inspect its parameter schema at least once in the session with `get_mcp_tool_schema(tool_name=...)` or `search_mcp_tools(query=...)`.
3. Correlate entity context, threat intelligence reputation, and SIEM event history before stating a disposition or taking containment action.
4. Call `write_report(report_name, report_contents)` with a structured Markdown report summarizing the entities inspected, telemetry findings, disposition, and recommended next steps.
"""

DEFAULT_GUARDRAILS = """Standing rules:
- Never execute containment (isolating hosts, blocking IOCs, disabling accounts) without first verifying threat intelligence or SIEM telemetry.
- Never call SIEM, SOAR, GTI, or `run_*_workflow` tools directly as top-level functions; always inspect schemas with `get_mcp_tool_schema` and invoke via `execute_mcp_tool`.
- Ground every finding in tool outputs from the current session.

Skill triggers:
"""

DEFAULT_LONG_TERM_MEMORY = """- Progressive disclosure protocol: `load_skill` -> `get_mcp_tool_schema` -> `execute_mcp_tool`.
- Internal RFC1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are private corporate space; external routable IPs require Threat Intelligence checks.
"""

DEFAULT_TOOL_GUIDANCE = """# Tool Guidance

- `list_available_skills(category="")`: List on-demand skills available in the current harness.
- `load_skill(skill_name)`: Load step-by-step instructions for a skill before starting investigation.
- `search_mcp_tools(query="", server="")`: Search SIEM (`siem`), SOAR (`soar`), Threat Intelligence (`gti`), and workflow (`workflows`) tools by keyword.
- `get_mcp_tool_schema(tool_name)`: Inspect required arguments and JSON schema for a tool before calling `execute_mcp_tool`.
- `execute_mcp_tool(tool_name, arguments)`: Execute a registered MCP or workflow tool with a dictionary of arguments.
- `write_report(report_name, report_contents)`: Save the final Markdown triage report for the task.
"""

_JINJA_BRACES = re.compile(r"\{\{|\{%|\{#")
_ADK_TEMPLATE_VAR_RE = re.compile(r"\{+([^{}\n]*)\}+")
_ADK_STATE_PREFIXES = ("app:", "user:", "temp:")
_OFFLINE_ENV_LOCK = threading.Lock()
_OFFLINE_ENV_REFCOUNT = 0
_OFFLINE_ENV_PREV: str | None = None


def _is_valid_adk_state_name(var_name: str) -> bool:
    """Match google.adk.utils.instructions_utils._is_valid_state_name."""
    parts = var_name.split(":")
    if len(parts) == 1:
        return var_name.isidentifier()
    if len(parts) == 2 and f"{parts[0]}:" in _ADK_STATE_PREFIXES:
        return parts[1].isidentifier()
    return False


def _escape_adk_template_placeholders(text: str) -> str:
    """Replace ADK state/artifact `{VAR}` or `{{VAR}}` placeholders with `<VAR>`.

    Leaves MyST code fences (```` ```{mermaid} ````) and JSON literals
    (`{"ioc": "1.2.3.4"}`) intact while preventing ADK `inject_session_state`
    from treating prompt placeholders as missing session state keys.
    """
    if "{" not in text:
        return text

    def _replace(match: re.Match[str]) -> str:
        start = match.start()
        if start >= 3 and text[start - 3 : start] == "```":
            return match.group(0)
        raw_inner = match.group(1).strip()
        check_name = raw_inner[:-1] if raw_inner.endswith("?") else raw_inner
        if check_name.startswith("artifact.") or _is_valid_adk_state_name(check_name):
            return f"<{raw_inner}>"
        return match.group(0)

    cleaned = _ADK_TEMPLATE_VAR_RE.sub(_replace, text)
    return cleaned.replace("{{", "{").replace("}}", "}").replace("{%", "{").replace("{#", "{")


def _make_static_instruction_provider(instruction_text: str) -> Callable[[Any], str]:
    """Return an ADK InstructionProvider callable that bypasses session-state regex injection."""
    safe_text = _escape_adk_template_placeholders(instruction_text)

    def _provider(_ctx: Any) -> str:
        return safe_text

    return _provider


@contextlib.contextmanager
def _offline_mcp_mocks_env() -> Iterator[None]:
    """Thread-safe ref-counted guard keeping ADK_OFFLINE_MCP_MOCKS=1 across parallel rollouts."""
    global _OFFLINE_ENV_REFCOUNT, _OFFLINE_ENV_PREV
    with _OFFLINE_ENV_LOCK:
        if _OFFLINE_ENV_REFCOUNT == 0:
            _OFFLINE_ENV_PREV = os.environ.get("ADK_OFFLINE_MCP_MOCKS")
            os.environ["ADK_OFFLINE_MCP_MOCKS"] = "1"
        _OFFLINE_ENV_REFCOUNT += 1
    try:
        yield
    finally:
        with _OFFLINE_ENV_LOCK:
            _OFFLINE_ENV_REFCOUNT -= 1
            if _OFFLINE_ENV_REFCOUNT == 0:
                if _OFFLINE_ENV_PREV is None:
                    os.environ.pop("ADK_OFFLINE_MCP_MOCKS", None)
                else:
                    os.environ["ADK_OFFLINE_MCP_MOCKS"] = _OFFLINE_ENV_PREV


class AdkSubstrate:
    """ADK agent framework adapter exposing the OpenCode c1..c8 editable surface."""

    name = "adk"

    def surface(self) -> harness_tree.SurfaceSpec:
        return OPENCODE_SURFACE


def _prepare_skill_for_harness(skill_name: str, raw_md: str) -> str:
    """Normalize frontmatter, strip grading rubrics, and escape ADK template braces."""
    body = raw_md
    fm_data: dict[str, Any] = {}
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", raw_md, re.DOTALL)
    if match:
        try:
            loaded = yaml.safe_load(match.group(1))
            if isinstance(loaded, dict):
                fm_data = loaded
        except Exception:
            fm_data = {}
        body = match.group(2)

    body = re.split(r"\n##\s+Rubrics\b", body, maxsplit=1)[0].strip()
    body = _escape_adk_template_placeholders(body)

    desc = str(fm_data.get("description") or f"Workflow guidance for {skill_name}.").strip()
    desc = " ".join(desc.split())
    desc = _escape_adk_template_placeholders(desc)

    lines = [
        "---",
        f"name: {skill_name}",
        f"description: {desc}",
    ]
    if fm_data.get("category"):
        lines.append(f"category: {fm_data['category']}")
    raw_meta = fm_data.get("metadata")
    tools: list[str] = []
    if isinstance(raw_meta, dict) and isinstance(raw_meta.get("adk_additional_tools"), list):
        tools = [str(t) for t in raw_meta["adk_additional_tools"] if t]
    elif isinstance(fm_data.get("adk_additional_tools"), list):
        tools = [str(t) for t in fm_data["adk_additional_tools"] if t]
    if tools:
        lines.append("metadata:")
        lines.append("  adk_additional_tools:")
        for t in tools:
            lines.append(f"  - {t}")
    lines.append("---")
    lines.append("")
    lines.append(body)
    lines.append("")
    return "\n".join(lines)


class AdkRunbooksAdapter:
    """BenchmarkAdapter wrapping ADK Runbooks SOC scenarios for Harness2."""

    def __init__(
        self,
        runs_root: Path | str,
        *,
        dataset_name: str = "core_workflows",
        task_ids: Sequence[str] | None = None,
        solver_model: str = "gemini-3-flash-preview",
        improver_model: str = "gemini-3-flash-preview",
        skills_source_dir: Path | str | None = None,
        solver_fn: Callable[[str, Path, Path], tuple[str, str, dict[str, Any]]] | None = None,
    ):
        self.runs_root = Path(runs_root).resolve()
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.dataset_name = dataset_name
        self.solver_model = solver_model
        self.improver_model = improver_model
        self.skills_source_dir = Path(skills_source_dir or (REPO_ROOT / "skills")).resolve()
        self.solver_fn = solver_fn
        self.substrate = AdkSubstrate()
        self.execution_count = 0

        all_cases = load_dataset(dataset_name)
        if task_ids is not None:
            wanted = set(task_ids)
            all_cases = [c for c in all_cases if c.get("test_id") in wanted]
        if not all_cases:
            raise ValueError(f"No test cases matched in dataset {dataset_name!r} for task_ids={task_ids!r}")

        self._cases_by_id: dict[str, dict[str, Any]] = {
            str(c["test_id"]): dict(c) for c in all_cases
        }
        self._ordered_ids = [str(c["test_id"]) for c in all_cases]

        channel_model = improver_model if "/" in improver_model else f"vertex/{improver_model}"
        channel = ChannelSpec("opencode", channel_model, effort="high", steps=30, timeout=900)
        prompts = BenchPrompts(
            work=(
                "investigate Security Operations Center alerts and cases using SIEM, SOAR, "
                "and Threat Intelligence tools to produce grounded triage reports"
            ),
            domain_word="security operations",
            deliverable_word="triage report",
            inv_levers=(
                "Ensure progressive skill loading and tool schema checks happen before "
                "executing MCP or workflow tools."
            ),
            dom_levers=(
                "Ensure every disposition is grounded in entity context, threat intelligence "
                "reputation, and SIEM event history."
            ),
            yardstick=(
                "A thorough investigation loads the relevant skill first, inspects tool "
                "schemas before calling them, correlates user/host/IP telemetry, and writes "
                "a clear report with disposition and next steps."
            ),
        )
        self.spec = BenchSpec(
            name="adk_runbooks",
            runs_root=self.runs_root,
            install_mode="workspace_config",
            prompts=prompts,
            channels={"proposer": channel, "selector": channel},
            domain_word="security operations",
            allow_subagents=False,
        )

        self._base_dir = self.runs_root / "base_harness"
        self._build_base_harness()

    def _build_base_harness(self) -> None:
        source_registry = SkillRegistry(skills_dir=self.skills_source_dir)
        skill_names: set[str] = set(COMMON_SUPPORTING_SKILLS)
        for case in self._cases_by_id.values():
            wf_name = str(case.get("workflow_name") or "")
            wf_def = WORKFLOW_REGISTRY.get(wf_name)
            if wf_def and wf_def.skill_path:
                skill_names.add(Path(wf_def.skill_path).parent.name)
            ref = str(case.get("skill_reference") or case.get("runbook_reference") or "")
            if ref.endswith("SKILL.md"):
                skill_names.add(Path(ref).parent.name)

        base_tree: harness_tree.Tree = {
            "systemprompt.md": DEFAULT_SYSTEM_PROMPT,
            "guardrails.md": DEFAULT_GUARDRAILS,
            "LongTermMEMORY.md": DEFAULT_LONG_TERM_MEMORY,
            "tool_descriptions/tool_guidance.md": DEFAULT_TOOL_GUIDANCE,
        }
        for name in sorted(skill_names):
            meta = source_registry.get_skill(name)
            if meta is None or not meta.path.is_file():
                continue
            raw_md = meta.path.read_text(encoding="utf-8")
            # Normalize directory slug to match OPENCODE_SURFACE _NAME rule
            slug = re.sub(r"[^a-z0-9_\-]", "-", meta.name.lower()).strip("-")
            base_tree[f"skills/{slug}/SKILL.md"] = _prepare_skill_for_harness(slug, raw_md)

        harness_tree.autotrigger(OPENCODE_SURFACE, base_tree)
        harness_tree.validate(
            OPENCODE_SURFACE,
            base_tree,
            allow_subagents=self.spec.allow_subagents,
        )
        self.validate_tree(base_tree)
        harness_tree.write_tree(OPENCODE_SURFACE, base_tree, self._base_dir, stubs=False)

    def tasks(self, split: str = "all") -> list[str]:
        del split
        return list(self._ordered_ids)

    def domain_of(self, task_id: str) -> str:
        case = self._cases_by_id[task_id]
        return str(case.get("rubric_type") or "TRIAGE_IRP").strip().lower()

    def reference_domain_order(self) -> list[str]:
        domains = {self.domain_of(tid) for tid in self._ordered_ids}
        return sorted(domains)

    def task_prompt(self, task_id: str) -> str:
        case = self._cases_by_id[task_id]
        desc = str(case.get("description") or "Investigate the security alert and document findings.")
        wf_name = str(case.get("workflow_name") or "")
        inputs = dict(case.get("input") or {})
        input_lines = "\n".join(f"- {k}: {v}" for k, v in inputs.items())
        return (
            "Investigate the security incident below and produce a complete triage report "
            "and SOAR case summary.\n\n"
            f"Task: {desc}\n"
            f"Target workflow area: {wf_name}\n\n"
            "Incident Inputs:\n"
            f"{input_lines}\n\n"
            "Deliver a clear Markdown investigation report covering the entities inspected, "
            "enrichment findings, risk disposition, and recommended next steps."
        )

    def task_files(self, task_id: str) -> Path | None:
        del task_id
        return None

    def base_harness(self) -> Path:
        return self._base_dir

    def validate_tree(self, tree: harness_tree.Tree) -> None:
        errs: list[str] = []
        if not tree.get("systemprompt.md", "").strip():
            errs.append("systemprompt.md must not be empty")
        for rel in OPENCODE_SURFACE.always_on:
            text = tree.get(rel, "")
            m = _JINJA_BRACES.search(text)
            if m:
                errs.append(
                    f"{rel} contains Jinja template braces ({m.group(0)!r}); use single braces or words"
                )
        if errs:
            raise ValueError(" | ".join(errs))

    def execute(
        self, task_id: str, harness_dir: Path | None, run_id: str, *, timeout: int | None = None
    ) -> Path:
        run_dir = self.runs_root / "executions" / run_id
        if (
            (run_dir / "deliverable.md").is_file()
            and (run_dir / "trajectory.md").is_file()
            and (run_dir / "trace.json").is_file()
        ):
            return run_dir

        run_dir.mkdir(parents=True, exist_ok=True)
        active_harness = Path(harness_dir) if harness_dir is not None else self.base_harness()
        self.execution_count += 1

        if self.solver_fn is not None:
            deliverable, trajectory, trace_payload = self.solver_fn(task_id, active_harness, run_dir)
        else:
            deliverable, trajectory, trace_payload = asyncio.run(
                self._run_adk_rollout(task_id, active_harness, run_dir, timeout=timeout)
            )

        (run_dir / "deliverable.md").write_text(deliverable, encoding="utf-8")
        (run_dir / "trajectory.md").write_text(trajectory, encoding="utf-8")
        (run_dir / "trace.json").write_text(
            json.dumps(trace_payload, indent=2, default=str), encoding="utf-8"
        )
        return run_dir

    async def _run_adk_rollout(
        self, task_id: str, harness_dir: Path, run_dir: Path, *, timeout: int | None = None
    ) -> tuple[str, str, dict[str, Any]]:
        case = self._cases_by_id[task_id]
        wf_name = str(case.get("workflow_name") or "soc_triage")

        local_skill_registry = SkillRegistry(skills_dir=harness_dir / "skills")
        local_mcp_registry = MCPToolRegistry()
        for server in ("siem", "soar", "gti"):
            build_canonical_mcp_tools(server, local_mcp_registry)
        local_mcp_registry.register_mcp_toolset(get_all_workflow_tools(), server_name="workflows")

        trace = WorkflowTrace(
            workflow_name=wf_name,
            session_id=f"h2_{uuid.uuid4().hex[:8]}",
            disclosure_mode="dual_progressive",
            token_source="usage_metadata",
        )
        written_reports: list[str] = []
        tool_outputs: list[dict[str, Any]] = []
        reports_dir = run_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        turn_counter = 0

        def list_available_skills(category: str = "") -> str:
            """List available progressive disclosure skills in the current harness."""
            if category:
                items = local_skill_registry.list_skills_by_category(category)
                if not items:
                    return f"No skills found in category {category!r}."
                return "\n".join(f"- `{s.name}`: {s.description}" for s in items)
            return local_skill_registry.get_skill_catalog() or "No skills registered."

        def load_skill(skill_name: str) -> str:
            """Load full instructions for a skill from the current harness."""
            nonlocal turn_counter
            turn_counter += 1
            content = local_skill_registry.get_skill_content(skill_name)
            ok = not content.startswith("Error:")
            if ok:
                trace.activated_skills.append(skill_name)
            trace.tool_calls.append(
                ToolCallRecord(
                    turn_index=turn_counter,
                    agent_name="soc_analyst",
                    tool_name="load_skill",
                    args={"skill_name": skill_name},
                    status="success" if ok else "error",
                    error_message=None if ok else content,
                    result_summary=content[:240],
                    disclosure_skill_loaded=ok,
                    mcp_schema_inspected=len(trace.inspected_schemas) > 0,
                )
            )
            return content

        def search_mcp_tools(query: str = "", server: str = "") -> str:
            """Search available SIEM, SOAR, GTI, and workflow tools by keyword or server."""
            nonlocal turn_counter
            turn_counter += 1
            matches = local_mcp_registry.search_tools(query=query, server=server)
            trace.tool_calls.append(
                ToolCallRecord(
                    turn_index=turn_counter,
                    agent_name="soc_analyst",
                    tool_name="search_mcp_tools",
                    args={"query": query, "server": server},
                    status="success",
                    result_summary=f"matched {len(matches)} tools",
                    disclosure_skill_loaded=len(trace.activated_skills) > 0,
                    mcp_schema_inspected=True,
                )
            )
            if not matches:
                return "No MCP tools matched."
            return "\n".join(f"- `{t['name']}` ({t['server']}): {t['description']}" for t in matches)

        def get_mcp_tool_schema(tool_name: str) -> str:
            """Inspect the JSON schema and required parameters for an MCP or workflow tool."""
            nonlocal turn_counter
            turn_counter += 1
            schema = local_mcp_registry.get_tool_schema(tool_name)
            ok = schema is not None
            if ok:
                trace.inspected_schemas.append(tool_name)
            res = (
                json.dumps(schema, indent=2)
                if ok
                else f"Error: MCP tool {tool_name!r} not found. Call search_mcp_tools first."
            )
            trace.tool_calls.append(
                ToolCallRecord(
                    turn_index=turn_counter,
                    agent_name="soc_analyst",
                    tool_name="get_mcp_tool_schema",
                    args={"tool_name": tool_name},
                    status="success" if ok else "error",
                    error_message=None if ok else res,
                    result_summary=res[:240],
                    disclosure_skill_loaded=len(trace.activated_skills) > 0,
                    mcp_schema_inspected=ok,
                )
            )
            return res

        def execute_mcp_tool(tool_name: str, arguments: dict[str, Any] | str | None = None) -> str:
            """Execute a SIEM, SOAR, GTI, or workflow tool with arguments matching its schema."""
            nonlocal turn_counter
            turn_counter += 1
            parsed_args: dict[str, Any] = {}
            if isinstance(arguments, dict):
                parsed_args = dict(arguments)
            elif isinstance(arguments, str) and arguments.strip():
                try:
                    parsed_args = json.loads(arguments)
                except Exception as exc:
                    err = f"Error parsing arguments JSON: {exc}"
                    trace.tool_calls.append(
                        ToolCallRecord(
                            turn_index=turn_counter,
                            agent_name="soc_analyst",
                            tool_name="execute_mcp_tool",
                            args={"tool_name": tool_name, "arguments": arguments},
                            status="error",
                            error_message=err,
                            disclosure_skill_loaded=len(trace.activated_skills) > 0,
                            mcp_schema_inspected=tool_name in trace.inspected_schemas,
                        )
                    )
                    return err

            schema_checked = (
                tool_name in trace.inspected_schemas
                or any(tc.tool_name == "search_mcp_tools" for tc in trace.tool_calls)
            )
            try:
                raw_res = local_mcp_registry.execute_tool(tool_name, parsed_args)
                if inspect.iscoroutine(raw_res):
                    raw_res = asyncio.run(raw_res)
                out_str = (
                    raw_res
                    if isinstance(raw_res, str)
                    else json.dumps(raw_res, indent=2, default=str)
                )
                trace.executed_nodes.append(tool_name)
                tool_outputs.append(
                    {"tool_name": tool_name, "arguments": parsed_args, "output": raw_res}
                )
                trace.tool_calls.append(
                    ToolCallRecord(
                        turn_index=turn_counter,
                        agent_name="soc_analyst",
                        tool_name="execute_mcp_tool",
                        args={"tool_name": tool_name, "arguments": parsed_args},
                        status="success",
                        result_summary=out_str[:240],
                        disclosure_skill_loaded=len(trace.activated_skills) > 0,
                        mcp_schema_inspected=schema_checked,
                    )
                )
                return out_str
            except Exception as exc:
                err = f"Error executing {tool_name!r}: {exc}"
                trace.tool_calls.append(
                    ToolCallRecord(
                        turn_index=turn_counter,
                        agent_name="soc_analyst",
                        tool_name="execute_mcp_tool",
                        args={"tool_name": tool_name, "arguments": parsed_args},
                        status="error",
                        error_message=err,
                        result_summary=err[:240],
                        disclosure_skill_loaded=len(trace.activated_skills) > 0,
                        mcp_schema_inspected=schema_checked,
                    )
                )
                return err

        def write_report(report_name: str, report_contents: str) -> str:
            """Write the final Markdown triage report for the current incident."""
            nonlocal turn_counter
            turn_counter += 1
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", report_name.strip() or "triage_report")
            if not safe.endswith(".md"):
                safe += ".md"
            dest = reports_dir / safe
            dest.write_text(report_contents, encoding="utf-8")
            written_reports.append(report_contents)
            trace.tool_calls.append(
                ToolCallRecord(
                    turn_index=turn_counter,
                    agent_name="soc_analyst",
                    tool_name="write_report",
                    args={"report_name": report_name},
                    status="success",
                    result_summary=f"wrote {dest.name} ({len(report_contents)} chars)",
                    disclosure_skill_loaded=len(trace.activated_skills) > 0,
                    mcp_schema_inspected=len(trace.inspected_schemas) > 0,
                )
            )
            return json.dumps({"status": "saved", "path": str(dest.name), "chars": len(report_contents)})

        tools: list[Any] = [
            list_available_skills,
            load_skill,
            search_mcp_tools,
            get_mcp_tool_schema,
            execute_mcp_tool,
            write_report,
        ]

        scripts_dir = harness_dir / "scripts"
        if scripts_dir.is_dir() and any(scripts_dir.glob("*.py")):
            def run_harness_script(script_name: str, args_json: str = "[]") -> str:
                """Run a deterministic helper script from scripts/<script_name>.py."""
                safe_name = Path(script_name).name
                script_path = scripts_dir / safe_name
                if not script_path.is_file():
                    return f"Error: script {safe_name!r} not found in scripts/."
                try:
                    extra_args = [str(x) for x in json.loads(args_json or "[]")]
                except Exception as exc:
                    return f"Error parsing args_json: {exc}"
                proc = subprocess.run(
                    [sys.executable, str(script_path), *extra_args],
                    cwd=run_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                return proc.stdout if proc.returncode == 0 else f"rc={proc.returncode}: {proc.stderr}"

            tools.append(run_harness_script)

        always_on_parts = []
        for rel in OPENCODE_SURFACE.always_on:
            p = harness_dir / rel
            if p.is_file():
                txt = p.read_text(encoding="utf-8", errors="replace").strip()
                if txt:
                    always_on_parts.append(txt)

        catalog = local_skill_registry.get_skill_catalog()
        description = "SOC Analyst agent for alert triage and incident response."
        if catalog:
            description += "\n\n" + catalog

        agent = Agent(
            name="soc_analyst",
            model=self.solver_model,
            description=description,
            instruction=_make_static_instruction_provider("\n\n---\n\n".join(always_on_parts)),
            tools=tools,
        )

        session_service = InMemorySessionService()
        user_id = "harness2_eval"
        session_id = trace.session_id or f"s_{uuid.uuid4().hex[:8]}"
        await session_service.create_session(
            app_name="harness2_adk",
            user_id=user_id,
            session_id=session_id,
        )

        traj_lines: list[str] = []
        assistant_texts: list[str] = []
        tokens_in = 0
        tokens_out = 0
        start_ts = time.perf_counter()

        prompt_text = self.task_prompt(task_id)
        user_msg = genai_types.Content(
            role="user", parts=[genai_types.Part.from_text(text=prompt_text)]
        )

        with _offline_mcp_mocks_env():
            try:
                async with Runner(
                    app_name="harness2_adk",
                    agent=agent,
                    session_service=session_service,
                    plugins=[EnsureRetryOptionsPlugin(name="ensure_retry_options")],
                ) as runner:
                    async for event in runner.run_async(
                        user_id=user_id,
                        session_id=session_id,
                        new_message=user_msg,
                    ):
                        usage = getattr(event, "usage_metadata", None)
                        if usage is not None:
                            tokens_in += int(getattr(usage, "prompt_token_count", 0) or 0)
                            tokens_out += int(getattr(usage, "candidates_token_count", 0) or 0)

                        content = getattr(event, "content", None)
                        if not content or not content.parts:
                            continue
                        for part in content.parts:
                            if getattr(part, "thought", False):
                                thought_txt = (getattr(part, "text", None) or "").strip()
                                if thought_txt:
                                    traj_lines.append(f"[THINKING] {thought_txt[:2000]}")
                                continue
                            fc = getattr(part, "function_call", None)
                            if fc is not None:
                                args_str = json.dumps(dict(fc.args or {}), default=str)
                                traj_lines.append(f"[ACTION] {fc.name}({args_str[:400]})")
                            fr = getattr(part, "function_response", None)
                            if fr is not None:
                                resp_str = json.dumps(fr.response, default=str)
                                if "Error" in resp_str or "error" in resp_str.lower()[:60]:
                                    traj_lines.append(f"[OBSERVATION ERROR] {resp_str[:4000]}")
                                else:
                                    traj_lines.append(f"[OBSERVATION] {resp_str[:4000]}")
                            txt = getattr(part, "text", None)
                            if txt and txt.strip():
                                assistant_texts.append(txt.strip())
                                traj_lines.append(f"[ASSISTANT] {txt.strip()}")
            except Exception as exc:
                trace.status = "error"
                trace.error = f"{type(exc).__name__}: {exc}"
                traj_lines.append(f"[ERROR] {trace.error}")

        trace.duration_seconds = round(time.perf_counter() - start_ts, 3)
        trace.estimated_tokens_in = tokens_in
        trace.estimated_tokens_out = tokens_out
        trace.total_tokens = tokens_in + tokens_out

        deliverable = "\n\n".join(written_reports).strip()
        if not deliverable:
            deliverable = "\n\n".join(assistant_texts).strip()
        trace.raw_output = deliverable

        trajectory = "\n".join(traj_lines).strip() or "(no trajectory events recorded)"
        trace_payload = {
            "trace": asdict(trace),
            "tool_outputs": tool_outputs,
            "written_reports_count": len(written_reports),
        }
        return deliverable, trajectory, trace_payload

    def delivered(self, run_dir: Path) -> bool:
        p = Path(run_dir) / "deliverable.md"
        return p.is_file() and bool(p.read_text(encoding="utf-8", errors="replace").strip())

    def trajectory(self, run_dir: Path, *, obs_trunc: int) -> str:
        p = Path(run_dir) / "trajectory.md"
        if not p.is_file():
            return "(no trajectory file)"
        text = p.read_text(encoding="utf-8", errors="replace")
        if obs_trunc > 0 and len(text) > obs_trunc * 4:
            return text[: obs_trunc * 4]
        return text

    def deliverable_text(self, run_dir: Path) -> str:
        p = Path(run_dir) / "deliverable.md"
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

    def deliverable_files(self, run_dir: Path) -> dict[str, str]:
        text = self.deliverable_text(run_dir)
        return {"deliverable.md": text} if text.strip() else {}

    def score(self, run_dir: Path, task_id: str) -> dict[str, Any] | None:
        run_dir = Path(run_dir)
        trace_path = run_dir / "trace.json"
        if not trace_path.is_file():
            return None

        case = self._cases_by_id[task_id]
        wf_name = str(case.get("workflow_name") or "")
        min_score = float(case.get("min_passing_score") or 80.0)
        inputs = dict(case.get("input") or {})

        raw_payload = json.loads(trace_path.read_text(encoding="utf-8"))
        t_dict = dict(raw_payload.get("trace") or {})
        tool_calls = [ToolCallRecord(**tc) for tc in (t_dict.get("tool_calls") or [])]
        trace = WorkflowTrace(
            workflow_name=t_dict.get("workflow_name") or wf_name,
            executed_nodes=list(t_dict.get("executed_nodes") or []),
            route=t_dict.get("route"),
            duration_seconds=float(t_dict.get("duration_seconds") or 0.0),
            estimated_tokens_in=int(t_dict.get("estimated_tokens_in") or 0),
            estimated_tokens_out=int(t_dict.get("estimated_tokens_out") or 0),
            total_tokens=int(t_dict.get("total_tokens") or 0),
            status=str(t_dict.get("status") or "success"),
            raw_output=t_dict.get("raw_output"),
            error=t_dict.get("error"),
            session_id=t_dict.get("session_id"),
            disclosure_mode=str(t_dict.get("disclosure_mode") or "dual_progressive"),
            tool_calls=tool_calls,
            activated_skills=list(t_dict.get("activated_skills") or []),
            inspected_schemas=list(t_dict.get("inspected_schemas") or []),
        )

        deliverable = self.deliverable_text(run_dir)
        tool_outputs = list(raw_payload.get("tool_outputs") or [])
        output_dict = _build_scored_output_dict(deliverable, inputs, trace, tool_outputs)

        eval_res = RubricEvaluator.evaluate(
            test_id=task_id,
            workflow_name=wf_name,
            raw_output=output_dict,
            trace=trace,
            min_passing_score=min_score,
        )
        verdicts = CategoricalRubricSuite.evaluate_all(trace, output_dict)
        gates_passed = all(v.passed for v in verdicts.values() if not v.exclude_from_gate)

        return {
            "n_passed": int(round(eval_res.total_score)),
            "n_criteria": int(round(eval_res.max_score)),
            "all_pass": bool(eval_res.passed and gates_passed),
            "rubric_score": eval_res.total_score,
            "rubric_passed": eval_res.passed,
            "gates_passed": gates_passed,
            "category_scores": (
                dict(eval_res.scorecard.category_scores) if eval_res.scorecard else {}
            ),
            "feedback": list(eval_res.scorecard.feedback) if eval_res.scorecard else [],
            "categorical_verdicts": {
                k: {"category": v.category, "passed": v.passed, "reason": v.reason}
                for k, v in verdicts.items()
            },
            "tool_calls_count": len(trace.tool_calls),
            "activated_skills": list(trace.activated_skills),
            "inspected_schemas": list(trace.inspected_schemas),
            "total_tokens": trace.total_tokens,
            "duration_seconds": trace.duration_seconds,
        }


def _build_scored_output_dict(
    deliverable: str,
    inputs: dict[str, Any],
    trace: WorkflowTrace,
    tool_outputs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Extract grounded fields from the rollout's deliverable and tool calls for RubricEvaluator."""
    out: dict[str, Any] = {
        "report_markdown": deliverable,
        "soar_comment": deliverable,
        "has_sequence_diagram": (
            "sequenceDiagram" in deliverable or "```mermaid" in deliverable
        ),
        "execution_metadata": {
            "duration_seconds": trace.duration_seconds,
            "tool_calls": len(trace.tool_calls),
        },
    }

    haystack = deliverable + "\n" + json.dumps(tool_outputs, default=str)
    for key, val in inputs.items():
        if val is None or isinstance(val, bool):
            continue
        if isinstance(val, (str, int, float)) and str(val) in haystack:
            out[key] = val
        elif isinstance(val, list) and val and any(str(x) in haystack for x in val):
            out[key] = val

    low = deliverable.lower()
    for item in tool_outputs:
        tname = str(item.get("tool_name") or "").lower()
        targs = item.get("arguments") or {}
        if "post_case_comment" in tname and isinstance(targs, dict) and targs.get("comment"):
            out["soar_comment"] = str(targs["comment"])
        if any(k in tname for k in ("lookup", "search", "report", "enrich", "workflow", "case")):
            out["enrichment_summary"] = f"Grounded via {tname}"
        if any(k in tname for k in ("search", "hunt", "events", "query", "workflow")):
            out["search_summary"] = f"Executed {tname}"
        if any(k in tname for k in ("gti", "threat", "collection", "report", "ioc")):
            out["gti_summary"] = f"Correlated via {tname}"

    for word in (
        "escalate",
        "benign",
        "malicious",
        "suspicious",
        "high",
        "low",
        "isolate",
        "block",
        "close",
        "deploy_production",
    ):
        if word in low:
            out["verdict"] = word
            out["action_taken"] = word
            out["summary"] = deliverable[:300]
            break

    return out


class AdkGeminiProposer(Proposer):
    """Native Vertex AI Gemini Proposer with jailed context/ and context/harness/ tools."""

    def call(
        self,
        mission: str,
        context_dir: Path | str | None,
        label: str,
        *,
        system: str = "",
        timeout: int | None = None,
        max_attempts: int | None = None,
        harvest: str | None = None,
    ) -> Reply:
        cache_key = _call_fingerprint(label, mission, system, context_dir)
        cached = self._cached(label, cache_key, require_workspace=bool(harvest))
        if cached is not None:
            self._calls.append(cached)
            return cached

        tries = max(1, int(self.attempts if max_attempts is None else max_attempts))
        last = ""
        spent_usd = 0.0
        t0 = time.time()

        for attempt in range(1, tries + 1):
            if attempt > 1:
                time.sleep(2 * (attempt - 1))
            tmp = Path(tempfile.mkdtemp(prefix="harness2-adk-prop-"))
            try:
                if context_dir and Path(context_dir).is_dir():
                    shutil.copytree(context_dir, tmp / "context", dirs_exist_ok=True)
                text, cost, err = self._run_gemini_session(tmp, mission, system, harvest)
                spent_usd += cost
                if not text.strip():
                    last = err or "empty reply"
                    continue
                r = Reply(
                    label=label,
                    text=text,
                    ok=True,
                    cost_usd=spent_usd,
                    wall_s=round(time.time() - t0, 1),
                    attempts=attempt,
                    channel=self.spec.kind,
                )
                if harvest:
                    r.workspace = self._harvest(tmp, harvest, label, cache_key)
                    if r.workspace is None:
                        _drop_workspace(self._paths(label, cache_key))
                self._write_audit(r, mission, system, cache_key)
                self._calls.append(r)
                return r
            except Exception as exc:
                last = f"{type(exc).__name__}: {exc}"
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

        r = Reply(
            label=label,
            text="",
            ok=False,
            wall_s=round(time.time() - t0, 1),
            attempts=tries,
            channel=self.spec.kind,
            error=last,
            cost_usd=spent_usd,
        )
        self._calls.append(r)
        self._write_audit(r, mission, system, cache_key)
        raise ProposerError(
            f"[{label}] {self.spec.kind}/{self.spec.model}: {last}",
            attempts=tries,
            cost_usd=spent_usd,
        )

    def _run_gemini_session(
        self, tmp: Path, mission: str, system: str, harvest: str | None
    ) -> tuple[str, float, str]:
        project = (
            os.environ.get("GCP_PROJECT_ID")
            or os.environ.get("GOOGLE_CLOUD_PROJECT")
            or self.project
        )
        location = os.environ.get("GOOGLE_CLOUD_LOCATION") or self.region or "global"
        client = genai.Client(vertexai=True, project=project, location=location)

        raw_model = self.spec.model.strip()
        model_id = raw_model.split("/", 1)[1] if "/" in raw_model else raw_model

        ctx_root = (tmp / "context").resolve()
        harness_root = (ctx_root / "harness").resolve()
        can_edit = harvest == "context/harness"

        def _resolve_in_ctx(rel: str) -> Path:
            clean = rel.strip().lstrip("/")
            if clean.startswith("context/"):
                clean = clean[len("context/") :]
            target = (ctx_root / clean).resolve()
            if target != ctx_root and ctx_root not in target.parents:
                raise ValueError(f"path {rel!r} escapes context/")
            return target

        def _resolve_in_harness(rel: str) -> tuple[str, Path]:
            clean = rel.strip().lstrip("/")
            for prefix in ("context/harness/", "harness/"):
                if clean.startswith(prefix):
                    clean = clean[len(prefix) :]
            norm = harness_tree.normalize_rel(clean)
            if not harness_tree.is_allowed(OPENCODE_SURFACE, norm):
                raise ValueError(
                    f"path {norm!r} is off the editable surface. Allowed paths: "
                    f"{list(OPENCODE_SURFACE.always_on)}, skills/<name>/SKILL.md, "
                    "scripts/<name>.py, sub_agents/<name>/AGENT.md."
                )
            target = (harness_root / norm).resolve()
            if harness_root not in target.parents:
                raise ValueError(f"path {rel!r} escapes context/harness/")
            return norm, target

        def list_context_files(subdir: str = ".") -> str:
            try:
                base = _resolve_in_ctx(subdir)
                if not base.exists():
                    return f"No directory at {subdir!r}."
                if base.is_file():
                    return f"context/{base.relative_to(ctx_root)} ({base.stat().st_size} bytes)"
                rows = [
                    f"context/{p.relative_to(ctx_root)} ({p.stat().st_size} bytes)"
                    for p in sorted(base.rglob("*"))
                    if p.is_file() and "__pycache__" not in p.parts
                ]
                return "\n".join(rows) if rows else "(empty directory)"
            except Exception as exc:
                return f"Error: {exc}"

        def read_context_file(path: str) -> str:
            try:
                p = _resolve_in_ctx(path)
                if not p.is_file():
                    return f"Error: file {path!r} does not exist."
                return p.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                return f"Error: {exc}"

        def write_harness_file(path: str, content: str) -> str:
            try:
                norm, p = _resolve_in_harness(path)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
                return f"Wrote context/harness/{norm} ({len(content)} chars)."
            except Exception as exc:
                return f"Error: {exc}"

        def delete_harness_file(path: str) -> str:
            try:
                norm, p = _resolve_in_harness(path)
                if p.is_file():
                    p.unlink()
                    return f"Deleted context/harness/{norm}."
                return f"File context/harness/{norm} did not exist."
            except Exception as exc:
                return f"Error: {exc}"

        decls = [
            genai_types.FunctionDeclaration(
                name="list_context_files",
                description="List files inside context/ (or a subdirectory of context/).",
                parameters_json_schema={
                    "type": "object",
                    "properties": {
                        "subdir": {
                            "type": "string",
                            "description": "Subdirectory under context/, default '.'",
                        }
                    },
                },
            ),
            genai_types.FunctionDeclaration(
                name="read_context_file",
                description="Read a UTF-8 text file under context/.",
                parameters_json_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path inside context/, e.g. 'task.md' or 'rollouts/base1.md'",
                        }
                    },
                    "required": ["path"],
                },
            ),
        ]
        dispatch: dict[str, Callable[..., str]] = {
            "list_context_files": list_context_files,
            "read_context_file": read_context_file,
        }
        if can_edit:
            decls.extend(
                [
                    genai_types.FunctionDeclaration(
                        name="write_harness_file",
                        description="Create or replace a file on the editable surface under context/harness/.",
                        parameters_json_schema={
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Relative path under context/harness/, e.g. 'guardrails.md' or 'skills/suspicious-login-triage/SKILL.md'",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Full UTF-8 file contents to write.",
                                },
                            },
                            "required": ["path", "content"],
                        },
                    ),
                    genai_types.FunctionDeclaration(
                        name="delete_harness_file",
                        description="Delete a file under context/harness/.",
                        parameters_json_schema={
                            "type": "object",
                            "properties": {
                                "path": {
                                    "type": "string",
                                    "description": "Relative path under context/harness/ to delete.",
                                }
                            },
                            "required": ["path"],
                        },
                    ),
                ]
            )
            dispatch["write_harness_file"] = write_harness_file
            dispatch["delete_harness_file"] = delete_harness_file

        sys_text = (
            (f"{system.strip()}\n\n" if system.strip() else "")
            + "You are running in a workspace where `context/` contains the evidence files. "
            "Use `list_context_files` and `read_context_file` to inspect them"
            + (
                ", and use `write_harness_file` or `delete_harness_file` to edit `context/harness/` in place."
                if can_edit
                else "."
            )
        )

        contents: list[genai_types.Content] = [
            genai_types.Content(role="user", parts=[genai_types.Part.from_text(text=mission)])
        ]
        max_steps = max(4, min(int(self.spec.steps), 30))
        tokens_in = 0
        tokens_out = 0

        for step in range(max_steps):
            is_last = step == max_steps - 1
            active_tools = [] if is_last else [genai_types.Tool(function_declarations=decls)]
            if is_last:
                contents.append(
                    genai_types.Content(
                        role="user",
                        parts=[
                            genai_types.Part.from_text(
                                text="Tool budget reached. Now emit your final response in the exact format requested by the mission."
                            )
                        ],
                    )
                )

            resp = client.models.generate_content(
                model=model_id,
                contents=contents,
                config=genai_types.GenerateContentConfig(
                    system_instruction=sys_text,
                    tools=active_tools,
                    temperature=0.2,
                ),
            )
            if resp.usage_metadata:
                tokens_in += int(resp.usage_metadata.prompt_token_count or 0)
                tokens_out += int(resp.usage_metadata.candidates_token_count or 0)

            if not resp.candidates or not resp.candidates[0].content:
                return "", 0.0, "model returned no candidates"

            cand_content = resp.candidates[0].content
            contents.append(cand_content)

            fcs = [p.function_call for p in (cand_content.parts or []) if p.function_call]
            if not fcs:
                texts = [
                    p.text
                    for p in (cand_content.parts or [])
                    if getattr(p, "text", None) and not getattr(p, "thought", False)
                ]
                final_text = "\n".join(texts).strip()
                cost_usd = round((tokens_in * 0.15 + tokens_out * 0.60) / 1_000_000, 6)
                return final_text, cost_usd, ""

            resp_parts: list[genai_types.Part] = []
            for fc in fcs:
                fn = dispatch.get(fc.name)
                if fn is None:
                    result_str = f"Error: unknown tool {fc.name!r}"
                else:
                    try:
                        result_str = fn(**dict(fc.args or {}))
                    except Exception as exc:
                        result_str = f"Error calling {fc.name}: {exc}"
                resp_parts.append(
                    genai_types.Part.from_function_response(
                        name=fc.name,
                        response={"result": result_str},
                    )
                )
            contents.append(genai_types.Content(role="user", parts=resp_parts))

        return "", 0.0, f"exhausted {max_steps} tool turns without final text"
