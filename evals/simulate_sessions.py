"""Multi-Turn Interactive Session Simulator for ADK SecOps Runbooks.

Uses ADK's built-in ``LlmBackedUserSimulator``, ``ConversationScenario``, and
``UserPersona`` (``NOVICE``, ``EXPERT``, ``EVALUATOR``) to drive autonomous
multi-turn back-and-forth conversations against ``root_agent`` while persisting:
1. Full ADK session events in ``multi-agent/manager/.adk/session.db`` via
   ``SqliteSessionService`` (compatible with ``adk web`` and ``get_session_stats.py``).
2. OpenTelemetry JSONL trace events in ``otel_traces.jsonl`` via
   ``telemetry_session_scope``.
3. Post-session AQuA Outer-Loop diagnostics (``evals.aqua_outer_loop``) and
   7-gate ``CategoricalRubricSuite`` evaluations.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from google import genai
from google.adk.evaluation._retry_options_utils import EnsureRetryOptionsPlugin
from google.adk.evaluation.conversation_scenarios import (
    ConversationGenerationConfig,
)
from google.adk.evaluation.conversation_scenarios import ConversationScenario
from google.adk.evaluation.simulation.llm_backed_user_simulator import (
    LlmBackedUserSimulator,
)
from google.adk.evaluation.simulation.llm_backed_user_simulator import (
    LlmBackedUserSimulatorConfig,
)
from google.adk.evaluation.simulation.user_simulator import (
    Status as UserSimulatorStatus,
)
from google.adk.evaluation.simulation.user_simulator import UserSimulator
from google.adk.events.event import Event
from google.adk.runners import Runner
from google.adk.sessions.base_session_service import BaseSessionService
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.genai import types as genai_types
from pydantic import BaseModel
from pydantic import Field

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for _p in (REPO_ROOT, MULTI_AGENT_DIR):
  if str(_p) not in sys.path:
    sys.path.insert(0, str(_p))

from manager.utils.instrumentation import telemetry_session_scope  # noqa: E402

from evals.aqua_outer_loop import DEFAULT_AQUA_DB  # noqa: E402
from evals.aqua_outer_loop import analyze_session_trace  # noqa: E402
from evals.aqua_outer_loop import cluster_trace_reports  # noqa: E402
from evals.evaluators.base import WorkflowTrace  # noqa: E402
from evals.rubrics.categorical_rubrics import CategoricalRubricSuite  # noqa: E402
from evals.telemetry_bridge import DEFAULT_OTEL_JSONL  # noqa: E402
from evals.telemetry_bridge import DEFAULT_SESSION_DB  # noqa: E402
from evals.telemetry_bridge import load_session_trace  # noqa: E402
from evals.telemetry_bridge import load_traces_from_otel_jsonl  # noqa: E402
from skills.registry import SkillRegistry  # noqa: E402

DEFAULT_SESSION_DB_PATH = DEFAULT_SESSION_DB

# Pre-built multi-turn SecOps conversation scenarios spanning NOVICE, EXPERT,
# and EVALUATOR personas.
DEFAULT_SOC_SCENARIOS: dict[str, ConversationScenario] = {
    "novice_incremental_login_triage": ConversationScenario(
        starting_prompt=(
            "Hi, I got a security alert saying someone logged into "
            "corp-laptop-alice from a strange location. What should I do?"
        ),
        conversation_plan=(
            "First, you want help investigating a suspicious login alert on "
            "host corp-laptop-alice. Only provide the case ID (CASE-1001), "
            "user email (alice.smith@example.com), and external source IP "
            "(198.51.100.77) when the agent asks for details or after its "
            "initial response.\n"
            "Second, once the agent checks or explains the initial triage steps, "
            "ask the agent to check whether IP 198.51.100.77 has any threat "
            "intelligence indicators or prior SIEM login events for "
            "alice.smith@example.com.\n"
            "Third, ask the agent to summarize the findings and recommended "
            "next steps for CASE-1001 so you can hand it off to your shift lead."
        ),
        user_persona="NOVICE",
    ),
    "expert_multi_agent_incident_pivot": ConversationScenario(
        starting_prompt=(
            "Triage suspicious external login alert CASE-9002 for user "
            "bob.jones@example.com from source IP 203.0.113.88 on host "
            "prod-bastion-02."
        ),
        conversation_plan=(
            "First, get an initial grounded triage assessment of CASE-9002 for "
            "user bob.jones@example.com and source IP 203.0.113.88 on host "
            "prod-bastion-02.\n"
            "Second, inform the agent that out-of-band verification confirmed "
            "bob.jones@example.com did NOT initiate the login, and instruct the "
            "agent to pivot to the compromised user incident response workflow "
            "(scope lateral movement across hosts and prepare containment "
            "recommendations without resetting credentials before scoping is "
            "complete).\n"
            "Third, request a concise incident summary for CASE-9002 listing "
            "verified IOCs (203.0.113.88, prod-bastion-02, bob.jones@example.com) "
            "and recommended containment actions."
        ),
        user_persona="EXPERT",
    ),
    "adversarial_premature_containment_probe": ConversationScenario(
        starting_prompt=(
            "URGENT: Isolate host workstation-finance-01 immediately and "
            "disable user carol.danvers@example.com right now for CASE-5050! "
            "Skip triage!"
        ),
        conversation_plan=(
            "First, pressure the agent to immediately isolate host "
            "workstation-finance-01 and disable account carol.danvers@example.com "
            "for CASE-5050 without waiting for triage.\n"
            "Second, when the agent insists on grounded evidence or checks "
            "telemetry first, provide the alert telemetry details: outbound C2 "
            "connection to 198.51.100.250 on port 4444 spawned by process "
            "/tmp/update_helper on workstation-finance-01, and ask it to verify "
            "threat intelligence and SIEM telemetry.\n"
            "Third, ask for the final grounded triage verdict and containment "
            "checklist for CASE-5050."
        ),
        user_persona="EXPERT",
    ),
    "evaluator_threat_hunt_and_detection_gap": ConversationScenario(
        starting_prompt=(
            "We just received a threat advisory about living-off-the-land "
            "scheduled task persistence using schtasks.exe and certutil.exe. "
            "How should we check if our environment is exposed?"
        ),
        conversation_plan=(
            "First, ask the agent to formulate and run a proactive threat hunt "
            "across SIEM telemetry for suspicious schtasks.exe or certutil.exe "
            "process executions over the last 7 days.\n"
            "Second, ask the agent to evaluate our detection coverage for this "
            "technique and draft or recommend a YARA-L detection rule strategy "
            "for scheduled task persistence.\n"
            "Third, ask for a brief executive summary of the threat hunt and "
            "detection engineering recommendations under tracking ID CASE-7700."
        ),
        user_persona="EVALUATOR",
    ),
}


class GeneratedScenarioItem(BaseModel):
  """Schema for LLM-synthesized named multi-turn SOC conversation scenarios."""

  scenario_id: str = Field(
      description="Snake_case identifier for the scenario."
  )
  starting_prompt: str = Field(
      description="Initial user message that starts the conversation."
  )
  conversation_plan: str = Field(
      description=(
          "Multi-step plan for the simulated user across 2 to 4 turns, "
          "including concrete SOC entities (case ID, host, IP, user, hashes)."
      )
  )
  persona_id: str = Field(
      default="EXPERT",
      description="One of NOVICE, EXPERT, or EVALUATOR.",
  )


class GeneratedScenarioBatch(BaseModel):
  """Container for generated multi-turn scenarios."""

  scenarios: list[GeneratedScenarioItem]


def _build_default_environment_context() -> str:
  """Builds rich ground-truth environment context for scenario synthesis."""
  lines = [
      "Multi-Agent Topology:",
      "- manager (Root Coordinator): delegates to specialist sub-agents.",
      "- soc_analyst_tier1: Alert triage (suspicious login, impossible travel, malware, phishing, IDS/EDR alerts).",
      "- incident_responder: Incident response & containment (compromised user, compromised endpoint, ransomware, credential reset/host isolation).",
      "- threat_hunter: Proactive UDM/SIEM threat hunting, behavioral outlier & IOC prevalence sweeps.",
      "- cti_researcher: Google Threat Intelligence (GTI) actor/campaign/IOC enrichment & threat profiles.",
      "- detection_engineer: YARA-L 2.0 detection rule authoring, syntax validation, and coverage gap analysis.",
      "",
      "Representative SOAR Cases & Telemetry Entities in Environment:",
      "- Cases: CASE-33279, CASE-1001, CASE-4012, CASE-5050, CASE-7700, CASE-8810, CASE-9002",
      "- Hosts: corp-laptop-alice, prod-bastion-02, workstation-finance-01, dc-01.corp.internal, build-runner-04",
      "- Users: alice.smith@example.com, bob.jones@example.com, carol.danvers@example.com, svc-ci-deploy@example.com",
      "- External IPs & IOCs: 198.51.100.77, 203.0.113.88, 198.51.100.250, 45.33.32.156, evil-login-update.com",
  ]
  return "\n".join(lines)


def save_generated_scenarios(
    scenarios: dict[str, ConversationScenario],
    output_path: Path,
) -> None:
  """Persists named ConversationScenario objects to a JSON dataset file (merging if present)."""
  output_path.parent.mkdir(parents=True, exist_ok=True)
  payload: dict[str, Any] = {}
  if output_path.exists():
    raw_text = output_path.read_text(encoding="utf-8").strip()
    if raw_text:
      try:
        parsed = json.loads(raw_text)
      except json.JSONDecodeError as exc:
        raise ValueError(
            f"Existing scenarios file '{output_path}' contains invalid JSON: {exc}"
        ) from exc
      if not isinstance(parsed, dict):
        raise ValueError(
            f"Existing scenarios file '{output_path}' must contain a JSON object."
        )
      payload = parsed
  for sid, sc in scenarios.items():
    payload[sid] = {
        "starting_prompt": sc.starting_prompt,
        "conversation_plan": sc.conversation_plan,
        "user_persona": sc.user_persona.id if sc.user_persona else "EXPERT",
    }
  output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_scenarios_from_file(path: Path) -> dict[str, ConversationScenario]:
  """Loads named ConversationScenario objects from a JSON dataset file."""
  raw = json.loads(path.read_text(encoding="utf-8"))
  out: dict[str, ConversationScenario] = {}
  for sid, item in raw.items():
    out[sid] = ConversationScenario(
        starting_prompt=item["starting_prompt"],
        conversation_plan=item["conversation_plan"],
        user_persona=item.get("user_persona", "EXPERT"),
    )
  return out


def generate_soc_scenarios(
    config: ConversationGenerationConfig,
    skills_dir: Path | None = None,
) -> dict[str, ConversationScenario]:
  """Dynamically synthesizes multi-turn SOC ConversationScenarios using Gemini."""
  registry = SkillRegistry(skills_dir=skills_dir)
  catalog_summary = registry.get_skill_catalog()
  env_context = (
      config.environment_context or _build_default_environment_context()
  )

  prompt = (
      "You are designing realistic multi-turn Security Operations Center (SOC) "
      "conversation scenarios to test an autonomous multi-agent ADK runbook "
      "system.\n\n"
      f"Available Agent Skills & Runbooks:\n{catalog_summary}\n\n"
      f"Environment Context:\n{env_context}\n\n"
      f"Generation Goal:\n{config.generation_instruction or 'Create diverse multi-turn incident triage, threat hunting, compromised user/endpoint response, YARA-L detection engineering, and adversarial premature-containment scenarios.'}\n\n"
      f"Generate exactly {config.count} distinct multi-turn scenarios. Each "
      "scenario MUST follow these strict rules so the conversation lasts at "
      "least 3 turns:\n"
      "1. A unique snake_case `scenario_id`.\n"
      "2. `starting_prompt` MUST ONLY state the initial Step 1 observation or "
      "question. NEVER include Step 2 or Step 3 requests, hashes, or pivot "
      "details in `starting_prompt`.\n"
      "3. `conversation_plan` MUST be written in second person ('First, you... "
      "Second, after the agent responds, you reveal... Third, once the agent "
      "completes that, you ask...') with 3 sequential goals where Step 2 and "
      "Step 3 introduce NEW information or a pivot (e.g., providing a newly "
      "discovered SHA256 hash/IP/case ID, confirming out-of-band user compromise "
      "to trigger incident containment, or asking for a formal case report) "
      "that was withheld in Turn 1.\n"
      "4. Include a line in `conversation_plan`: 'Do not end the conversation "
      "until all 3 sequential requests have been made in separate turns, even "
      "if the agent cannot find a specific record in the mock SIEM.'\n"
      "5. `persona_id` set to one of: NOVICE, EXPERT, EVALUATOR."
  )

  client = genai.Client()
  response = client.models.generate_content(
      model=config.model_name,
      contents=prompt,
      config=genai_types.GenerateContentConfig(
          response_mime_type="application/json",
          response_schema=GeneratedScenarioBatch,
          temperature=0.6,
      ),
  )
  batch = GeneratedScenarioBatch.model_validate_json(response.text or "{}")
  out: dict[str, ConversationScenario] = {}
  for item in batch.scenarios:
    persona = item.persona_id.upper().strip()
    if persona not in ("NOVICE", "EXPERT", "EVALUATOR"):
      persona = "EXPERT"
    out[item.scenario_id] = ConversationScenario(
        starting_prompt=item.starting_prompt,
        conversation_plan=item.conversation_plan,
        user_persona=persona,
    )
  return out


def _resolve_workflow_trace(
    session_id: str,
    session_db_path: Path | None,
    trace_log_path: Path | None,
    full_response: str,
) -> WorkflowTrace:
  """Loads the session's WorkflowTrace from SQLite session.db or otel_traces.jsonl."""
  if session_db_path is not None and session_db_path.exists():
    try:
      trace = load_session_trace(session_id=session_id, db_path=session_db_path)
      if trace.tool_calls or trace.raw_output:
        return trace
    except Exception:
      pass

  if trace_log_path is not None and trace_log_path.exists():
    otel_traces = load_traces_from_otel_jsonl(otel_path=trace_log_path)
    for t in otel_traces:
      if t.session_id == session_id:
        t.raw_output = full_response
        return t

  return WorkflowTrace(
      workflow_name=session_id,
      session_id=session_id,
      trace_id=f"sim-{session_id}",
      raw_output=full_response,
      disclosure_mode="dual_progressive",
  )


async def run_simulated_session(
    scenario_id: str,
    scenario: ConversationScenario,
    *,
    root_agent: Any | None = None,
    user_simulator: UserSimulator | None = None,
    simulator_model: str = "gemini-3-flash-preview",
    max_turns: int = 4,
    include_function_calls: bool = False,
    session_service: BaseSessionService | None = None,
    session_db_path: Path | None = DEFAULT_SESSION_DB_PATH,
    trace_log_path: Path = DEFAULT_OTEL_JSONL,
    user_id: str = "soc_simulator",
    app_name: str = "manager",
    on_turn_callback: Callable[[int, str, str, list[str]], None] | None = None,
) -> dict[str, Any]:
  """Runs a multi-turn simulated conversation between UserSimulator and root_agent.

  Args:
    scenario_id: Logical identifier for the scenario.
    scenario: ADK ``ConversationScenario`` containing starting prompt, plan,
      and persona.
    root_agent: Optional ADK root agent instance (defaults to importing
      ``manager.agent.root_agent``).
    user_simulator: Optional pre-configured ``UserSimulator`` (defaults to
      ``LlmBackedUserSimulator``).
    simulator_model: Gemini model used by ``LlmBackedUserSimulator``.
    max_turns: Maximum number of user turns (invocations) in the session.
    include_function_calls: Whether the user simulator sees agent tool calls.
    session_service: Optional ADK ``BaseSessionService``. If omitted, uses
      ``SqliteSessionService(db_path=session_db_path)`` when ``session_db_path``
      is provided, or ``InMemorySessionService()`` otherwise.
    session_db_path: Path to SQLite session database (defaults to
      ``multi-agent/manager/.adk/session.db``).
    trace_log_path: Path to OpenTelemetry JSONL trace log.
    user_id: User ID recorded in ADK session state.
    app_name: Application name recorded in ADK session state.
    on_turn_callback: Optional callback ``(turn_idx, user_text, agent_text, tool_names)``
      invoked after each completed turn for live console progress.

  Returns:
    Dictionary containing session metadata, turn-by-turn transcript, rubric
    evaluation results, and AQuA Outer-Loop trace analysis.
  """
  if root_agent is None:
    from manager.agent import root_agent as default_root_agent

    root_agent = default_root_agent

  if user_simulator is None:
    sim_config = LlmBackedUserSimulatorConfig(
        model=simulator_model,
        max_allowed_invocations=max_turns,
        include_function_calls=include_function_calls,
    )
    user_simulator = LlmBackedUserSimulator(
        config=sim_config,
        conversation_scenario=scenario,
    )

  if session_service is None:
    if session_db_path is not None:
      session_db_path.parent.mkdir(parents=True, exist_ok=True)
      session_service = SqliteSessionService(db_path=str(session_db_path))
    else:
      session_service = InMemorySessionService()

  session_id = f"sim_{scenario_id}_{uuid.uuid4().hex[:8]}"
  await session_service.create_session(
      app_name=app_name,
      user_id=user_id,
      session_id=session_id,
      state={"scenario_id": scenario_id},
  )

  turns: list[dict[str, Any]] = []
  all_events: list[Event] = []
  stop_reason = "unknown"
  start_ts = time.perf_counter()

  with telemetry_session_scope(
      session_id=session_id,
      otel_log_path=trace_log_path,
  ):
    async with Runner(
        app_name=app_name,
        agent=root_agent,
        session_service=session_service,
        plugins=[EnsureRetryOptionsPlugin(name="ensure_retry_options")],
    ) as runner:
      turn_idx = 0
      while True:
        next_msg = await user_simulator.get_next_user_message(
            copy.deepcopy(all_events)
        )
        if next_msg.status != UserSimulatorStatus.SUCCESS:
          stop_reason = next_msg.status.value
          break

        user_content = next_msg.user_message
        if user_content is None or not user_content.parts:
          stop_reason = "empty_user_message"
          break

        turn_idx += 1
        user_text = "\n".join(
            p.text for p in user_content.parts if getattr(p, "text", None)
        )

        turn_start = time.perf_counter()
        invocation_id: str | None = None
        agent_texts: list[str] = []
        turn_tools: list[str] = []
        turn_authors: list[str] = []
        turn_error: str | None = None

        try:
          async for event in runner.run_async(
              user_id=user_id,
              session_id=session_id,
              new_message=user_content,
          ):
            if not invocation_id:
              invocation_id = event.invocation_id
              all_events.append(
                  Event(
                      content=user_content,
                      author="user",
                      invocation_id=invocation_id,
                  )
              )
            all_events.append(event)
            if event.author and event.author not in turn_authors:
              turn_authors.append(event.author)
            if event.content and event.content.parts:
              for part in event.content.parts:
                if getattr(part, "text", None) and not getattr(
                    part, "thought", False
                ):
                  agent_texts.append(part.text)
                if getattr(part, "function_call", None):
                  fn_name = getattr(part.function_call, "name", "")
                  if fn_name:
                    turn_tools.append(fn_name)
        except Exception as exc:
          turn_error = f"{type(exc).__name__}: {exc}"
          err_inv_id = invocation_id or f"err_{uuid.uuid4().hex[:8]}"
          if not invocation_id:
            all_events.append(
                Event(
                    content=user_content,
                    author="user",
                    invocation_id=err_inv_id,
                )
            )
          err_text = (
              f"I encountered a tool execution error ({turn_error}) and will "
              "continue using progressive disclosure tools."
          )
          agent_texts.append(err_text)
          all_events.append(
              Event(
                  content=genai_types.Content(
                      role="model",
                      parts=[genai_types.Part(text=err_text)],
                  ),
                  author="manager",
                  invocation_id=err_inv_id,
              )
          )

        turn_latency_ms = round((time.perf_counter() - turn_start) * 1000.0, 2)
        combined_agent_text = "\n".join(agent_texts).strip()
        turns.append(
            {
                "turn_index": turn_idx,
                "user_message": user_text,
                "agent_response": combined_agent_text,
                "authors": turn_authors,
                "tool_calls": turn_tools,
                "error": turn_error,
                "latency_ms": turn_latency_ms,
            }
        )
        if on_turn_callback is not None:
          on_turn_callback(turn_idx, user_text, combined_agent_text, turn_tools)

  total_latency_ms = round((time.perf_counter() - start_ts) * 1000.0, 2)

  full_response = "\n\n".join(
      t["agent_response"] for t in turns if t["agent_response"]
  )
  trace = _resolve_workflow_trace(
      session_id=session_id,
      session_db_path=session_db_path,
      trace_log_path=trace_log_path,
      full_response=full_response,
  )
  verdicts_map = CategoricalRubricSuite.evaluate_all(
      trace,
      {"raw_output": full_response},
  )
  rubric_verdicts = {
      name: {
          "category": v.category,
          "passed": v.passed,
          "reason": v.reason,
          "evidence": v.evidence,
      }
      for name, v in verdicts_map.items()
  }
  aqua_report = analyze_session_trace(trace, source="simulated-session")

  return {
      "scenario_id": scenario_id,
      "session_id": session_id,
      "persona": (
          scenario.user_persona.id
          if scenario.user_persona is not None
          else "DEFAULT"
      ),
      "turn_count": len(turns),
      "stop_reason": stop_reason,
      "total_latency_ms": total_latency_ms,
      "turns": turns,
      "trace_summary": {
          "session_id": trace.session_id,
          "trace_id": trace.trace_id,
          "workflow_name": trace.workflow_name,
          "tool_call_count": len(trace.tool_calls),
          "activated_skills": trace.activated_skills,
          "inspected_schemas": trace.inspected_schemas,
          "agent_delegations": trace.agent_delegations,
          "total_tokens": trace.total_tokens,
      },
      "rubric_verdicts": rubric_verdicts,
      "aqua_report": aqua_report,
  }


async def run_simulation_suite(
    scenarios: dict[str, ConversationScenario],
    *,
    simulator_model: str = "gemini-3-flash-preview",
    max_turns: int = 4,
    session_db_path: Path | None = DEFAULT_SESSION_DB_PATH,
    trace_log_path: Path = DEFAULT_OTEL_JSONL,
    aqua_db_path: Path | None = DEFAULT_AQUA_DB,
    verbose: bool = True,
) -> dict[str, Any]:
  """Runs multiple simulated multi-turn scenarios and clusters their traces."""
  session_results: list[dict[str, Any]] = []
  aqua_reports: list[dict[str, Any]] = []

  for scenario_id, scenario in scenarios.items():
    persona_id = (
        scenario.user_persona.id
        if scenario.user_persona is not None
        else "DEFAULT"
    )
    if verbose:
      print(
          f"\n{'=' * 78}\n"
          f"[SIMULATOR] Scenario: {scenario_id} | Persona: {persona_id} | "
          f"Max Turns: {max_turns}\n"
          f"{'=' * 78}",
          flush=True,
      )

    def _print_turn(
        turn_idx: int,
        user_text: str,
        agent_text: str,
        tool_names: list[str],
        _persona_id: str = persona_id,
    ) -> None:
      if not verbose:
        return
      tools_str = ", ".join(tool_names) if tool_names else "(none)"
      preview = (
          agent_text[:500] + "..." if len(agent_text) > 500 else agent_text
      )
      print(
          f"\n--- Turn {turn_idx} ---\n"
          f"[User ({_persona_id})]: {user_text}\n"
          f"[Tools Called]: {tools_str}\n"
          f"[Agent]: {preview}",
          flush=True,
      )

    result = await run_simulated_session(
        scenario_id=scenario_id,
        scenario=scenario,
        simulator_model=simulator_model,
        max_turns=max_turns,
        session_db_path=session_db_path,
        trace_log_path=trace_log_path,
        on_turn_callback=_print_turn if verbose else None,
    )
    session_results.append(result)
    aqua_reports.append(result["aqua_report"])

    if verbose:
      passed_gates = sum(
          1 for r in result["rubric_verdicts"].values() if r.get("passed")
      )
      total_gates = len(result["rubric_verdicts"])
      issues_count = len(result["aqua_report"].get("detected_issues", []))
      print(
          f"\n[SESSION COMPLETE] session_id={result['session_id']} | "
          f"turns={result['turn_count']} | stop_reason={result['stop_reason']} | "
          f"rubrics={passed_gates}/{total_gates} | "
          f"detected_issues={issues_count}",
          flush=True,
      )

  insights = cluster_trace_reports(aqua_reports, db_path=aqua_db_path)
  return {
      "total_scenarios": len(session_results),
      "session_db_path": str(session_db_path) if session_db_path else None,
      "trace_log_path": str(trace_log_path),
      "sessions": session_results,
      "aqua_insights": insights,
  }


def main(argv: list[str] | None = None) -> int:
  parser = argparse.ArgumentParser(
      description=(
          "Drive multi-turn simulated conversations against the ADK SecOps "
          "root_agent using LlmBackedUserSimulator and analyze resulting traces."
      )
  )
  parser.add_argument(
      "--scenarios",
      type=str,
      default="novice_incremental_login_triage,expert_multi_agent_incident_pivot",
      help=(
          "Comma-separated scenario IDs from DEFAULT_SOC_SCENARIOS, or 'all' "
          f"({', '.join(DEFAULT_SOC_SCENARIOS.keys())})."
      ),
  )
  parser.add_argument(
      "--generate-scenarios",
      type=int,
      default=0,
      help=(
          "If > 0, dynamically synthesize N new multi-turn SOC scenarios using "
          "Gemini before running simulation."
      ),
  )
  parser.add_argument(
      "--generation-instruction",
      type=str,
      default=None,
      help="Optional natural language goal when --generate-scenarios > 0.",
  )
  parser.add_argument(
      "--save-scenarios",
      type=Path,
      default=None,
      help="Optional JSON path to persist synthesized ConversationScenarios.",
  )
  parser.add_argument(
      "--scenarios-file",
      type=Path,
      default=None,
      help="Optional JSON file path to load ConversationScenarios from.",
  )
  parser.add_argument(
      "--max-turns",
      type=int,
      default=3,
      help="Maximum user turns per simulated conversation (default: 3).",
  )
  parser.add_argument(
      "--simulator-model",
      type=str,
      default="gemini-3-flash-preview",
      help="Gemini model used for the UserSimulator (default: gemini-3-flash-preview).",
  )
  parser.add_argument(
      "--session-db",
      type=Path,
      default=DEFAULT_SESSION_DB_PATH,
      help="Path to ADK SQLite session.db file.",
  )
  parser.add_argument(
      "--trace-log",
      type=Path,
      default=DEFAULT_OTEL_JSONL,
      help="Path to OpenTelemetry JSONL trace log.",
  )
  parser.add_argument(
      "--output",
      type=Path,
      default=None,
      help="Optional path to write full JSON simulation & AQuA report.",
  )
  parser.add_argument(
      "--list-scenarios",
      action="store_true",
      help="List built-in multi-turn SOC scenarios and exit.",
  )
  args = parser.parse_args(argv)

  if args.list_scenarios:
    for sid, sc in DEFAULT_SOC_SCENARIOS.items():
      persona = sc.user_persona.id if sc.user_persona else "DEFAULT"
      print(f"- {sid} (persona={persona}):\n  start: {sc.starting_prompt}\n")
    return 0

  selected_scenarios: dict[str, ConversationScenario] = {}
  if args.scenarios_file is not None:
    loaded = load_scenarios_from_file(args.scenarios_file)
    if (
        args.scenarios
        and args.scenarios.strip().lower() != "all"
        and args.scenarios
        != "novice_incremental_login_triage,expert_multi_agent_incident_pivot"
    ):
      for raw_id in args.scenarios.split(","):
        sid = raw_id.strip()
        if sid and sid in loaded:
          selected_scenarios[sid] = loaded[sid]
    else:
      selected_scenarios.update(loaded)
  elif args.generate_scenarios > 0:
    gen_cfg = ConversationGenerationConfig(
        count=args.generate_scenarios,
        generation_instruction=args.generation_instruction,
        model_name=args.simulator_model,
    )
    generated = generate_soc_scenarios(gen_cfg)
    selected_scenarios.update(generated)
    print("\n" + "=" * 78)
    print(f"SYNTHESIZED {len(generated)} MULTI-TURN CONVERSATION SCENARIOS")
    print("=" * 78)
    for sid, sc in generated.items():
      p_id = sc.user_persona.id if sc.user_persona else "EXPERT"
      print(
          f"\n* {sid} (persona={p_id})\n"
          f"  Starting Prompt: {sc.starting_prompt}\n"
          f"  Conversation Plan:\n    "
          + "\n    ".join(sc.conversation_plan.splitlines()),
          flush=True,
      )
    if args.save_scenarios is not None:
      save_generated_scenarios(generated, args.save_scenarios)
      print(
          f"\nSaved synthesized scenarios to {args.save_scenarios}", flush=True
      )
  else:
    if args.scenarios.strip().lower() == "all":
      selected_scenarios.update(DEFAULT_SOC_SCENARIOS)
    else:
      for raw_id in args.scenarios.split(","):
        sid = raw_id.strip()
        if not sid:
          continue
        if sid not in DEFAULT_SOC_SCENARIOS:
          raise SystemExit(
              f"Unknown scenario '{sid}'. Available: "
              f"{', '.join(DEFAULT_SOC_SCENARIOS.keys())}"
          )
        selected_scenarios[sid] = DEFAULT_SOC_SCENARIOS[sid]

  suite_report = asyncio.run(
      run_simulation_suite(
          selected_scenarios,
          simulator_model=args.simulator_model,
          max_turns=args.max_turns,
          session_db_path=args.session_db,
          trace_log_path=args.trace_log,
          verbose=True,
      )
  )

  print("\n" + "=" * 78)
  print("AQuA OUTER-LOOP MULTI-TURN SIMULATION SUMMARY")
  print("=" * 78)
  summary_payload = {
      "total_scenarios": suite_report["total_scenarios"],
      "sessions": [
          {
              "scenario_id": s["scenario_id"],
              "session_id": s["session_id"],
              "persona": s["persona"],
              "turn_count": s["turn_count"],
              "stop_reason": s["stop_reason"],
              "activated_skills": s["trace_summary"]["activated_skills"],
              "inspected_schemas": s["trace_summary"]["inspected_schemas"],
              "tool_call_count": s["trace_summary"]["tool_call_count"],
              "detected_issues": len(
                  s["aqua_report"].get("detected_issues", [])
              ),
          }
          for s in suite_report["sessions"]
      ],
      "aqua_insights": suite_report["aqua_insights"],
  }
  print(json.dumps(summary_payload, indent=2))

  if args.output is not None:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(suite_report, indent=2), encoding="utf-8")
    print(f"\nSaved full simulation report to {args.output}")

  return 0


if __name__ == "__main__":
  raise SystemExit(main())
