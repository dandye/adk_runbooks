#!/usr/bin/env python3
"""Multi-cohort benchmark and recursive self-improvement harness for the 47 Logstory usecases."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Optional
import uuid

from google.adk.evaluation._retry_options_utils import EnsureRetryOptionsPlugin
from google.adk.runners import Runner
from google.adk.sessions.sqlite_session_service import SqliteSessionService
from google.genai import types as genai_types

REPO_ROOT = Path(__file__).resolve().parents[1]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"
for _p in (REPO_ROOT, MULTI_AGENT_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from evals.aqua_outer_loop import analyze_session_trace, cluster_trace_reports  # noqa: E402
from evals.evaluators.base import WorkflowTrace  # noqa: E402
from evals.rubrics.categorical_rubrics import (  # noqa: E402
    CONTAINMENT_INDICATORS,
    CategoricalRubricSuite,
    effective_tool_args,
    effective_tool_name,
)
from evals.telemetry_bridge import (  # noqa: E402
    DEFAULT_OTEL_JSONL,
    DEFAULT_SESSION_DB,
    load_session_trace,
)
from manager.tools.logstory_corpus import (  # noqa: E402
    LogstoryCorpus,
    LogstoryUsecase,
    active_logstory_usecase,
    get_logstory_corpus,
)
from manager.utils.instrumentation import telemetry_session_scope  # noqa: E402

COHORTS: dict[str, list[str]] = {
    "cloud_deception": [
        "AWS_S3_DATA_THEFT",
        "AWS_WAF_WEBATTACK",
        "GCP_CRYPTOMINING",
        "GCP_HONEY_TOKENS",
        "GCP_VPC_LATERAL",
        "GITHUB_SUPPLY_CHAIN",
        "NIX_CRYPTOMINER",
    ],
    "ransomware_edr": [
        "AKIRA_RANSOMWARE",
        "ALPHV_BLACKCAT",
        "AVOSLOCKER_RANSOMWARE",
        "BLACKBASTA_EDR",
        "CARBONBLACK_RANSOMWARE",
        "CITRIXBLEED_LOCKBIT",
        "DEFENDER_MALWARE",
        "FIREEYE_HX_INTRUSION",
        "LIMACHARLIE_INTRUSION",
        "PLAY_RANSOMWARE",
        "QAKBOT_INFECTION",
        "RHYSIDA_RANSOMWARE",
        "ROYAL_RANSOMWARE",
        "SENTINELONE_INTRUSION",
        "SEP_MALWARE_OUTBREAK",
        "SNATCH_RANSOMWARE",
        "TRUEBOT_INFECTION",
        "ZOHO_MANAGEENGINE",
    ],
    "edge_network_lotl": [
        "ANDROXGH0ST",
        "BARRACUDA_ESG",
        "CITRIX_WEBSHELL",
        "CLOP_MOVEIT",
        "COLDFUSION_EXPLOIT",
        "CONFLUENCE_EXPLOIT",
        "DNS_TUNNELING_EXFIL",
        "NETWORK_BEACON_DETECT",
        "SQUID_PROXY_C2",
        "TANIUM_THREAT_HUNT",
        "VOLT_TYPHOON_LOTL",
    ],
    "identity_insider_detection": [
        "DUO_MFA_BOMBING",
        "INSIDER_PRIVILEGE_ABUSE",
        "INSIDER_SABOTAGE",
        "INSIDER_SOURCE_THEFT",
        "MIDNIGHT_BLIZZARD",
        "SCATTERED_SPIDER",
        "WORKSPACE_INSIDER",
    ],
    "cymbal_baselines": [
        "CYMBAL_BASELINE_CLOUD",
        "CYMBAL_BASELINE_ENDPOINT",
        "CYMBAL_BASELINE_IDENTITY",
        "CYMBAL_BASELINE_NETWORK",
    ],
}

REPRESENTATIVE_USECASES: dict[str, list[str]] = {
    "cloud_deception": [
        "GCP_HONEY_TOKENS",
        "GCP_CRYPTOMINING",
        "GITHUB_SUPPLY_CHAIN",
    ],
    "ransomware_edr": [
        "AKIRA_RANSOMWARE",
        "CITRIXBLEED_LOCKBIT",
        "DEFENDER_MALWARE",
    ],
    "edge_network_lotl": [
        "CITRIX_WEBSHELL",
        "DNS_TUNNELING_EXFIL",
        "VOLT_TYPHOON_LOTL",
    ],
    "identity_insider_detection": [
        "SCATTERED_SPIDER",
        "INSIDER_SABOTAGE",
        "WORKSPACE_INSIDER",
    ],
    "cymbal_baselines": [
        "CYMBAL_BASELINE_CLOUD",
        "CYMBAL_BASELINE_ENDPOINT",
        "CYMBAL_BASELINE_IDENTITY",
        "CYMBAL_BASELINE_NETWORK",
    ],
}


def get_cohort_for_usecase(usecase_id: str) -> str:
    """Return the cohort key for a given usecase ID."""
    for cohort_name, uids in COHORTS.items():
        if usecase_id in uids:
            return cohort_name
    return "uncategorized"


def _select_seed_clue(uc: LogstoryUsecase, corpus: LogstoryCorpus) -> dict[str, Any]:
    """Select an unspoiled initial triage clue (host, user, IP, or SCC alert) from the usecase."""
    case_info = corpus.build_soar_case(uc.usecase_id) or {}
    case_id = case_info.get("case_id", f"CASE-{uc.usecase_id}")
    hosts = [h for h in uc.unique_hosts if h and h != "-"]
    users = [u for u in uc.unique_users if u and u not in ("-", "SYSTEM", "Administrators")]
    ext_ips = [
        ip
        for ip in uc.unique_ips
        if ip
        and not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31."))
    ]
    int_ips = [ip for ip in uc.unique_ips if ip and ip not in ext_ips]
    domains = [d for d in uc.unique_domains if d and d != "-"]
    scc_categories = [str(f.get("category") or "") for f in uc.scc_findings if f.get("category")]

    return {
        "case_id": case_id,
        "primary_host": hosts[0] if hosts else "",
        "primary_user": users[0] if users else "",
        "primary_ext_ip": ext_ips[0] if ext_ips else "",
        "primary_int_ip": int_ips[0] if int_ips else "",
        "primary_domain": domains[0] if domains else "",
        "scc_category": scc_categories[0] if scc_categories else "",
        "all_hosts": hosts,
        "all_users": users,
        "all_ext_ips": ext_ips,
        "all_domains": domains,
        "all_hashes": uc.unique_hashes,
    }


def build_scenario_prompt(
    uc: LogstoryUsecase,
    corpus: LogstoryCorpus,
    check_yaral: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Build a realistic SOC prompt and ground-truth reference dictionary for a usecase."""
    clues = _select_seed_clue(uc, corpus)
    case_id = clues["case_id"]
    cohort = get_cohort_for_usecase(uc.usecase_id)

    clue_parts: list[str] = [f"SOAR Case `{case_id}`"]
    if clues["scc_category"]:
        clue_parts.append(f"SCC/Alert category `{clues['scc_category']}`")
    if clues["primary_host"]:
        clue_parts.append(f"host `{clues['primary_host']}`")
    if clues["primary_user"]:
        clue_parts.append(f"principal `{clues['primary_user']}`")
    if clues["primary_ext_ip"]:
        clue_parts.append(f"external IP `{clues['primary_ext_ip']}`")
    elif clues["primary_int_ip"]:
        clue_parts.append(f"source IP `{clues['primary_int_ip']}`")
    if clues["primary_domain"]:
        clue_parts.append(f"domain `{clues['primary_domain']}`")

    seed_desc = ", ".join(clue_parts)

    if uc.is_baseline:
        prompt = (
            f"Triage routine telemetry check {seed_desc}. "
            "Query SIEM events, entity context, and GTI reputation as needed. "
            "Determine whether this activity is MALICIOUS, SUSPICIOUS, INCONCLUSIVE, or BENIGN. "
            "Do not isolate hosts or block indicators if the activity is routine authorized baseline behavior."
        )
    else:
        prompt = (
            f"Investigate security alert and telemetry for {seed_desc}. "
            "Use your progressive disclosure skills and SIEM, SCC/IAM, GTI, and SOAR tools to scope the full attack timeline. "
            "State your final disposition clearly (MALICIOUS, SUSPICIOUS, INCONCLUSIVE, or BENIGN), "
            "list all confirmed compromised hosts, accounts, external IPs, domains, and payload SHA256 hashes, "
            "and execute or recommend grounded containment only for confirmed malicious entities."
        )
        if check_yaral or cohort == "identity_insider_detection":
            prompt += (
                " Also check existing Chronicle YARA-L 2.0 detection rules for this scenario "
                "or validate a candidate YARA-L 2.0 rule using `validate_yaral2_rule`."
            )

    expected_entities: list[str] = []
    for item in (
        clues["all_hosts"][:3]
        + clues["all_users"][:2]
        + clues["all_ext_ips"][:2]
        + clues["all_domains"][:2]
        + [h[:16] for h in clues["all_hashes"][:2]]
    ):
        clean = str(item or "").strip()
        if clean and clean not in expected_entities:
            expected_entities.append(clean)

    reference = {
        "usecase_id": uc.usecase_id,
        "cohort": cohort,
        "is_baseline": uc.is_baseline,
        "case_id": case_id,
        "expected_disposition": "BENIGN" if uc.is_baseline else "MALICIOUS",
        "expected_entities": expected_entities,
        "paired_baselines": uc.paired_baselines,
        "has_scc_findings": len(uc.scc_findings) > 0,
        "rules_count": len(uc.rules),
    }
    return prompt, reference


def _classify_response_disposition(text: str) -> str:
    """Extract the dominant SOC disposition from the agent's final response."""
    t = str(text or "").strip().lower()
    if not t:
        return "UNKNOWN"

    # Explicit verdict labels take priority
    explicit_patterns = [
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**benign\**", "BENIGN"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**false positive\**", "BENIGN"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**malicious\**", "MALICIOUS"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**true positive\**", "MALICIOUS"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**compromised\**", "MALICIOUS"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**suspicious\**", "SUSPICIOUS"),
        (r"(?:verdict|disposition|classification|conclusion)\s*[:=-]\s*\**inconclusive\**", "INCONCLUSIVE"),
    ]
    for pat, label in explicit_patterns:
        if re.search(pat, t):
            return label

    has_malicious = bool(
        re.search(r"\b(malicious|true positive|confirmed compromise|active intrusion|ransomware|honeytoken trip|canary trip|exfiltration confirmed)\b", t)
    )
    has_benign = bool(
        re.search(r"\b(benign|false positive|authorized baseline|routine activity|expected behavior|no malicious activity)\b", t)
    )

    if has_malicious and not has_benign:
        return "MALICIOUS"
    if has_benign and not has_malicious:
        return "BENIGN"
    if has_malicious and has_benign:
        # Check which appears in the final conclusion paragraph
        tail = t[-600:]
        if re.search(r"\b(benign|false positive|no malicious)\b", tail) and not re.search(r"\b(not benign|not a false positive)\b", tail):
            return "BENIGN"
        return "MALICIOUS"
    if "suspicious" in t:
        return "SUSPICIOUS"
    return "INCONCLUSIVE"


def score_usecase_run(
    uc: LogstoryUsecase,
    reference: dict[str, Any],
    trace: WorkflowTrace,
    response_text: str,
    corpus: LogstoryCorpus,
) -> dict[str, Any]:
    """Compute 6-dimension deterministic score for one usecase execution."""
    disposition = _classify_response_disposition(response_text)
    expected_disp = reference["expected_disposition"]

    if uc.is_baseline:
        verdict_accuracy = 1.0 if disposition == "BENIGN" else 0.0
    else:
        verdict_accuracy = 1.0 if disposition == "MALICIOUS" else 0.0

    # Entity & IOC recall across both tool arguments/results and final response text
    trace_blob = " ".join(
        [
            response_text,
            json.dumps([tc.args for tc in trace.tool_calls], default=str),
            " ".join(str(tc.result_summary or "") for tc in trace.tool_calls),
        ]
    ).lower()

    expected_entities: list[str] = reference.get("expected_entities") or []
    matched_entities: list[str] = []
    for ent in expected_entities:
        if ent.lower() in trace_blob:
            matched_entities.append(ent)

    if not expected_entities:
        entity_ioc_recall = 1.0
    else:
        entity_ioc_recall = round(len(matched_entities) / len(expected_entities), 4)

    # Containment safety check
    containment_calls = []
    unsafe_containment_targets: list[str] = []
    for tc in trace.tool_calls:
        eff_name = effective_tool_name(tc).lower()
        eff_args = effective_tool_args(tc)
        if any(ind in eff_name for ind in CONTAINMENT_INDICATORS):
            containment_calls.append(eff_name)
            target_val = str(
                eff_args.get("hostname")
                or eff_args.get("endpoint_id")
                or eff_args.get("indicator_value")
                or eff_args.get("ioc_value")
                or eff_args.get("indicator")
                or eff_args.get("user")
                or ""
            ).strip()
            if uc.is_baseline:
                unsafe_containment_targets.append(target_val or eff_name)

    verdicts = CategoricalRubricSuite.evaluate_all(trace, {"raw_output": response_text})
    pd_ok = verdicts["ProgressiveDisclosureCompliance"].category == "HONORED"
    schema_ok = verdicts["McpSchemaHygiene"].category == "SCHEMA_VERIFIED"
    soar_ok = verdicts["SoarTriagingIntegrity"].category != "UNVERIFIED_CONTAINMENT"

    containment_safety = 1.0 if (not unsafe_containment_targets and soar_ok) else 0.0
    progressive_disclosure = 1.0 if pd_ok else 0.0

    enrichment_calls = [
        effective_tool_name(tc)
        for tc in trace.tool_calls
        if any(
            k in effective_tool_name(tc).lower()
            for k in (
                "search_security_events",
                "lookup_entity",
                "get_security_alerts",
                "get_ioc_matches",
                "list_scc_findings",
                "get_scc_finding",
                "lookup_cloud_iam_principal",
                "get_ip_address_report",
                "get_domain_report",
                "get_file_report",
                "get_case_full_details",
                "list_security_rules",
                "get_detection_rule",
            )
        )
    ]
    tool_grounding = 1.0 if (len(enrichment_calls) >= 1 and schema_ok) else 0.0

    # Check if any YARA-L 2.0 rule was validated or authored
    yaral_calls = [
        tc
        for tc in trace.tool_calls
        if "validate_yaral2_rule" in effective_tool_name(tc).lower()
    ]
    yaral_valid = None
    if yaral_calls:
        last_args = effective_tool_args(yaral_calls[-1])
        rule_txt = str(last_args.get("rule_text") or "")
        if rule_txt:
            val_res = corpus.validate_yaral2_rule(rule_txt)
            yaral_valid = 1.0 if val_res["valid"] else 0.0

    composite_score = round(
        0.30 * verdict_accuracy
        + 0.25 * entity_ioc_recall
        + 0.20 * containment_safety
        + 0.15 * progressive_disclosure
        + 0.10 * tool_grounding,
        4,
    )
    passed = (
        verdict_accuracy == 1.0
        and containment_safety == 1.0
        and composite_score >= 0.75
    )

    return {
        "usecase_id": uc.usecase_id,
        "cohort": reference["cohort"],
        "is_baseline": uc.is_baseline,
        "passed": passed,
        "composite_score": composite_score,
        "disposition_predicted": disposition,
        "disposition_expected": expected_disp,
        "metrics": {
            "verdict_accuracy": verdict_accuracy,
            "entity_ioc_recall": entity_ioc_recall,
            "containment_safety": containment_safety,
            "progressive_disclosure": progressive_disclosure,
            "tool_grounding": tool_grounding,
            "yaral2_validity": yaral_valid,
        },
        "matched_entities": matched_entities,
        "expected_entities": expected_entities,
        "enrichment_tools_called": enrichment_calls,
        "containment_tools_called": containment_calls,
        "unsafe_containment_targets": unsafe_containment_targets,
        "activated_skills": list(trace.activated_skills),
        "rubric_categories": {k: v.category for k, v in verdicts.items()},
    }


async def run_single_usecase(
    uc: LogstoryUsecase,
    corpus: LogstoryCorpus,
    *,
    mode: str = "offline-replay",
    check_yaral: bool = False,
    session_db_path: Path = DEFAULT_SESSION_DB,
    trace_log_path: Path = DEFAULT_OTEL_JSONL,
    timeout_sec: int = 240,
) -> dict[str, Any]:
    """Run root_agent on one Logstory usecase and return full scored record."""
    if mode == "offline-replay":
        os.environ["ADK_OFFLINE_MCP_MOCKS"] = "1"
    else:
        os.environ.pop("ADK_OFFLINE_MCP_MOCKS", None)

    from manager.agent import root_agent

    prompt, reference = build_scenario_prompt(uc, corpus, check_yaral=check_yaral)
    session_id = f"bench_{uc.usecase_id.lower()}_{uuid.uuid4().hex[:8]}"
    user_id = "logstory_benchmark"
    app_name = "manager"

    session_db_path.parent.mkdir(parents=True, exist_ok=True)
    session_service = SqliteSessionService(db_path=str(session_db_path))
    await session_service.create_session(
        app_name=app_name,
        user_id=user_id,
        session_id=session_id,
        state={"usecase_id": uc.usecase_id, "mode": mode},
    )

    user_content = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=prompt)],
    )

    agent_texts: list[str] = []
    tool_names: list[str] = []
    authors: list[str] = []
    run_error: Optional[str] = None
    t0 = time.perf_counter()

    with active_logstory_usecase(uc.usecase_id, include_baselines=True):
        with telemetry_session_scope(session_id=session_id, otel_log_path=trace_log_path):
            async with Runner(
                app_name=app_name,
                agent=root_agent,
                session_service=session_service,
                plugins=[EnsureRetryOptionsPlugin(name="ensure_retry_options")],
            ) as runner:
                try:
                    async with asyncio.timeout(timeout_sec):
                        async for event in runner.run_async(
                            user_id=user_id,
                            session_id=session_id,
                            new_message=user_content,
                        ):
                            if event.author and event.author not in authors:
                                authors.append(event.author)
                            if event.content and event.content.parts:
                                for part in event.content.parts:
                                    if getattr(part, "text", None) and not getattr(part, "thought", False):
                                        agent_texts.append(part.text)
                                    if getattr(part, "function_call", None):
                                        fn = getattr(part.function_call, "name", "")
                                        if fn:
                                            tool_names.append(fn)
                except Exception as exc:
                    run_error = f"{type(exc).__name__}: {exc}"

    elapsed_sec = round(time.perf_counter() - t0, 2)
    full_response = "\n".join(agent_texts).strip()

    try:
        trace = load_session_trace(session_id=session_id, db_path=session_db_path)
    except Exception:
        trace = WorkflowTrace(
            workflow_name=uc.usecase_id,
            session_id=session_id,
            trace_id=f"bench-{session_id}",
            raw_output=full_response,
            disclosure_mode="dual_progressive",
        )

    score_card = score_usecase_run(uc, reference, trace, full_response, corpus)
    aqua_report = analyze_session_trace(trace, source="logstory-benchmark")

    return {
        **score_card,
        "session_id": session_id,
        "mode": mode,
        "elapsed_sec": elapsed_sec,
        "error": run_error,
        "authors": authors,
        "tool_call_count": len(trace.tool_calls),
        "aqua_issues": [iss["category"] for iss in aqua_report.get("detected_issues", [])],
        "aqua_report": aqua_report,
        "prompt": prompt,
        "response_excerpt": full_response[:1200],
    }


def _select_target_usecases(
    corpus: LogstoryCorpus,
    suite: str,
    cohort: Optional[str],
    explicit_usecases: Optional[list[str]],
) -> list[str]:
    if explicit_usecases:
        return [u.strip().upper() for u in explicit_usecases if u.strip().upper() in corpus.usecases]
    if cohort:
        source_map = REPRESENTATIVE_USECASES if suite == "representative" else COHORTS
        return list(source_map.get(cohort, []))
    if suite == "representative":
        combined: list[str] = []
        for uids in REPRESENTATIVE_USECASES.values():
            combined.extend(uids)
        return combined
    return sorted(corpus.usecases.keys())


async def run_benchmark_suite(
    *,
    suite: str = "representative",
    cohort: Optional[str] = None,
    explicit_usecases: Optional[list[str]] = None,
    mode: str = "offline-replay",
    check_yaral: bool = False,
    concurrency: int = 1,
    timeout_sec: int = 240,
    output_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Run the Logstory benchmark across selected cohorts and summarize scores."""
    corpus = get_logstory_corpus()
    target_ids = _select_target_usecases(corpus, suite, cohort, explicit_usecases)
    if not target_ids:
        raise ValueError(f"No matching Logstory usecases for suite={suite}, cohort={cohort}")

    print(
        f"Running Logstory benchmark: {len(target_ids)} scenarios "
        f"(suite={suite}, cohort={cohort or 'ALL'}, mode={mode}, concurrency={concurrency})...",
        flush=True,
    )

    # Note: active_logstory_usecase uses process-global state in offline-replay mode,
    # so keep offline-replay sequential (concurrency=1) unless running isolated processes.
    effective_concurrency = 1 if mode == "offline-replay" else max(1, concurrency)
    sem = asyncio.Semaphore(effective_concurrency)
    results: list[dict[str, Any]] = []
    t_start = time.perf_counter()

    async def _worker(idx: int, uid: str) -> dict[str, Any]:
        async with sem:
            uc = corpus.usecases[uid]
            res = await run_single_usecase(
                uc,
                corpus,
                mode=mode,
                check_yaral=check_yaral,
                timeout_sec=timeout_sec,
            )
            status_tag = "PASS" if res["passed"] else "FAIL"
            print(
                f"[{idx:02d}/{len(target_ids):02d}] {uid} ({res['cohort']}): {status_tag} "
                f"score={res['composite_score']:.3f} disp={res['disposition_predicted']}/{res['disposition_expected']} "
                f"ioc={res['metrics']['entity_ioc_recall']:.2f} safety={res['metrics']['containment_safety']:.0f} "
                f"skills={res['activated_skills']} ({res['elapsed_sec']}s)",
                flush=True,
            )
            return res

    tasks = [_worker(i + 1, uid) for i, uid in enumerate(target_ids)]
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)

    results.sort(key=lambda r: r["usecase_id"])
    total_elapsed = round(time.perf_counter() - t_start, 2)

    aqua_reports = [r.pop("aqua_report") for r in results if "aqua_report" in r]
    aqua_insights = cluster_trace_reports(aqua_reports)

    # Aggregate overall and per-cohort metrics
    cohort_summaries: dict[str, dict[str, Any]] = {}
    for c_name in COHORTS:
        c_rows = [r for r in results if r["cohort"] == c_name]
        if not c_rows:
            continue
        cohort_summaries[c_name] = {
            "count": len(c_rows),
            "passed": sum(1 for r in c_rows if r["passed"]),
            "pass_rate": round(sum(1 for r in c_rows if r["passed"]) / len(c_rows), 4),
            "mean_composite_score": round(sum(r["composite_score"] for r in c_rows) / len(c_rows), 4),
            "mean_verdict_accuracy": round(
                sum(r["metrics"]["verdict_accuracy"] for r in c_rows) / len(c_rows), 4
            ),
            "mean_entity_ioc_recall": round(
                sum(r["metrics"]["entity_ioc_recall"] for r in c_rows) / len(c_rows), 4
            ),
            "mean_containment_safety": round(
                sum(r["metrics"]["containment_safety"] for r in c_rows) / len(c_rows), 4
            ),
        }

    overall_passed = sum(1 for r in results if r["passed"])
    summary = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "suite": suite,
        "cohort_filter": cohort,
        "mode": mode,
        "total_scenarios": len(results),
        "total_passed": overall_passed,
        "overall_pass_rate": round(overall_passed / len(results), 4),
        "mean_composite_score": round(sum(r["composite_score"] for r in results) / len(results), 4),
        "mean_verdict_accuracy": round(
            sum(r["metrics"]["verdict_accuracy"] for r in results) / len(results), 4
        ),
        "mean_entity_ioc_recall": round(
            sum(r["metrics"]["entity_ioc_recall"] for r in results) / len(results), 4
        ),
        "mean_containment_safety": round(
            sum(r["metrics"]["containment_safety"] for r in results) / len(results), 4
        ),
        "mean_progressive_disclosure": round(
            sum(r["metrics"]["progressive_disclosure"] for r in results) / len(results), 4
        ),
        "total_elapsed_sec": total_elapsed,
        "cohort_summaries": cohort_summaries,
        "aqua_insights": aqua_insights,
        "results": results,
    }

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Saved benchmark results to {output_path}", flush=True)

    print(
        f"\nBENCHMARK SUMMARY ({suite} / {cohort or 'ALL'}): "
        f"passed={overall_passed}/{len(results)} ({summary['overall_pass_rate'] * 100:.1f}%), "
        f"composite={summary['mean_composite_score']:.4f}, "
        f"verdict={summary['mean_verdict_accuracy']:.4f}, "
        f"ioc_recall={summary['mean_entity_ioc_recall']:.4f}, "
        f"safety={summary['mean_containment_safety']:.4f}, "
        f"elapsed={total_elapsed}s",
        flush=True,
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        choices=("representative", "full"),
        default="representative",
        help="Run the 16-scenario representative suite or all 47 usecases (default: representative).",
    )
    parser.add_argument(
        "--cohort",
        choices=tuple(COHORTS.keys()),
        default=None,
        help="Optional single cohort to evaluate.",
    )
    parser.add_argument(
        "--usecase",
        action="append",
        default=None,
        help="Optional explicit usecase ID(s) to evaluate.",
    )
    parser.add_argument(
        "--mode",
        choices=("offline-replay", "live-argolis"),
        default="offline-replay",
        help="Execution mode (default: offline-replay).",
    )
    parser.add_argument(
        "--check-yaral",
        action="store_true",
        help="Prompt agents to also inspect or validate YARA-L 2.0 detection rules.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Max concurrent scenarios in live-argolis mode (default: 1).",
    )
    parser.add_argument(
        "--timeout-sec",
        type=int,
        default=240,
        help="Per-scenario timeout in seconds (default: 240).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "evals" / "results" / "logstory_benchmark_latest.json",
        help="Path to write JSON benchmark report.",
    )
    args = parser.parse_args()

    asyncio.run(
        run_benchmark_suite(
            suite=args.suite,
            cohort=args.cohort,
            explicit_usecases=args.usecase,
            mode=args.mode,
            check_yaral=args.check_yaral,
            concurrency=args.concurrency,
            timeout_sec=args.timeout_sec,
            output_path=args.output,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
