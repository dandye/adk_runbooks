# Logstory Recursive Self-Improvement Report (47 Usecases)

## Executive Summary

Over 5 iterative hillclimbing cycles on `logstory__recursive-self-improvement`, we wired all 43 attack usecases and 4 enterprise noise baselines from `dandye/logstory_usecases` into `adk_runbooks` (both offline replay and live Argolis Chronicle via `chronicle/logstory`) and improved the multi-agent SOC runbook system to a **100.0% pass rate (47/47)** and **0.9871 mean composite score** across the full 47-usecase suite.

- **Representative Suite (16 scenarios, 5 cohorts)**: Improved from `14/16` (`87.5%`, `0.9042` composite, `0.8295` entity recall, `0.6250` progressive disclosure) in Iteration 0 to `16/16` (`100.0%`, `0.9918` composite, `0.9922` entity recall, `0.9375` progressive disclosure) in Iteration 3.
- **Full Suite (all 47 usecases)**: Achieved `47/47` (`100.0%` pass rate), `1.0000` verdict accuracy, `1.0000` containment safety, `0.9699` entity/IOC recall, `0.9787` progressive disclosure (`46/47`), and `0.9871` mean composite score (`40/47` scenarios at a perfect `1.0000`).
- **Live Argolis Validation (`dandye-0324-chronicle`)**: All 47 usecases were ingested via `logstory` (`47/47` event sets, `30/33` entity sets); live Argolis validation passed `3/3` scenarios (`GCP_HONEY_TOKENS`, `CITRIXBLEED_LOCKBIT`, `CYMBAL_BASELINE_CLOUD`) at `1.0000` composite.
- **Multi-Turn Adversarial Simulator (`LlmBackedUserSimulator`)**: Passed `4/4` 3-turn sessions with `0` AQuA issues, including refusing premature host isolation on benign `CYMBAL_BASELINE_ENDPOINT` (`CASE-4015`) under explicit urgency pressure (`"URGENT: Isolate host CYM-BKP01 immediately... cannot wait for triage!"`).

## Iteration Progression

| Iteration | Scope | Pass Rate | Composite | Verdict | Entity Recall | Safety | Progressive Disclosure | Key Change |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Iter 0 (Baseline)** | 16 Representative | 87.5% (14/16) | 0.9042 | 1.0000 | 0.8295 | 1.0000 | 0.6250 (10/16) | Frozen pre-improvement baseline (`6e0da23`) |
| **Iter 1** | 16 Representative | 100.0% (16/16) | 0.9687 | 1.0000 | 0.8747 | 1.0000 | 1.0000 (16/16) | Added `cloud-honeytoken-deception-triage`, compressed 3 core skills to `<= 350` words, enforced `load_skill`-first (`c2f26db`) |
| **Iter 2** | 16 Representative | 93.8% (15/16) | 0.9430 | 0.9375 | 0.9219 | 1.0000 | 0.9375 (15/16) | Wired `list_alerts_by_case`, `list_events_by_alert`, `get_url_report`; added `edge-appliance-webshell-hunt` & `dns-tunneling-network-beacon-hunt` (`06f8935`) |
| **Iter 3** | 16 Representative | 100.0% (16/16) | 0.9918 | 1.0000 | 0.9922 | 1.0000 | 0.9375 (15/16) | Normalized bare numeric case IDs on baselines, added `!=` negation & NL stop words, unescaped `\n` in `validate_yaral2_rule`, added `insider-threat-workspace-sabotage-triage` (`e147d48`) |
| **Iter 4a (Multi-Turn)** | 4 Adversarial Sessions | 100.0% (4/4) | 4/4 Rubrics | 1.0000 | 1.0000 | 1.0000 | 1.0000 (4/4) | Wired `logstory_usecase_id` into `simulate_sessions.py`; hardened `basic-endpoint-triage-isolation` (`305` words) & `incident_responder` pre-isolation gate (`2045307`) |
| **Iter 5 (Full 47 + Live)** | All 47 Usecases | 100.0% (47/47) | 0.9871 | 1.0000 | 0.9699 | 1.0000 | 0.9787 (46/47) | Scoped `get_run_metrics()` to active session (fixing 3.28 MB cross-session context overflow); verified live Argolis (`3/3` at `1.0000`) |

## Final 47-Usecase Cohort Breakdown (`evals/results/final_full_47.json`)

| Cohort | Scenarios | Passed | Pass Rate | Mean Composite | Verdict Accuracy | Entity Recall | Containment Safety |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `cloud_deception` | 7 | 7 | 100.0% | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| `ransomware_edr` | 18 | 18 | 100.0% | 0.9921 | 1.0000 | 0.9907 | 1.0000 |
| `edge_network_lotl` | 11 | 11 | 100.0% | 0.9712 | 1.0000 | 0.9394 | 1.0000 |
| `identity_insider_detection` | 7 | 7 | 100.0% | 0.9881 | 1.0000 | 0.9524 | 1.0000 |
| `cymbal_baselines` | 4 | 4 | 100.0% | 0.9844 | 1.0000 | 0.9375 | 1.0000 |
| **Total / Mean** | **47** | **47** | **100.0%** | **0.9871** | **1.0000** | **0.9699** | **1.0000** |

## Root Causes Discovered & Fixed Across Iterations

1. **Progressive Disclosure Bypasses (Iteration 0 -> Iteration 1)**:
   - In Iteration 0, 6 of 16 scenarios called `execute_mcp_tool` before `load_skill`.
   - Updating `manager` and all 7 specialist sub-agents to enforce `load_skill(skill_name)` before any `execute_mcp_tool` call lifted progressive disclosure from `0.6250` (`10/16`) to `1.0000` (`16/16`) on the representative suite and `0.9787` (`46/47`) on the full 47-usecase sweep.
2. **Cloud Honeytoken & Benign Baseline Entity Recall (Iteration 0 -> Iteration 1)**:
   - Agents initially summarized benign baselines (`CYMBAL_BASELINE_*`) as "routine activity" without enumerating observed hosts and accounts, and lacked a dedicated cloud deception runbook.
   - Adding `skills/triage/cloud-honeytoken-deception-triage/SKILL.md` (`349` words) and requiring full entity enumeration even on `BENIGN` closures lifted Cohort 1 (`cloud_deception`) and Cohort 5 (`cymbal_baselines`) to `1.0000` composite on the representative suite.
3. **Missing Alert/Event/URL Tool Coverage (Iteration 1 -> Iteration 2)**:
   - `soar-mcp_list_alerts_by_case`, `soar-mcp_list_events_by_alert`, and `gti-mcp_get_url_report` were missing in offline replay, causing partial IOC recall on edge appliance, DNS tunneling, and EDR alerts.
   - Wiring those 3 tools plus `edge-appliance-webshell-hunt` (`349` words) and `dns-tunneling-network-beacon-hunt` (`348` words) raised perfect-recall scenarios from `11/16` to `14/16`.
4. **Bare Numeric Case IDs, `!=` Query Negation, and Escaped YARA-L Newlines (Iteration 2 -> Iteration 3)**:
   - `CYMBAL_BASELINE_CLOUD` timed out in Iteration 2 when the agent passed `case_id="4014"` (without `"CASE-"`) and issued natural-language / negated `!=` queries that matched every event via `"all"` and `"events"`.
   - `DEFENDER_MALWARE` failed YARA-L validation when the LLM passed literal JSON-escaped `\n` and `\"` from `get_detection_rule` into `validate_yaral2_rule`.
   - Fixing bare numeric case ID normalization, `!=` negation + stop words, and `\n` unescaping lifted Iteration 3 to `16/16` (`0.9918` composite, `0.9922` entity recall).
5. **Adversarial Premature Host Isolation on Benign Baselines (Iteration 4a)**:
   - Multi-turn adversarial simulation (`cymbal_baseline_endpoint_premature_containment_probe`) exposed that `incident_responder` isolated `CYM-BKP01` on benign `CASE-4015` when urged to skip triage.
   - Compressing `basic-endpoint-triage-isolation` (`305` words) with a mandatory pre-isolation telemetry gate and updating `incident_responder` fixed the vulnerability (`3/3` turns, `0` AQuA issues).
6. **Cross-Session `RUN_METRICS` Context Overflow in Long Sweeps (Iteration 4b -> Iteration 5)**:
   - During the first full 47-usecase sweep, 3 late scenarios (`WORKSPACE_INSIDER`, `AVOSLOCKER_RANSOMWARE`, `AKIRA_RANSOMWARE`) hit Gemini's `1,048,576`-token input limit because `get_execution_metrics()` dumped the process-global `RUN_METRICS` list (`3.28 MB` accumulated across 40+ prior sessions).
   - Scoping `get_run_metrics()` in `multi-agent/manager/utils/instrumentation.py` to `current_session_id` (capped to 50 compact spans) eliminated the context overflow and lifted the full 47-usecase sweep from `44/47` (`93.6%`) to `47/47` (`100.0%`).

## New & Refactored Skills (All `<= 350` Words, `<= 50` Body Lines)

- **New Skills Added (4)**:
  - `skills/triage/cloud-honeytoken-deception-triage/SKILL.md` (`349` words)
  - `skills/hunting/edge-appliance-webshell-hunt/SKILL.md` (`349` words)
  - `skills/hunting/dns-tunneling-network-beacon-hunt/SKILL.md` (`348` words)
  - `skills/triage/insider-threat-workspace-sabotage-triage/SKILL.md` (`349` words)
- **Existing Skills Compressed & Hardened (8)**:
  - `skills/triage/triage-alerts/SKILL.md` (`339` words)
  - `skills/investigation/prioritize-and-investigate-case/SKILL.md` (`349` words)
  - `skills/investigation/case-event-timeline-analysis/SKILL.md` (`345` words)
  - `skills/irps/ransomware-response/SKILL.md` (`350` words)
  - `skills/triage/malware-triage/SKILL.md` (`337` words)
  - `skills/detection/detection-rule-validation-tuning/SKILL.md` (`341` words)
  - `skills/triage/suspicious-login-triage/SKILL.md` (`337` words)
  - `skills/triage/basic-endpoint-triage-isolation/SKILL.md` (`305` words)

## Verification Commands & Artifacts

- **Unit Tests**: `direnv exec . pytest tests/ evals/tests/ -q` (`104 passed, 71 subtests passed`).
- **Full 47-Usecase Benchmark**: `PYTHONPATH=".:multi-agent" direnv exec . python evals/run_logstory_benchmark.py --suite full --mode offline-replay --check-yaral --output evals/results/final_full_47.json`.
- **Live Argolis Benchmark**: `PYTHONPATH=".:multi-agent" direnv exec . python evals/run_logstory_benchmark.py --mode live-argolis --usecase GCP_HONEY_TOKENS --usecase CITRIXBLEED_LOCKBIT --usecase CYMBAL_BASELINE_CLOUD --check-yaral --output evals/results/iter5_live_argolis_validation.json`.
- **Multi-Turn Simulator**: `PYTHONPATH=".:multi-agent" direnv exec . python evals/simulate_sessions.py --scenarios-file evals/datasets/logstory_multi_turn_scenarios.json --max-turns 3`.
- **Decision Log**: `decisions.tsv` records all 7 milestones from worktree setup through Iteration 5.
