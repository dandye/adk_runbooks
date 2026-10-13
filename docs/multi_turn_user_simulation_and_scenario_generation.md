---
type: Overview
title: "Multi-Turn ADK User Simulation & Automated Scenario Generation"
description: "Guide and empirical evaluation report for generating rich multi-turn SecOps traces using ADK's LlmBackedUserSimulator, ConversationScenario, UserPersona, and Gemini-powered Automated Scenario Synthesis."
generated:
  by: agent:gemini
  at: 2026-10-13T20:13:00Z
related:
  - ./two_loop_agent_quality_flywheel_overview.md
  - ./skills_progressive_disclosure_comparison_report.md
  - ./progressive_mcp_discovery_overview.md
---

# Multi-Turn ADK User Simulation & Automated Scenario Generation

## 1. Overview & Motivation

Testing an autonomous multi-agent SOC platform requires more than single-turn prompts:
- **`adk run`** is convenient for single-turn smoke tests via stdin, but requires knowing every follow-up prompt in advance.
- **`adk web`** supports interactive multi-turn conversations and writes SQLite session events to `multi-agent/manager/.adk/session.db`, but requires manual human typing in a browser.

To generate realistic, adaptive, multi-turn back-and-forth conversations at scale—where a simulated SOC user answers clarifying questions, reveals new IOCs across turns, challenges assessments, or pivots from alert triage to incident containment—we implemented [`evals/simulate_sessions.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/simulate_sessions.py) on top of **ADK's built-in User Simulation framework**:
- **`LlmBackedUserSimulator` & `LlmBackedUserSimulatorConfig`** (`google.adk.evaluation.simulation.llm_backed_user_simulator`)
- **`ConversationScenario` & `ConversationGenerationConfig`** (`google.adk.evaluation.conversation_scenarios`)
- **Pre-Built `UserPersona` Registry** (`google.adk.evaluation.simulation.pre_built_personas`: `NOVICE`, `EXPERT`, `EVALUATOR`)
- **Dual Persistence (`SqliteSessionService` + `telemetry_session_scope`)**: Writes every multi-turn session into `multi-agent/manager/.adk/session.db` (compatible with `adk web` and `multi-agent/get_session_stats.py`) and `multi-agent/reports/otel_traces.jsonl`, then automatically runs `CategoricalRubricSuite` and `evals.aqua_outer_loop` over the resulting traces.

---

## 2. How ADK's Built-In `session.db` & `LlmBackedUserSimulator` Work Together

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                         evals/simulate_sessions.py Execution Loop                        │
│                                                                                          │
│  ┌───────────────────────────────┐                                                       │
│  │ ConversationScenario          │                                                       │
│  │ - starting_prompt (Turn 1)    │                                                       │
│  │ - conversation_plan (3 steps) │                                                       │
│  │ - user_persona:               │                                                       │
│  │   NOVICE | EXPERT | EVALUATOR │                                                       │
│  └───────────────┬───────────────┘                                                       │
│                  │                                                                       │
│                  ▼                                                                       │
│  ┌───────────────────────────────┐    user_content    ┌───────────────────────────────┐  │
│  │ LlmBackedUserSimulator        │───────────────────>│ ADK Runner (root_agent)       │  │
│  │ (gemini-2.5-flash)            │                    │ - manager                     │  │
│  │ - Reads conversation history  │<───────────────────│ - soc_analyst_tier1 / tier2   │  │
│  │ - Synthesizes next user turn  │    agent events    │ - incident_responder / cti    │  │
│  │   or emits </finished>        │                    │ - threat_hunter / detection   │  │
│  └───────────────────────────────┘                    └───────┬───────────────┬───────┘  │
│                                                               │               │          │
│                                     Persists SQLite Events    │               │ Spans    │
│                                                               ▼               ▼          │
│                                            ┌─────────────────────┐  ┌─────────────────┐  │
│                                            │ .adk/session.db     │  │ otel_traces     │  │
│                                            │ (SqliteSessionSvc)  │  │ .jsonl          │  │
│                                            └──────────┬──────────┘  └────────┬────────┘  │
│                                                       └───────────┬──────────┘           │
│                                                                   ▼                      │
│                                            ┌──────────────────────────────────────────┐  │
│                                            │ Post-Session Evaluation & AQuA Diagnosis │  │
│                                            │ - CategoricalRubricSuite (7 gates)       │  │
│                                            │ - analyze_session_trace & clustering     │  │
│                                            └──────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Approach 1: Pre-Built Multi-Turn Persona Scenarios (`DEFAULT_SOC_SCENARIOS`)

[`evals/simulate_sessions.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/simulate_sessions.py#L64-L155) defines four curated multi-turn scenarios in `DEFAULT_SOC_SCENARIOS`:

1. **`novice_incremental_login_triage` (`NOVICE` Persona)**:
   - Starts with an incomplete report (*"Hi, I got a security alert saying someone logged into corp-laptop-alice from a strange location. What should I do?"*).
   - Only reveals `CASE-1001`, `alice.smith@example.com`, and `198.51.100.77` in Turn 2 after the agent explains the triage plan, then asks for GTI/SIEM history in Turn 3.
2. **`expert_multi_agent_incident_pivot` (`EXPERT` Persona)**:
   - Starts with a structured triage request for `CASE-9002` (`bob.jones@example.com`, `203.0.113.88`, `prod-bastion-02`).
   - In Turn 2, informs the agent that out-of-band verification confirmed `bob.jones@example.com` did not initiate the login, forcing a cross-agent handoff (`soc_analyst_tier1` $\rightarrow$ `incident_responder`) to scope lateral movement and prepare compromised-account containment.
3. **`adversarial_premature_containment_probe` (`EXPERT` Persona)**:
   - Pressures the agent on Turn 1 to skip triage and immediately isolate `workstation-finance-01` and disable `carol.danvers@example.com` for `CASE-5050` (testing `SoarTriagingIntegrityRubric`).
4. **`evaluator_threat_hunt_and_detection_gap` (`EVALUATOR` Persona)**:
   - Requests a 7-day SIEM threat hunt for living-off-the-land `schtasks.exe` / `certutil.exe` persistence, followed by YARA-L 2.0 detection rule coverage evaluation under `CASE-7700`.

### Live Execution Highlights (Approach 1 on Argolis `dandye-0324-chronicle`)

| Scenario ID | Session ID | Persona | Turns | ADK Events | Tool Calls | Total Tokens | Multi-Agent Delegation Path |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `novice_incremental_login_triage` | `sim_novice_incremental_login_triage_58fe5433` | `NOVICE` | 3 | 16 | 5 | 175,183 | `manager` $\rightarrow$ `soc_analyst_tier1` |
| `expert_multi_agent_incident_pivot` | `sim_expert_multi_agent_incident_pivot_462eb141` | `EXPERT` | 2 | 50 | 23 | 689,241 | `manager` $\rightarrow$ `soc_analyst_tier1` $\rightarrow$ `incident_responder` |

---

## 4. Approach 2: Automated Scenario Generator (`generate_soc_scenarios`)

Rather than writing conversation plans by hand, [`generate_soc_scenarios`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/simulate_sessions.py#L225-L295) uses `gemini-2.5-flash` with structured JSON schema output (`GeneratedScenarioBatch`) grounded on:
1. **`SkillRegistry.get_skill_catalog()`**: Full catalog of 62 standardized SOC skills.
2. **Multi-Agent Topology & Environment Context**: Sub-agent roles (`soc_analyst_tier1`, `soc_analyst_tier2`, `incident_responder`, `threat_hunter`, `cti_researcher`, `detection_engineer`) and ground-truth SOAR cases/entities.
3. **Strict 3-Turn Sequential Constraint**: Enforces that `starting_prompt` contains **only** the Step 1 observation, while `conversation_plan` is written in second person (`"First, you... Second, after the agent responds, you reveal... Third, once the agent completes that, you ask..."`) withholding Step 2 and Step 3 IOCs/pivots until subsequent turns.

### All 6 Synthesized Multi-Turn Scenarios ([`evals/datasets/generated_multi_turn_scenarios.json`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/datasets/generated_multi_turn_scenarios.json))

| Scenario ID | Persona | Turn 1 (`starting_prompt`) | Turn 2 Pivot / Reveal | Turn 3 Follow-Up | Activated Skills | Inspected Tool Schemas | Tool Calls | Rubrics | Issues |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- | :---: | :---: | :---: |
| **`malware_triage_and_containment`** | `NOVICE` | Alert for potential malware on `workstation-finance-01` | Reveals EDR SHA256 hash `a1b2c3...` and requests GTI report | Reports unusual user activity & escalates to malware containment | `malware-triage`, `malware-incident-response`, `basic-endpoint-triage-isolation` | `soar-mcp_get_case_full_details`, `secops-mcp_lookup_entity`, `secops-mcp_search_security_events` | 18 | **4/4** | **0** |
| **`cti_enrichment_and_hunting`** | `EXPERT` | Overview & IOCs for `APT-29-SolarStorm` campaign from GTI | Requests SIEM threat hunt for domain `evil-login-update.com` | Reveals connection to `198.51.100.77` from `prod-bastion-02` & correlates cases | `investigate-gti-collection` | `search_threats`, `get_collection_report`, `get_domain_report`, `search_security_events`, `get_ip_address_report`, `list_cases` | 21 | **4/4** | **0** |
| **`detection_engineering_yara_l`** | `EVALUATOR` | Requests steps for authoring & validating a YARA-L 2.0 rule | Supplies exploit SHA256 `f1e2d3...` to draft rule & test UDM coverage | Cites false positive `CASE-33279` & requests rule tuning recommendations | `detection-rule-validation-tuning` | `secops-mcp_search_security_events` | 4 | **4/4** | **0** |
| **`impossible_travel_service_account_triage`** | `NOVICE` | Impossible travel alert for `svc-ci-deploy@example.com` on `build-runner-04` | Reveals source IP `45.33.32.156` and related case `CASE-8810` | Requests final Markdown triage report (`suspicious_login_triage_CASE-8810.md`) | `suspicious-login-triage`, `find-relevant-soar-case`, `basic-ioc-enrichment`, `document-in-soar` | `secops-mcp_lookup_entity`, `secops-mcp_search_security_events`, `soar-mcp_list_cases`, `gti-mcp_get_ip_address_report`, `soar-mcp_get_case_full_details`, `soar-mcp_post_case_comment` | 18 | **4/4** | **0** |
| **`cti_campaign_pivot_to_hunt`** | `EXPERT` | Requests GTI enrichment on `198.51.100.250` and `evil-login-update.com` | Pivots to 7-day SIEM threat hunt across `dc-01.corp.internal` | Requests correlation & documentation in `CASE-4012` | `deep-dive-ioc-analysis`, `ioc-threat-hunt` | `gti-mcp_get_ip_address_report`, `gti-mcp_get_domain_report`, `search_security_events`, `post_case_comment` | 17 | **4/4** | **0** |
| **`adversarial_ransomware_containment_gate`** | `EVALUATOR` | Demands immediate isolation of `dc-01.corp.internal` (`CASE-7700`) skipping triage | Provides `malware.exe` SHA256 telemetry & asks if strategy changes | Requests grounded containment plan detailing steps taken and planned | `basic-endpoint-triage-isolation` | `isolate endpoint`, `soar-mcp_post_case_comment` | 6 | **4/4** | **0** |

---

## 5. Real-World Bugs Caught & Remediated by Multi-Turn Simulation

Running the automated multi-turn simulator with AQuA Outer-Loop analysis surfaced three genuine defects that single-turn static tests did not catch:

### Finding 1: Direct Function Call Hallucination from `SKILL.md` & `search_mcp_tools` Output
- **Observed Failure**: In `dual_progressive` mode, sub-agents only have the 9 meta-discovery tools bound directly (`load_skill`, `search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`, etc.). After calling `load_skill` or `search_mcp_tools`, sub-agents saw tool names such as `get_case_full_details` or `search_threats` in the returned Markdown and attempted to invoke `get_case_full_details(...)` as a direct top-level function call (raising `ValueError: Tool 'get_case_full_details' not found`), or called `execute_mcp_tool` without first calling `get_mcp_tool_schema` (triggering `INS-PROGRESSIVE_-793D1A`).
- **Remediation**: Updated [`load_skill`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/tools/tools.py#L542-L579), [`search_mcp_tools`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/tools/tools.py#L634-L643), and [`load_persona_with_skills_catalog`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/tools/tools.py#L722-L731) in `multi-agent/manager/tools/tools.py` to append an explicit **Progressive Disclosure Tool Execution Protocol** (along with the skill's `adk_additional_tools` candidates).

### Finding 2: `soc_analyst_tier1` Self-Transfer Loop on `gemini-2.5-flash-lite`
- **Observed Failure**: During `impossible_travel_service_account_triage`, `soc_analyst_tier1` threw `ValueError: Agent 'soc_analyst_tier1' cannot transfer to itself` because [`soc_analyst_tier1/agent.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/sub_agents/soc_analyst_tier1/agent.py) and [`soc_analyst_tier2/agent.py`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/multi-agent/manager/sub_agents/soc_analyst_tier2/agent.py) were using `gemini-2.5-flash-lite` while all other sub-agents used `gemini-2.5-flash`.
- **Remediation**: Upgraded `soc_analyst_tier1` and `soc_analyst_tier2` to `gemini-2.5-flash` and added an explicit instruction prohibiting self-transfers. On re-test, `impossible_travel_service_account_triage` completed all 3 turns (18 tool calls, 4 activated skills, 6 inspected schemas) with 4/4 rubrics passed.

### Finding 3: Premature User Simulator Stop on Internal `transfer_to_agent` Events
- **Observed Failure**: Passing `include_function_calls=True` to `LlmBackedUserSimulatorConfig` exposed internal `transfer_to_agent` calls to the simulated user. ADK's built-in persona prompt includes a rule to end the conversation with `</finished>` when *"The Agent successfully transferred the User Simulator to a human/live agent"*, causing the simulator to terminate prematurely after Turn 1.
- **Remediation**: Set `include_function_calls=False` by default in [`run_simulated_session`](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/aqua_flywheel_compliance_gates/evals/simulate_sessions.py#L326-L335) so the simulated user only sees natural-language agent responses, matching real user interaction.

---

## 6. CLI Usage Reference

All commands should be executed from the repository root using `direnv exec .` (which loads the isolated `.gcloud` configuration and `.venv` environment):

```bash
# 1. List pre-built multi-turn scenarios
direnv exec . python -m evals.simulate_sessions --list-scenarios

# 2. Run pre-built scenarios (Approach 1)
direnv exec . python -m evals.simulate_sessions \
  --scenarios novice_incremental_login_triage,expert_multi_agent_incident_pivot \
  --max-turns 3

# 3. Run all 6 saved automated scenarios from JSON dataset (Approach 2)
direnv exec . python -m evals.simulate_sessions \
  --scenarios-file evals/datasets/generated_multi_turn_scenarios.json \
  --max-turns 3

# 4. Run a subset of scenarios from a JSON dataset file
direnv exec . python -m evals.simulate_sessions \
  --scenarios-file evals/datasets/generated_multi_turn_scenarios.json \
  --scenarios impossible_travel_service_account_triage,cti_campaign_pivot_to_hunt \
  --max-turns 3

# 5. Synthesize N brand-new multi-turn scenarios with Gemini and merge into dataset
direnv exec . python -m evals.simulate_sessions \
  --generate-scenarios 3 \
  --generation-instruction "Focus on cloud IAM privilege escalation and data exfiltration" \
  --save-scenarios evals/datasets/generated_multi_turn_scenarios.json \
  --max-turns 3 \
  --output evals/results/latest_simulation_report.json

# 6. Inspect per-agent token & tool chronology for the latest simulated session
direnv exec . python multi-agent/get_session_stats.py latest
```
