# How to write agentic SOC runbooks

Agentic SOC runbooks are system instructions for autonomous worker and supervisor models, not wiki pages for human analysts. When a runbook mixes human documentation conventions with agent instructions, smaller models (`gemini-2.5-flash-lite`, `gemma-4-e4b`, `gemma-3-4b`) copy template syntax into tool calls, stall on nonexistent IDE commands, or burn tens of thousands of tokens repeating verbose checklists.

Across 29 experiments in the Gen 3 (`gen3_10`) and Gen 5 (`gen5_val_20`) benchmarks, enforcing the ten rules below cut the four core runbooks from `3,648` words to `1,260` words (`-65.5%`), reduced worst-case worker completion tokens by `83.6%` (`68,652` to `6,771` tokens on `CASE-GEN5-LATERAL-PSEXEC-05`), and lifted Harbor 60/20/20 reward from `0.4361` to `0.9869` on `gemini-2.5-flash-lite` and `0.9898` on `gemini-2.5-flash`.

---

## 1. Keep each runbook under 350 words and 50 lines

Long runbooks dilute attention and inflate reasoning loops on every ReAct turn.

- Cap each runbook at **300 to 350 words** (`<= 50` lines).
- Cut background explanations of what an attack is. State only what the agent must query, verify, and decide.
- When evolving runbooks with GEPA (`agent/gepa_runbook_optimizer.py`), pass `--max-words 350`. `WordLimitReflectionLM` targets `80%` of the word cap (`280` words) during reflection so single-pass rewrites stay below the hard ceiling.

| Runbook | Raw Upstream (`third_party/ai-runbooks`) | Clean Seed (`strip_runbook_scaffolding`) | Promoted (`arena_grafted_all4_w300`) | Compression vs Raw |
| :--- | :--- | :--- | :--- | :--- |
| `basic_ioc_enrichment.md` | `842` words | `576` words | `313` words (`48` lines) | `-62.8%` |
| `lateral_movement_hunt_psexec_wmi.md` | `1,069` words | `710` words | `321` words (`48` lines) | `-70.0%` |
| `malware_triage.md` | `876` words | `561` words | `300` words (`46` lines) | `-65.8%` |
| `suspicious_login_triage.md` | `861` words | `529` words | `326` words (`49` lines) | `-62.1%` |
| **Total (4 Core Runbooks)** | **`3,648` words** | **`2,376` words** | **`1,260` words** | **`-65.5%`** |

---

## 2. Use a fixed 6-section Markdown skeleton

Structure every runbook with the same six headings in the same order so both the worker (`SOCRunbookWorkerAgent`) and the AQuA trajectory diagnostics engine (`agent/aqua_diagnostics.py`) can locate each stage deterministically:

1. `# <Runbook Title>`
2. `## Objective` (one sentence)
3. `## Scope` (one to two sentences)
4. `## Inputs` (bulleted `<angle_bracket>` parameters)
5. `## Tools` (grouped by MCP server or tool namespace)
6. `## Workflow Steps` (four ordered stages: `Stage A` through `Stage D`)

---

## 3. Structure workflow steps into the 4-stage epistemic sequence (`Stage A` to `Stage D`)

Agentic SOC runbooks fall into two operational tracks that work in opposite epistemic directions:
- **Track 1: Reactive Alert & Case Triage (Entity-First / Narrow-to-Broad)** — starts from a fired alert (`<case_id>`, `<asset_identifier>`, `<ioc_value>`), enriches that single asset, and closes or contains the existing case.
- **Track 2: Proactive Threat Hunting & CTI Sweeps (Hypothesis-First / Broad-to-Narrow)** — starts from a threat intelligence collection (such as the GTI collection `"Unwrapping Ursnifs Gifts"`, `alienvault_63bbee81b55c8ba00724605a`, or `report--22-00022539`), domain/actor hypothesis, or MITRE ATT&CK technique (`<mitre_technique_ids>`) with **no pre-identified host**, sweeps the fleet across a multi-horizon window, filters out legitimate LOLBins (`rundll32.exe`, `wscript.exe`) and benign collateral files, and identifies Patient Zero plus detection gaps.

### Track 1: Reactive Alert & Case Triage (`Stage A` to `Stage D`)

Order investigation steps from lowest cost and highest disambiguation power to final containment. Never instruct the agent to contain an asset before checking asset role, network scope, and threat intelligence.

- **Stage A: Asset Identity, CMDB Context, & SOAR Case Correlation**
  - Query `lookup_entity` on the host or user to determine business role, owner, and criticality tier (`LOW`, `STANDARD`, `HIGH`, `CRITICAL`) and check for active change tickets (`CHG-...`).
  - Query `list_cases` with the primary entity or IOC to detect existing or duplicate SOAR cases before opening new containment paths.
- **Stage B: Network Routing & Scope Verification**
  - Query `get_ip_address_report` or `get_domain_report` to classify IP routing (`PUBLIC`, `PRIVATE`, or RFC-5737 documentation space) and domain registration age/registrar.
- **Stage C: Threat Intelligence Reputation**
  - Query `get_file_report`, `get_ip_address_report`, or `get_domain_report` to retrieve VirusTotal/GTI detection ratios and known malware families.
- **Stage D: Behavioral Corroboration, Verdict, & Action**
  - Query `search_security_events` (UDM search) to verify whether the alerted activity executed on the host (process lineage, command line, child processes, revocations, or volume).
  - Map the corroborated evidence to one of the four canonical verdicts (`MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, `BENIGN`) and its exact tool actions.

### Track 2: Proactive Threat Hunting & CTI Collection Sweeps (`Stage A` to `Stage D`)

When authoring a proactive threat hunt runbook (such as hunting GTI Collection `alienvault_63bbee81b55c8ba00724605a` *"Unwrapping Ursnifs Gifts"*, `report--22-00022539`, or MITRE ATT&CK TTPs), use this 4-stage broad-to-narrow funnel:

- **Stage A: CTI Collection Expansion & Indicator Prioritization**
  - Query `get_collection_report` on `<collection_id>` (or `get_threat_intel` / `get_domain_report` on `<hunt_seed>`) to extract campaign context and TTPs.
  - Query `get_entities_related_to_a_collection` across `domains`, `files`, `ip_addresses`, and `attack_techniques`.
  - If hunting a seed domain (e.g., `superstarts.top`), pivot via `get_entities_related_to_a_domain` (`relationship_name="communicating_files"` and `"resolutions"`) to discover second-hop payload hashes that may execute locally even when direct domain/IP network logs are absent.
- **Stage B: Multi-Horizon SIEM Sweep (`72h` -> `168h` Widening) & Baseline Exclusion**
  - Query `get_ioc_matches` and `search_security_events` for the extracted domains, IPs, and file hashes using an initial `<time_frame_hours>` window (`72` hours).
  - **Mandatory Horizon Widening**: If `72` hours returns zero SIEM events in a sparse or replayed tenant, automatically widen `hours_back` to `168` hours (`7` days) before concluding the environment is clean.
  - If network searches (`NETWORK_DNS`, `NETWORK_CONNECTION`) return zero hits, pivot to endpoint module/process telemetry (`PROCESS_MODULE_LOAD`, `PROCESS_LAUNCH`) for the communicating file hashes discovered in Stage A.
- **Stage C: LOLBin / Collateral Disambiguation, Patient-Zero Scoping, & Case Correlation**
  - **LOLBin & Benign Collateral Guard**: Threat intelligence collections frequently list legitimate Windows binaries (such as signed `rundll32.exe` hash `7d99c80a...` or `wscript.exe`) alongside malicious payloads (such as Ursnif DLL `8e570e32...` / `dfdfd0a3...`) or benign downloaded web files (`index.html`). Always call `get_file_report` on every matched hash before recommending `block_indicator` — never block signed OS LOLBins.
  - **Patient-Zero Process Lineage**: On every host with SIEM hits (`<matched_hostname>`, e.g., `malwaretest-win`), inspect the parent-child process tree and command-line obfuscation (such as `wscript.exe` executing a `.js` stager with reversed strings `revreSretsigeRllD` / `lldnur` launching a renamed `rundll32.exe` binary from `\Device\CdRom1\`).
  - Query `lookup_entity` on `<matched_hostname>` and `list_cases` to correlate existing or unalerted SOAR cases (such as an open Critical case with zero attached alerts indicating a detection rule gap).
- **Stage D: Hunt Verdict, Containment, & Detection-Gap Handoff**
  - **MALICIOUS** (*Confirmed Campaign / TTP Compromise*): Local SIEM confirms execution (`PROCESS_LAUNCH` / `PROCESS_MODULE_LOAD`) or C2 beaconing (`NETWORK_DNS` / `NETWORK_CONNECTION`) of a GTI-verified malicious payload on `<matched_hostname>`. Execute `isolate_host` on `<matched_hostname>`, `block_indicator` on verified malicious C2 domains/IPs/payload hashes (excluding legitimate LOLBins), and `update_case_comment` documenting Patient Zero, the execution chain, and any detection gap.
  - **SUSPICIOUS** (*Anomalous TTP / Unconfirmed Outlier*): Low-prevalence LOLBin or administrative tool anomaly (`<= 2` hosts) without confirmed malicious payload hash or C2 reputation, or activity on a critical server where unverified isolation is prohibited. Call `update_case_comment` with the outlier timeline and recommend a YARA-L 2.0 (`YL2`) detection rule. Never call `isolate_host` or `close_case`.
  - **INCONCLUSIVE** (*Partial Sweep / Tool Outage*): GTI or SIEM search returns a service error (`503`). Pivot to available local telemetry (`get_ioc_matches`, `lookup_entity`, `list_cases`), set verdict to `INCONCLUSIVE`, and document the partial sweep in `update_case_comment`. Never contain or close.
  - **BENIGN** (*Clean Environment Sweep*): Zero malicious indicators or TTP matches across both the `72h` and widened `168h` lookback windows, or all matched activity is verified as authorized administration. Record the clean hunt audit trail via `update_case_comment` (if linked to a hunt ticket) and `close_case` only when closing a dedicated clean-hunt ticket.

---

## 4. Write `<angle_bracket>` input slots, never `${VAR_NAME}` shell placeholders

Smaller models treat `${IOC_VALUE}` or `${SRC_IP}` as literal strings or environment variables and emit broken tool calls such as `{"ip": "${SRC_IP}"}`.

- **Bad**: `Query gti-mcp.get_ip_address_report for ${SRC_IP} on ${TARGET_HOST}.`
- **Good**: `Query gti-mcp.get_ip_address_report on <source_ip> and secops-mcp.lookup_entity on <hostname>.`
- Enforced by: `validate_runbook_candidate(..., forbid_template_vars=True)` (`TEMPLATE_VAR_REGEX`) and `strip_runbook_scaffolding(..., normalize_template_vars=True)`.

---

## 5. Omit Mermaid diagrams and ASCII flowcharts

A 55-line ```` ```{mermaid} sequenceDiagram ``` ```` block adds 250 to 350 tokens of non-executable syntax per runbook and introduces participant names (`Actor`, `SIEM`, `EDR`) that do not match the agent's registered tool names.

- Keep diagrams in human architecture docs, never in agent runbooks.
- Enforced by: `validate_runbook_candidate(..., forbid_mermaid_diagrams=True)` (`MERMAID_BLOCK_REGEX`) and `strip_runbook_scaffolding()`.

---

## 6. Reference only registered sandbox tools, never IDE pseudo-tools

Runbooks adapted from interactive coding assistants (such as Cline `.clinerules`) often tell the agent to call `ask_followup_question`, `write_to_file`, `generate_report_file.md`, or `attempt_completion`. In an autonomous SOC sandbox, calling an unregistered tool either errors out or causes the worker to halt and wait for human input.

- List only executable MCP/sandbox tools (`lookup_entity`, `search_security_events`, `get_ip_address_report`, `get_domain_report`, `get_file_report`, `list_cases`, `update_case_comment`, `close_case`, `isolate_host`, `block_indicator`).
- Enforced by: `validate_runbook_candidate(..., forbid_interactive_pseudotools=True)` (`INTERACTIVE_PSEUDOTOOL_PATTERNS`).

---

## 7. Never include short-circuit directives

Statements such as `"if the IP is in documentation space, skip all enrichment"` or `"proceed directly to Step 4"` trigger zero-tool premature termination (`PREMATURE_TERMINATION_ZERO_TOOLS`). Even when an alert looks obviously benign, the agent must execute at least one epistemic verification tool (`epistemic_step_count >= 1`) to ground its report in environment state.

- Enforced by: `SHORT_CIRCUIT_PATTERNS` in `validate_runbook_candidate()` and the zero-tool hesitation gate (`fitness = 0.0`) in `RunbookGEPAAdapter.evaluate()`.

---

## 8. Never hardcode benchmark IPs, hostnames, case IDs, or instance literals

Runbooks must teach generalizable investigative procedure, not lookup tables of test answers.

- Never include literal IPv4 addresses or CIDR blocks (such as `192.0.2.0/24` or `10.0.99.50`), benchmark hostnames (`WKSTN-FIN-042`, `SRV-PROD-PAYMENT-01`), case IDs (`CASE-02`, `CASE-GEN5-...`), or Gen 5 `manifest.forbidden_literals`.
- If you include an illustrative example inside prose, wrap it in `(e.g., ...)` using generic class names (`(e.g., known corporate VPN or authorized vulnerability scanner)`), not test-set literals.
- Enforced by: Rules 1–6 in `validate_runbook_candidate()`.

---

## 9. Define explicit, mutually exclusive decision rules for all 4 verdicts in Stage D

Ambiguous closing instructions cause over-containment on critical servers (`$50,000` false-positive downtime loss) or premature case closure during tool outages. Every runbook's Stage D must define the exact condition and tool action for all four verdicts:

- **MALICIOUS**: High-confidence threat intelligence AND corroborated malicious execution on the alerted asset. Execute `isolate_host` and/or `block_indicator` on the compromised asset (unless prohibited by asset criticality policy) and document via `update_case_comment`.
- **SUSPICIOUS**: Anomalous telemetry that lacks corroboration, involves unverified dual-use administrative activity, or touches a business-critical asset where unverified isolation is prohibited. Call `update_case_comment` to escalate for human review. Never call `isolate_host` or `close_case`.
- **INCONCLUSIVE**: A primary enrichment tool fails or returns an outage error (such as HTTP `503`). Pivot to available local telemetry (`lookup_entity`, `search_security_events`), set verdict to `INCONCLUSIVE`, and call `update_case_comment` documenting both the fallback evidence and the service error. Never call `isolate_host` or `close_case`.
- **BENIGN**: Activity is corroborated as authorized (such as an approved `CHG-...` change window, authorized scanner, or non-routable RFC-5737 documentation check with zero malicious host activity). Call `update_case_comment` and `close_case`.

Avoid negated verdict phrases in report templates (such as `"not a false positive"`, `"not command and control"`, or `"neither confirmed safe nor confirmed malicious"`), which collide with case-insensitive substring assertions. State the positive finding directly (`"Verified threat activity"`, `"Authorized traffic"`, `"Telemetry incomplete due to service outage"`).

---

## 10. Validate every new or edited runbook before deployment

Run `validate_runbook_candidate()` with all structural and anti-memorization flags enabled before committing any runbook change:

```bash
WORKTREE_DIR="/usr/local/google/home/dandye/Projects/gemma_deploy__worktrees/dspy__context-engineering"
cd "$WORKTREE_DIR"
direnv exec "$WORKTREE_DIR" python3 -c '
from pathlib import Path
from agent.gepa_runbook_optimizer import load_forbidden_literals, load_seed_runbooks, validate_runbook_candidate

candidate = load_seed_runbooks(Path("docs/soc_eval_results/dspy_overnight/candidates/arena_grafted_all4_w300"))
forbidden = load_forbidden_literals(Path("configs/evals/gen5/manifest.json"))
ok, violations = validate_runbook_candidate(
    candidate,
    forbidden_literals=forbidden,
    forbid_template_vars=True,
    forbid_mermaid_diagrams=True,
    forbid_interactive_pseudotools=True,
    max_words=350,
)
assert ok, f"Validation failed: {violations}"
print("All 4 runbooks passed validation. Total words:", sum(len(v.split()) for v in candidate.values()))
'
```

---

## Canonical Templates (`<= 325` words)

### Template A: Reactive Alert & Case Triage (`<= 325` words)

```markdown
# <Runbook Title>

## Objective

<One sentence stating the triage goal and target alert class.>

## Scope

<One to two sentences defining the alert scope and entity types covered.>

## Inputs

*   `<case_id>`: The associated SOAR case identifier.
*   `<asset_identifier>`: The primary host or user account involved.
*   `<ioc_value>`: The primary indicator (IP address, domain, or file hash).

## Tools

*   `secops-mcp`: `lookup_entity`, `search_security_events`
*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`
*   `secops-soar`: `list_cases`, `update_case_comment`, `isolate_host`, `block_indicator`, `close_case`

## Workflow Steps

### Stage A: Asset Identity & Case Correlation

1.  Query `secops-mcp.lookup_entity` on `<asset_identifier>` to determine business role, criticality, and active change windows.
2.  Query `secops-soar.list_cases` with `<asset_identifier>` and `<ioc_value>` to identify existing related incidents.

### Stage B: Network Scope Verification

3.  For an IP or domain, query `gti-mcp.get_ip_address_report` or `gti-mcp.get_domain_report` to determine if routing is public, private, or reserved documentation space.

### Stage C: Threat Intelligence Reputation

4.  Query the appropriate `gti-mcp` tool for `<ioc_value>` to retrieve detection ratios and known malware associations.

### Stage D: Behavioral Corroboration, Verdict, and Action

5.  Query `secops-mcp.search_security_events` on `<asset_identifier>` to corroborate host execution or login behavior.
6.  Apply a verdict and execute the matching action:
    *   **MALICIOUS:** High-confidence threat intelligence and corroborated host execution. Execute `isolate_host` and/or `block_indicator` on the compromised asset and call `update_case_comment`.
    *   **SUSPICIOUS:** Anomalous but unconfirmed activity, or activity on a business-critical asset where unverified isolation is prohibited. Call `update_case_comment` to escalate. Do not call `isolate_host` or `close_case`.
    *   **INCONCLUSIVE:** A primary enrichment tool returns a service error. Pivot to available local telemetry, set verdict to `INCONCLUSIVE`, and call `update_case_comment`. Do not contain or close.
    *   **BENIGN:** Activity is corroborated as authorized or confined to non-routable test space. Call `update_case_comment` and `close_case`.
```

### Template B: Proactive Threat Hunting & CTI Collection Sweep (`<= 325` words)

```markdown
# Proactive GTI Collection & Campaign Threat Hunt

## Objective

Sweep enterprise telemetry for indicators and execution chains linked to a GTI collection or threat hypothesis to identify Patient Zero, scope, and detection gaps.

## Scope

Covers fleet-wide CTI collection sweeps (GTI reports, C2 domains, and MITRE ATT&CK execution chains) across SIEM, GTI, and SOAR.

## Inputs

*   `<collection_id>`: Target GTI collection or report ID.
*   `<time_frame_hours>`: SIEM lookback in hours (default `72`; widen to `168` on zero hits).
*   `<target_scope_query>`: Optional UDM host-group filter.

## Tools

*   `gti-mcp`: `get_collection_report`, `get_entities_related_to_a_collection`, `get_entities_related_to_a_domain`, `get_domain_report`, `get_file_report`, `get_ip_address_report`
*   `secops-mcp`: `get_ioc_matches`, `search_security_events`, `lookup_entity`, `get_security_alerts`
*   `secops-soar`: `list_cases`, `update_case_comment`, `isolate_host`, `block_indicator`, `close_case`

## Workflow Steps

### Stage A: CTI Collection & Second-Hop Indicator Expansion

1.  Query `gti-mcp.get_collection_report` and `gti-mcp.get_entities_related_to_a_collection` on `<collection_id>` across `domains`, `files`, `ip_addresses`, and `attack_techniques`.
2.  For C2 domains, query `gti-mcp.get_entities_related_to_a_domain` (`relationship_name="communicating_files"`) to collect second-hop payload hashes.

### Stage B: Multi-Horizon SIEM Sweep (`72h` to `168h`)

3.  Query `secops-mcp.get_ioc_matches` and `secops-mcp.search_security_events` for extracted domains, IPs, and hashes over `<time_frame_hours>` (`72` hours).
4.  If `72` hours returns zero events, widen `hours_back` to `168` hours (`7` days) and search `PROCESS_MODULE_LOAD` and `PROCESS_LAUNCH` events for communicating file hashes.

### Stage C: LOLBin Filtering, Patient-Zero Lineage, & Case Correlation

5.  Query `gti-mcp.get_file_report` on matched hashes to separate malicious payloads from signed OS LOLBins (e.g., `rundll32.exe`, `wscript.exe`) or benign web files.
6.  On matched hosts (`<matched_hostname>`), inspect parent-child lineage (`wscript.exe` spawning `rundll32.exe` DLL load), call `secops-mcp.lookup_entity`, and query `secops-soar.list_cases` for related or unalerted cases.

### Stage D: Hunt Verdict, Containment, & Detection-Gap Handoff

7.  Apply a verdict:
    *   **MALICIOUS:** Campaign C2 or payload execution confirmed on `<matched_hostname>`. Call `isolate_host` on `<matched_hostname>`, `block_indicator` on verified C2 domains, IPs, and payload hashes (never block signed OS LOLBins), and `update_case_comment` documenting Patient Zero and detection gaps.
    *   **SUSPICIOUS:** Unconfirmed LOLBin/TTP outlier or critical-asset activity where isolation is prohibited. Call `update_case_comment` with YARA-L 2.0 (`YL2`) detection criteria. Never call `isolate_host` or `close_case`.
    *   **INCONCLUSIVE:** Tool outage. Pivot to local telemetry, set `INCONCLUSIVE`, and call `update_case_comment`.
    *   **BENIGN:** Zero malicious hits across `72h` and `168h`, or authorized activity. Call `update_case_comment` and `close_case`.
```
