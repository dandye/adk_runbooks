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

## Canonical Template (`<= 325` words)

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
