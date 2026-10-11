# Overnight Handoff: Grounded Google Docs Runbook Review and Argolis SOAR Case Experiments

## 1. Environment and Workspace State

- **Worktree Path**: `/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/drive-mcp-runbooks__grounded-docs`
- **Git Branch**: `drive-mcp-runbooks__grounded-docs` stacked on `drive-mcp-runbooks`
- **Target Tenant**: Argolis `dandye-0324-chronicle`
  - **Account**: `admin@dandye.altostrat.com`
  - **GCP Project**: `dandye-0324-chronicle` with project number `1002894625780`
  - **Chronicle Customer ID**: `7e977ce4-f45d-43b2-aea0-52f8b66acd80`
  - **SOAR Endpoint**: `https://ltstrtn.siemplify-soar.com`
  - **Drive Folders**:
    - `SOC Runbooks`: `1HccC-I-0YkdnRYfphnXXkVnau3RX_-vv` containing 63 `.md` runbooks
    - `SOC Reports`: `1YvyfyaO_o07WJJOrrkctv5-4Cctk1gte`

```bash
WORKTREE_DIR="/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/drive-mcp-runbooks__grounded-docs"
ACCOUNT="admin@dandye.altostrat.com"
PROJECT_ID="dandye-0324-chronicle"
```

---

## 2. Completed Work and Live Artifacts

### Grounded Google Docs Review Architecture
- `multi-agent/manager/tools/grounding_tools.py` integrates the Google Developer Knowledge Remote MCP server at `https://developerknowledge.googleapis.com/mcp` with `tool_name_prefix="devknowledge"` and wraps `google_search` inside an isolated `AgentTool(web_search_verifier)`.
- `multi-agent/manager/tools/docs_review_tools.py` implements Google Docs API v1 non-destructive review primitives:
  - `create_google_doc` creates a native Google Doc in `SOC Reports`.
  - `read_google_doc` extracts text and builds a 1-based UTF-16 index map across paragraphs and table cells.
  - `insert_doc_comments` anchors review comments to exact Kix spans via `insertComment`, accepting either `quote` or explicit 1-based UTF-16 `start_index` and `end_index`.
  - `propose_doc_suggested_edits` stages non-destructive red-lines via descending-sorted `deleteContentRange` and `insertText` requests under `writeControl: {"writeMode": "SUGGEST"}`, accepting either `quote` or `start_index` and `end_index`.
  - `sanitize_telemetry_text` replaces raw Base64 stagers and `comsvcs.dll, MiniDump` arguments with deterministic forensic tokens `<REDACTED_B64:len=N,sha256=XXXXXXXXXXXX>` and `<REDACTED_DUMP_ARGS:sha256=XXXXXXXXXXXX>`.
  - `find_deterministic_indicator_spans` scans plain text and index maps in pure Python to stage span-addressed URL defanging without requiring the LLM to echo malicious URLs.
- `multi-agent/manager/tools/tools.py` passes `env=dict(os.environ)` to `StdioServerParameters` in `init_shared_mcp_tools()` so child `uv run` MCP servers inherit `direnv` per-worktree `GOOGLE_APPLICATION_CREDENTIALS` and `CLOUDSDK_CONFIG`.
- `tests/test_docs_review_tools.py` and `tests/test_grounding_tools.py` pass all 112 unit tests across the repository.

### Live Google Docs Created and Red-Lined in `SOC Reports`

| Experiment / Case | Google Doc ID | Google Doc URL | Verified Review Operations |
| :--- | :--- | :--- | :--- |
| Smoke Test (`Grounded_Runbook_Review_Smoke_Test`) | `1DV3E98OQSNuSuV_dClYJ21PF7xnSHLq6vioDthXEx3M` | https://docs.google.com/document/d/1DV3E98OQSNuSuV_dClYJ21PF7xnSHLq6vioDthXEx3M/edit | 1 Kix-anchored comment and 1 Suggested Edit |
| Synthetic Postmortem (`INC_2026_1011_Postmortem_and_Runbook_Redline`) | `18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI` | https://docs.google.com/document/d/18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI/edit | 4 Kix-anchored comments and 4 Suggested Edits across 813 UTF-16 chars |
| Argolis SOAR Case `33278` (`SOAR_Case_33278_GCP_Service_Account_Privilege_Escalation`) | `1wH5XBHqH1g_nqAIZ04ebKqiBu0CU_umuSXpl7kIBwQA` | https://docs.google.com/document/d/1wH5XBHqH1g_nqAIZ04ebKqiBu0CU_umuSXpl7kIBwQA/edit | Correlated 5 `GCP_CLOUDAUDIT` UDM events from `104.198.226.161`, applied 3 comments and 3 Suggested Edits across 2,260 UTF-16 chars |
| Argolis SOAR Cases `33287` & `33281` (`SOAR_Case_33287_33281_Workspace_Admin_Takeover_Review`) | `1tDrz_tM2qwlP2weizVGRSEvikDPaLxp-MIylOL49kns` | https://docs.google.com/document/d/1tDrz_tM2qwlP2weizVGRSEvikDPaLxp-MIylOL49kns/edit | Correlated 15 `WORKSPACE_ACTIVITY` UDM events from `79.154.246.114` overturning 4 prior analyst comments, applied 3 comments and 3 Suggested Edits across 2,171 UTF-16 chars |
| Argolis SOAR Case `33288` (`SOAR_Case_33288_Sanitized_3Stage_Intrusion_Review`) | `14kr7gtw5AJd4a53vCrQ4bIQdyW-t_v48LTtzWMhSg58` | https://docs.google.com/document/d/14kr7gtw5AJd4a53vCrQ4bIQdyW-t_v48LTtzWMhSg58/edit | Sanitized 3-stage intrusion chain and applied Stage A span-based URL defanging (`start_index=526, end_index=570`) plus 2 Stage B semantic edits across 1,370 UTF-16 chars |

---

## 3. Critical Guardrails for Overnight Execution

- **Do not echo raw Base64 stagers from SOAR Case `33269` into LLM context.** Case `33269` (`Powershell Empire Launch Parameters`) contains a 1.4 KB raw Base64 PowerShell stager in `principal.process.command_line`. Always wrap SOAR and SIEM event text with `sanitize_telemetry_text()` from `multi-agent/manager/tools/docs_review_tools.py` before printing to stdout or passing to an LLM.
- **Preserve Google Docs index invariants.** Always execute `read_google_doc` first, then `insert_doc_comments` second, and `propose_doc_suggested_edits` third. Never interleave comments after suggested edits without re-running `read_google_doc`, because `writeMode="SUGGEST"` inserts suggested text into the document body immediately and shifts subsequent UTF-16 character offsets.

---

## 4. Prioritized Overnight Backlog

### Task 1: End-to-End ADK `Runner` Integration for SOAR Case Review and Runbook Hardening
- Wire `sanitize_telemetry_text` and `find_deterministic_indicator_spans` into an automated ADK workflow or `before_tool_callback` / `after_tool_callback` in `multi-agent/manager/sub_agents/report_writer.py` so that any SOAR case report written via `create_google_doc` automatically runs Stage A deterministic indicator defanging followed by Stage B Developer Knowledge MCP grounding.
- Add a closed-loop SOAR comment callback (`siemplify_post_case_comment`) that posts the reviewed Google Doc URL and summary of red-lined items back to the originating SOAR case timeline (`33278`, `33287`, `33288`).

### Task 2: Expand Argolis SOAR Case Coverage (Sanitized)
- Process additional open Argolis SOAR cases through `sanitize_telemetry_text`:
  - **Case `33269`** (`Powershell Empire Launch Parameters`, alert `488681`): Run `get_case_full_details` through `sanitize_telemetry_text()` in Python before inspection, correlate with Chronicle SIEM (`udm_search`), load `malware-incident-response` from `SOC Runbooks`, publish the sanitized postmortem to `SOC Reports`, and red-line any ungrounded MITRE ATT&CK or UDM syntax claims.
  - **Cases `33279` & `33280`** (`gcp_Compute Engine instance created` and `gcp_Firewall rule modified or deleted`): Correlate with Case `33278` to build a unified Cloud Infrastructure Intrusion campaign timeline Google Doc.
  - **Cases `33285`, `33284`, `33283`, `33282`** (`Impossible Travel` and `User Login Success from FEodo Tracker IP`): Correlate with the Workspace Admin Takeover (`33287` / `33281`) and GTI threat intelligence (`get_ip_report`).

### Task 3: Direct Runbook Red-Lining in `SOC Runbooks`
- Implement a helper `stage_runbook_update_as_google_doc(skill_name, lessons_learned)` that copies a Markdown runbook from `SOC Runbooks` (`1HccC-I-0YkdnRYfphnXXkVnau3RX_-vv`) into a native Google Doc draft, anchors comments citing the specific Argolis SOAR case IDs (`33278`, `33287`, `33288`), and proposes the detection and containment improvements using `writeMode="SUGGEST"`.

---

## 5. Verification Commands

```bash
WORKTREE_DIR="/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/drive-mcp-runbooks__grounded-docs"

# 1. Run full unit test suite (112 tests)
direnv exec "$WORKTREE_DIR" "$WORKTREE_DIR/.venv/bin/python" -m pytest "$WORKTREE_DIR/tests/"

# 2. Re-run the 3-case live Argolis SOAR experiment
direnv exec "$WORKTREE_DIR" "$WORKTREE_DIR/.venv/bin/python" "$WORKTREE_DIR/scripts/experiment_argolis_soar_cases.py"

# 3. If ADC Drive/Docs OAuth scopes expire overnight, re-authenticate interactively
ACCOUNT="admin@dandye.altostrat.com"
direnv exec "$WORKTREE_DIR" gcloud auth login "$ACCOUNT" --enable-gdrive-access --update-adc
```
