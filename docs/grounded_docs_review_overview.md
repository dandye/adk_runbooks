---
type: Reference
title: "Grounded Google Docs Runbook & Report Review (Developer Knowledge MCP + Docs API v1)"
description: "How the SOC multi-agent verifies technical claims against Google Developer Knowledge MCP and Google Search Grounding (via AgentTool) and proposes non-destructive comments and Suggested Edits in Google Docs."
generated:
  by: agent:jetski
  at: 2026-10-10T22:00:00-04:00
related:
  - ./drive_runbooks_overview.md
  - ./skills_progressive_disclosure_overview.md
  - ./progressive_mcp_discovery_overview.md
---

# Grounded Google Docs Runbook & Report Review

**Source Branch:** `drive-mcp-runbooks__grounded-docs` (stacked on `drive-mcp-runbooks`)
**References:**
- Romin Irani, *Building an AI Document Reviewer with Google ADK, Gemini and the New Google Docs Comments & Suggested Edits API* (Oct 2026)
- Romin Irani, *Grounding Google Docs Suggested Edits with Developer Knowledge MCP and Google Search* (Oct 2026)

---

## Executive Summary

On the `drive-mcp-runbooks` branch, SOC runbooks and incident reports live in Google Drive as `text/markdown` files served via `https://drivemcp.googleapis.com/mcp/v1`. Because in-place blob revision uploads (`upload_file_revision`) are gated behind `WORKSPACE_MCP_INTERNAL`, modifying existing runbooks or collaboratively reviewing incident reports requires a human-in-the-loop review surface.

This branch adds two complementary capabilities from Irani (2026):

1. **Two-Source External Grounding (`multi-agent/manager/tools/grounding_tools.py`)**:
   - **Google Developer Knowledge Remote MCP Server** (`https://developerknowledge.googleapis.com/mcp`, tools prefixed `devknowledge_`): Exposes `answer_query`, `search_documents`, and `get_documents` across official Google documentation (Google Cloud, Chronicle SIEM/SOAR, IAM, Vertex AI, Gemini, ADK).
   - **Isolated Web Search Sub-Agent (`AgentTool(web_search_verifier)`)**: Wraps a dedicated child `Agent(name="web_search_verifier", tools=[google_search])` inside `AgentTool` so the root `manager` and specialist sub-agents can invoke Google Search Grounding alongside custom `FunctionTool`s and `McpToolset`s without triggering Gemini's single-tool constraint.

2. **Google Docs API v1 Non-Destructive Review Tools (`multi-agent/manager/tools/docs_review_tools.py`)**:
   - `create_google_doc`: Creates a native collaborative Google Doc (`application/vnd.google-apps.document`) in `DRIVE_REPORTS_FOLDER_ID` or `DRIVE_RUNBOOKS_FOLDER_ID`.
   - `read_google_doc`: Reads a Google Doc via `GET https://docs.googleapis.com/v1/documents/{id}?includeTabsContent=true` and maps every character across paragraphs and table cells to its 1-based UTF-16 index.
   - `insert_doc_comments`: Anchors native Google Docs comments (`insertComment`) with rationale and canonical citation URLs to the pre-edit index spans.
   - `propose_doc_suggested_edits`: Validates non-overlapping spans, sorts replacements **descending by `startIndex`** (back-to-front) so earlier edits never shift subsequent UTF-16 character offsets, and submits `deleteContentRange` + `insertText` under `"writeControl": {"writeMode": "SUGGEST"}`.

---

## 1. Architecture & Ordering Invariants

```mermaid
flowchart TD
    MGR["SOC Manager / Specialist Agent"]
    DK["Developer Knowledge MCP\ndeveloperknowledge.googleapis.com/mcp\n(answer_query, search_documents, get_documents)"]
    WS["AgentTool(web_search_verifier)\nIsolated child Agent(tools=[google_search])"]
    RD["1. read_google_doc(doc_id)\nBuilds 1-based UTF-16 doc_index_map"]
    IC["2. insert_doc_comments(doc_id, comments)\nbatchUpdate: insertComment (BEFORE edits)"]
    SE["3. propose_doc_suggested_edits(doc_id, edits)\nSorted descending by startIndex\nwriteControl: {writeMode: SUGGEST}"]

    MGR -- "Google Cloud / Chronicle / IAM / ADK claims" --> DK
    MGR -- "External CVEs / 3P vendor advisories" --> WS
    MGR --> RD
    RD --> IC
    IC --> SE
```

### Key Implementation Nuances

| Mechanism | Why It Matters |
| --- | --- |
| **Static headers + `httpx.Auth` on `StreamableHTTPConnectionParams`** | During A2A Agent Card startup, ADK calls `McpToolset.get_tools(readonly_context=None)`. `header_provider` is skipped when `readonly_context` is `None`, and in ADK 2.7.1 `mcp_tool.py:L434` dereferences `tool_context._invocation_context` whenever `header_provider` is non-null. Putting `X-Goog-User-Project` / `X-Goog-Api-Key` in static headers and injecting rotating OAuth tokens via `BearerTokenAuth` works across both startup (`readonly_context=None`) and direct `run_async(tool_context=None)` calls. |
| **`AgentTool(web_search_verifier)`** | Gemini's built-in `google_search` tool cannot sit in the same `tools=[...]` array as custom `FunctionTool`s or `McpToolset`s. Wrapping a single-tool child agent in `AgentTool` exposes web search as a standard function call. |
| **Dual-Identity Token Resolution (`resolve_docs_token`)** | Prefers `tool_context.state["user_access_token"]` (end-user OAuth 2.0 token) so comments and suggested edits carry the human analyst's identity, falling back to the worktree's `AdcTokenSource` for CLI/headless execution. |
| **Comments Before Edits + Back-to-Front Sorting** | `insert_doc_comments` and `propose_doc_suggested_edits` both resolve quotes against the pre-edit `doc_index_map` from `read_google_doc`. Inserting comments first and sorting `deleteContentRange` + `insertText` descending by `startIndex` (`reverse=True`) guarantees UTF-16 offsets never drift mid-batch. |

---

## 2. Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEVELOPERKNOWLEDGE_MCP_URL` | `https://developerknowledge.googleapis.com/mcp` | Developer Knowledge Remote MCP endpoint. |
| `DEVELOPERKNOWLEDGE_API_KEY` | unset | Optional API key sent as `X-Goog-Api-Key` (falls back to ADC bearer token when unset). |
| `DEVELOPERKNOWLEDGE_QUOTA_PROJECT` | `$GCP_PROJECT_ID` | Sent as `X-Goog-User-Project`; requires `developerknowledge.googleapis.com` enabled. |
| `DEVELOPERKNOWLEDGE_MCP_TOOLSET` | `1` | Set to `0` to disable the Developer Knowledge toolset. |
| `WEB_SEARCH_VERIFIER_MODEL` | `gemini-2.5-flash` | Model used by the isolated `web_search_verifier` child agent. |

---

## 3. Master 5-Pillar Cross-Horizon Architecture (`H1`–`H28`, Cycles 1–27)

Across 27 autonomous evolution cycles (`H1` through `H28`), the Grounded Google Docs SecOps reviewer unifies 30+ specialized verification, attribution, readiness, routing, and remediation tools into five capability pillars (`H28_CAPABILITY_PILLAR_CATALOG`) orchestrated by `synthesize_master_secops_doc_readiness` and `audit_master_secops_doc_readiness_in_doc`:

| Pillar ID | Capability Pillar | Horizons Covered | Primary Verifiers & Guardrails |
| :--- | :--- | :--- | :--- |
| `UDM_YL2_AND_ENTITY_GRAPH` | Chronicle SIEM UDM, YARA-L 2.0 (`YL2`) & Entity Graph `$g.graph.*` Joins | `H1`, `H2`, `H13`, `H14`–`H19`, `H22`, `H26`, `H27` | UDM field/enum/operator syntax, zero-hit single-clause ablation, YARA-L 2.0 (`YL2`, strictly separated from standard file/payload YARA `strings:` rules) compiler & `outcome:` max-1-agg gates, sliding windows (`over <W> after/before $<ev>`), and Entity Graph `$g.graph.entity.*` / `$g.graph.metadata.entity_type` joins & criticality `$risk_score` scaling. |
| `TELEMETRY_CREDENTIAL_AND_SOAR_SAFETY` | Telemetry Hygiene, Leaked Credentials & SOAR/Siemplify Actuation Safety | `H3`, `H6`, `H10`, `H13`, `H26`, `H27` | Untrusted URL defanging (`hxxps://`), Base64/MiniDump payload sanitization, safe JWT claim decoding & live SIEM credential blast-radius triage, shell `export VAR="..."` enforcement, SOAR containment pre-flight blast-radius & rollback gates, Siemplify SOAR `/api/1p/external/v1/cases` vs. unmigrated native Chronicle `v1alpha/.../cases` endpoint routing (`secops-demo-env`), and Spanner `/span/global/` vs. invalid `/span/prod/` path verification. |
| `MITRE_CVE_WAVED_AND_GTI_ATTRIBUTION` | MITRE ATT&CK v16.1, CVE/KEV, 4-Layer WAVED Ontology & GTI Attribution | `H4`, `H11`, `H21`, `H23` | MITRE ATT&CK technique/sub-technique grounding, CISA KEV CVE verification, 4-layer WAVED (`Weakness CWE -> Vulnerability CVE -> Exploit ATT&CK -> Defense D3FEND`) ontology chain verification, and live GTI (`gti-mcp`) IoC reputation & threat-actor/malware attribution (`RFC-5737`, `8.8.8.8`, and 0-byte SHA-256 false-positive block prevention). |
| `CAMPAIGN_TIMELINE_AND_TDO_COVERAGE` | Cross-Case Campaign Correlation & Threat Detection Opportunity (TDO) Synthesis | `H5`, `H8`, `H20` | Multi-case campaign graph correlation (`CAMP-GCP-CONTROL-PLANE-33278`, `CAMP-WORKSPACE-SUPERADMIN-TAKEOVER`, `CAMP-WINS-D19-ENDPOINT`), claim-to-evidence grounding, and TDO coverage gap matrix with compiler-verified YARA-L 2.0 (`YL2`) rule synthesis. |
| `WIKISKILL_RRSI_ORCHESTRA_AND_SKILLRL` | WikiSkill/RRSI Promotion Gate, SkillOrchestra Routing & SkillRL Guardrails | `H7`, `H20`, `H24`, `H25`, `H28` | `WikiSkill` / `RRSI` IoC parameterization & $L_1$ churn / noise-floor promotion gate (`skill-impact.md`), `SkillOrchestra` Stage A/B competence-cost routing & `SkillToolset` MCP schema filtering (`-68.94%`), `LocalGoogleDocsSimulator` Kix AST parity, and 8-rule `SkillRL` failure-trajectory distillation (`SKILLRL-01` through `SKILLRL-08`). |

### Master 14-Scenario Verification Benchmark Suite (`evaluate_verification_benchmark_suite`)

Running `evaluate_verification_benchmark_suite(include_extended_night2=True)` (or `generate_master_evolution_synthesis_report()`) evaluates all 14 scenarios (`BENCH-01` through `BENCH-14`) hermetically against `LocalGoogleDocsSimulator` (`0` Google Drive write calls):

- **Scenarios Evaluated:** `14` (`BENCH-01`..`BENCH-06` Night 1 Core + `BENCH-07` WAVED + `BENCH-08` YL2 Sliding Window + `BENCH-09` GTI IoC Attribution + `BENCH-10` SkillOrchestra + `BENCH-11` SkillRL + `BENCH-12` YL2 Entity Graph + `BENCH-13` SOAR Actuation Safety + `BENCH-14` Master 5-Pillar Composite Synthesis)
- **Seeded Defects Detected (TP):** `73 / 73` (`FP = 0`, `FN = 0`)
- **Negative Controls Preserved (TN):** `29 / 29` (including standard file/payload YARA `strings:` rules, valid Siemplify `/api/1p/external/v1/cases` endpoints, `/span/global/` Spanner paths, and valid `$g.graph.entity.*` joins)
- **Micro Precision / Recall / F1:** `1.0000 / 1.0000 / 1.0000`
- **Pass-2 Idempotency Rate:** `1.0000` (`0` duplicate edits on second pass)
- **SkillRL Failure-Distillation Rules (`SKILLRL-01`..`SKILLRL-08`):** `8` rules across `H25`, `H26`, `H27`, and `H28` (`SKILLRL-08-MASTER-CROSS-PILLAR-READINESS-GATE`).

---

## 4. Verification

Run the hermetic unit test suite (263 passing tests across Drive MCP, Developer Knowledge MCP, `AgentTool(web_search_verifier)`, and Google Docs API v1 review & master synthesis tools):

```bash
direnv exec . uv run pytest tests/ -q
```

