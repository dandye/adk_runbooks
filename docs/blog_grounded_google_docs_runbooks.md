---
type: BlogPost
title: "Red-lining SOC runbooks and postmortems in Google Docs with grounded ADK agents"
description: "How we use Google Docs API v1 suggested edits, Developer Knowledge MCP, and dual-identity OAuth to catch destructive containment commands, broken Chronicle UDM queries, and live C2 links without overwriting analyst work."
author: Dan Dye
date: 2026-10-11
branch: drive-mcp-runbooks__grounded-docs
related:
  - ./drive_runbooks_overview.md
  - ./grounded_docs_review_overview.md
  - ./adk_graph_workflows_overview.md
---

# Red-lining SOC runbooks and postmortems in Google Docs with grounded ADK agents

In the first two posts of this series, [Exploring Agent Graphs for SecOps AI Runbooks](https://security.googlecloudcommunity.com/community-blog-42/exploring-agent-graphs-for-secops-ai-runbooks-8113) and [Evaluating Agent Graphs for SecOps AI Runbooks](https://security.googlecloudcommunity.com/community-blog-42/evaluating-agent-graphs-for-secops-ai-runbooks-8232), we moved our SOC triage agents off open-ended ReAct loops and onto explicit control-flow graphs with dynamic skill loading. That cut token burn and raised automated report grades from a C average to an A-/A range across realistic incident scenarios.

Then we ran into the postmortem graveyard.

Every security operations center has one. At 3 a.m., after containing a compromised cloud service account or an encoded PowerShell intrusion, the incident commander writes up a postmortem in Google Docs. The postmortem lists three concrete gaps in the team's runbooks. Maybe a containment step broke production workload identity, or a Google SecOps UDM hunting query failed to match child processes. Everyone agrees on the bridge that the runbook needs to be updated.

It almost never is. Our 63 operational runbooks lived as Markdown files inside a Git repository, and tired incident responders do not open Git pull requests after an all-night bridge. On the `drive-mcp-runbooks` branch, we solved the storage half of that disconnect by wiring our agents to the [Google Drive remote MCP server](https://developers.google.com/workspace/drive/api/guides/configure-mcp-server) at `https://drivemcp.googleapis.com/mcp/v1`. Runbooks now live in a shared `SOC Runbooks` Drive folder where analysts actually work, and `write_report` publishes incident reports directly into `SOC Reports`.

That raised a harder security engineering problem. Once incident reports and runbooks live in Google Workspace, how do we let an AI agent audit a postmortem or propose updates to a production runbook without creating a new operational hazard?

Building on Romin Irani's recent two-part reference architecture, [Building an AI Document Reviewer with Google ADK, Gemini, and the New Google Docs Comments](https://medium.com/google-cloud/building-an-ai-document-reviewer-with-google-adk-gemini-and-the-new-google-docs-comments-1f79fb6cb86f) and [Grounding Google Docs Suggested Edits with Developer Knowledge MCP and Google Search](https://medium.com/google-cloud/grounding-google-docs-suggested-edits-with-developer-knowledge-mcp-and-google-search-9e2a3bf2800e), we extended `adk_runbooks` so our incident response and report writer agents can verify technical claims against official cloud documentation and stage non-destructive red-lines inside Google Docs.

---

## Four mistakes that happen in 3 a.m. incident docs

If you ask an ungrounded LLM to rewrite an incident postmortem or a SOC runbook in place, you trade human fatigue for machine hallucination. In security operations, four specific errors show up constantly in draft postmortems and AI-generated playbooks:

1. **Destructive containment commands.** Under pressure to cut off an attacker using a compromised GCP service account, a responder writes `gcloud iam service-accounts delete sa-prod-etl@...` into the containment section. Deleting a service account destroys its unique numeric resource ID. Even if you recreate a service account with the same email address 20 minutes later, its underlying unique ID changes, silently breaking IAM policy bindings and Workload Identity Federation pools across production. The reversible triage command is `gcloud iam service-accounts disable`.
2. **Hallucinated Chronicle UDM field paths.** Both tired analysts and ungrounded LLMs routinely write UDM queries like `process.command_line = /.*-enc.*/` without the required entity prefix. In Google SecOps, unprefixed `process.command_line` is not a valid UDM field; the query compiler requires `target.process.command_line` or `principal.process.command_line`. Putting an unverified query into a runbook guarantees the next responder gets zero hits during an active hunt.
3. **Live clickable C2 links in shared reports.** When analysts paste active phishing or stage-2 payload URLs like `https://login-micros0ft-update.com/stage2.ps1` into a Google Doc, Workspace automatically turns them into clickable hyperlinks. As soon as that postmortem is shared with executives, legal counsel, or IT administrators, a live C2 beacon sits one accidental click away. Indicators in shared docs must be defanged to `hxxps://` and `[.]`.
4. **Mislabeled MITRE ATT&CK sub-techniques.** Draft reports frequently tag an encoded `powershell.exe -enc` cradle as `T1059.003` for Windows Command Shell instead of `T1059.001` for PowerShell, skewing detection coverage heatmaps.

---

## Changing the trust contract between agents and responders

Most document-editing agents handle these mistakes in one of two broken ways. Either the agent overwrites the file in place, which no SOC lead will ever allow on a production runbook, or it dumps a wall of critique into a chat window, forcing the human to hunt through a 15-page report and copy-paste fixes by hand.

Google Docs API v1 recently added two features that let an agent act like a senior peer reviewer red-lining a draft:

- **Native anchored comments via `insertComment`.** Earlier workarounds had to call the Google Drive API v3 `comments.create` endpoint, which attaches comments at the file level without reliable character-range anchoring inside the document body. Docs API v1 `batchUpdate` now accepts an `insertComment` request with an explicit `startIndex` and `endIndex`, binding the comment highlight to the exact command or UDM field under review.
- **Suggested edits via `writeControl.writeMode = "SUGGEST"`.** When a `batchUpdate` request includes `"writeControl": {"writeMode": "SUGGEST"}`, standard `deleteContentRange` and `insertText` operations do not overwrite the document. Google Docs records them as green insertion spans and pink strikethrough deletion spans with native Accept and Reject buttons in the margin.

```mermaid
flowchart LR
    subgraph Sources["Two-source epistemic grounding"]
        DK["Developer Knowledge MCP\ndeveloperknowledge.googleapis.com/mcp\nChronicle UDM + gcloud IAM"]
        WS["web_search_verifier\nAgentTool + google_search\nMITRE ATT&CK + CVEs"]
    end

    subgraph Agent["ADK 2.7.1 SOC review workflow"]
        RD["1. read_google_doc\nBuild 1-based UTF-16 map"]
        CM["2. insert_doc_comments\nAnchor citations pre-edit"]
        SE["3. propose_doc_suggested_edits\nBack-to-front writeMode=SUGGEST"]
    end

    subgraph Workspace["Google Drive & Docs API v1"]
        DOC["Postmortem & Runbook Doc\nAnalyst clicks Accept or Reject"]
    end

    DOC --> RD
    RD --> DK
    RD --> WS
    DK --> CM
    WS --> CM
    CM --> SE
    SE --> DOC
```

This also solves a governance problem we hit in our earlier evolutionary runbook optimization work. When an automated evaluator discovers that a runbook needs a pre-flight check for RFC-5737 documentation subnets or internal vulnerability scanners to prevent a $50,000 false-positive host isolation, you still need a human gate before mutating the production playbook. Staging that mutation as a Google Docs Suggested Edit with an anchored comment citing the incident postmortem gives the detection lead a one-click approval workflow.

---

## Five engineering problems under the hood

Wiring an ADK agent to Google Docs and two grounding sources surfaced five concrete engineering problems across security boundaries, Unicode indexing, and the ADK 2.7.1 runtime.

### 1. Dual-identity OAuth to prevent confused-deputy exfiltration of breach docs

In a security operations center, the `SOC Reports` folder holds some of the most sensitive documents in the company, including active breach timelines, unredacted command-line arguments, and legally privileged findings.

A naive architecture grants a single backend service account read and write access to every incident Google Doc. That creates a classic confused-deputy vulnerability. SOC agents routinely ingest untrusted attacker-controlled strings from SIEM telemetry, such as crafted `principal.process.command_line` values, HTTP user agents, and phishing email bodies. If an indirect prompt injection inside a log event tricks the agent into reading another incident document and copying its contents into the current case comment, a backend service account with broad Drive permissions gives the attacker access to every breach report in the organization.

To close that blast radius, `resolve_docs_token` in `multi-agent/manager/tools/docs_review_tools.py` implements a dual-identity model:

- **Backend service account ADC for model and public docs.** Vertex AI model calls using `roles/aiplatform.user` and queries to the public Developer Knowledge MCP server use the backend environment credentials, which hold zero permissions on confidential Google Docs when deployed in multi-user mode.
- **Per-user OAuth token for Google Docs operations.** When an analyst runs a review session, their short-lived OAuth 2.0 access token is placed in `tool_context.state["user_access_token"]`. Every `read_google_doc`, `insert_doc_comments`, and `propose_doc_suggested_edits` call authenticates with that user token first, falling back to local ADC only for single-operator CLI testing.

Because Google Docs enforces ACLs against the analyst's own identity, the agent cannot open a single postmortem the logged-in responder is not authorized to read. Every suggested edit and comment in the Google Docs audit trail is also attributed to the human session that triggered it.

### 2. Two-source epistemic grounding and the Gemini tool-mixing constraint

An agent that checks a `gcloud` command or a Chronicle UDM field using only its training weights will hallucinate flags or revert new syntax back to pre-cutoff patterns. Conversely, relying only on public web search often surfaces outdated blog posts or forum threads over canonical documentation.

We route verification across two grounding tools based on domain:

- **Google Developer Knowledge Remote MCP Server.** Hosted at `https://developerknowledge.googleapis.com/mcp`, this managed Streamable HTTP MCP server exposes `search_documents`, `get_documents`, and `answer_query` over Google's official documentation corpus. That corpus includes both the Google Cloud IAM documentation under `docs.cloud.google.com/iam/docs` and the Google SecOps Chronicle UDM reference at `docs.cloud.google.com/chronicle/docs/reference/udm-field-list`.
- **Google Search Grounding for external security standards.** For MITRE ATT&CK technique definitions, NVD CVE advisories, CISA KEV dates, and AWS or Okta CLI syntax, the agent routes queries to Google Search.

Here we hit a hard constraint in the Gemini API. Built-in `google_search` is a model-internal grounding tool that cannot be combined in the same `tools=[...]` list alongside custom `FunctionTool` declarations or `McpToolset` instances on a single `Agent`. Passing both causes the API to reject the request.

We bypass that constraint in `multi-agent/manager/tools/grounding_tools.py` by isolating `google_search` inside a child `Agent` wrapped in ADK's `AgentTool`:

```python
from google.adk.agents import Agent
from google.adk.tools import google_search
from google.adk.tools.agent_tool import AgentTool

web_search_verifier_agent = Agent(
    name="web_search_verifier",
    model="gemini-2.5-flash",
    instruction="Verify non-Google technical claims using Google Search and return URLs.",
    tools=[google_search],
)

web_search_tool = AgentTool(agent=web_search_verifier_agent)
```

To the parent SOC orchestrator, `web_search_verifier` looks like a standard function tool accepting `{"request": "..."}`. Calling it executes an isolated child model call where `google_search` runs on its own.

### 3. Translating LLM quotes into 1-based UTF-16 Google Docs indices

LLMs cannot reliably count character offsets across a long postmortem. Asking a model to output raw integer indices guarantees off-by-one corruption that slices words in half. Instead, our tools require the LLM to pass exact quoted substrings like `{"quote": "process.command_line", "replacement": "target.process.command_line"}`, while deterministic Python code resolves those quotes into Google Docs API v1 coordinates.

Even in Python, mapping `str.find(quote)` directly to Google Docs indices fails whenever a postmortem includes a MITRE ATT&CK table or a non-BMP Unicode character:

- **Google Docs indices are 1-based UTF-16 code units.** Python 3 strings index by Unicode code points. Any character outside the Basic Multilingual Plane takes 1 index in a Python `str`, but 2 UTF-16 code units in Google Docs.
- **Tables nest structural elements.** Text inside a Google Doc table does not sit under top-level `paragraph` elements; it sits inside `table.tableRows[].tableCells[].content[].paragraph`.

In `multi-agent/manager/tools/docs_review_tools.py`, `_extract_text_and_index_map` walks `tabs[0].documentTab.body.content` recursively across paragraphs and table cells, stepping the Google Docs index by `len(ch.encode("utf-16-le")) // 2` for every character:

```python
def _utf16_code_units(ch: str) -> int:
    return len(ch.encode("utf-16-le")) // 2
```

When `read_google_doc` runs, it caches both the plain text and the `list[int]` mapping each Python character position to its 1-based UTF-16 Google Docs `startIndex`. For a match spanning `pos` through `last_pos = pos + len(quote) - 1`, its exact Docs range is:

```python
start_idx = index_map[pos]
end_idx = index_map[last_pos] + _utf16_code_units(plain_text[last_pos])
```

### 4. Comments before edits, and back-to-front batching

Once you have exact UTF-16 ranges from `read_google_doc`, two ordering bugs will still corrupt your `batchUpdate` calls if you are not careful.

**First, comments must be inserted before suggested edits.** It is easy to assume that because `propose_doc_suggested_edits` uses `"writeMode": "SUGGEST"`, the document's character indices stay frozen until a human clicks Accept. That is false. A suggested replacement inserts the new text into the document body immediately with `suggestedInsertionIds` alongside the old text marked with `suggestedDeletionIds`. The moment a suggested edit is applied, every character offset after that point shifts, invalidating the cached `doc_index_map`. Running `insert_doc_comments` first and `propose_doc_suggested_edits` second ensures both operations use the pre-edit index map from `read_google_doc`.

**Second, suggested replacements must be sorted back-to-front.** In our `INC-2026-1011` smoke test, a single `propose_doc_suggested_edits` call applies four length-changing edits across the document:

1. Replacing the 33-character string `"T1059.003 (Windows Command Shell)"` with the 22-character string `"T1059.001 (PowerShell)"`, shrinking the text by 11 characters.
2. Replacing the 45-character URL `"https://login-micros0ft-update.com/stage2.ps1"` with the 47-character defanged URL `"hxxps://login-micros0ft-update[.]com/stage2.ps1"`, growing the text by 2 characters.
3. Replacing the 20-character field `"process.command_line"` with the 27-character field `"target.process.command_line"`, growing the text by 7 characters.
4. Replacing the 34-character command `"gcloud iam service-accounts delete"` with the 35-character command `"gcloud iam service-accounts disable"`, growing the text by 1 character.

Because `batchUpdate` executes requests sequentially inside the array, applying those edits from top to bottom would shift every subsequent target range off its intended words. Sorting validated, non-overlapping edits in descending order by `startIndex` eliminates index drift completely:

```python
resolved_edits.sort(key=lambda item: item[0], reverse=True)

requests_list = []
for start_idx, end_idx, replacement in resolved_edits:
    requests_list.append(
        {"deleteContentRange": {"range": {"startIndex": start_idx, "endIndex": end_idx}}}
    )
    if replacement:
        requests_list.append(
            {"insertText": {"location": {"index": start_idx}, "text": replacement}}
        )
```

Because every edit in the batch mutates text strictly closer to the end of the document than the edits that follow it, earlier `startIndex` values never move.

### 5. An ADK 2.7.1 `McpToolset` bug with `header_provider` and session pooling

Connecting ADK's `McpToolset` to authenticated remote MCP servers like `drivemcp.googleapis.com` and `developerknowledge.googleapis.com` surfaced a bug in `google-adk==2.7.1` worth noting for anyone building with remote MCP servers.

Many ADK examples pass `header_provider` to `McpToolset` to inject per-request headers. We hit two failures with `header_provider` in ADK 2.7.1:

1. **Startup discovery skips `header_provider`.** When a server boots or builds an A2A Agent Card, ADK calls `McpToolset.get_tools(readonly_context=None)`. When `readonly_context` is `None`, `McpToolset.get_tools` skips `header_provider` entirely, sending an unauthenticated `tools/list` request.
2. **Direct tool execution with `tool_context=None` crashes.** In `google/adk/tools/mcp_tool/mcp_tool.py` at line 434, `McpTool._run_async_impl` checks `if self._header_provider:` and unconditionally evaluates `ReadonlyContext(tool_context._invocation_context)` without checking whether `tool_context` is `None`. Calling `mcp_tool.run_async(args=..., tool_context=None)` in a test or CLI script immediately raises `AttributeError: 'NoneType' object has no attribute '_invocation_context'`.

In addition, ADK's `MCPSessionManager` pools sessions keyed by a hash of the static `StreamableHTTPConnectionParams.headers` dictionary. Putting a rotating OAuth bearer token into static headers changes the hash on every token refresh and leaks sessions.

Our implementation in `multi-agent/manager/tools/grounding_tools.py` and `drive_tools.py` avoids `header_provider` completely. When authenticating with Application Default Credentials using an OAuth bearer token and `X-Goog-User-Project`, we leave `StreamableHTTPConnectionParams.headers` empty and pass a custom `httpx_client_factory` backed by `_BearerAndProjectAuth`. Because `httpx.Auth.auth_flow` signs each outgoing HTTP request at the transport layer, ADK sees stable connection parameters for session pooling, startup `get_tools(readonly_context=None)` is authenticated, and `run_async(args=..., tool_context=None)` never triggers the `NoneType` crash in `mcp_tool.py`.

---

## Live verification on an `INC-2026-1011` postmortem and runbook

We ran `scripts/grounded_docs_smoke_test.py` against our `dandye-0324-chronicle` Argolis environment to test the full SecOps red-lining workflow end to end:

```bash
WORKTREE_DIR="/usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/drive-mcp-runbooks__grounded-docs"
ACCOUNT="admin@dandye.altostrat.com"
PROJECT_ID="dandye-0324-chronicle"

direnv exec "$WORKTREE_DIR" gcloud auth login "$ACCOUNT" --enable-gdrive-access --update-adc
direnv exec "$WORKTREE_DIR" "$WORKTREE_DIR/.venv/bin/python" "$WORKTREE_DIR/scripts/grounded_docs_smoke_test.py" --create-review-doc
```

Here is what happened on the wire during the live run:

1. **Developer Knowledge MCP resolved canonical IAM and Chronicle UDM docs via ADC.** Using standard Application Default Credentials without an API key, `search_documents` resolved `https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable` for the service account containment check and `https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list` for the UDM field check.
2. **Created and indexed the postmortem Google Doc.** `create_google_doc` created [`INC_2026_1011_Postmortem_and_Runbook_Redline`](https://docs.google.com/document/d/18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI/edit) with document ID `18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI` in `SOC Reports`, and `read_google_doc` mapped all 813 UTF-16 character positions.
3. **Anchored four grounded SOC comments to exact Kix spans.** Inspecting `GET /drive/v3/files/18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI/comments` confirmed that all four review comments bound to native Kix anchors over the exact offending phrases:
   ```json
   [
     {
       "id": "AAACIbZVxNU",
       "anchor": "kix.jsub1u90xbjs",
       "quotedFileContent": { "value": "gcloud iam service-accounts delete" },
       "content": "High blast-radius containment warning: deleting a production service account destroys its unique resource ID and breaks Workload Identity bindings. Use reversible 'gcloud iam service-accounts disable' during triage (https://docs.cloud.google.com/iam/docs/service-accounts-disable-enable)."
     },
     {
       "id": "AAACIbZVxNQ",
       "anchor": "kix.plvnk95sibns",
       "quotedFileContent": { "value": "process.command_line" },
       "content": "Invalid Chronicle UDM field path: UDM requires an entity prefix such as target.process.command_line or principal.process.command_line (https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list)."
     },
     {
       "id": "AAACIbZVxNM",
       "anchor": "kix.4yir6x8defx",
       "quotedFileContent": { "value": "https://login-micros0ft-update.com/stage2.ps1" },
       "content": "Live C2 URL auto-linkifies in Google Docs and creates a click hazard for bridge reviewers. Defang indicator to hxxps:// and [.] before sharing."
     },
     {
       "id": "AAACIbZVxNI",
       "anchor": "kix.9t5839q3lmou",
       "quotedFileContent": { "value": "T1059.003 (Windows Command Shell)" },
       "content": "MITRE ATT&CK mismatch: powershell.exe -enc payloads map to T1059.001 (PowerShell), not T1059.003 (cmd.exe) (https://attack.mitre.org/techniques/T1059/001/)."
     }
   ]
   ```
4. **Applied all four back-to-front `writeMode="SUGGEST"` edits without character drift.** Inspecting `GET /v1/documents/18lUrLtd42tlxAh3SDuHBZHDdYi0JEORGjiaIfAYTlZI?includeTabsContent=true` confirmed that each deletion span paired cleanly with its insertion span across all four locations:
   - `suggest.5zryddz0zyff` replaces `"T1059.003 (Windows Command Shell)"` with `"T1059.001 (PowerShell)"`.
   - `suggest.pvuzeec7wbe` defangs `"https://login-micros0ft-update.com/stage2.ps1"` to `"hxxps://login-micros0ft-update[.]com/stage2.ps1"`.
   - `suggest.du136hpq9scc` corrects `"process.command_line"` to `"target.process.command_line"`.
   - `suggest.m31glb161cw6` changes `"gcloud iam service-accounts delete"` to `"gcloud iam service-accounts disable"`.

---

## Closing the postmortem-to-runbook loop

With runbooks stored in Google Drive, incident reports published to Google Docs, and verification grounded against Developer Knowledge MCP and Google Search, the postmortem graveyard disappears.

When an incident commander finishes a postmortem, the review agent can audit the report for live C2 links, broken UDM syntax, and dangerous containment commands before the document leaves the SOC. Better yet, the agent can open the matching playbook in `SOC Runbooks` and stage the lessons learned from the incident as non-destructive Suggested Edits. The detection lead reviews the red-lined Google Doc over morning coffee, clicks Accept on the changes that hold up, and `DriveSkillRegistry` serves the hardened runbook on the next alert.
