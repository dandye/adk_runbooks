# AG-UI Prototype

A static HTML/JS/CSS mock of a SecOps HITL (human-in-the-loop) approval interface,
delegation graph, IOC enrichment card, YARA-L rule sandbox, and IRP tracker.

By default this runs **fully simulated** — every button works with no backend at
all, using hardcoded demo data. It can also connect to the real ADK `manager`
agent (`multi-agent/manager/`) and its live SIEM/SOAR/GTI (VirusTotal) MCP
tools, if you run one.

## Running simulated (no setup)

Just open `index.html`, or serve the directory with any static file server:

```bash
cd ag-ui-prototype
python3 -m http.server 5500
# open http://localhost:5500
```

The protocol badge in the header will read **SIMULATED — no live agent backend
connected**.

## Running live, against the real agent

### 1. Check out the MCP tool servers submodule

```bash
git submodule update --init external/mcp-security
```

### 2. Configure credentials

Two separate `.env` files are needed — don't skip either one:

- **`multi-agent/manager/.env`** — auto-loaded by the ADK CLI from the agent's
  own folder, for the root agent's own Gemini calls. Without this, `adk web`
  can start but the agent itself can't respond at all.
  ```
  GOOGLE_API_KEY=...
  GOOGLE_GENAI_USE_VERTEXAI=FALSE
  ```
  (`GEMINI_API_KEY` also works as a fallback per the underlying `google-genai`
  SDK, but this repo's own `.env.example` uses `GOOGLE_API_KEY` — stick with
  that rather than mixing the two.)

- **`external/mcp-security/.env`** — passed explicitly via `--env-file` to
  each of the three MCP subprocesses (SIEM/SOAR/GTI) that `tools.py` spawns.
  ```
  SOAR_APP_KEY=...
  SOAR_URL=...
  VT_APIKEY=...
  CHRONICLE_REGION=...
  CHRONICLE_PROJECT_ID=...
  CHRONICLE_CUSTOMER_ID=...
  ```

Simplest approach: copy `multi-agent/manager/.env.example` (it already lists
all of the above in one file) to both locations and fill in real values.

### 3. Install `google-adk` and start the agent backend

```bash
cd multi-agent
uv pip install -r requirements.txt   # or: pip install google-adk==1.28.1 (see requirements.txt)
adk web --allow_origins http://localhost:5500
```

`--allow_origins` must match wherever you serve `ag-ui-prototype/` from (see
below) — the ADK dev server has no CORS enabled by default, so without this
flag every fetch from the browser will be blocked. Default port is 8000.

### 4. Serve the frontend and point it at the backend

```bash
cd ag-ui-prototype
python3 -m http.server 5500
```

If the backend runs on a different host/port than `http://localhost:8000`,
set it before `app.js` loads — add this line to `index.html` right before the
`<script src="app.js">` tag:

```html
<script>window.ADK_API_BASE = "http://localhost:8000";</script>
```

Open `http://localhost:5500`. The protocol badge should read **LIVE —
connected to "manager" agent**. If it still says SIMULATED, open the browser
console — `adkInit()` logs the actual connection failure there.

## What's actually real vs. simulated, per button

| UI action | When live | Real tool it maps to |
|---|---|---|
| Approve & Execute Action (scenario 2: deploy rule) | Real | `create_rule` (Chronicle SIEM) |
| Approve & Execute Action (scenario 3: bulk close) | Real | `siemplify_close_alert` / `siemplify_close_case` |
| Approve & Execute Action (scenario 1: isolate + block C2) | Partially real | IP block → `google_chronicle_add_values_to_reference_list`. **Host isolation has no real tool in the current SOAR integration set** (see below) — the agent is instructed to say so rather than silently pretend it happened. |
| Reject Action | Real | No tool call — sends your feedback back to the agent as a new turn |
| Pivot UDM Log Search / Delegate to Threat Hunter | Real | `search_security_events` (Chronicle SIEM) |
| Block IOC at Perimeter Firewall | Real | `google_chronicle_add_values_to_reference_list` |
| Run Synthetic Event Test | Real, but reframed | No synthetic-log-injection tool exists; this calls `validate_rule` (syntax check) instead of literally injecting test events |
| Deploy Rule to Google SecOps | Real | `create_rule` |
| Tune Rule Logic, Update Parameters | Simulated only | No corresponding tool either way |

**Why host isolation isn't real:** `multi-agent/manager/tools/tools.py` starts
the SOAR MCP server with `--integrations CSV,GoogleChronicle,Siemplify,SiemplifyUtilities`.
None of those four integrations expose an EDR/firewall host-quarantine action —
that would require enabling a marketplace integration like `crowdstrikefalcon`
or `paloaltonextgenfirewall` (with its own separate credentials) in that same
`--integrations` list. That's a deliberate config change for whoever runs this,
not something this prototype does on your behalf.

## Safety

**"Live" mode makes real write calls** against whatever Chronicle/SOAR/VT
tenant your `.env` points to: it can add IPs to production reference lists,
create and enable live detection rules, and close real cases/alerts. Point
`.env` at a sandbox/test tenant unless you specifically intend to act on
production. There is no confirmation dialog beyond the existing Approve/Reject
flow — the persistent LIVE badge in the header is the only standing indicator
that clicks are real.

## Known limitations

This client (`app.js`'s `adkInit`/`adkSendMessage`/`summarizeAdkEvents`) was
written by reading the `google-adk` server source (the exact pinned version,
`1.28.1`, wasn't installable in the environment that wrote this — a newer
2.0.0 install elsewhere was used as reference for the API shape), not by
testing against a running instance with real credentials. If session creation
or `/run` response parsing doesn't work as expected against your real backend:

- Check the browser console — every failure is logged via `console.warn`.
- Real events always land in the right-hand event stream panel as raw JSON
  (`tool_calls` / `tool_responses` / `agent_summary`) even if the UI text
  elsewhere looks off, so you can see exactly what the API actually returned
  and adjust `summarizeAdkEvents()`'s key lookups in `app.js` accordingly.
