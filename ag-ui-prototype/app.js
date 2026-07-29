// AG-UI Protocol Simulated Event Stream & HITL Remediation Approval Component Logic

const scenarios = {
  scenario1: {
    id: "scenario1",
    incidentId: "INC-2026-9042",
    agentName: "Incident Responder Sub-Agent",
    actionType: "isolate_host_and_block_c2",
    title: "Isolate Compromised Host & Block C2 IP",
    subtitle: "High confidence malware C2 beaconing detected from internal host",
    severity: "CRITICAL",
    entityName: "prod-db-gateway-01",
    entityIp: "192.168.1.105",
    entityMac: "00:1B:44:11:3A:B7",
    c2Ip: "198.51.100.42",
    threatIntel: "VirusTotal score 64/72 (Malicious). C2 IP: 198.51.100.42 (Emotet Infrastructure)",
    mitreTtp: "T1059.001 (PowerShell Execution), T1071.001 (Web Protocols C2)",
    defaultParams: {
      isolationScope: "full_network_isolation",
      durationHours: "4",
      preserveRam: true,
      notifySOCLead: true,
      firewallPriority: "100"
    },
    payloadBefore: {
      "host_status": "ACTIVE",
      "network_access": "UNRESTRICTED",
      "egress_firewall_rules": [
        "ALLOW 0.0.0.0/0 ANY"
      ]
    },
    payloadAfter: {
      "host_status": "ISOLATED",
      "network_access": "FORENSIC_ONLY",
      "egress_firewall_rules": [
        "DENY 198.51.100.42/32 ALL (Rule ID: AG-FW-9042)",
        "ALLOW 10.0.0.0/8 PORT 8443 (Forensic Agent Server)"
      ]
    },
    mcpToolCall: "secops_execute_action(action='isolate_host', asset='prod-db-gateway-01', c2_ip='198.51.100.42')"
  },

  scenario2: {
    id: "scenario2",
    incidentId: "INC-2026-8812",
    agentName: "Detection Engineer Sub-Agent",
    actionType: "deploy_yaral_rule",
    title: "Deploy New YARA-L Detection Rule",
    subtitle: "Automated rule generated to detect privilege escalation attempt via token impersonation",
    severity: "HIGH",
    entityName: "secops-tenant-prod",
    entityIp: "Global Chronicle Instance",
    entityMac: "N/A",
    threatIntel: "Threat Intel Campaign: APT29 Token Abuse pattern identified in recent CTI report",
    mitreTtp: "T1134.001 (Token Impersonation/Dual Privilege)",
    defaultParams: {
      ruleState: "ENABLED",
      alertSeverity: "HIGH",
      deduplicationWindow: "10m",
      notifySOCLead: false,
      firewallPriority: "N/A"
    },
    payloadBefore: {
      "rule_id": "ru_new_draft_8812",
      "status": "DRAFT_UNTESTED",
      "rule_text": "// Rule pending deployment validation"
    },
    payloadAfter: {
      "rule_id": "ru_apt29_token_impersonation_v1",
      "status": "LIVE_ENABLED",
      "rule_text": "rule apt29_token_impersonation {\n  meta:\n    author = \"Detection Engineer Agent\"\n    severity = \"HIGH\"\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n    $e.target.user.attribute = \"ELEVATED\"\n  condition:\n    $e\n}"
    },
    mcpToolCall: "secops_create_rule(rule_name='apt29_token_impersonation', status='ENABLED')"
  },

  scenario3: {
    id: "scenario3",
    incidentId: "INC-2026-7491",
    agentName: "SOC Analyst Tier 1 Sub-Agent",
    actionType: "bulk_close_cases",
    title: "Bulk Close False Positive Security Alerts",
    subtitle: "Deduplicated 42 low-confidence port scan alerts triggered by scheduled scanner",
    severity: "MEDIUM",
    entityName: "scanner-vault-internal",
    entityIp: "10.0.4.12",
    entityMac: "52:54:00:12:34:56",
    threatIntel: "Whitelisted Internal Asset: Vulnerability Scanner (Approved Maintenance Window)",
    mitreTtp: "T1046 (Network Service Discovery)",
    defaultParams: {
      closeReason: "FALSE_POSITIVE",
      rootCause: "Approved Vulnerability Scan",
      preserveRam: false,
      notifySOCLead: false,
      firewallPriority: "N/A"
    },
    payloadBefore: {
      "active_alert_count": 42,
      "case_status": "OPEN_UNASSIGNED"
    },
    payloadAfter: {
      "active_alert_count": 0,
      "case_status": "CLOSED_RESOLVED",
      "resolution_comment": "Bulk closed by Tier 1 Agent after verifying maintenance schedule"
    },
    mcpToolCall: "secops_execute_bulk_close_case(case_ids=['CASE-7491-1'...'CASE-7491-42'])"
  }
};

let currentScenarioKey = 'scenario1';
let currentTab = 'summary';
let eventsLog = [];

// Handles for in-flight setTimeout-based simulations, so a reset or a
// repeat click can cancel work that's still pending instead of letting it
// land later and silently overwrite whatever the user triggered next.
let pendingTimers = [];

function scheduleTimeout(fn, delay) {
  const id = setTimeout(fn, delay);
  pendingTimers.push(id);
  return id;
}

function clearPendingTimers() {
  pendingTimers.forEach(id => clearTimeout(id));
  pendingTimers = [];
}

// ============================================================
// Live ADK Agent Backend (optional)
// ============================================================
// Talks to a running `adk web --allow_origins <this-page's-origin>` process
// (google-adk==1.28.1, per multi-agent/requirements.txt), started from the
// `multi-agent/` directory, which exposes the `manager` root agent and its
// real SIEM/SOAR/GTI MCP tools over HTTP. See ag-ui-prototype/README.md for
// exact run instructions and required .env vars.
//
// This client was written by reading the ADK FastAPI server source, not by
// testing against a live instance with real credentials -- if the session
// or /run contract differs in practice, adkInit()/adkSendMessage() log the
// failure via console.warn and the UI falls back to the pre-existing
// simulated behavior rather than breaking. Every button below still works
// standalone with no backend running at all.
//
// SAFETY: with the SOAR integrations currently enabled in
// multi-agent/manager/tools/tools.py (CSV, GoogleChronicle, Siemplify,
// SiemplifyUtilities), there is no host-isolation/EDR tool wired in. "Block
// C2 IP" has a real backing action (Chronicle reference-list management);
// "isolate host" does not, by design of what's configured -- the agent is
// instructed to say so rather than silently no-op. Adding a real
// host-isolation integration is a deliberate config change in tools.py,
// not something this prototype does on your behalf.
const ADK_CONFIG = {
  baseUrl: (typeof window !== 'undefined' && window.ADK_API_BASE) || 'http://localhost:8000',
  appName: 'manager',
  userId: 'ag-ui-analyst'
};

let adkSessionId = null;
let adkLive = false;

async function adkInit() {
  const sessionId = 'ag-ui-' + Math.floor(Math.random() * 1e9);
  try {
    const res = await fetch(
      `${ADK_CONFIG.baseUrl}/apps/${ADK_CONFIG.appName}/users/${ADK_CONFIG.userId}/sessions/${sessionId}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      }
    );
    if (!res.ok) throw new Error(`session create failed: HTTP ${res.status}`);
    adkSessionId = sessionId;
    adkLive = true;
  } catch (err) {
    adkLive = false;
    console.warn('[adk] live backend unavailable, staying in simulated mode:', err.message);
  }
  updateLiveModeBadge();
}

function updateLiveModeBadge() {
  const badge = document.getElementById('protocolBadge');
  if (!badge) return;
  badge.textContent = '';
  badge.classList.toggle('protocol-badge-live', adkLive);
  badge.classList.toggle('protocol-badge-sim', !adkLive);

  const dot = document.createElement('span');
  dot.className = 'status-dot';
  const label = document.createElement('span');
  label.textContent = adkLive
    ? `LIVE — connected to "${ADK_CONFIG.appName}" agent`
    : 'SIMULATED — no live agent backend connected';

  badge.appendChild(dot);
  badge.appendChild(label);
}

// Sends `text` as one user turn to the live agent. Never throws -- callers
// must check `.ok` and fall back to simulated behavior when it's false.
async function adkSendMessage(text, { timeoutMs = 45000 } = {}) {
  if (!adkLive || !adkSessionId) return { ok: false, reason: 'not_live' };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${ADK_CONFIG.baseUrl}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        app_name: ADK_CONFIG.appName,
        user_id: ADK_CONFIG.userId,
        session_id: adkSessionId,
        new_message: { role: 'user', parts: [{ text }] }
      })
    });
    clearTimeout(timer);

    if (!res.ok) {
      const bodyText = await res.text().catch(() => '');
      console.warn('[adk] /run returned', res.status, bodyText);
      return { ok: false, reason: 'http_error', status: res.status };
    }

    const events = await res.json();
    return { ok: true, events, ...summarizeAdkEvents(events) };
  } catch (err) {
    clearTimeout(timer);
    const reason = err.name === 'AbortError' ? 'timeout' : 'network_error';
    console.warn('[adk] /run failed:', reason, err);
    return { ok: false, reason };
  }
}

// Best-effort extraction across the ADK Event/Content schema. Tolerant of
// snake_case/camelCase key variants since this was written from the ADK
// server source, not a captured live response -- if fields come back empty
// against a real backend, check the browser console (raw events are always
// logged to the event stream regardless) and adjust the key lookups here.
function summarizeAdkEvents(events) {
  const toolCalls = [];
  const toolResponses = [];
  let finalText = '';

  if (!Array.isArray(events)) return { toolCalls, toolResponses, finalText };

  for (const evt of events) {
    const content = evt && (evt.content || evt.Content);
    const parts = content && (content.parts || content.Parts);
    if (!Array.isArray(parts)) continue;

    for (const part of parts) {
      const fc = part.functionCall || part.function_call;
      if (fc) toolCalls.push({ name: fc.name, args: fc.args || fc.arguments });

      const fr = part.functionResponse || part.function_response;
      if (fr) toolResponses.push({ name: fr.name, response: fr.response });

      if (typeof part.text === 'string' && part.text.trim()) {
        finalText = part.text; // last text part wins -- typically the agent's closing summary
      }
    }
  }
  return { toolCalls, toolResponses, finalText };
}

function renderAdkResult(eventName, result) {
  logAgUiEvent(eventName, {
    live: true,
    tool_calls: result.toolCalls,
    tool_responses: result.toolResponses,
    agent_summary: result.finalText
  });
}

function setButtonBusy(btnId, busyLabel) {
  const btn = document.getElementById(btnId);
  if (!btn) return () => {};
  const original = btn.innerText;
  btn.disabled = true;
  btn.innerText = busyLabel;
  return () => {
    btn.disabled = false;
    btn.innerText = original;
  };
}

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  renderScenarioSelectors();
  loadScenario(currentScenarioKey);
  setupTabListeners();
  selectGraphNode('ir');
  updateAdvanceIrpButtonLabel();
  adkInit();
}

function renderScenarioSelectors() {
  const container = document.getElementById('scenarioList');
  if (!container) return;

  container.innerHTML = Object.keys(scenarios).map(key => {
    const s = scenarios[key];
    const badgeClass = s.severity === 'CRITICAL' ? 'badge-critical' : (s.severity === 'HIGH' ? 'badge-high' : 'badge-medium');
    const isActive = key === currentScenarioKey ? 'active' : '';
    return `
      <div class="scenario-card ${isActive}" onclick="switchScenario('${key}')">
        <div class="scenario-header">
          <span class="scenario-agent">${s.agentName}</span>
          <span class="badge ${badgeClass}">${s.severity}</span>
        </div>
        <div class="scenario-title">${s.title}</div>
        <div class="scenario-desc">${s.subtitle}</div>
      </div>
    `;
  }).join('');
}

function switchScenario(key) {
  currentScenarioKey = key;
  renderScenarioSelectors();
  loadScenario(key);
}

function loadScenario(key) {
  const s = scenarios[key];
  
  // Set text values
  document.getElementById('cardIncidentId').innerText = s.incidentId;
  document.getElementById('cardAgentName').innerText = s.agentName;
  document.getElementById('cardActionType').innerText = s.actionType;
  document.getElementById('cardMainTitle').innerText = s.title;
  document.getElementById('cardSubtitle').innerText = s.subtitle;
  
  document.getElementById('entityName').innerText = s.entityName;
  document.getElementById('entityIp').innerText = s.entityIp;
  document.getElementById('entityMac').innerText = s.entityMac;
  
  document.getElementById('threatIntelText').innerText = s.threatIntel;
  document.getElementById('mitreTtpText').innerText = s.mitreTtp;

  // Set Payload Diff
  const diffBox = document.getElementById('payloadDiffBox');
  diffBox.innerHTML = `
<span class="diff-remove">- BEFORE: ${JSON.stringify(s.payloadBefore, null, 2)}</span>
<br/>
<span class="diff-add">+ AFTER (PROPOSED): ${JSON.stringify(s.payloadAfter, null, 2)}</span>
  `;

  // Set Form Parameters
  document.getElementById('paramDuration').value = s.defaultParams.durationHours || "4";
  document.getElementById('paramPreserveRam').checked = !!s.defaultParams.preserveRam;
  document.getElementById('paramNotifySOC').checked = !!s.defaultParams.notifySOCLead;

  // Clear rejection panel if open
  hideRejectionForm();
  resetStatusBanner();

  // Log AG-UI Event for scenario request
  logAgUiEvent('ag_ui.hitl_requested', {
    session_id: "ag-sess-" + Math.floor(Math.random() * 100000),
    agent: s.agentName,
    action_type: s.actionType,
    incident_id: s.incidentId,
    params: s.defaultParams,
    mcp_tool: s.mcpToolCall
  });
}

function setupTabListeners() {
  // Scoped to the HITL approval card only. The IOC Enrichment card has its
  // own .tab-btn elements (wired via switchIocTab's inline onclick) — a
  // document-wide querySelectorAll('.tab-btn') here previously matched both
  // tab systems, so clicking an IOC tab also ran this handler, which cleared
  // .active from every .tab-content on the page (including the HITL card's)
  // and then threw on getElementById(null) because IOC buttons have no
  // data-tab attribute.
  const scope = document.getElementById('approvalCardComponent');
  if (!scope) return;

  const tabs = scope.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      const targetId = e.target.getAttribute('data-tab');
      if (!targetId) return;
      const targetPanel = document.getElementById(targetId);
      if (!targetPanel) return;

      tabs.forEach(t => t.classList.remove('active'));
      scope.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      e.target.classList.add('active');
      targetPanel.classList.add('active');
    });
  });
}

// Builds the natural-language instruction sent to the live agent for an
// approved action. The agent (not this client) decides which real tool(s)
// to call -- see the SAFETY note above adkSendMessage's definition re:
// host isolation having no real backing tool in the current config.
function buildApprovalInstruction(s, params) {
  switch (s.actionType) {
    case 'isolate_host_and_block_c2':
      return `An analyst has approved containment for incident ${s.incidentId}. `
        + `Block C2 IP ${s.c2Ip} using whatever real IP-blocking capability you have available `
        + `(e.g. add it to the relevant Chronicle IP blocklist reference list). Separately, attempt to `
        + `isolate host ${s.entityName} (${s.entityIp}); if you do not have a real host-isolation or EDR tool `
        + `available, say so explicitly rather than treating it as done. Approved parameters: isolation `
        + `duration ${params.durationHours}h, preserve RAM: ${params.preserveRam}, notify SOC lead: ${params.notifySOCLead}.`;
    case 'deploy_yaral_rule':
      return `An analyst has approved deployment of this Chronicle YARA-L 2.0 detection rule for incident `
        + `${s.incidentId}. Create and enable it:\n\n${s.payloadAfter.rule_text}`;
    case 'bulk_close_cases':
      return `An analyst has approved bulk-closing the false-positive alerts for incident ${s.incidentId} `
        + `on asset ${s.entityName} (${s.entityIp}). Reason: approved vulnerability scan during a whitelisted `
        + `maintenance window. Close the related case/alerts accordingly.`;
    default:
      return `An analyst has approved the proposed action for incident ${s.incidentId}: ${s.title}.`;
  }
}

// Action Handlers
async function approveAction() {
  const s = scenarios[currentScenarioKey];
  const duration = document.getElementById('paramDuration').value;
  const preserveRam = document.getElementById('paramPreserveRam').checked;
  const notifySOC = document.getElementById('paramNotifySOC').checked;

  const updatedParams = {
    ...s.defaultParams,
    durationHours: duration,
    preserveRam: preserveRam,
    notifySOCLead: notifySOC
  };

  logAgUiEvent('ag_ui.action_approved', {
    status: "APPROVED_BY_ANALYST",
    session_id: "ag-sess-active",
    action_type: s.actionType,
    confirmed_params: updatedParams,
    timestamp: new Date().toISOString()
  });

  if (adkLive) {
    showStatusBanner('success', 'Action approved. Sending to live agent for execution...');
    const restoreButton = setButtonBusy('btnApproveAction', 'Sending to agent…');
    const result = await adkSendMessage(buildApprovalInstruction(s, updatedParams));
    restoreButton();

    if (result.ok) {
      renderAdkResult('ag_ui.mcp_tool_executed', result);
      showStatusBanner('success', result.finalText || `Live agent processed the approved action for ${s.mcpToolCall}.`);
      return;
    }
    showStatusBanner('danger', `Live agent call failed (${result.reason}) — falling back to simulated execution.`);
  } else {
    showStatusBanner('success', `Action Approved! Executing MCP Tool Call: ${s.mcpToolCall}`);
  }

  clearPendingTimers();
  // Simulate MCP Tool Execution after 1s
  scheduleTimeout(() => {
    logAgUiEvent('ag_ui.mcp_tool_executed', {
      mcp_tool: s.mcpToolCall,
      execution_status: "SUCCESS",
      result_code: 200,
      details: "Operation successfully applied to target asset. (SIMULATED — no live agent backend)"
    });
  }, 1000);
}

function toggleRejectionForm() {
  const panel = document.getElementById('rejectionFormPanel');
  const mainFooter = document.getElementById('mainCardFooter');
  if (panel.style.display === 'none' || !panel.style.display) {
    panel.style.display = 'flex';
    mainFooter.style.display = 'none';
  } else {
    hideRejectionForm();
  }
}

function hideRejectionForm() {
  const panel = document.getElementById('rejectionFormPanel');
  const mainFooter = document.getElementById('mainCardFooter');
  if (panel) panel.style.display = 'none';
  if (mainFooter) mainFooter.style.display = 'flex';
}

async function submitRejection() {
  const reason = document.getElementById('rejectionReasonInput').value;
  if (!reason) {
    alert('Please enter a feedback message for the agent.');
    return;
  }

  const s = scenarios[currentScenarioKey];

  logAgUiEvent('ag_ui.action_rejected', {
    status: "REJECTED_WITH_FEEDBACK",
    action_type: s.actionType,
    analyst_feedback: reason,
    timestamp: new Date().toISOString()
  });

  showStatusBanner('danger', `Action Rejected. Feedback sent to ${s.agentName}: "${reason}"`);
  hideRejectionForm();

  if (adkLive) {
    const restoreButton = setButtonBusy('btnConfirmRejection', 'Sending feedback…');
    const result = await adkSendMessage(
      `An analyst rejected your proposed action "${s.title}" for incident ${s.incidentId} with this feedback: `
      + `"${reason}". Re-evaluate and propose an alternative approach; do not execute the original action.`
    );
    restoreButton();
    if (result.ok) {
      renderAdkResult('ag_ui.agent_re-thinking', result);
      return;
    }
  }

  clearPendingTimers();
  // Simulate agent re-evaluation event
  scheduleTimeout(() => {
    logAgUiEvent('ag_ui.agent_re-thinking', {
      agent: s.agentName,
      thought: `Received analyst feedback "${reason}". Adjusting remediation strategy... (SIMULATED)`
    });
  }, 1200);
}

function modifyParameters() {
  const s = scenarios[currentScenarioKey];
  const duration = document.getElementById('paramDuration').value;
  const preserveRam = document.getElementById('paramPreserveRam').checked;
  const notifySOC = document.getElementById('paramNotifySOC').checked;

  const modifiedParams = {
    ...s.defaultParams,
    durationHours: duration,
    preserveRam: preserveRam,
    notifySOCLead: notifySOC
  };

  logAgUiEvent('ag_ui.parameters_modified', {
    status: "PARAMETERS_UPDATED",
    action_type: s.actionType,
    new_params: modifiedParams,
    timestamp: new Date().toISOString()
  });

  showStatusBanner('success', `Parameters updated. Sent modified plan to ${s.agentName}.`);
}

function showStatusBanner(type, message) {
  const banner = document.getElementById('statusBanner');
  banner.style.display = 'flex';
  banner.className = `status-banner ${type === 'success' ? 'status-banner-success' : 'status-banner-danger'}`;
  // message can contain analyst-entered text (rejection reason, etc.) — use
  // textContent, not innerHTML, so it can never be interpreted as markup.
  banner.textContent = '';
  const span = document.createElement('span');
  span.textContent = message;
  banner.appendChild(span);
}

function resetStatusBanner() {
  const banner = document.getElementById('statusBanner');
  if (banner) {
    banner.style.display = 'none';
  }
}

// AG-UI Protocol Logging Helper
function logAgUiEvent(eventName, payload) {
  const stream = document.getElementById('eventStream');
  if (!stream) return;

  const timeStr = new Date().toLocaleTimeString();
  const eventObj = {
    event: eventName,
    time: timeStr,
    data: payload
  };

  eventsLog.unshift(eventObj);

  // payload can carry analyst-entered text (rejection feedback, injected
  // directives, forensic notes) — JSON.stringify does not escape "<"/">",
  // so this is built with textContent/createElement rather than innerHTML
  // to rule out DOM XSS regardless of what payload contains.
  const eventCard = document.createElement('div');
  eventCard.className = 'event-card';

  const header = document.createElement('div');
  header.className = 'event-header';
  const nameSpan = document.createElement('span');
  nameSpan.className = 'event-name';
  nameSpan.textContent = eventName;
  const timeSpan = document.createElement('span');
  timeSpan.className = 'event-time';
  timeSpan.textContent = timeStr;
  header.appendChild(nameSpan);
  header.appendChild(timeSpan);

  const body = document.createElement('div');
  body.className = 'event-body';
  body.textContent = JSON.stringify(payload, null, 2);

  eventCard.appendChild(header);
  eventCard.appendChild(body);

  stream.insertBefore(eventCard, stream.firstChild);
}

// Multi-Agent Delegation Graph Interactive Logic (<AgentDelegationGraph />)
const nodeDetails = {
  manager: {
    role: "ROOT ORCHESTRATOR",
    title: "ADK Manager Agent",
    task: "Orchestrate incident triage, delegate sub-tasks to specialized sub-agents, and aggregate security evidence.",
    thinking: "[13:10:00] Initialized Manager Agent session ag-sess-9042\n[13:10:01] Received security alert INC-2026-9042\n[13:10:02] Delegating CTI lookup to CTI Researcher...\n[13:10:04] Delegating log search to SOC Tier 1...\n[13:10:06] Delegating containment plan to Incident Responder...",
    toolOutput: `{\n  "orchestration": "ACTIVE",\n  "delegated_subagents": ["cti", "soc", "ir", "de"],\n  "current_phase": "HITL_APPROVAL_WAIT"\n}`
  },
  cti: {
    role: "SUB-AGENT",
    title: "CTI Researcher Sub-Agent",
    task: "Query VirusTotal API and Threat Intelligence repository for C2 IP 198.51.100.42 reputation.",
    thinking: "[13:10:02] Received CTI search request for IP 198.51.100.42\n[13:10:03] Executed tool vt_ip_lookup(ip='198.51.100.42')\n[13:10:04] Found 64/72 malicious engines (Emotet C2)\n[13:10:04] Task completed. Returned evidence to Manager.",
    toolOutput: `{\n  "ip": "198.51.100.42",\n  "vt_malicious_score": 64,\n  "threat_family": "Emotet",\n  "confidence": "HIGH"\n}`
  },
  soc: {
    role: "SUB-AGENT",
    title: "SOC Analyst Tier 1 Sub-Agent",
    task: "Search Chronicle UDM logs for network connection events matching asset prod-db-gateway-01.",
    thinking: "[13:10:04] Received log search task for asset prod-db-gateway-01\n[13:10:05] Executed tool udm_search(target='prod-db-gateway-01')\n[13:10:06] Located 142 outbound socket connection events to C2 IP\n[13:10:06] Task completed. Returned UDM log summary.",
    toolOutput: `{\n  "asset": "prod-db-gateway-01",\n  "matching_events": 142,\n  "first_seen": "2026-07-29T12:45:00Z",\n  "protocol": "TCP/8443"\n}`
  },
  ir: {
    role: "SUB-AGENT",
    title: "Incident Responder Sub-Agent",
    task: "Synthesize containment parameters and trigger HITL approval for host isolation and firewall block.",
    thinking: "[13:10:06] Evaluating CTI & SOC evidence for prod-db-gateway-01\n[13:10:07] High threat severity detected - initiating host isolation plan\n[13:10:08] Emitted ag_ui.hitl_requested event to user interface...",
    toolOutput: `{\n  "proposed_action": "ISOLATE_HOST_AND_BLOCK_C2",\n  "target_asset": "prod-db-gateway-01",\n  "hitl_status": "WAITING_APPROVAL"\n}`
  },
  de: {
    role: "SUB-AGENT",
    title: "Detection Engineer Sub-Agent",
    task: "Generate YARA-L 2.0 detection rules based on verified TTPs and test against synthetic UDM logs.",
    thinking: "[13:10:08] Standing by for post-remediation detection rule synthesis.\n[13:10:09] Rule template pre-loaded for MITRE T1059.001.",
    toolOutput: `{\n  "status": "IDLE",\n  "ready_for_rule_gen": true,\n  "target_ttp": "T1059.001"\n}`
  }
};

let activeSelectedNodeKey = 'ir';

function selectGraphNode(nodeKey) {
  activeSelectedNodeKey = nodeKey;

  // Clear previous selection highlighting
  document.querySelectorAll('.agent-node').forEach(n => n.classList.remove('selected-node'));

  const nodeEl = document.getElementById(`node-${nodeKey}`);
  if (nodeEl) nodeEl.classList.add('selected-node');

  const info = nodeDetails[nodeKey];
  if (!info) return;

  document.getElementById('detailAgentRole').innerText = info.role;
  document.getElementById('detailAgentTitle').innerText = info.title;
  document.getElementById('detailTaskText').innerText = info.task;
  document.getElementById('detailThinkingText').innerText = info.thinking;
  document.getElementById('detailToolOutput').innerText = info.toolOutput;

  logAgUiEvent('ag_ui.node_inspected', {
    selected_node: nodeKey,
    agent_name: info.title,
    role: info.role
  });
}

function runDelegationSimulation() {
  // Cancel any still-pending steps from a previous run so overlapping
  // clicks can't interleave two simulations or resurrect a stale one after
  // a reset.
  clearPendingTimers();

  logAgUiEvent('ag_ui.delegation_started', {
    orchestrator: "ADK Manager Agent",
    incident_id: "INC-2026-9042",
    mode: "MULTI_AGENT_PARALLEL_EXECUTION"
  });

  // Step 1: Highlight CTI Researcher
  scheduleTimeout(() => {
    selectGraphNode('cti');
    logAgUiEvent('ag_ui.subagent_tool_executing', {
      agent: "CTI Researcher",
      tool: "vt_ip_lookup",
      status: "EXECUTING"
    });
  }, 600);

  // Step 2: Highlight SOC Tier 1
  scheduleTimeout(() => {
    selectGraphNode('soc');
    logAgUiEvent('ag_ui.subagent_tool_executing', {
      agent: "SOC Analyst Tier 1",
      tool: "udm_search",
      status: "EXECUTING"
    });
  }, 1400);

  // Step 3: Highlight Incident Responder
  scheduleTimeout(() => {
    selectGraphNode('ir');
    logAgUiEvent('ag_ui.subagent_hitl_triggered', {
      agent: "Incident Responder",
      action: "ISOLATE_HOST_AND_BLOCK_C2",
      status: "WAITING_APPROVAL"
    });
  }, 2200);

  // Step 4: Highlight Detection Engineer
  scheduleTimeout(() => {
    selectGraphNode('de');
    logAgUiEvent('ag_ui.delegation_completed', {
      status: "WORKFLOW_READY",
      active_node: "Incident Responder"
    });
  }, 3000);
}

function resetDelegationGraph() {
  clearPendingTimers();
  selectGraphNode('ir');
  logAgUiEvent('ag_ui.graph_reset', {
    status: "GRAPH_STATE_RESET"
  });
}

function pauseSubAgentTask() {
  const info = nodeDetails[activeSelectedNodeKey];
  logAgUiEvent('ag_ui.analyst_override', {
    action: "PAUSE_SUBAGENT",
    target_agent: info ? info.title : activeSelectedNodeKey,
    timestamp: new Date().toISOString()
  });
  alert(`Task paused for ${info ? info.title : activeSelectedNodeKey}. Sub-agent state held.`);
}

function openDirectiveModal() {
  const info = nodeDetails[activeSelectedNodeKey];
  const directive = prompt(`Enter manual directive / context override for ${info ? info.title : activeSelectedNodeKey}:`, "Perform deep PCAP packet capture before host isolation.");
  if (directive) {
    logAgUiEvent('ag_ui.analyst_override', {
      action: "INJECT_DIRECTIVE",
      target_agent: info ? info.title : activeSelectedNodeKey,
      directive: directive,
      timestamp: new Date().toISOString()
    });
    alert(`Directive injected into ${info ? info.title : activeSelectedNodeKey}'s context memory!`);
  }
}

// Component 3: Threat Intel & IOC Enrichment Card Interactive Logic (<IOCEnrichmentCard />)
// This card's body (VT score, hashes, passive DNS, MITRE chips) is static
// markup in index.html and is NOT re-rendered by loadScenario() when the
// sidebar scenario changes — it always reflects scenario1's Emotet C2
// incident. So its action buttons below intentionally read scenario1's
// data directly rather than `scenarios[currentScenarioKey]`, and they act
// on scenario1's C2 IP (the actual IOC this card enriches), not the
// currently-selected scenario's target *host* IP.
function switchIocTab(tabName) {
  const btnHashes = document.getElementById('iocTabBtnHashes');
  const btnDns = document.getElementById('iocTabBtnDns');
  const btnMitre = document.getElementById('iocTabBtnMitre');

  const tabHashes = document.getElementById('tabIocHashes');
  const tabDns = document.getElementById('tabIocDns');
  const tabMitre = document.getElementById('tabIocMitre');

  [btnHashes, btnDns, btnMitre].forEach(b => b && b.classList.remove('active'));
  [tabHashes, tabDns, tabMitre].forEach(t => t && t.classList.remove('active'));

  if (tabName === 'hashes') {
    if (btnHashes) btnHashes.classList.add('active');
    if (tabHashes) tabHashes.classList.add('active');
  } else if (tabName === 'dns') {
    if (btnDns) btnDns.classList.add('active');
    if (tabDns) tabDns.classList.add('active');
  } else if (tabName === 'mitre') {
    if (btnMitre) btnMitre.classList.add('active');
    if (tabMitre) tabMitre.classList.add('active');
  }
}

async function delegateToThreatHunter() {
  const ioc = scenarios.scenario1;
  logAgUiEvent('ag_ui.delegate_threat_hunt', {
    target_agent: "Threat Hunter Sub-Agent",
    target_ioc: ioc.c2Ip,
    incident_id: ioc.incidentId,
    directive: "Search all internal UDM logs across all organizational endpoints for matching IOC communication."
  });

  if (adkLive) {
    const restore = setButtonBusy('btnDelegateThreatHunter', 'Delegating…');
    const result = await adkSendMessage(
      `Search all internal Chronicle UDM logs across all endpoints for any communication with IOC ${ioc.c2Ip}.`
    );
    restore();
    if (result.ok) {
      renderAdkResult('ag_ui.delegate_threat_hunt_result', result);
      alert(result.finalText || `Live agent completed the threat-hunt search for ${ioc.c2Ip}.`);
      return;
    }
  }

  alert(`Delegated IOC threat hunt task for ${ioc.c2Ip} to Threat Hunter Sub-Agent. (SIMULATED)`);
}

async function pivotUdmSearch() {
  const ioc = scenarios.scenario1;
  logAgUiEvent('ag_ui.pivot_udm_search', {
    mcp_tool: "udm_search",
    query: `target.ip = "${ioc.c2Ip}" OR principal.ip = "${ioc.c2Ip}"`,
    timestamp: new Date().toISOString()
  });

  if (adkLive) {
    const restore = setButtonBusy('btnPivotUdmSearch', 'Searching…');
    const result = await adkSendMessage(
      `Search Chronicle UDM logs for events where target.ip or principal.ip is ${ioc.c2Ip}.`
    );
    restore();
    if (result.ok) {
      renderAdkResult('ag_ui.pivot_udm_search_result', result);
      alert(result.finalText || `Live agent completed the UDM search pivot for ${ioc.c2Ip}.`);
      return;
    }
  }

  alert(`Executing UDM search pivot for IOC ${ioc.c2Ip}... (SIMULATED)`);
}

async function blockIocPerimeter() {
  const ioc = scenarios.scenario1;
  logAgUiEvent('ag_ui.block_ioc_firewall', {
    action: "BLOCK_PERIMETER_IP",
    ioc: ioc.c2Ip,
    rule_id: `FW-BLOCK-${Math.floor(Math.random() * 9000 + 1000)}`
  });

  if (adkLive) {
    const restore = setButtonBusy('btnBlockIocPerimeter', 'Blocking…');
    const result = await adkSendMessage(
      `Add IP ${ioc.c2Ip} to the appropriate Chronicle IP blocklist reference list. This is a real, `
      + `production write action — confirm what list you added it to.`
    );
    restore();
    if (result.ok) {
      renderAdkResult('ag_ui.block_ioc_firewall_result', result);
      alert(result.finalText || `Live agent blocked IOC ${ioc.c2Ip}.`);
      return;
    }
  }

  alert(`Perimeter firewall rule created blocking IOC ${ioc.c2Ip}. (SIMULATED)`);
}

// Component 4: Detection Engineering Sandbox Logic (<DetectionEngineeringSandbox />)
async function runSyntheticRuleTest() {
  const ruleText = document.getElementById('ruleCodeText').textContent;

  if (adkLive) {
    const restore = setButtonBusy('btnRunSyntheticTest', 'Validating…');
    // There is no real "inject synthetic logs and count matches" tool in the
    // currently-enabled toolset -- the closest real capability is syntax
    // validation, so that's what actually gets asked for in live mode
    // rather than pretending a synthetic-simulation tool exists.
    const result = await adkSendMessage(
      `Validate the syntax of this YARA-L 2.0 rule and report any errors or warnings:\n\n${ruleText}`
    );
    restore();
    if (result.ok) {
      renderAdkResult('ag_ui.test_rule_synthetic', result);
      alert(result.finalText || 'Live agent validated the rule syntax.');
      return;
    }
  }

  logAgUiEvent('ag_ui.test_rule_synthetic', {
    rule_id: "ru_apt29_token_impersonation_v1",
    synthetic_events_injected: 14,
    matches_found: 12,
    precision_score: "85.7%",
    status: "SIMULATION_PASSED (SIMULATED)"
  });

  alert('Ran synthetic UDM log simulation test. 12 matches detected (85.7% precision). (SIMULATED)');
}

function tuneRuleParameters() {
  const newDeduplication = prompt("Enter updated deduplication window duration (e.g. 5m, 10m, 30m):", "15m");
  if (newDeduplication) {
    logAgUiEvent('ag_ui.tune_rule_parameters', {
      rule_id: "ru_apt29_token_impersonation_v1",
      updated_deduplication_window: newDeduplication,
      timestamp: new Date().toISOString()
    });
    alert(`Rule parameters updated. Set deduplication window to ${newDeduplication}.`);
  }
}

async function deployRuleToSecOps() {
  const ruleText = document.getElementById('ruleCodeText').textContent;

  if (adkLive) {
    const restore = setButtonBusy('btnDeployRule', 'Deploying…');
    const result = await adkSendMessage(
      `Create and enable this Chronicle YARA-L 2.0 detection rule:\n\n${ruleText}`
    );
    restore();
    if (result.ok) {
      renderAdkResult('ag_ui.deploy_rule_secops', result);
      alert(result.finalText || 'Live agent processed the rule deployment.');
      return;
    }
  }

  logAgUiEvent('ag_ui.deploy_rule_secops', {
    mcp_tool: "secops_create_rule",
    rule_name: "apt29_token_impersonation",
    status: "LIVE_ENABLED",
    chronicle_tenant: "secops-tenant-prod (SIMULATED)"
  });

  alert('Deployed YARA-L 2.0 detection rule to Google SecOps production instance! (SIMULATED)');
}

// Component 5: IRP Progress Tracker Logic (<IRPProgressTracker />)
function toggleIrpCheck(chkId, label) {
  const el = document.getElementById(chkId);
  const isChecked = el ? el.checked : false;

  logAgUiEvent('ag_ui.irp_step_toggled', {
    step_label: label,
    completed: isChecked,
    analyst_override: true,
    timestamp: new Date().toISOString()
  });
}

function attachForensicNote() {
  const note = prompt("Enter forensic investigation note to attach to active IRP:", "Volatile RAM dump captured via MemoryForensicsAgent. Extracted suspicious DLL payload.");
  if (note) {
    logAgUiEvent('ag_ui.irp_note_attached', {
      playbook: "irp_malware_c2.md",
      incident_id: "INC-2026-9042",
      forensic_note: note,
      timestamp: new Date().toISOString()
    });

    alert("Forensic note successfully attached to active Incident Response Plan!");
  }
}

const irpPhases = [
  { step: 1, label: "PHASE 1: IDENTIFICATION (25%)", percentage: 25 },
  { step: 2, label: "PHASE 2: CONTAINMENT (60%)", percentage: 60 },
  { step: 3, label: "PHASE 3: ERADICATION (75%)", percentage: 75 },
  { step: 4, label: "PHASE 4: RECOVERY (100%)", percentage: 100 }
];
let currentIrpPhaseIndex = 1; // starts at Phase 2: Containment (index 1), matching the initial HTML

function updateAdvanceIrpButtonLabel() {
  const btn = document.getElementById('btnAdvanceIrpPhase');
  if (!btn) return;
  if (currentIrpPhaseIndex >= irpPhases.length - 1) {
    btn.innerText = "Advance IRP Phase";
    btn.disabled = true;
  } else {
    const nextPhaseName = irpPhases[currentIrpPhaseIndex + 1].label.split(': ')[1].split(' (')[0];
    btn.innerText = `Advance IRP Phase • ${nextPhaseName.charAt(0)}${nextPhaseName.slice(1).toLowerCase()}`;
  }
}

function advanceIrpPhase() {
  if (currentIrpPhaseIndex >= irpPhases.length - 1) {
    alert("Incident Response Plan is already at the final phase (Recovery).");
    return;
  }

  const previous = irpPhases[currentIrpPhaseIndex];
  currentIrpPhaseIndex += 1;
  const current = irpPhases[currentIrpPhaseIndex];

  // Mark the step we're leaving as completed, and the connector before it.
  const prevStepEl = document.getElementById(`irpStep${previous.step}`);
  const prevConnectorEl = document.getElementById(`irpConnector${previous.step}`);
  if (prevStepEl) {
    prevStepEl.classList.remove('step-active');
    prevStepEl.classList.add('step-completed');
  }
  if (prevConnectorEl) prevConnectorEl.classList.add('line-completed');

  const currentStepEl = document.getElementById(`irpStep${current.step}`);
  if (currentStepEl) currentStepEl.classList.add('step-active');

  const badge = document.getElementById('irpPhaseBadge');
  if (badge) {
    badge.innerText = current.label;
    badge.style.color = current.step === irpPhases.length ? "var(--severity-success)" : "var(--severity-high)";
  }

  logAgUiEvent('ag_ui.irp_phase_advanced', {
    previous_phase: previous.label,
    current_phase: current.label,
    completion_percentage: current.percentage,
    timestamp: new Date().toISOString()
  });

  updateAdvanceIrpButtonLabel();
  alert(`Advanced Incident Response Plan to ${current.label}!`);
}




