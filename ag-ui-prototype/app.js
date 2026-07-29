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

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  renderScenarioSelectors();
  loadScenario(currentScenarioKey);
  setupTabListeners();
  selectGraphNode('ir');
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
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      e.target.classList.add('active');
      const targetId = e.target.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });
}

// Action Handlers
function approveAction() {
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

  showStatusBanner('success', `Action Approved! Executing MCP Tool Call: ${s.mcpToolCall}`);

  // Simulate MCP Tool Execution after 1s
  setTimeout(() => {
    logAgUiEvent('ag_ui.mcp_tool_executed', {
      mcp_tool: s.mcpToolCall,
      execution_status: "SUCCESS",
      result_code: 200,
      details: "Operation successfully applied to target asset."
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

function submitRejection() {
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

  // Simulate agent re-evaluation event
  setTimeout(() => {
    logAgUiEvent('ag_ui.agent_re-thinking', {
      agent: s.agentName,
      thought: `Received analyst feedback "${reason}". Adjusting remediation strategy...`
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
  banner.innerHTML = `<span>${message}</span>`;
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

  const eventCard = document.createElement('div');
  eventCard.className = 'event-card';
  eventCard.innerHTML = `
    <div class="event-header">
      <span class="event-name">${eventName}</span>
      <span class="event-time">${timeStr}</span>
    </div>
    <div class="event-body">${JSON.stringify(payload, null, 2)}</div>
  `;

  stream.insertBefore(eventCard, stream.firstChild);
}

// Workbench View Switcher Logic
function switchWorkbenchView(viewName) {
  const btnHitl = document.getElementById('viewBtnHitl');
  const btnGraph = document.getElementById('viewBtnGraph');
  const viewHitl = document.getElementById('viewHitlCard');
  const viewGraph = document.getElementById('viewGraphView');

  if (viewName === 'hitl') {
    btnHitl.classList.add('active');
    btnGraph.classList.remove('active');
    viewHitl.style.display = 'block';
    viewGraph.style.display = 'none';

    logAgUiEvent('ag_ui.view_switched', {
      active_view: "HITL_REMEDIATION_APPROVAL_CARD"
    });
  } else if (viewName === 'graph') {
    btnGraph.classList.add('active');
    btnHitl.classList.remove('active');
    viewHitl.style.display = 'none';
    viewGraph.style.display = 'block';

    logAgUiEvent('ag_ui.view_switched', {
      active_view: "MULTI_AGENT_DELEGATION_GRAPH"
    });
  }
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
  logAgUiEvent('ag_ui.delegation_started', {
    orchestrator: "ADK Manager Agent",
    incident_id: "INC-2026-9042",
    mode: "MULTI_AGENT_PARALLEL_EXECUTION"
  });

  // Step 1: Highlight CTI Researcher
  setTimeout(() => {
    selectGraphNode('cti');
    logAgUiEvent('ag_ui.subagent_tool_executing', {
      agent: "CTI Researcher",
      tool: "vt_ip_lookup",
      status: "EXECUTING"
    });
  }, 600);

  // Step 2: Highlight SOC Tier 1
  setTimeout(() => {
    selectGraphNode('soc');
    logAgUiEvent('ag_ui.subagent_tool_executing', {
      agent: "SOC Analyst Tier 1",
      tool: "udm_search",
      status: "EXECUTING"
    });
  }, 1400);

  // Step 3: Highlight Incident Responder
  setTimeout(() => {
    selectGraphNode('ir');
    logAgUiEvent('ag_ui.subagent_hitl_triggered', {
      agent: "Incident Responder",
      action: "ISOLATE_HOST_AND_BLOCK_C2",
      status: "WAITING_APPROVAL"
    });
  }, 2200);

  // Step 4: Highlight Detection Engineer
  setTimeout(() => {
    selectGraphNode('de');
    logAgUiEvent('ag_ui.delegation_completed', {
      status: "WORKFLOW_READY",
      active_node: "Incident Responder"
    });
  }, 3000);
}

function resetDelegationGraph() {
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

function delegateToThreatHunter() {
  const s = scenarios[currentScenarioKey];
  logAgUiEvent('ag_ui.delegate_threat_hunt', {
    target_agent: "Threat Hunter Sub-Agent",
    target_ioc: s.entityIp,
    incident_id: s.incidentId,
    directive: "Search all internal UDM logs across all organizational endpoints for matching IOC communication."
  });

  alert(`Delegated IOC threat hunt task for ${s.entityIp} to Threat Hunter Sub-Agent.`);
}

function pivotUdmSearch() {
  const s = scenarios[currentScenarioKey];
  logAgUiEvent('ag_ui.pivot_udm_search', {
    mcp_tool: "udm_search",
    query: `target.ip = "${s.entityIp}" OR principal.ip = "${s.entityIp}"`,
    timestamp: new Date().toISOString()
  });

  alert(`Executing UDM search pivot for IOC ${s.entityIp}...`);
}

function blockIocPerimeter() {
  const s = scenarios[currentScenarioKey];
  logAgUiEvent('ag_ui.block_ioc_firewall', {
    action: "BLOCK_PERIMETER_IP",
    ioc: s.entityIp,
    rule_id: `FW-BLOCK-${Math.floor(Math.random() * 9000 + 1000)}`
  });

  alert(`Perimeter firewall rule created blocking IOC ${s.entityIp}.`);
}


