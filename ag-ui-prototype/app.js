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
