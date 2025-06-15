# A2A Multi-Agent Security System

This setup enables the SOC Manager to coordinate with specialized security agents through the Agent-to-Agent (A2A) protocol.

## Architecture

- **SOC Manager Host Agent**: Orchestrates security operations by delegating to specialized agents
- **CTI Researcher Agent**: Handles threat intelligence research and IOC analysis
- **SOC Analyst Tier 1 Agent**: Performs initial alert triage and basic investigation
- **SOC Analyst Tier 2 Agent**: Conducts deeper investigation and threat analysis
- **SOC Analyst Tier 3 Agent**: Handles complex incidents and advanced threat hunting
- **Threat Hunter Agent**: Proactively searches for threats and anomalies
- **Detection Engineer Agent**: Develops and maintains detection rules and signatures
- **Incident Responder Agent**: Manages incident containment and recovery operations

## Setup Instructions

### 1. Install Dependencies

```bash
cd multi-agent
pip install -r requirements.txt
```

### 2. Start the A2A Agents

Run the startup script to launch all A2A agents:

```bash
./start_a2a_system.sh
```

This will start:
- CTI Researcher on http://localhost:8001
- SOC Analyst Tier 1 on http://localhost:8002
- SOC Analyst Tier 2 on http://localhost:8004
- Threat Hunter on http://localhost:8005
- Detection Engineer on http://localhost:8006
- Incident Responder on http://localhost:8007
- SOC Analyst Tier 3 on http://localhost:8008

### 3. Start the SOC Manager Host

In a new terminal, from the `multi-agent` directory:

```bash
adk web agents/
```

This will start ADK Web with agent discovery. You'll see both available agents:
- **soc_manager_host**: A2A-enabled SOC Manager that coordinates with remote agents
- **soc_manager_traditional**: Traditional multi-agent system with integrated sub-agents

Select **soc_manager_host** to use the A2A system. The host agent will automatically discover and connect to all A2A agents running on their respective ports.

## Using the System

Once all components are running, you can interact with the SOC Manager through the ADK Web interface. The manager can:

1. **Delegate to CTI Researcher**: 
   - "Research the Lazarus Group threat actor"
   - "Analyze these IOCs: 192.168.1.1, malware.exe"
   - "Investigate GTI collection ID GTI-2024-001"

2. **Delegate to SOC Analyst Tier 1**:
   - "Triage this malware alert from CrowdStrike"
   - "Investigate suspicious login from IP 192.168.1.100"
   - "Analyze critical phishing alert ALT-2024-001"

3. **Delegate to SOC Analyst Tier 2**:
   - "Perform deep analysis of ransomware incident"
   - "Investigate complex multi-stage attack"
   - "Analyze lateral movement patterns"

4. **Delegate to SOC Analyst Tier 3**:
   - "Handle advanced persistent threat investigation"
   - "Perform forensic analysis of compromised systems"
   - "Lead critical incident response"

5. **Delegate to Threat Hunter**:
   - "Hunt for signs of APT29 in our environment"
   - "Search for anomalous PowerShell activity"
   - "Investigate potential data exfiltration"

6. **Delegate to Detection Engineer**:
   - "Create SIEM rule for ransomware behavior"
   - "Develop detection for new phishing campaign"
   - "Tune false positive alerts"

7. **Delegate to Incident Responder**:
   - "Contain ransomware outbreak on finance servers"
   - "Execute incident response plan for data breach"
   - "Coordinate recovery efforts"

8. **Coordinate Multiple Agents**:
   - "Investigate security incident CASE-123: Start with alert triage, then perform threat intelligence analysis"

## Example Interactions

### Single Agent Delegation
```
User: "Research APT campaigns targeting financial institutions"
SOC Manager: [Delegates to CTI Researcher]
CTI Researcher: [Returns research form for completion]
```

### Multi-Agent Coordination
```
User: "Critical malware alert on workstation WS-001 needs investigation"
SOC Manager: [Delegates initial triage to SOC Tier 1]
SOC Tier 1: [Performs triage and identifies IOCs]
SOC Manager: [Delegates IOC analysis to CTI Researcher]
CTI Researcher: [Provides threat intelligence]
SOC Manager: [Synthesizes findings and provides recommendations]
```

## Technical Details

### A2A Communication

The system uses the A2A SDK for agent communication:
- Each agent exposes a REST API with `/` (card) and `/message` endpoints
- The host agent maintains persistent connections to all sub-agents
- Messages are exchanged asynchronously with session management

### Form-Based Interactions

All A2A agents use form-based interactions:
- Agents return structured forms for data collection
- Forms use JSON Schema for validation
- A2A escalation is triggered via `tool_context.actions`
- Each agent has specialized forms for their domain

### Adding New Agents

To add a new A2A agent:

1. Create the agent with A2A capabilities (see `agent_a2a.py` examples)
2. Create a server script (`run_server.py`)
3. Add the agent URL to `host_agent.py`
4. Update `start_a2a_system.sh` to include the new agent

## Troubleshooting

### Common Issues and Solutions

- **Agent Connection Errors**: Ensure all agents are running before starting the host
- **Port Conflicts**: Modify port numbers in server scripts if needed
- **Import Errors**: Ensure you're in the virtual environment with dependencies installed

### Checking Agent Logs

If agents fail to start, check the log files:
```bash
# View CTI Researcher logs
cat manager/sub_agents/cti_researcher/cti_agent.log

# View SOC Analyst Tier 1 logs
cat manager/sub_agents/soc_analyst_tier1/soc_agent.log

# View other agent logs
cat manager/sub_agents/soc_analyst_tier2/soc_tier2_agent.log
cat manager/sub_agents/soc_analyst_tier3/soc_tier3_agent.log
cat manager/sub_agents/threat_hunter/threat_hunter_agent.log
cat manager/sub_agents/detection_engineer/detection_engineer_agent.log
cat manager/sub_agents/incident_responder/incident_responder_agent.log
```

### Manual Agent Testing

You can test agents individually:
```bash
# Test CTI Researcher
cd manager/sub_agents/cti_researcher
python run_server.py

# Test SOC Analyst Tier 1 (in new terminal)
cd manager/sub_agents/soc_analyst_tier1
python run_server.py
```

### Dependency Issues

If you encounter module import errors:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Check for missing packages
pip list | grep -E "(fastapi|uvicorn|a2a-sdk|google-adk)"
```

## Architecture Benefits

- **Modularity**: Each agent can be developed and deployed independently
- **Scalability**: New agents can be added without modifying existing ones
- **Flexibility**: Agents can be built with different frameworks (ADK, LangGraph, etc.)
- **Resilience**: Individual agent failures don't crash the entire system