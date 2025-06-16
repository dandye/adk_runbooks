# ADK Security Operations - A2A Multi-Agent System

Next-generation cybersecurity powered by AI agents using Agent-to-Agent (A2A) communication for distributed, intelligent security operations.

## System Overview

The ADK Security Operations platform revolutionizes cybersecurity by orchestrating specialized AI agents that collaborate through the Agent-to-Agent (A2A) protocol. Each agent brings focused expertise in areas like threat intelligence, alert triage, incident response, and threat hunting.

### A2A Multi-Agent Architecture

```
                        A2A Protocol                      
    SOC Manager     ┌─────────────────┬─► CTI Researcher (8001)
    (Host Agent)    │                 ├─► SOC Analyst T1 (8002)
                    │                 ├─► SOAR Specialist (8003)
                    │                 ├─► SOC Analyst T2 (8004)
                    │                 ├─► Threat Hunter (8005)
                    │                 ├─► Detection Engineer (8006)
                    │                 ├─► Incident Responder (8007)
                    │                 └─► SOC Analyst T3 (8008)
```

### Key Features

#### 🧠 Specialized Intelligence
Each agent focuses on specific security domains with deep expertise and tailored toolsets.

#### 🔄 Distributed Architecture
Agents communicate via A2A protocol, enabling scalable and resilient operations.

#### 📋 Form-Based Interactions
Structured data collection through interactive forms for precise task execution.

#### 🛡️ Security-First Design
Built specifically for cybersecurity operations with industry-standard workflows.

## Available Security Agents

Our multi-agent system includes specialized agents for different aspects of security operations:

| Agent | Specialty | A2A Status | Primary Functions |
|-------|-----------|------------|-------------------|
| **SOC Manager** | Orchestration | Host Agent | Coordinates operations, executes IRPs, delegates tasks |
| **CTI Researcher** | Threat Intelligence | A2A Ready | IOC analysis, threat actor research, campaign tracking |
| **SOC Analyst Tier 1** | Alert Triage | A2A Ready | Initial investigation, basic enrichment, false positive detection |
| **SOC Analyst Tier 2** | Investigation | A2A Ready | Deep analysis, SOAR integration, complex alert handling |
| **SOC Analyst Tier 3** | Advanced Response | A2A Ready | Complex incident coordination, forensics oversight |
| **Threat Hunter** | Proactive Defense | A2A Ready | Hypothesis-driven hunting, TTP analysis, advanced queries |
| **Detection Engineer** | Rule Development | A2A Ready | Detection logic creation, rule tuning, false positive reduction |
| **Incident Responder** | Crisis Management | A2A Ready | Containment, eradication, recovery procedures |
| **SOAR Specialist** | Automation | A2A Ready | SOAR platform operations, workflow automation, playbook management |

## Quick Start Guide

### Prerequisites
- Python 3.10 or higher
- Google API Key (for Gemini models)
- Virtual environment (recommended)
- Git (for cloning the repository)

### Installation Steps

#### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/adk-runbooks.git
cd adk-runbooks/multi-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

#### 2. Configure Environment

```bash
# Create .env file in multi-agent/manager/
echo "GOOGLE_API_KEY=your_api_key_here" > manager/.env

# Update MCP tool paths in manager/tools/tools.py if needed
```

#### 3. Start A2A System

```bash
# Start all A2A agents (8 specialized security agents)
./start_a2a_system.sh
```

**✅ Success!** You should see agents starting on ports 8001-8008:
- CTI Researcher - http://localhost:8001
- SOC Analyst Tier 1 - http://localhost:8002
- SOAR Specialist - http://localhost:8003
- SOC Analyst Tier 2 - http://localhost:8004
- Threat Hunter - http://localhost:8005
- Detection Engineer - http://localhost:8006
- Incident Responder - http://localhost:8007
- SOC Analyst Tier 3 - http://localhost:8008

#### 4. Launch Host Agent

```bash
# In a new terminal, from the multi-agent directory
adk web agents/

# This will show both available agents in the web interface:
# - soc_manager_host (A2A-enabled)
# - soc_manager_traditional (integrated sub-agents)
```

**🎉 Ready!** Access the SOC Manager at the ADK web interface URL.

## Usage Examples

### Threat Intelligence Research

```
User: "Research the Lazarus Group threat actor"
SOC Manager → CTI Researcher:
  - Analyzes threat actor TTPs
  - Gathers latest campaign information
  - Returns structured intelligence report
```

### Alert Investigation

```
User: "Investigate suspicious login from IP 192.168.1.100"
SOC Manager → SOC Analyst Tier 1:
  - Performs initial triage
  - Enriches IP reputation
  - Checks user context
  - Determines escalation needs
```

### Complex Incident Response

```
User: "Ransomware detected on finance server FIN-001"
SOC Manager orchestrates:
  → SOC Analyst T1: Initial assessment
  → CTI Researcher: Ransomware strain identification
  → Incident Responder: Containment actions
  → SOC Analyst T3: Forensic coordination
  → Detection Engineer: New detection rules
```

### Proactive Threat Hunting

```
User: "Hunt for signs of APT29 in our environment"
SOC Manager → Threat Hunter:
  - Develops hunting hypotheses
  - Queries SIEM for suspicious patterns
  - Analyzes PowerShell activity
  - Identifies potential compromises
```

## Configuration & Customization

### Port Configuration

Each A2A agent runs on a dedicated port. You can modify these in the respective `run_server.py` files:

```python
# Example: manager/sub_agents/cti_researcher/run_server.py
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)  # Change port here
```

### Adding New Agents

1. Create a new directory under `manager/sub_agents/your_agent/`
2. Implement `agent_a2a.py` with form-based interactions
3. Create `run_server.py` to host the agent
4. Update `host_agent.py` to include the new agent URL
5. Add to `start_a2a_system.sh` startup script

### MCP Tool Integration

Security tools are configured in `manager/tools/tools.py`. Update paths as needed:

```python
# Update these paths to match your environment
MCP_SERVERS = {
    "siem": "/path/to/mcp-security/server/siem_connector.py",
    "threat_intel": "/path/to/mcp-security/server/threat_intel.py",
    "sandbox": "/path/to/mcp-security/server/sandbox_analyzer.py"
}
```

#### Technical Implementation Details

A2A agents with MCP tool access use an async initialization pattern:

```python
# Example from SOAR Specialist agent
async def _initialize_mcp_tools(self):
    """Initialize MCP tools asynchronously"""
    if self.tools is None:
        self.exit_stack = contextlib.ExitStack()
        self.tools = await CustomMCPToolset.create(
            stdio_servers=[
                StdioServerParameters(
                    command='uv',
                    args=[
                        "--directory", "/path/to/mcp-server",
                        "run", "server.py",
                        "--integrations", "CSV,GoogleChronicle,Siemplify"
                    ]
                )
            ],
            exit_stack=self.exit_stack
        )

async def _ensure_initialized(self):
    """Lazy initialization on first request"""
    if not self.initialized:
        await self._initialize_mcp_tools()
        self.initialized = True

def cleanup(self):
    """Proper resource cleanup"""
    if hasattr(self, 'exit_stack') and self.exit_stack:
        self.exit_stack.close()
```

**Key Benefits:**
- **Async Loading**: MCP tools initialize without blocking agent startup
- **Resource Management**: Proper cleanup prevents connection leaks  
- **Timeout Handling**: Custom timeout (60s) prevents premature disconnections
- **Lazy Initialization**: Tools load only when first needed

## Troubleshooting

### Common Issues

#### Agent Connection Errors
**Problem:** "Failed to connect to agent" errors  
**Solution:** Ensure all A2A agents are running before starting the host agent. Check that ports 8001-8008 are not in use.

#### Import Errors
**Problem:** ModuleNotFoundError when starting agents  
**Solution:** Activate virtual environment and reinstall dependencies:  
`source venv/bin/activate && pip install -r requirements.txt`

#### MCP Tool Failures
**Problem:** MCP tools not initializing  
**Solution:** Update tool paths in `manager/tools/tools.py` and ensure MCP servers are accessible.

#### MCP Timeout Issues
**Problem:** MCP tools failing with timeout errors  
**Solution:** Use `CustomMCPToolset` with extended timeout (60s) instead of default (5s):
```python
from utils.custom_adk_patches import CustomMCPToolset
```

#### Port Conflicts  
**Problem:** "Address already in use" when starting agents  
**Solution:** Check for existing processes and kill if needed:
```bash
# Find processes using ports 8001-8008
lsof -ti:8001-8008 | xargs kill -9
```

### Checking Logs

```bash
# View agent logs
tail -f manager/sub_agents/cti_researcher/cti_agent.log
tail -f manager/sub_agents/soc_analyst_tier1/soc_agent.log

# Check A2A system startup
ps aux | grep "run_server.py"
```

## Advanced Topics

### Hybrid Deployment

You can mix A2A and traditional agents. For example, run critical agents locally while distributing others:
- Local: SOC Manager, CTI Researcher
- Remote: SOC Analysts, Threat Hunter
- Cloud: Detection Engineer, SOAR Specialist

### Security Considerations

- **Authentication:** Implement API keys for production A2A deployments
- **Encryption:** Use HTTPS for A2A communication in production
- **Network Segmentation:** Deploy agents in appropriate security zones
- **Audit Logging:** Enable comprehensive logging for compliance

### Performance Optimization

- **Connection Pooling:** Reuse HTTP connections between agents
- **Async Operations:** Leverage async/await for concurrent operations
- **Resource Limits:** Configure appropriate CPU/memory limits per agent
- **Load Balancing:** Deploy multiple instances of high-traffic agents

## Additional Resources

### Documentation
- [Google ADK Documentation](https://github.com/google/adk)
- [Detailed A2A Setup Guide](../../multi-agent/A2A_README.md)
- [Security Rules Bank](../)
- [GTI MCP Tools Reference](../tools/GTI_MCP_TOOLS_REFERENCE.md)

### Getting Help
- **Issues:** Report bugs via GitHub Issues
- **Discussions:** Join our community forums
- **Security:** Report vulnerabilities to security@example.com