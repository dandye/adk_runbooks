# ADK Security Operations Multi-Agent System

A comprehensive multi-agent cybersecurity platform built on Google's Agent Development Kit (ADK) that orchestrates specialized security agents through Agent-to-Agent (A2A) communication for incident response, threat hunting, and security operations.

## 🚀 Quick Start

### A2A Multi-Agent System (Recommended)

The A2A system enables distributed agent coordination with the SOC Manager as a host agent:

```bash
# 1. Install dependencies
cd multi-agent
pip install -r requirements.txt

# 2. Start A2A agents
./start_a2a_system.sh

# 3. In a new terminal, start the host agent
adk web
```

### Traditional Multi-Agent System

For the integrated multi-agent approach:

```bash
cd multi-agent
adk run manager
# or
adk web
```

## 🏗 Architecture Overview

### A2A Architecture (New)

```
                        A2A Protocol                      
    SOC Manager     ┌─────────────────┬─► CTI Researcher (8001)
    (Host Agent)    │                 ├─► SOC Analyst T1 (8002)
                    │                 ├─► SOC Analyst T2 (8004)
                    │                 ├─► Threat Hunter (8005)
                    │                 ├─► Detection Engineer (8006)
                    │                 ├─► Incident Responder (8007)
                    │                 └─► SOC Analyst T3 (8008)
```

### Traditional Architecture

```
                 
  SOC Manager    
                 
        ├─ CTI Researcher
        ├─ SOC T1/T2/T3  
        ├─ Threat Hunter 
        ├─ Inc. Responder
        └─ Det. Engineer 
                 
```

## 👥 Available Agents

| Agent | Specialty | A2A Enabled | Purpose |
|-------|-----------|-------------|---------|
| **SOC Manager** | Orchestration | Host Agent | Coordinates operations, executes IRPs |
| **CTI Researcher** | Threat Intel | ✅ | IOC analysis, threat actor research, campaign tracking |
| **SOC Analyst Tier 1** | Alert Triage | ✅ | Initial alert investigation, basic enrichment |
| **SOC Analyst Tier 2** | Investigation | ✅ | Deep alert analysis, SOAR integration |
| **SOC Analyst Tier 3** | Advanced Response | ✅ | Complex incident coordination |
| **Threat Hunter** | Proactive Defense | ✅ | Hypothesis-driven hunting, TTPs analysis |
| **Incident Responder** | Crisis Management | ✅ | Containment, eradication, recovery |
| **Detection Engineer** | Rule Development | ✅ | Detection logic, rule tuning |
| **SOAR Specialist** | Automation | ✅ | SOAR platform operations, workflow automation |

## 🎯 Key Features

### 🔬 Specialized Expertise
- **Domain-specific agents** with focused knowledge and tools
- **Persona-driven behavior** from curated rules bank
- **Runbook-guided operations** for consistent execution

### 🔄 Flexible Architecture
- **A2A Protocol**: Distributed agents communicating via REST APIs
- **Traditional Multi-Agent**: Integrated agents in single deployment
- **Hybrid Support**: Mix both approaches as needed

### 🛡 Security Operations Focus
- **Incident Response Plans (IRPs)** for malware, phishing, ransomware
- **Threat Intelligence workflows** with GTI integration
- **SIEM/SOAR connectivity** via MCP security tools
- **Automated reporting** with comprehensive documentation

### 🛠 Production-Ready Tools
- **MCP Security Tools**: SIEM queries, threat intel, sandbox analysis
- **Form-based interactions**: Structured data collection via A2A cards
- **Session management**: Persistent conversations and context
- **Error handling**: Graceful degradation and recovery

## 💡 Use Cases

### 1. Incident Response Orchestration
```
User: "Start Malware IRP for CASE-2024-001"
SOC Manager: 
   → Delegates initial triage to SOC Analyst T1
   → Coordinates threat intel with CTI Researcher  
   → Manages containment via Incident Responder
   → Generates comprehensive incident report
```

### 2. Threat Intelligence Research
```
User: "Research Lazarus Group activities targeting crypto exchanges"
CTI Researcher:
   → Analyzes latest campaign TTPs
   → Enriches IOCs from multiple sources
   → Provides attribution assessment
   → Suggests detection opportunities
```

### 3. Alert Investigation Pipeline
```
User: "Investigate suspicious login from 192.168.1.100"
SOC Analyst T1:
   → Performs initial triage
   → Enriches IP and user context
   → Determines escalation needs
   → Documents findings
```

## 📋 Getting Started

### Prerequisites
- Python 3.10+
- Google API Key (for Gemini models)
- Virtual environment setup

### Environment Setup
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Configuration
1. Create `.env` file in `multi-agent/manager/`:
   ```
   GOOGLE_API_KEY=your_api_key_here
   ```

2. Update MCP tool paths in `multi-agent/manager/tools/tools.py`

### Running the System

#### A2A Mode (Recommended)
1. **Start A2A Agents**:
   ```bash
   ./start_a2a_system.sh
   ```
   This launches all A2A agents:
   - CTI Researcher on http://localhost:8001
   - SOC Analyst Tier 1 on http://localhost:8002
   - SOAR Specialist on http://localhost:8003
   - SOC Analyst Tier 2 on http://localhost:8004
   - Threat Hunter on http://localhost:8005
   - Detection Engineer on http://localhost:8006
   - Incident Responder on http://localhost:8007
   - SOC Analyst Tier 3 on http://localhost:8008

2. **Start Host Agent**:
   ```bash
   adk web agents/
   ```
   Then select **soc_manager_host** from the web interface

3. **Interact**: Use the web interface to coordinate agents

#### Traditional Mode
```bash
adk run manager  # CLI mode
# or
adk web agents/  # Web interface - select soc_manager_traditional
```

## 📚 Documentation

- **[A2A Setup Guide](A2A_README.md)** - Detailed A2A configuration
- **[Rules Bank](../rules-bank/)** - Agent personas and runbooks
- **[MCP Tools](manager/tools/)** - Security tool integrations

## 👥 Contributing

This project follows the ADK multi-agent patterns with security-focused extensions:

1. **Agent Development**: Follow persona + runbook pattern
2. **A2A Integration**: Implement form-based interactions
3. **Tool Integration**: Use MCP protocol for external services
4. **Documentation**: Update rules bank and examples

## 📄 License

This project is built on Google's ADK framework and follows associated licensing terms.

---

**🔒 Ready to revolutionize your security operations with AI agents?**

Start with the A2A system for maximum flexibility, or use traditional mode for integrated operations. Each approach offers unique benefits for different deployment scenarios.