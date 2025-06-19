# ADK Runbooks

A comprehensive multi-agent cybersecurity operations system built on Google's Agent Development Kit (ADK). This project provides specialized AI agents that collaborate to handle security operations tasks including incident response, threat hunting, detection engineering, and security operations center (SOC) activities.

## Documentation

The full documentation for this project, including detailed runbooks and agent information, is available at:
[https://dandye.github.io/adk_runbooks](https://dandye.github.io/adk_runbooks)

## Overview

ADK Runbooks implements a manager-orchestrated multi-agent system where specialized security agents work together to handle complex cybersecurity tasks. Each agent has deep expertise in its domain and follows industry-standard procedures and playbooks.

### Key Features

- **Multi-Agent Architecture**: Manager agent coordinates specialized sub-agents for different security functions
- **Production-Ready Runbooks**: Battle-tested incident response plans, threat hunting playbooks, and detection engineering guides
- **MCP Tool Integration**: Leverages Model Context Protocol (MCP) for security tool integration
- **Flexible Deployment**: Can run standalone or integrate with existing security orchestration platforms

## Security Agents

The system includes specialized agents organized by security function:

### Orchestration
- **Manager Agent**: Orchestrates and delegates tasks to appropriate specialist agents

### Security Operations Center (SOC)
- **SOC Analyst Tier 1**: Performs initial alert triage and basic investigations
- **SOC Analyst Tier 2**: Handles escalated alerts and deeper investigations  
- **SOC Analyst Tier 3**: Manages complex incidents and advanced forensic analysis

### Proactive Security
- **Threat Hunter**: Proactively searches for threats, anomalies, and signs of compromise
- **CTI Researcher**: Gathers and analyzes cyber threat intelligence to inform defensive strategies

### Security Engineering
- **Detection Engineer**: Designs, develops, and maintains security detection rules and analytics
- **Incident Responder**: Executes incident response plans for containment, eradication, and recovery

## Project Structure

```
adk_runbooks/
├── multi-agent/              # Multi-agent system implementation
│   ├── manager/              # Manager agent and sub-agents
│   └── requirements.txt      # Python dependencies
├── rules-bank/               # Security runbooks and procedures
│   ├── personas/             # Agent behavior definitions
│   ├── run_books/            # Operational procedures
│   └── irps/                 # Incident Response Plans
├── source/                   # Sphinx documentation source
└── docs/                     # Generated documentation (GitHub Pages)
```

## Quick Start

For detailed setup instructions, see [SETUP_CLAUDE.md](SETUP_CLAUDE.md).

### Prerequisites

- Python 3.8+
- Google API key (for Gemini models)
- Virtual environment tool (venv, conda, etc.)

### Basic Setup

```bash
# Clone the repository with submodules
git clone --recurse-submodules https://github.com/dandye/adk_runbooks.git
cd adk_runbooks

# If you already cloned without submodules:
# git submodule update --init --recursive

# Set up virtual environment
cd multi-agent
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp manager/.env.example manager/.env
# Edit .env and add your GOOGLE_API_KEY

# Configure MCP Security tools
cp ../external/mcp-security/.env.example ../external/mcp-security/.env
# Edit .env and add your security tool API keys

# Run the system
adk run manager
```

## Use Cases

- **Incident Response**: Automated triage, investigation, and response to security incidents
- **Threat Hunting**: Proactive search for indicators of compromise and advanced threats
- **Detection Engineering**: Development and tuning of security detection rules
- **SOC Operations**: Streamlined alert management and investigation workflows
- **Threat Intelligence**: Automated collection and analysis of threat actor information

## Contributing

Contributions are welcome! Please see our contributing guidelines for more information.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on [Google's Agent Development Kit (ADK)](https://github.com/google/adk)
- Leverages [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) for tool integration
- Security procedures based on industry best practices and frameworks