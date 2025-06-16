# Agent Configuration System

This directory contains the structured configuration system for the multi-agent SOC platform. The configuration system enables:

- Dynamic agent delegation based on capabilities
- Centralized MCP tool management
- Tool-to-agent mapping for intelligent routing
- Reduced hardcoding in agent instructions

## Directory Structure

```
config/
├── agents/                    # Individual agent capability files
│   ├── soc_analyst_tier1.yaml
│   ├── soc_analyst_tier2.yaml
│   ├── soc_analyst_tier3.yaml
│   ├── cti_researcher.yaml
│   ├── detection_engineer.yaml
│   ├── incident_responder.yaml
│   ├── threat_hunter.yaml
│   └── soar_specialist.yaml
├── mcp_tools_config.yaml      # Centralized MCP server configuration
├── tool_agent_mapping.yaml    # Tool-to-agent mapping registry
├── config_loader.py           # Python module for loading configs
└── README.md                  # This file
```

## Configuration Files

### Agent Capability Files (`agents/*.yaml`)

Each agent has a YAML file defining:

- **Basic Info**: Name, display name, description
- **Expertise Areas**: List of specializations
- **MCP Servers**: Which MCP toolsets the agent can access
- **Delegation Triggers**: Keywords/phrases that indicate this agent should handle a task
- **Capabilities**: Additional metadata (escalation paths, severity handling, etc.)
- **Tool Cards**: Agent-specific workflow tools

Example structure:
```yaml
agent_name: soc_analyst_tier2
display_name: "SOC Analyst Tier 2"
description: "Deep investigation and SOAR case management specialist"

expertise_areas:
  - deep_investigation
  - soar_case_management
  
mcp_servers:
  - name: soar_toolset
    tools: [list_cases, get_case_full_details]
    
delegation_triggers:
  - "SOAR case"
  - "deep investigation"
```

### MCP Tools Configuration (`mcp_tools_config.yaml`)

Centralizes all MCP server configurations:

- Server paths and execution parameters
- Tool categories for grouping
- Environment-specific configurations
- Descriptions and metadata

### Tool-Agent Mapping (`tool_agent_mapping.yaml`)

Maps specific tools to agents and provides:

- **Tool Mappings**: Which agents can use each tool (primary/secondary)
- **Expertise Matrix**: Best agent for each type of work
- **Request Patterns**: Regex patterns for matching requests to agents

## Using the Configuration System

### 1. Loading Configuration

```python
from config.config_loader import load_agent_config

# Load all configurations
config_loader = load_agent_config()

# Get best agent for a request
agent = config_loader.get_agent_for_request("I need to analyze malware")

# Get agent capabilities
capabilities = config_loader.get_agent_capabilities("soc_analyst_tier3")

# Get MCP server config
server_config = config_loader.get_mcp_server_config("gti_toolset")
```

### 2. Manager Agent Integration

The enhanced manager agent (`agent_enhanced.py`) demonstrates how to:

- Load configurations at startup
- Use pattern matching for delegation
- Build dynamic instructions from configs
- Provide configuration-aware delegation

### 3. Adding New Agents

To add a new agent:

1. Create `config/agents/new_agent.yaml`
2. Define expertise areas and MCP servers
3. Add delegation triggers
4. Update tool mappings if needed
5. The manager will automatically discover it

### 4. Updating Tool Access

To change which tools an agent can access:

1. Edit the agent's YAML file
2. Update the `mcp_servers` section
3. Add/remove tools from the list
4. No code changes required

## Benefits

1. **Maintainability**: Update agent capabilities without code changes
2. **Clarity**: See all agent capabilities in one place
3. **Flexibility**: Easy to add/modify agents and tools
4. **Intelligence**: Pattern-based delegation with fallbacks
5. **Documentation**: Configs serve as living documentation

## Tool Cards Organization

Tool cards are now organized into categories:

- `tool_cards/mcp_tools/`: Documentation for MCP server tools
- `tool_cards/agent_tools/`: Agent-specific forms and workflows

This separation makes it clear which tools are external integrations vs internal workflows.