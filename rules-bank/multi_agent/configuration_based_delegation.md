# Configuration-Based Delegation System

## Overview

The Configuration-Based Delegation System enables the SOC Manager agent to intelligently route security tasks to specialized sub-agents using structured YAML configuration files. This approach replaces hardcoded delegation logic with a maintainable, data-driven system that can be updated without code changes.

## Key Benefits

- **Maintainability**: Update agent capabilities without modifying code
- **Clarity**: All agent capabilities defined in one place
- **Flexibility**: Easy to add new agents or modify existing ones
- **Intelligence**: Pattern-based delegation with fallback options
- **Documentation**: Configuration files serve as living documentation

## System Architecture

### Configuration Structure

```
multi-agent/manager/config/
├── agents/                      # Individual agent capability files
│   ├── soc_analyst_tier1.yaml
│   ├── soc_analyst_tier2.yaml
│   ├── soc_analyst_tier3.yaml
│   ├── cti_researcher.yaml
│   ├── detection_engineer.yaml
│   ├── incident_responder.yaml
│   ├── threat_hunter.yaml
│   └── soar_specialist.yaml
├── mcp_tools_config.yaml       # Centralized MCP server configuration
├── tool_agent_mapping.yaml     # Tool-to-agent mapping registry
└── config_loader.py            # Python module for loading configs
```

## Configuration Files Explained

### 1. Agent Capability Files (`agents/*.yaml`)

Each agent has a YAML file defining its capabilities:

```yaml
agent_name: soc_analyst_tier2
display_name: "SOC Analyst Tier 2"
description: "Deep investigation and SOAR case management specialist"

expertise_areas:
  - deep_investigation
  - soar_case_management
  - advanced_ioc_analysis
  - entity_investigation

mcp_servers:
  - name: soar_toolset
    description: "SOAR platform operations"
    tools:
      - list_cases
      - get_case_full_details
      - post_case_comment
  - name: siem_toolset
    description: "Advanced security investigation"
    tools:
      - search_security_events
      - get_security_alerts

delegation_triggers:
  - "SOAR case"
  - "deep investigation"
  - "case management"

capabilities:
  can_escalate_to:
    - soc_analyst_tier3
    - incident_responder
  handles_alert_severity:
    - medium
    - high
  response_time: "minutes"
```

### 2. MCP Tools Configuration (`mcp_tools_config.yaml`)

Centralizes all MCP server configurations:

```yaml
mcp_servers:
  soar_toolset:
    name: "SOAR Platform Integration"
    server_path: "/path/to/soar/server.js"
    node_args: ["node"]
    description: "Google SOAR (Siemplify) operations"
    
  gti_toolset:
    name: "Google Threat Intelligence"
    server_path: "/path/to/gti/server.js"
    description: "Threat intelligence platform"

tool_categories:
  incident_response:
    - soar_toolset
    - siem_toolset
  threat_intelligence:
    - gti_toolset
```

### 3. Tool-to-Agent Mapping (`tool_agent_mapping.yaml`)

Maps specific tools to agents and provides delegation patterns:

```yaml
tool_mappings:
  search_security_events:
    primary_agents:
      - soc_analyst_tier1
      - soc_analyst_tier2
    secondary_agents:
      - threat_hunter
    use_cases:
      - "Event investigation"
      - "IOC search"

request_patterns:
  - pattern: "triage.*alert|investigate.*alert"
    agent: soc_analyst_tier1
    confidence: high
    
  - pattern: "SOAR.*case|deep.*investigation"
    agent: soc_analyst_tier2
    confidence: high

expertise_matrix:
  alert_triage:
    best_agent: soc_analyst_tier1
    alternatives:
      - soc_analyst_tier2
```

## How Delegation Works

### 1. Request Analysis

When the manager receives a request, it:

1. **Pattern Matching**: Checks request against regex patterns
2. **Keyword Detection**: Looks for delegation triggers
3. **Tool Requirements**: Identifies needed MCP tools
4. **Expertise Matching**: Considers required expertise areas

### 2. Agent Selection Algorithm

```python
# Simplified delegation logic
def get_agent_for_request(request):
    # 1. Check request patterns (highest priority)
    for pattern in request_patterns:
        if pattern.matches(request):
            return pattern.agent
    
    # 2. Score agents by keyword matches
    best_score = 0
    best_agent = None
    
    for agent in agents:
        score = 0
        # Check expertise areas
        for expertise in agent.expertise_areas:
            if expertise in request:
                score += 2
        # Check delegation triggers
        for trigger in agent.delegation_triggers:
            if trigger in request:
                score += 3
                
        if score > best_score:
            best_agent = agent
            
    return best_agent
```

### 3. Delegation Process

1. **Analyze Request**: Manager understands the task
2. **Find Best Agent**: Uses configuration to select agent
3. **Check Availability**: Ensures agent has required tools
4. **Delegate Task**: Passes request with context
5. **Monitor Progress**: Tracks execution

## Usage Examples

### Example 1: Alert Triage

**Request**: "Triage security alert ID 12345"

**Delegation Process**:
- Pattern match: `"triage.*alert"` → SOC Analyst Tier 1
- Required tools: `get_security_alerts`, `search_security_events`
- Agent has tools: ✓
- **Result**: Delegates to SOC Analyst Tier 1

### Example 2: Threat Research

**Request**: "Research FIN7 threat actor capabilities"

**Delegation Process**:
- Pattern match: `"threat.*actor"` → CTI Researcher
- Expertise match: "threat_intelligence_research"
- Required tools: `search_threat_actors`, `get_threat_profile`
- **Result**: Delegates to CTI Researcher

### Example 3: Complex Investigation

**Request**: "Investigate SOAR case 2955 with potential malware"

**Delegation Process**:
- Pattern match: `"SOAR.*case"` → SOC Analyst Tier 2
- Secondary match: `"malware"` → Could use Tier 3
- Tool check: Tier 2 has SOAR tools
- **Result**: Delegates to SOC Analyst Tier 2, may escalate to Tier 3

## Adding New Agents

To add a new agent to the system:

### 1. Create Agent Configuration

Create `config/agents/new_agent.yaml`:

```yaml
agent_name: forensics_analyst
display_name: "Digital Forensics Analyst"
description: "Memory and disk forensics specialist"

expertise_areas:
  - memory_forensics
  - disk_forensics
  - artifact_analysis

mcp_servers:
  - name: forensics_toolset
    tools:
      - analyze_memory_dump
      - extract_artifacts

delegation_triggers:
  - "forensic analysis"
  - "memory dump"
  - "artifact extraction"
```

### 2. Update Tool Mappings

Add to `tool_agent_mapping.yaml`:

```yaml
request_patterns:
  - pattern: "forensic.*analysis|memory.*dump"
    agent: forensics_analyst
    confidence: high
```

### 3. No Code Changes Required

The manager will automatically discover and use the new agent!

## Testing the Configuration

### Validation Script

Run the configuration validator:

```bash
cd multi-agent/manager/tests
python3 validate_configs.py
```

This checks for:
- Valid YAML syntax
- Required fields present
- Cross-references valid
- No duplicate agents

### Interactive Testing

Test delegation decisions:

```bash
python3 demo_delegation.py
# Select option 4 for interactive mode
```

### Unit Tests

Run the test suite:

```bash
python3 test_config_system.py
```

## Best Practices

### 1. Agent Design

- **Single Responsibility**: Each agent should have a focused role
- **Clear Expertise**: Define specific areas of knowledge
- **Tool Alignment**: Only assign tools the agent needs

### 2. Delegation Triggers

- Use specific, unambiguous keywords
- Avoid overlapping triggers between agents
- Order triggers by specificity

### 3. Pattern Design

- Test patterns with regex tools
- Use confidence levels appropriately
- Provide fallback options

### 4. Tool Assignment

- Primary agents: Main users of the tool
- Secondary agents: Occasional users
- Document use cases for clarity

## Configuration Maintenance

### Regular Reviews

1. **Monthly**: Review delegation patterns against actual usage
2. **Quarterly**: Update agent capabilities based on new tools
3. **Annually**: Refactor overlapping responsibilities

### Change Process

1. Update YAML configuration files
2. Run validation script
3. Test with demo tool
4. Deploy (no restart required for next request)

## Troubleshooting

### Common Issues

**No Agent Selected**
- Check if request matches any patterns
- Verify delegation triggers are comprehensive
- Add more specific patterns

**Wrong Agent Selected**
- Review pattern priority (first match wins)
- Check for overlapping triggers
- Adjust confidence levels

**Tool Not Available**
- Verify tool assignment in agent config
- Check MCP server configuration
- Ensure tool name matches exactly

### Debug Mode

Enable detailed logging:

```python
config_loader = load_agent_config()
# Get detailed delegation reasoning
agent = config_loader.get_agent_for_request(request)
print(config_loader.get_delegation_reasoning())
```

## Integration with A2A System

The configuration system works seamlessly with both deployment modes:

### Traditional Mode
- Manager loads configs at startup
- Direct delegation to sub-agents
- Shared configuration instance

### A2A Mode
- Each agent can load its own config
- Manager uses configs for routing
- Enables distributed decision making

## Future Enhancements

### Planned Features

1. **Dynamic Reloading**: Hot-reload configurations without restart
2. **ML-Based Routing**: Learn from delegation history
3. **Workload Balancing**: Consider agent availability
4. **Capability Discovery**: Agents self-report capabilities

### Configuration API

Future API for dynamic updates:

```python
# Planned API
config_api.update_agent_capability(
    agent="soc_analyst_tier1",
    add_tools=["new_tool"],
    add_triggers=["new trigger"]
)
```

## Summary

The Configuration-Based Delegation System transforms agent coordination from a hardcoded, maintenance-heavy approach to a flexible, data-driven system. By separating delegation logic from code, it enables security teams to adapt quickly to changing requirements while maintaining clear documentation of agent capabilities.