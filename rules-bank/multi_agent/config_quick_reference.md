# Configuration System Quick Reference

## File Locations

```
multi-agent/manager/config/
├── agents/*.yaml              # Agent capabilities
├── mcp_tools_config.yaml      # MCP servers
├── tool_agent_mapping.yaml    # Delegation rules
└── config_loader.py           # Python loader
```

## Agent Configuration Template

```yaml
agent_name: agent_id
display_name: "Human Readable Name"
description: "What this agent does"

expertise_areas:
  - area_1
  - area_2

mcp_servers:
  - name: toolset_name
    tools:
      - tool_1
      - tool_2

delegation_triggers:
  - "keyword phrase"
  - "another trigger"

capabilities:
  can_escalate_to: [agent_names]
  handles_alert_severity: [low, medium, high]
```

## Common Delegation Patterns

| Request Type | Pattern | Delegates To |
|-------------|---------|--------------|
| Alert Triage | `triage.*alert` | SOC Tier 1 |
| SOAR Cases | `SOAR.*case` | SOC Tier 2 |
| Malware Analysis | `malware.*analysis` | SOC Tier 3 |
| Threat Research | `threat.*actor\|CTI` | CTI Researcher |
| Incident Response | `incident.*response` | Incident Responder |
| Threat Hunting | `threat.*hunt` | Threat Hunter |
| Rule Creation | `detection.*rule` | Detection Engineer |

## Testing Commands

```bash
# Validate configurations
cd multi-agent/manager/tests
python3 validate_configs.py

# Test delegation logic
python3 demo_delegation.py

# Run all tests
./run_tests.sh
```

## Adding a New Agent

1. Create `config/agents/new_agent.yaml`
2. Define expertise, tools, and triggers
3. Update `tool_agent_mapping.yaml` if needed
4. Test with `demo_delegation.py`
5. No code changes required!

## Debugging Delegation

```python
from config.config_loader import load_agent_config

config = load_agent_config()
agent = config.get_agent_for_request("your request here")
print(f"Selected: {agent}")

# Get all details
details = config.get_agent_capabilities(agent)
print(details)
```

## Key Configuration Files

### `mcp_tools_config.yaml`
- MCP server paths
- Tool categories
- Environment settings

### `tool_agent_mapping.yaml`
- Tool → Agent mappings
- Request patterns
- Expertise matrix

### `agents/*.yaml`
- Individual agent capabilities
- Tool permissions
- Delegation triggers