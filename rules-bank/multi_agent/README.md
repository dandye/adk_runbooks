# Multi-Agent Configuration System

This directory contains documentation and configuration specifications for the ADK Runbooks multi-agent system's intelligent delegation framework.

## Overview

The multi-agent system uses a configuration-based approach to intelligently route security tasks to specialized sub-agents without hardcoded logic. This enables dynamic agent management through YAML configuration files.

## Files

### Core Documentation

- **`configuration_based_delegation.md`** - Complete system architecture and implementation guide
- **`config_quick_reference.md`** - Quick reference for YAML configuration syntax
- **`agent_workflow_references.md`** - 15+ agent workflow patterns with Mermaid diagrams

## Key Features

- **Data-Driven Delegation**: Route tasks based on YAML configurations
- **Pattern Matching**: Intelligent request analysis and agent selection
- **Tool Assignment**: Automatic MCP tool provisioning per agent
- **Expertise Mapping**: Agent capabilities and specialization areas
- **Escalation Paths**: Defined agent-to-agent escalation routes

## Quick Start

1. **Review Patterns**: Start with `agent_workflow_references.md` for design patterns
2. **Configuration Syntax**: Check `config_quick_reference.md` for YAML structure
3. **Implementation**: Follow `configuration_based_delegation.md` for full setup

## Configuration Structure

```
multi-agent/manager/config/
├── agents/*.yaml              # Individual agent capabilities
├── mcp_tools_config.yaml      # MCP server configurations
├── tool_agent_mapping.yaml    # Tool-to-agent mappings
└── config_loader.py           # Python configuration loader
```

## Agent Types Supported

- SOC Analyst (Tier 1, 2, 3)
- CTI Researcher
- Incident Responder
- Threat Hunter
- Detection Engineer
- SOAR Specialist

## Benefits

- **No Code Changes**: Update agent behavior via configuration
- **Maintainable**: Centralized capability definitions
- **Flexible**: Easy addition of new agents and tools
- **Intelligent**: Pattern-based task routing
- **Documented**: Configuration serves as living documentation

## Integration

This system integrates with the main ADK Runbooks multi-agent system located in `/multi-agent/manager/` and works with both traditional and A2A (Agent-to-Agent) deployment modes.