# Multi-Agent Systems Documentation

This section contains documentation for the ADK multi-agent security operations system.

## Overview

The ADK Security Operations platform implements a sophisticated multi-agent system where specialized AI agents collaborate to handle complex cybersecurity tasks. The system supports both traditional (integrated) and A2A (distributed) deployment models.

## Documentation Structure

### Core Documentation
- [Multi-Agent Systems Overview](../multi_agent_overview.md) - General concepts and architecture
- [A2A Multi-Agent System](a2a_system.md) - Agent-to-Agent distributed architecture
- [A2A Next Steps](a2a_next_steps.md) - Implementation roadmap and future development

### Related Documentation
- [Agent Personas](../personas/) - Detailed behavior profiles for each agent type
- [Security Runbooks](../run_books/) - Operational procedures agents follow
- [MCP Tool Best Practices](../mcp_tool_best_practices.md) - Tool integration guidelines
- [GTI MCP Tools Reference](../tools/GTI_MCP_TOOLS_REFERENCE.md) - Threat intelligence tools

## Quick Links

### For Developers
- [Getting Started with A2A](a2a_system.md#quick-start-guide)
- [Adding New Agents](a2a_system.md#adding-new-agents)
- [Troubleshooting Guide](a2a_system.md#troubleshooting)

### For Security Teams
- [Available Security Agents](a2a_system.md#available-security-agents)
- [Usage Examples](a2a_system.md#usage-examples)
- [Security Considerations](a2a_system.md#security-considerations)

## Architecture Models

### Traditional Multi-Agent
- All agents run within a single ADK process
- Shared memory and direct communication
- Simpler deployment and management
- Best for single-team operations

### A2A (Agent-to-Agent)
- Agents run as independent services
- REST API communication via A2A protocol
- Scalable and distributed deployment
- Best for enterprise SOC operations

## Getting Help

For questions or issues:
- Check the [troubleshooting guide](a2a_system.md#troubleshooting)
- Review [ADK documentation](https://github.com/google/adk)
- File issues on GitHub