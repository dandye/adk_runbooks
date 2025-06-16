# Security Tools Documentation

This section contains documentation for the MCP (Model Context Protocol) security tools used by the ADK multi-agent system.

## Available Tools

### Threat Intelligence Tools
- [GTI MCP Tools Reference](GTI_MCP_TOOLS_REFERENCE.md) - GetTheIntel threat intelligence platform integration

### Coming Soon
- SecOps MCP Tools - SIEM and security operations tools
- SOAR MCP Tools - Security orchestration and automation tools
- SCC MCP Tools - Security command center integration

## Tool Categories

### Intelligence Gathering
- Threat actor research
- IOC enrichment and analysis
- Campaign tracking
- Vulnerability intelligence

### Security Operations
- SIEM queries and searches
- Alert management
- Case management
- Incident response automation

### Detection & Response
- Detection rule management
- Threat hunting queries
- Response playbook execution
- Forensic data collection

## Integration Guidelines

For integrating MCP tools with agents:
1. Review the [MCP Tool Best Practices](../mcp_tool_best_practices.md)
2. Configure tool paths in `multi-agent/manager/tools/tools.py`
3. Follow the deferred initialization pattern for async tool setup
4. Share tool instances across agents to avoid redundant connections

## Tool Development

To create new MCP security tools:
1. Follow the MCP protocol specification
2. Implement proper error handling and logging
3. Document all available functions and parameters
4. Provide example usage in agent contexts