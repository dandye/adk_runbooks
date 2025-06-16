"""
Configuration loader for agent capabilities and tool mappings.
Provides structured access to agent configurations for delegation decisions.
"""

import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional, Any


class AgentConfigLoader:
    """Loads and provides access to agent capability configurations."""
    
    def __init__(self, config_dir: Path = None):
        """Initialize the configuration loader.
        
        Args:
            config_dir: Path to configuration directory. Defaults to ./config
        """
        if config_dir is None:
            config_dir = Path(__file__).parent
        
        self.config_dir = config_dir
        self.agents_dir = config_dir / "agents"
        
        # Load all configurations
        self.agent_configs = self._load_agent_configs()
        self.mcp_config = self._load_mcp_config()
        self.tool_mapping = self._load_tool_mapping()
        
    def _load_yaml(self, file_path: Path) -> Dict[str, Any]:
        """Load a YAML file."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            return {}
    
    def _load_agent_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load all agent configuration files."""
        configs = {}
        if self.agents_dir.exists():
            for yaml_file in self.agents_dir.glob("*.yaml"):
                config = self._load_yaml(yaml_file)
                if 'agent_name' in config:
                    configs[config['agent_name']] = config
        return configs
    
    def _load_mcp_config(self) -> Dict[str, Any]:
        """Load MCP tools configuration."""
        mcp_config_path = self.config_dir / "mcp_tools_config.yaml"
        return self._load_yaml(mcp_config_path)
    
    def _load_tool_mapping(self) -> Dict[str, Any]:
        """Load tool-to-agent mapping configuration."""
        mapping_path = self.config_dir / "tool_agent_mapping.yaml"
        return self._load_yaml(mapping_path)
    
    def get_agent_for_request(self, request: str) -> Optional[str]:
        """Determine the best agent for a given request.
        
        Args:
            request: The user's request text
            
        Returns:
            The agent name best suited for the request, or None
        """
        request_lower = request.lower()
        
        # First, check request patterns
        if 'request_patterns' in self.tool_mapping:
            for pattern_config in self.tool_mapping['request_patterns']:
                pattern = pattern_config.get('pattern', '')
                if re.search(pattern, request_lower):
                    return pattern_config.get('agent')
        
        # Second, check for expertise area mentions
        best_score = 0
        best_agent = None
        
        for agent_name, config in self.agent_configs.items():
            score = 0
            
            # Check expertise areas
            for expertise in config.get('expertise_areas', []):
                if expertise.replace('_', ' ') in request_lower:
                    score += 2
            
            # Check delegation triggers
            for trigger in config.get('delegation_triggers', []):
                if trigger in request_lower:
                    score += 3
            
            if score > best_score:
                best_score = score
                best_agent = agent_name
        
        return best_agent
    
    def get_agents_for_tool(self, tool_name: str) -> Dict[str, List[str]]:
        """Get agents that can use a specific tool.
        
        Args:
            tool_name: Name of the MCP tool
            
        Returns:
            Dict with 'primary' and 'secondary' agent lists
        """
        if 'tool_mappings' in self.tool_mapping:
            tool_info = self.tool_mapping['tool_mappings'].get(tool_name, {})
            return {
                'primary': tool_info.get('primary_agents', []),
                'secondary': tool_info.get('secondary_agents', [])
            }
        return {'primary': [], 'secondary': []}
    
    def get_agent_capabilities(self, agent_name: str) -> Dict[str, Any]:
        """Get full capabilities for a specific agent.
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Agent configuration dict
        """
        return self.agent_configs.get(agent_name, {})
    
    def get_mcp_server_config(self, server_name: str) -> Dict[str, Any]:
        """Get configuration for a specific MCP server.
        
        Args:
            server_name: Name of the MCP server
            
        Returns:
            Server configuration dict
        """
        if 'mcp_servers' in self.mcp_config:
            return self.mcp_config['mcp_servers'].get(server_name, {})
        return {}
    
    def get_all_agent_summaries(self) -> str:
        """Generate a summary of all agents and their capabilities.
        
        Returns:
            Formatted string with agent summaries
        """
        summaries = []
        
        for agent_name, config in sorted(self.agent_configs.items()):
            summary = f"**{config.get('display_name', agent_name)}**"
            summary += f"\n- Description: {config.get('description', 'No description')}"
            
            expertise = config.get('expertise_areas', [])
            if expertise:
                summary += f"\n- Expertise: {', '.join(expertise[:3])}..."
            
            mcp_servers = config.get('mcp_servers', [])
            if mcp_servers:
                server_names = [s['name'] for s in mcp_servers]
                summary += f"\n- Tools: {', '.join(server_names)}"
            
            summaries.append(summary)
        
        return "\n\n".join(summaries)
    
    def build_delegation_instructions(self) -> str:
        """Build structured delegation instructions for the manager agent.
        
        Returns:
            Formatted delegation instructions
        """
        instructions = ["## Agent Delegation Guide\n"]
        
        # Add pattern-based rules
        instructions.append("### Request Pattern Matching")
        if 'request_patterns' in self.tool_mapping:
            for pattern in self.tool_mapping['request_patterns']:
                instructions.append(
                    f"- Pattern: `{pattern['pattern']}` → "
                    f"**{pattern['agent']}** (confidence: {pattern.get('confidence', 'medium')})"
                )
        
        instructions.append("\n### Agent Capabilities Summary")
        
        # Add agent summaries
        for agent_name, config in sorted(self.agent_configs.items()):
            instructions.append(f"\n**{config.get('display_name', agent_name)}**")
            
            # Delegation triggers
            triggers = config.get('delegation_triggers', [])
            if triggers:
                instructions.append(f"- Triggers: {', '.join(triggers[:5])}")
            
            # Key tools
            mcp_servers = config.get('mcp_servers', [])
            if mcp_servers:
                key_tools = []
                for server in mcp_servers[:2]:  # First 2 servers
                    tools = server.get('tools', [])
                    key_tools.extend(tools[:3])  # First 3 tools
                if key_tools:
                    instructions.append(f"- Key tools: {', '.join(key_tools[:5])}")
        
        return "\n".join(instructions)


# Convenience function for loading config
def load_agent_config(config_dir: Path = None) -> AgentConfigLoader:
    """Load agent configuration from the specified directory.
    
    Args:
        config_dir: Path to configuration directory
        
    Returns:
        Initialized AgentConfigLoader
    """
    return AgentConfigLoader(config_dir)