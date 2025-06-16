#!/usr/bin/env python3
"""
Validate the configuration files for consistency and completeness.
Checks for common issues and misconfigurations.
"""

import yaml
import sys
from pathlib import Path
from collections import defaultdict

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))


class ConfigValidator:
    """Validates the agent configuration system."""
    
    def __init__(self):
        self.config_dir = Path(__file__).parent.parent / "config"
        self.agents_dir = self.config_dir / "agents"
        self.errors = []
        self.warnings = []
        self.info = []
        
    def load_yaml(self, file_path):
        """Load a YAML file safely."""
        try:
            with open(file_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.errors.append(f"Failed to load {file_path}: {e}")
            return None
            
    def validate_all(self):
        """Run all validation checks."""
        print("🔍 Validating Agent Configuration System...\n")
        
        # Check directory structure
        self.check_directory_structure()
        
        # Validate individual agent configs
        self.validate_agent_configs()
        
        # Validate MCP tools config
        self.validate_mcp_config()
        
        # Validate tool mapping
        self.validate_tool_mapping()
        
        # Cross-reference checks
        self.cross_reference_checks()
        
        # Report results
        self.report_results()
        
    def check_directory_structure(self):
        """Check that required directories and files exist."""
        required_files = [
            self.config_dir / "mcp_tools_config.yaml",
            self.config_dir / "tool_agent_mapping.yaml",
            self.config_dir / "config_loader.py"
        ]
        
        for file_path in required_files:
            if not file_path.exists():
                self.errors.append(f"Missing required file: {file_path}")
            else:
                self.info.append(f"✓ Found {file_path.name}")
                
        if not self.agents_dir.exists():
            self.errors.append(f"Missing agents directory: {self.agents_dir}")
        else:
            agent_count = len(list(self.agents_dir.glob("*.yaml")))
            self.info.append(f"✓ Found {agent_count} agent configuration files")
            
    def validate_agent_configs(self):
        """Validate each agent configuration file."""
        if not self.agents_dir.exists():
            return
            
        required_fields = {
            'agent_name': str,
            'display_name': str,
            'description': str,
            'expertise_areas': list,
            'mcp_servers': list,
            'delegation_triggers': list
        }
        
        agent_names = set()
        
        for yaml_file in self.agents_dir.glob("*.yaml"):
            config = self.load_yaml(yaml_file)
            if not config:
                continue
                
            # Check required fields
            for field, expected_type in required_fields.items():
                if field not in config:
                    self.errors.append(f"{yaml_file.name}: Missing required field '{field}'")
                elif not isinstance(config[field], expected_type):
                    self.errors.append(
                        f"{yaml_file.name}: Field '{field}' should be {expected_type.__name__}"
                    )
                    
            # Check for duplicate agent names
            agent_name = config.get('agent_name')
            if agent_name:
                if agent_name in agent_names:
                    self.errors.append(f"Duplicate agent name: {agent_name}")
                agent_names.add(agent_name)
                
            # Validate MCP servers structure
            for server in config.get('mcp_servers', []):
                if 'name' not in server:
                    self.errors.append(
                        f"{yaml_file.name}: MCP server missing 'name' field"
                    )
                if 'tools' in server and not isinstance(server['tools'], list):
                    self.errors.append(
                        f"{yaml_file.name}: MCP server 'tools' should be a list"
                    )
                    
            # Check for empty lists
            if not config.get('expertise_areas'):
                self.warnings.append(f"{yaml_file.name}: No expertise areas defined")
            if not config.get('delegation_triggers'):
                self.warnings.append(f"{yaml_file.name}: No delegation triggers defined")
                
    def validate_mcp_config(self):
        """Validate the MCP tools configuration."""
        config_path = self.config_dir / "mcp_tools_config.yaml"
        config = self.load_yaml(config_path)
        
        if not config:
            return
            
        if 'mcp_servers' not in config:
            self.errors.append("mcp_tools_config.yaml: Missing 'mcp_servers' section")
            return
            
        for server_name, server_config in config['mcp_servers'].items():
            # Check required fields
            if 'server_path' not in server_config:
                self.errors.append(
                    f"MCP server '{server_name}': Missing 'server_path'"
                )
                
            # Warn about hardcoded paths
            server_path = server_config.get('server_path', '')
            if '/Users/' in server_path:
                self.warnings.append(
                    f"MCP server '{server_name}': Contains hardcoded user path"
                )
                
    def validate_tool_mapping(self):
        """Validate the tool-to-agent mapping."""
        mapping_path = self.config_dir / "tool_agent_mapping.yaml"
        mapping = self.load_yaml(mapping_path)
        
        if not mapping:
            return
            
        # Load agent names for validation
        agent_names = set()
        if self.agents_dir.exists():
            for yaml_file in self.agents_dir.glob("*.yaml"):
                config = self.load_yaml(yaml_file)
                if config and 'agent_name' in config:
                    agent_names.add(config['agent_name'])
                    
        # Validate tool mappings
        if 'tool_mappings' in mapping:
            for tool_name, tool_config in mapping['tool_mappings'].items():
                # Check agent references
                for agent_list in ['primary_agents', 'secondary_agents']:
                    for agent in tool_config.get(agent_list, []):
                        if agent not in agent_names:
                            self.warnings.append(
                                f"Tool '{tool_name}': References unknown agent '{agent}'"
                            )
                            
        # Validate request patterns
        if 'request_patterns' in mapping:
            for pattern in mapping['request_patterns']:
                if 'pattern' not in pattern:
                    self.errors.append("Request pattern missing 'pattern' field")
                if 'agent' not in pattern:
                    self.errors.append("Request pattern missing 'agent' field")
                elif pattern['agent'] not in agent_names:
                    self.warnings.append(
                        f"Request pattern references unknown agent: {pattern['agent']}"
                    )
                    
    def cross_reference_checks(self):
        """Perform cross-reference checks between configs."""
        # Load all configs
        mcp_config = self.load_yaml(self.config_dir / "mcp_tools_config.yaml")
        tool_mapping = self.load_yaml(self.config_dir / "tool_agent_mapping.yaml")
        
        if not mcp_config or not tool_mapping:
            return
            
        # Check that MCP servers referenced in agents exist
        mcp_server_names = set(mcp_config.get('mcp_servers', {}).keys())
        
        for yaml_file in self.agents_dir.glob("*.yaml"):
            config = self.load_yaml(yaml_file)
            if not config:
                continue
                
            for server in config.get('mcp_servers', []):
                server_name = server.get('name')
                if server_name and server_name not in mcp_server_names:
                    self.errors.append(
                        f"{config.get('agent_name')}: References unknown MCP server '{server_name}'"
                    )
                    
        # Track tool usage
        tool_usage = defaultdict(list)
        for yaml_file in self.agents_dir.glob("*.yaml"):
            config = self.load_yaml(yaml_file)
            if not config:
                continue
                
            agent_name = config.get('agent_name', 'unknown')
            for server in config.get('mcp_servers', []):
                for tool in server.get('tools', []):
                    tool_usage[tool].append(agent_name)
                    
        # Report tools with no agents
        if 'tool_mappings' in tool_mapping:
            for tool_name in tool_mapping['tool_mappings']:
                if tool_name not in tool_usage:
                    self.warnings.append(f"Tool '{tool_name}' is mapped but not used by any agent")
                    
    def report_results(self):
        """Report validation results."""
        print("\n📋 Validation Results:\n")
        
        if self.info:
            print("ℹ️  Information:")
            for msg in self.info:
                print(f"   {msg}")
                
        if self.warnings:
            print("\n⚠️  Warnings:")
            for warning in self.warnings:
                print(f"   {warning}")
                
        if self.errors:
            print("\n❌ Errors:")
            for error in self.errors:
                print(f"   {error}")
        else:
            print("\n✅ No errors found!")
            
        # Summary
        print(f"\nSummary: {len(self.errors)} errors, {len(self.warnings)} warnings")
        
        # Return exit code
        return 1 if self.errors else 0


def main():
    """Main entry point."""
    validator = ConfigValidator()
    exit_code = validator.validate_all()
    
    # Additional recommendations
    if exit_code == 0:
        print("\n💡 Recommendations:")
        print("   1. Run the demo_delegation.py script to test delegation logic")
        print("   2. Update hardcoded paths to use environment variables")
        print("   3. Add more detailed tool descriptions in agent configs")
        print("   4. Consider adding agent workload/availability tracking")
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())