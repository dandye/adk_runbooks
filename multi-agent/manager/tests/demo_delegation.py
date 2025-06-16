#!/usr/bin/env python3
"""
Interactive demonstration of the agent configuration and delegation system.
This script shows how the manager agent would delegate various security tasks.
"""

import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from config.config_loader import load_agent_config

console = Console()


def print_header(text):
    """Print a formatted header."""
    console.print(f"\n[bold blue]{'='*60}[/bold blue]")
    console.print(f"[bold cyan]{text}[/bold cyan]")
    console.print(f"[bold blue]{'='*60}[/bold blue]\n")


def demonstrate_delegation():
    """Demonstrate the delegation system with various scenarios."""
    config_loader = load_agent_config()
    
    # Test scenarios
    scenarios = [
        {
            "title": "Security Alert Triage",
            "requests": [
                "Triage security alert for suspicious login",
                "Initial investigation of alert ID 12345",
                "Check if this alert is a false positive"
            ]
        },
        {
            "title": "SOAR Case Management",
            "requests": [
                "Investigate SOAR case 2955",
                "Deep investigation of phishing case",
                "Update case priority based on findings"
            ]
        },
        {
            "title": "Malware Analysis",
            "requests": [
                "Analyze this malware sample hash abc123",
                "Check file behavior for malicious activity",
                "Perform advanced forensics on infected system"
            ]
        },
        {
            "title": "Threat Intelligence",
            "requests": [
                "Research FIN7 threat actor",
                "Get threat intelligence on Lazarus group",
                "Find IOCs related to recent campaign"
            ]
        },
        {
            "title": "Incident Response",
            "requests": [
                "Start incident response for ransomware",
                "Contain the malware outbreak",
                "Coordinate recovery efforts"
            ]
        },
        {
            "title": "Threat Hunting",
            "requests": [
                "Hunt for threats in our environment",
                "Look for signs of APT activity",
                "Develop hunting hypothesis for insider threat"
            ]
        },
        {
            "title": "Detection Engineering",
            "requests": [
                "Create detection rule for PowerShell abuse",
                "Develop SIEM rule for this TTP",
                "Tune detection to reduce false positives"
            ]
        }
    ]
    
    print_header("Agent Delegation Demonstration")
    
    for scenario in scenarios:
        console.print(f"[bold yellow]{scenario['title']}:[/bold yellow]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Request", style="cyan", width=40)
        table.add_column("Delegated To", style="green")
        table.add_column("Agent Expertise", style="dim")
        
        for request in scenario['requests']:
            agent = config_loader.get_agent_for_request(request)
            if agent:
                capabilities = config_loader.get_agent_capabilities(agent)
                display_name = capabilities.get('display_name', agent)
                expertise = ", ".join(capabilities.get('expertise_areas', [])[:2])
                table.add_row(request, display_name, expertise)
            else:
                table.add_row(request, "[red]No match[/red]", "-")
        
        console.print(table)
        console.print()


def show_agent_capabilities():
    """Display detailed agent capabilities."""
    config_loader = load_agent_config()
    
    print_header("Agent Capabilities Overview")
    
    for agent_name in sorted(config_loader.agent_configs.keys()):
        config = config_loader.agent_configs[agent_name]
        
        # Create panel content
        content = []
        content.append(f"[yellow]Description:[/yellow] {config.get('description', 'N/A')}")
        
        # Expertise areas
        expertise = config.get('expertise_areas', [])
        if expertise:
            content.append(f"\n[yellow]Expertise:[/yellow]")
            for exp in expertise[:5]:
                content.append(f"  • {exp}")
        
        # MCP Tools
        mcp_servers = config.get('mcp_servers', [])
        if mcp_servers:
            content.append(f"\n[yellow]MCP Tool Access:[/yellow]")
            for server in mcp_servers:
                content.append(f"  • {server['name']}: {server.get('description', 'N/A')}")
                if 'tools' in server and len(server['tools']) > 0:
                    content.append(f"    Tools: {', '.join(server['tools'][:3])}...")
        
        # Delegation triggers
        triggers = config.get('delegation_triggers', [])
        if triggers:
            content.append(f"\n[yellow]Delegation Keywords:[/yellow]")
            content.append(f"  {', '.join(triggers[:4])}...")
        
        panel = Panel(
            "\n".join(content),
            title=f"[bold cyan]{config.get('display_name', agent_name)}[/bold cyan]",
            border_style="blue"
        )
        console.print(panel)


def test_tool_mapping():
    """Test and display tool-to-agent mappings."""
    config_loader = load_agent_config()
    
    print_header("Tool to Agent Mapping Examples")
    
    # Select some key tools to demonstrate
    key_tools = [
        "search_security_events",
        "list_cases",
        "analyse_file",
        "search_threats",
        "get_case_full_details",
        "create_detection_rule"
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("MCP Tool", style="cyan", width=30)
    table.add_column("Primary Agents", style="green")
    table.add_column("Secondary Agents", style="yellow")
    table.add_column("Use Cases", style="dim", width=40)
    
    for tool in key_tools:
        if 'tool_mappings' in config_loader.tool_mapping:
            tool_info = config_loader.tool_mapping['tool_mappings'].get(tool, {})
            primary = ", ".join(tool_info.get('primary_agents', [])[:2])
            secondary = ", ".join(tool_info.get('secondary_agents', [])[:2])
            use_cases = "; ".join(tool_info.get('use_cases', [])[:2])
            
            table.add_row(tool, primary or "-", secondary or "-", use_cases or "-")
    
    console.print(table)


def interactive_test():
    """Interactive testing mode."""
    config_loader = load_agent_config()
    
    print_header("Interactive Delegation Test")
    console.print("[dim]Type 'quit' to exit[/dim]\n")
    
    while True:
        request = console.input("[bold]Enter a security request:[/bold] ")
        
        if request.lower() in ['quit', 'exit', 'q']:
            break
            
        agent = config_loader.get_agent_for_request(request)
        
        if agent:
            capabilities = config_loader.get_agent_capabilities(agent)
            console.print(f"\n[green]✓[/green] Best agent: [bold green]{capabilities.get('display_name', agent)}[/bold green]")
            console.print(f"   Reason: {capabilities.get('description', 'N/A')}")
            
            # Show matching triggers
            request_lower = request.lower()
            matching_triggers = [
                trigger for trigger in capabilities.get('delegation_triggers', [])
                if trigger in request_lower
            ]
            if matching_triggers:
                console.print(f"   Matched keywords: {', '.join(matching_triggers)}")
            
            # Show available tools
            mcp_servers = capabilities.get('mcp_servers', [])
            if mcp_servers:
                tools_preview = []
                for server in mcp_servers[:2]:
                    tools_preview.extend(server.get('tools', [])[:3])
                if tools_preview:
                    console.print(f"   Available tools: {', '.join(tools_preview[:5])}...")
        else:
            console.print(f"\n[red]✗[/red] No specific agent match found")
            console.print("   The manager would need to analyze this request manually")
        
        console.print()


def main():
    """Main entry point."""
    console.print("[bold]Agent Configuration System Demo[/bold]")
    console.print("[dim]This demonstrates the new configuration-based delegation system[/dim]\n")
    
    while True:
        console.print("\n[bold cyan]Options:[/bold cyan]")
        console.print("1. Demonstrate delegation scenarios")
        console.print("2. Show agent capabilities")
        console.print("3. Show tool mappings")
        console.print("4. Interactive delegation test")
        console.print("5. Exit")
        
        choice = console.input("\n[bold]Select option (1-5):[/bold] ")
        
        if choice == '1':
            demonstrate_delegation()
        elif choice == '2':
            show_agent_capabilities()
        elif choice == '3':
            test_tool_mapping()
        elif choice == '4':
            interactive_test()
        elif choice == '5':
            console.print("[dim]Goodbye![/dim]")
            break
        else:
            console.print("[red]Invalid option[/red]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted[/dim]")
    except ImportError:
        # Fallback if rich is not installed
        print("Note: Install 'rich' package for better formatting: pip install rich")
        
        # Simple version without rich
        config_loader = load_agent_config()
        print("\nSimple Delegation Test (install 'rich' for full demo)\n")
        
        test_requests = [
            "Triage security alert",
            "Investigate SOAR case", 
            "Analyze malware",
            "Research threat actor",
            "Start incident response"
        ]
        
        for request in test_requests:
            agent = config_loader.get_agent_for_request(request)
            if agent:
                print(f"'{request}' → {agent}")
            else:
                print(f"'{request}' → No match")