"""
SOC Blackboard Coordinator Agent

Orchestrates investigation workflows using the Blackboard pattern.
Manages investigator and synthesizer agents through a shared knowledge store.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import AsyncExitStack

from google.adk.agents import Agent

from .blackboard import InvestigationBlackboard, BlackboardManager


class BlackboardCoordinator:
    """
    Coordinates SOC investigations using the Blackboard architectural pattern.
    
    Manages the lifecycle of investigations by:
    1. Initializing shared blackboard knowledge store
    2. Activating relevant investigator agents
    3. Running correlation and synthesis
    4. Generating comprehensive reports
    """
    
    def __init__(self):
        self.blackboard_manager = BlackboardManager()
        self.shared_tools = None
        self.shared_exit_stack = None
        
        # Agent registrations - will be loaded dynamically
        self.investigators = {}
        self.synthesizers = {}
        self._load_agents()
    
    def _load_agents(self):
        """Load investigator and synthesizer agents dynamically."""
        try:
            # Import investigators
            from ..investigators import network_analyzer, endpoint_investigator, log_correlator, ioc_enricher, timeline_builder
            self.investigators = {
                "network_analyzer": network_analyzer,
                "endpoint_investigator": endpoint_investigator,
                "log_correlator": log_correlator,
                "ioc_enricher": ioc_enricher,
                "timeline_builder": timeline_builder
            }
            
            # Import synthesizers
            from ..synthesizers import correlation_engine, report_generator
            self.synthesizers = {
                "correlation_engine": correlation_engine,
                "report_generator": report_generator
            }
        except ImportError as e:
            print(f"Warning: Could not load some agents: {e}")
            # Set up minimal functionality for testing
            self.investigators = {}
            self.synthesizers = {}
    
    async def investigate(self, investigation_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a complete SOC investigation using the blackboard pattern.
        
        Args:
            investigation_context: Initial context including case_id, indicators, etc.
            
        Returns:
            Investigation report with findings and recommendations
        """
        case_id = investigation_context.get("case_id", f"INV-{int(asyncio.get_event_loop().time())}")
        
        # Create investigation blackboard
        blackboard = await self.blackboard_manager.create_investigation(
            case_id, investigation_context
        )
        
        try:
            # Phase 1: Initialize blackboard with initial context
            await self._initialize_investigation(blackboard, investigation_context)
            
            # Phase 2: Activate relevant investigators
            investigators = await self._select_investigators(investigation_context)
            
            # Phase 3: Run investigation in parallel
            await self._run_parallel_investigation(blackboard, investigators, investigation_context)
            
            # Phase 4: Run correlation analysis
            await self._run_correlation_analysis(blackboard)
            
            # Phase 5: Generate final report
            report = await self._generate_report(blackboard)
            
            return report
            
        finally:
            # Clean up investigation
            await self.blackboard_manager.close_investigation(case_id)
    
    async def _initialize_investigation(self, blackboard: InvestigationBlackboard, context: Dict[str, Any]):
        """Initialize the blackboard with investigation context."""
        
        # Write initial indicators to blackboard
        initial_indicators = context.get("initial_indicators", [])
        for indicator in initial_indicators:
            await blackboard.write(
                area="investigation_metadata",
                finding={
                    "type": "initial_indicator",
                    "indicator": indicator,
                    "source": "investigation_context"
                },
                agent_name="coordinator",
                confidence="high",
                tags=["initial", "context"]
            )
        
        # Set investigation parameters
        investigation_params = {
            "priority": context.get("priority", "medium"),
            "data_sources": context.get("data_sources", []),
            "investigation_type": context.get("investigation_type", "general"),
            "timeframe": context.get("timeframe", {})
        }
        
        await blackboard.write(
            area="investigation_metadata",
            finding={
                "type": "investigation_parameters",
                "parameters": investigation_params
            },
            agent_name="coordinator",
            confidence="high",
            tags=["configuration"]
        )
    
    async def _select_investigators(self, context: Dict[str, Any]) -> List[str]:
        """Select which investigators to activate based on context."""
        
        investigators = []
        
        # Always include these core investigators
        investigators.extend([
            "network_analyzer",
            "endpoint_investigator", 
            "log_correlator",
            "timeline_builder"
        ])
        
        # Add IOC enricher if we have indicators
        if context.get("initial_indicators"):
            investigators.append("ioc_enricher")
        
        # Could add logic to select investigators based on:
        # - investigation_type
        # - data_sources available
        # - priority level
        # - specific indicators present
        
        return investigators
    
    async def _run_parallel_investigation(self, blackboard: InvestigationBlackboard, 
                                        investigators: List[str], context: Dict[str, Any]):
        """Run multiple investigators in parallel."""
        
        if not self.shared_tools or not self.shared_exit_stack:
            raise RuntimeError("Shared tools not initialized. Call initialize_tools() first.")
        
        # Create investigator tasks
        tasks = []
        for investigator_name in investigators:
            if investigator_name in self.investigators:
                task = asyncio.create_task(
                    self._run_investigator(investigator_name, blackboard, context)
                )
                tasks.append(task)
        
        # Wait for all investigators to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_investigator(self, investigator_name: str, 
                              blackboard: InvestigationBlackboard, context: Dict[str, Any]):
        """Run a single investigator agent."""
        
        try:
            investigator_module = self.investigators[investigator_name]
            
            # Initialize investigator agent
            agent = investigator_module.get_agent(
                self.shared_tools, blackboard, self.shared_exit_stack
            )
            
            # Create investigation prompt based on context
            prompt = self._create_investigator_prompt(investigator_name, context)
            
            # Run the investigator
            await agent.execute(prompt)
            
        except Exception as e:
            # Log error and write to blackboard
            error_finding = {
                "type": "investigator_error",
                "investigator": investigator_name,
                "error": str(e),
                "context": context
            }
            
            await blackboard.write(
                area="investigation_metadata",
                finding=error_finding,
                agent_name="coordinator",
                confidence="high",
                tags=["error", investigator_name]
            )
    
    def _create_investigator_prompt(self, investigator_name: str, context: Dict[str, Any]) -> str:
        """Create a tailored prompt for each investigator."""
        
        base_prompt = f"""
You are investigating case {context.get('case_id', 'UNKNOWN')} - {context.get('title', 'Security Investigation')}.

Priority: {context.get('priority', 'medium')}

Initial Indicators:
"""
        
        # Add initial indicators
        for indicator in context.get("initial_indicators", []):
            base_prompt += f"- {indicator.get('type', 'unknown')}: {indicator.get('value', 'N/A')}\n"
        
        # Add investigator-specific instructions
        if investigator_name == "network_analyzer":
            base_prompt += """
Focus on network traffic analysis:
1. Analyze traffic patterns for the given indicators
2. Look for data exfiltration or C2 communication
3. Identify suspicious connections and protocols
4. Write all findings to the 'network_analysis' knowledge area
"""
        
        elif investigator_name == "endpoint_investigator":
            base_prompt += """
Focus on endpoint behavior analysis:
1. Examine process activities and file system changes
2. Look for persistence mechanisms and lateral movement
3. Analyze running services and registry modifications
4. Write all findings to the 'endpoint_behaviors' knowledge area
"""
        
        elif investigator_name == "log_correlator":
            base_prompt += """
Focus on cross-system log correlation:
1. Correlate authentication and access logs
2. Find timing patterns across different systems
3. Identify coordinated activities
4. Write all findings to the 'log_correlations' knowledge area
"""
        
        elif investigator_name == "ioc_enricher":
            base_prompt += """
Focus on indicator enrichment:
1. Query threat intelligence for all indicators
2. Check reputation services and threat feeds
3. Map to MITRE ATT&CK techniques
4. Write enrichments to 'ioc_enrichments' and threat intel to 'threat_intelligence'
"""
        
        elif investigator_name == "timeline_builder":
            base_prompt += """
Focus on temporal analysis:
1. Build chronological sequence of events
2. Identify event clusters and gaps
3. Highlight critical moments in the attack
4. Write timeline events to 'timeline_events' knowledge area
"""
        
        base_prompt += """
Remember to:
- Read existing findings from other knowledge areas for context
- Use available security tools (Chronicle, SOAR, VirusTotal, etc.)
- Write clear, actionable findings with appropriate confidence levels
- Tag findings appropriately for correlation
"""
        
        return base_prompt
    
    async def _run_correlation_analysis(self, blackboard: InvestigationBlackboard):
        """Run correlation analysis on all findings."""
        
        try:
            correlation_module = self.synthesizers["correlation_engine"]
            
            # Initialize correlation engine
            agent = correlation_module.get_agent(
                self.shared_tools, blackboard, self.shared_exit_stack
            )
            
            # Run correlation analysis
            prompt = """
Analyze all findings in the blackboard to identify patterns and correlations:

1. Look for relationships between network, endpoint, and log findings
2. Identify potential attack chains and sequences
3. Calculate aggregate risk scores
4. Find hidden connections between indicators
5. Write correlation results and risk scores to appropriate knowledge areas

Focus on finding meaningful patterns that tell the story of what happened.
"""
            
            await agent.execute(prompt)
            
        except Exception as e:
            # Log correlation error
            await blackboard.write(
                area="investigation_metadata",
                finding={
                    "type": "correlation_error",
                    "error": str(e)
                },
                agent_name="coordinator",
                confidence="high",
                tags=["error", "correlation"]
            )
    
    async def _generate_report(self, blackboard: InvestigationBlackboard) -> Dict[str, Any]:
        """Generate comprehensive investigation report."""
        
        try:
            report_module = self.synthesizers["report_generator"]
            
            # Initialize report generator
            agent = report_module.get_agent(
                self.shared_tools, blackboard, self.shared_exit_stack
            )
            
            # Generate report
            prompt = """
Generate a comprehensive investigation report based on all blackboard findings:

1. Executive Summary with key findings and risk assessment
2. Detailed Timeline of Events
3. Technical Analysis by category (network, endpoint, logs, etc.)
4. Threat Intelligence summary
5. Risk Assessment and Impact Analysis
6. Recommendations for remediation and prevention
7. Indicators of Compromise list

Make the report actionable for both technical and executive audiences.
"""
            
            report_result = await agent.execute(prompt)
            
            # Also export raw blackboard data
            raw_data = await blackboard.export()
            stats = await blackboard.get_statistics()
            
            return {
                "report": report_result,
                "raw_data": raw_data,
                "statistics": stats,
                "investigation_id": blackboard.investigation_id
            }
            
        except Exception as e:
            # Fallback: create basic report from blackboard data
            raw_data = await blackboard.export()
            stats = await blackboard.get_statistics()
            
            return {
                "report": f"Report generation failed: {str(e)}",
                "raw_data": raw_data,
                "statistics": stats,
                "investigation_id": blackboard.investigation_id,
                "error": str(e)
            }


def get_agent(tools, exit_stack):
    """
    Create the SOC Blackboard Coordinator agent.
    
    Args:
        tools: Shared MCP tools
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for blackboard coordination
    """
    
    # Initialize coordinator with shared resources
    coordinator = BlackboardCoordinator()
    coordinator.shared_tools = tools
    coordinator.shared_exit_stack = exit_stack
    
    # Load persona and instructions
    persona = "You are a SOC Blackboard Coordinator responsible for orchestrating complex security investigations."
    
    # Add runbook instructions
    instructions = persona + """

## Investigation Workflow

1. **Initialize Investigation**: Set up blackboard with initial context
2. **Select Investigators**: Choose appropriate agents based on indicators and context  
3. **Parallel Investigation**: Run multiple investigators simultaneously
4. **Correlation Analysis**: Find patterns across all findings
5. **Report Generation**: Create comprehensive investigation report

## Available Commands

- `investigate(context)`: Start a new investigation with given context
- `list_investigations()`: Show active investigations
- `close_investigation(case_id)`: Close and clean up investigation

## Investigation Context Format

```json
{
    "case_id": "INC-2024-001",
    "title": "Suspicious Network Activity", 
    "priority": "high",
    "initial_indicators": [
        {"type": "ip", "value": "10.0.0.100"},
        {"type": "username", "value": "compromised_user"}
    ],
    "data_sources": ["chronicle", "edr", "firewall_logs"],
    "investigation_type": "data_exfiltration"
}
```

Always use the blackboard pattern - agents communicate through shared knowledge, not directly.

Use the coordinator.investigate(context) method to start investigations.
"""
    
    # Create blackboard tools for the coordinator
    async def start_investigation(context_json: str):
        """Start a new SOC investigation with the given context."""
        import json
        try:
            context = json.loads(context_json)
            result = await coordinator.investigate(context)
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def list_active_investigations():
        """List all active investigations."""
        try:
            investigations = await coordinator.blackboard_manager.list_active_investigations()
            return {"success": True, "investigations": investigations}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    # Add investigation tools to the agent's toolset
    investigation_tools = [start_investigation, list_active_investigations]
    all_tools = tools + investigation_tools
    
    return Agent(
        name="blackboard_coordinator",
        model="gemini-2.5-pro-preview-05-06",
        description="SOC investigation coordinator using Blackboard pattern",
        instruction=instructions,
        tools=all_tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the coordinator."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)