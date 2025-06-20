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


def ensure_tools_list(tools):
    """Ensure tools are in list format, handling various input types."""
    if tools is None:
        return []
    elif isinstance(tools, list):
        return tools
    elif isinstance(tools, tuple):
        return list(tools)
    elif isinstance(tools, dict):
        # If tools is a dict, it might be a processed format from ADK
        # Try to extract the actual tools if possible
        if 'tools' in tools:
            return ensure_tools_list(tools['tools'])
        elif hasattr(tools, 'values'):
            # If it's a dict-like object, try to get the values
            values = list(tools.values())
            # Check if the values look like tools (callables)
            if values and all(callable(v) or hasattr(v, '__call__') for v in values[:min(3, len(values))]):
                return values
            else:
                print(f"Warning: Tools dict doesn't contain callable values")
                return []
        else:
            print(f"Warning: Tools is a dict without 'tools' key: {list(tools.keys())[:5]}")
            return []
    elif hasattr(tools, '__iter__') and not isinstance(tools, str):
        # Handle other iterables
        try:
            return list(tools)
        except Exception as e:
            print(f"Warning: Failed to convert tools to list: {e}")
            return []
    else:
        # Single tool or unexpected type
        if callable(tools) or hasattr(tools, '__call__'):
            return [tools]
        else:
            print(f"Warning: Unexpected tools type: {type(tools)}")
            return []


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
        print("DEBUG: BlackboardCoordinator.__init__() called")
        self.blackboard_manager = BlackboardManager()
        self.shared_tools = None
        self.shared_exit_stack = None
        
        # Agent registrations - will be loaded dynamically
        self.investigators = {}
        self.synthesizers = {}
        print("DEBUG: About to call _load_agents()...")
        self._load_agents()
        print(f"DEBUG: _load_agents() completed. Final counts - Investigators: {len(self.investigators)}, Synthesizers: {len(self.synthesizers)}")
    
    def _load_agents(self):
        """Load investigator and synthesizer agents dynamically."""
        print("DEBUG: Starting agent loading...")
        
        # Load investigators
        try:
            print("DEBUG: Importing investigators...")
            try:
                from ..investigators import network_analyzer, endpoint_investigator, log_correlator, ioc_enricher, timeline_builder
                print("DEBUG: Successfully imported using relative imports")
            except ImportError as rel_error:
                print(f"DEBUG: Relative import failed: {rel_error}, trying absolute imports...")
                # Try absolute imports as fallback
                import sys
                from pathlib import Path
                parent_dir = Path(__file__).parent.parent
                if str(parent_dir) not in sys.path:
                    sys.path.insert(0, str(parent_dir))
                from investigators import network_analyzer, endpoint_investigator, log_correlator, ioc_enricher, timeline_builder
                print("DEBUG: Successfully imported using absolute imports")
                
            self.investigators = {
                "network_analyzer": network_analyzer,
                "endpoint_investigator": endpoint_investigator,
                "log_correlator": log_correlator,
                "ioc_enricher": ioc_enricher,
                "timeline_builder": timeline_builder
            }
            print(f"DEBUG: Successfully loaded {len(self.investigators)} investigators: {list(self.investigators.keys())}")
        except Exception as e:
            print(f"ERROR: Could not load investigators: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.investigators = {}
        
        # Load synthesizers  
        try:
            print("DEBUG: Importing synthesizers...")
            try:
                from ..synthesizers import correlation_engine, report_generator
                print("DEBUG: Successfully imported synthesizers using relative imports")
            except ImportError as rel_error:
                print(f"DEBUG: Relative import failed for synthesizers: {rel_error}, trying absolute imports...")
                # Try absolute imports as fallback
                import sys
                from pathlib import Path
                parent_dir = Path(__file__).parent.parent
                if str(parent_dir) not in sys.path:
                    sys.path.insert(0, str(parent_dir))
                from synthesizers import correlation_engine, report_generator
                print("DEBUG: Successfully imported synthesizers using absolute imports")
                
            self.synthesizers = {
                "correlation_engine": correlation_engine,
                "report_generator": report_generator
            }
            print(f"DEBUG: Successfully loaded {len(self.synthesizers)} synthesizers: {list(self.synthesizers.keys())}")
        except Exception as e:
            print(f"ERROR: Could not load synthesizers: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            self.synthesizers = {}
        
        print(f"DEBUG: Agent loading complete. Investigators: {len(self.investigators)}, Synthesizers: {len(self.synthesizers)}")
    
    async def investigate(self, investigation_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a complete SOC investigation using the blackboard pattern.
        
        Args:
            investigation_context: Initial context including case_id, indicators, etc.
            
        Returns:
            Investigation report with findings and recommendations
        """
        print(f"DEBUG: ========== STARTING INVESTIGATION ==========")
        case_id = investigation_context.get("case_id", f"INV-{int(asyncio.get_event_loop().time())}")
        print(f"DEBUG: Investigation Case ID: {case_id}")
        print(f"DEBUG: Investigation Context: {investigation_context}")
        
        # Create investigation blackboard
        print("DEBUG: Creating investigation blackboard...")
        blackboard = await self.blackboard_manager.create_investigation(
            case_id, investigation_context
        )
        print(f"DEBUG: Blackboard created for investigation: {blackboard.investigation_id}")
        
        investigation_successful = False
        
        try:
            # Phase 1: Initialize blackboard with initial context
            print("DEBUG: Phase 1 - Initializing investigation...")
            await self._initialize_investigation(blackboard, investigation_context)
            print("DEBUG: Phase 1 completed")
            
            # Phase 2: Activate relevant investigators
            print("DEBUG: Phase 2 - Selecting investigators...")
            investigators = await self._select_investigators(investigation_context)
            print(f"DEBUG: Selected investigators: {investigators}")
            
            # Phase 3: Run investigation in parallel
            print("DEBUG: Phase 3 - Running parallel investigation...")
            await self._run_parallel_investigation(blackboard, investigators, investigation_context)
            print("DEBUG: Phase 3 completed")
            
            # Phase 4: Run correlation analysis
            print("DEBUG: Phase 4 - Running correlation analysis...")
            await self._run_correlation_analysis(blackboard)
            print("DEBUG: Phase 4 completed")
            
            # Phase 5: Generate final report
            print("DEBUG: Phase 5 - Generating report...")
            report = await self._generate_report(blackboard)
            print("DEBUG: Phase 5 completed")
            
            print("DEBUG: ========== INVESTIGATION COMPLETED ==========")
            investigation_successful = True
            return report
            
        except Exception as e:
            print(f"ERROR: Investigation failed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            
            # Write error to blackboard for debugging
            await blackboard.write(
                area="investigation_metadata",
                finding={
                    "type": "investigation_error",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "phase": "unknown"
                },
                agent_name="coordinator",
                confidence="high",
                tags=["error", "investigation_failure"]
            )
            
            # Return error report
            raw_data = await blackboard.export()
            stats = await blackboard.get_statistics()
            return {
                "report": f"Investigation failed: {str(e)}",
                "raw_data": raw_data,
                "statistics": stats,
                "investigation_id": blackboard.investigation_id,
                "error": str(e),
                "error_type": type(e).__name__
            }
            
        finally:
            # Only clean up investigation if it completed successfully
            # Keep failed investigations active for debugging
            if investigation_successful:
                print(f"DEBUG: Cleaning up successful investigation {case_id}")
                await self.blackboard_manager.close_investigation(case_id)
            else:
                print(f"DEBUG: Keeping failed investigation {case_id} active for debugging")
    
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
        
        print(f"DEBUG: Starting parallel investigation with {len(investigators)} investigators: {investigators}")
        
        if not self.shared_tools or not self.shared_exit_stack:
            raise RuntimeError("Shared tools not initialized. Call initialize_tools() first.")
        
        print(f"DEBUG: Available investigators: {list(self.investigators.keys())}")
        
        # Create investigator tasks
        tasks = []
        for investigator_name in investigators:
            if investigator_name in self.investigators:
                print(f"DEBUG: Creating task for {investigator_name}")
                task = asyncio.create_task(
                    self._run_investigator(investigator_name, blackboard, context)
                )
                tasks.append(task)
            else:
                print(f"WARNING: Investigator {investigator_name} not found in available investigators")
        
        # Wait for all investigators to complete
        if tasks:
            print(f"DEBUG: Running {len(tasks)} investigator tasks...")
            results = await asyncio.gather(*tasks, return_exceptions=True)
            print(f"DEBUG: All investigator tasks completed. Results: {[type(r).__name__ if isinstance(r, Exception) else 'Success' for r in results]}")
        else:
            print("WARNING: No investigator tasks to run")
    
    async def _run_investigator(self, investigator_name: str, 
                              blackboard: InvestigationBlackboard, context: Dict[str, Any]):
        """Run a single investigator agent."""
        
        try:
            investigator_module = self.investigators[investigator_name]
            
            # Create blackboard tools for this investigation
            blackboard_tools = self._create_blackboard_tools(blackboard, investigator_name)
            
            # Combine shared tools with blackboard tools
            # Ensure both are lists before combining
            shared_tools_list = ensure_tools_list(self.shared_tools)
            all_tools = shared_tools_list + blackboard_tools
            
            
            # Initialize investigator agent with combined tools
            try:
                agent, _ = await investigator_module.initialize(all_tools, self.shared_exit_stack)
            except Exception as init_error:
                print(f"ERROR: Failed to initialize {investigator_name}: {type(init_error).__name__}: {init_error}")
                
                # Try to provide more context about the error
                if "'dict' object has no attribute 'append'" in str(init_error):
                    print(f"ERROR: Dict append error - tools format issue detected")
                raise
            
            # Create investigation prompt based on context
            prompt = self._create_investigator_prompt(investigator_name, context)
            
            # Run the investigator
            print(f"DEBUG: Running {investigator_name} with prompt: {prompt[:100]}...")
            
            # Use a Runner to properly invoke the agent
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
            
            # Create a temporary runner for this investigator
            runner = Runner(
                app_name='soc_blackboard',
                agent=agent,
                session_service=InMemorySessionService(),
            )
            
            # Create a session
            session = await runner.session_service.create_session(
                app_name='soc_blackboard',
                user_id='system'
            )
            
            # Create user message
            content = types.Content(role='user', parts=[types.Part(text=prompt)])
            
            # Run the agent
            results = []
            async for event in runner.run_async(
                session_id=session.id,
                user_id=session.user_id,
                new_message=content
            ):
                results.append(event)
                if hasattr(event, 'response') and event.response:
                    print(f"DEBUG: {investigator_name} generated response")
            print(f"DEBUG: {investigator_name} completed successfully with {len(results)} events")
            
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
    
    def _create_blackboard_tools(self, blackboard: InvestigationBlackboard, agent_name: str):
        """Create blackboard interaction tools for an agent."""
        from typing import Optional, List
        
        async def blackboard_read(area: str = ""):
            """Read findings from the investigation blackboard. Leave area empty to read all areas."""
            try:
                # Convert empty string to None for the actual call
                area_param = area if area else None
                return await blackboard.read(area_param)
            except Exception as e:
                return {"error": f"Failed to read from blackboard: {str(e)}"}
        
        async def blackboard_write(area: str, finding: dict, confidence: str = "medium", tags: Optional[List[str]] = None):
            """Write a finding to the investigation blackboard."""
            try:
                # Handle None tags properly
                if tags is None:
                    tags = []
                finding_id = await blackboard.write(
                    area=area,
                    finding=finding,
                    agent_name=agent_name,
                    confidence=confidence,
                    tags=tags
                )
                return {"success": True, "finding_id": finding_id}
            except Exception as e:
                return {"error": f"Failed to write to blackboard: {str(e)}"}
        
        async def blackboard_query(filters: dict):
            """Query the investigation blackboard with filters."""
            try:
                return await blackboard.query(filters)
            except Exception as e:
                return {"error": f"Failed to query blackboard: {str(e)}"}
        
        return [blackboard_read, blackboard_write, blackboard_query]
    
    async def _run_correlation_analysis(self, blackboard: InvestigationBlackboard):
        """Run correlation analysis on all findings."""
        print("DEBUG: Starting correlation analysis...")
        
        try:
            print(f"DEBUG: Available synthesizers: {list(self.synthesizers.keys())}")
            if "correlation_engine" not in self.synthesizers:
                raise KeyError("correlation_engine not available in synthesizers")
                
            correlation_module = self.synthesizers["correlation_engine"]
            print(f"DEBUG: Got correlation_engine module: {correlation_module}")
            
            # Create blackboard tools for correlation engine
            blackboard_tools = self._create_blackboard_tools(blackboard, "correlation_engine")
            print(f"DEBUG: Created blackboard tools, count: {len(blackboard_tools)}")
            
            # Combine shared tools with blackboard tools
            # Ensure both are lists before combining
            shared_tools_list = ensure_tools_list(self.shared_tools)
            all_tools = shared_tools_list + blackboard_tools
            print(f"DEBUG: Combined tools, total count: {len(all_tools)}")
            
            # Initialize correlation engine
            print("DEBUG: Initializing correlation engine...")
            agent, _ = await correlation_module.initialize(all_tools, self.shared_exit_stack)
            print(f"DEBUG: Correlation engine initialized: {agent.name}")
            
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
            
            print("DEBUG: Running correlation analysis...")
            
            # Use a Runner to properly invoke the agent
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
            
            # Create a temporary runner for correlation
            runner = Runner(
                app_name='soc_blackboard',
                agent=agent,
                session_service=InMemorySessionService(),
            )
            
            # Create a session
            session = await runner.session_service.create_session(
                app_name='soc_blackboard',
                user_id='system'
            )
            
            # Create user message
            content = types.Content(role='user', parts=[types.Part(text=prompt)])
            
            # Run the agent
            results = []
            async for event in runner.run_async(
                session_id=session.id,
                user_id=session.user_id,
                new_message=content
            ):
                results.append(event)
                if hasattr(event, 'response') and event.response:
                    print(f"DEBUG: Correlation analysis generated response")
            print(f"DEBUG: Correlation analysis completed successfully with {len(results)} events")
            
        except Exception as e:
            print(f"ERROR: Correlation analysis failed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            
            # Log correlation error
            await blackboard.write(
                area="investigation_metadata",
                finding={
                    "type": "correlation_error",
                    "error": str(e),
                    "error_type": type(e).__name__
                },
                agent_name="coordinator",
                confidence="high",
                tags=["error", "correlation"]
            )
    
    async def _generate_report(self, blackboard: InvestigationBlackboard) -> Dict[str, Any]:
        """Generate comprehensive investigation report."""
        print("DEBUG: Starting report generation...")
        
        try:
            print(f"DEBUG: Available synthesizers: {list(self.synthesizers.keys())}")
            if "report_generator" not in self.synthesizers:
                raise KeyError("report_generator not available in synthesizers")
                
            report_module = self.synthesizers["report_generator"]
            print(f"DEBUG: Got report_generator module: {report_module}")
            
            # Create blackboard tools for report generator
            blackboard_tools = self._create_blackboard_tools(blackboard, "report_generator")
            print(f"DEBUG: Created blackboard tools, count: {len(blackboard_tools)}")
            
            # Combine shared tools with blackboard tools
            # Ensure both are lists before combining
            shared_tools_list = ensure_tools_list(self.shared_tools)
            all_tools = shared_tools_list + blackboard_tools
            print(f"DEBUG: Combined tools, total count: {len(all_tools)}")
            
            # Initialize report generator
            print("DEBUG: Initializing report generator...")
            agent, _ = await report_module.initialize(all_tools, self.shared_exit_stack)
            print(f"DEBUG: Report generator initialized: {agent.name}")
            
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
            
            print("DEBUG: Running report generation...")
            
            # Use a Runner to properly invoke the agent
            from google.adk.runners import Runner
            from google.adk.sessions import InMemorySessionService
            from google.genai import types
            
            # Create a temporary runner for report generation
            runner = Runner(
                app_name='soc_blackboard',
                agent=agent,
                session_service=InMemorySessionService(),
            )
            
            # Create a session
            session = await runner.session_service.create_session(
                app_name='soc_blackboard',
                user_id='system'
            )
            
            # Create user message
            content = types.Content(role='user', parts=[types.Part(text=prompt)])
            
            # Run the agent
            report_results = []
            report_result = None
            async for event in runner.run_async(
                session_id=session.id,
                user_id=session.user_id,
                new_message=content
            ):
                report_results.append(event)
                if hasattr(event, 'response') and event.response:
                    report_result = event.response
                    print(f"DEBUG: Report generation generated response")
                elif hasattr(event, 'content'):
                    report_result = event.content
            print(f"DEBUG: Report generation completed successfully with {len(report_results)} events")
            
            if not report_result:
                report_result = f"Report generated with {len(report_results)} events"
            
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
            print(f"ERROR: Report generation failed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            
            # Fallback: create basic report from blackboard data
            raw_data = await blackboard.export()
            stats = await blackboard.get_statistics()
            
            return {
                "report": f"Report generation failed: {str(e)}",
                "raw_data": raw_data,
                "statistics": stats,
                "investigation_id": blackboard.investigation_id,
                "error": str(e),
                "error_type": type(e).__name__
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
    
    # Ensure tools are in list format
    tools_list = ensure_tools_list(tools)
    
    coordinator.shared_tools = tools_list
    coordinator.shared_exit_stack = exit_stack
    
    # Load persona and instructions
    persona = "You are a SOC Blackboard Coordinator responsible for orchestrating complex security investigations."
    
    # Add runbook instructions
    instructions = persona + """

## IMPORTANT: Tool Constraints

You DO NOT have access to code execution tools. Specifically:
- There is NO `run_code` function available
- There is NO `execute_code` function available
- You cannot run arbitrary code

You ONLY have access to the security tools listed below and the blackboard tools.

## Investigation Workflow

1. **Initialize Investigation**: Set up blackboard with initial context
2. **Select Investigators**: Choose appropriate agents based on indicators and context  
3. **Parallel Investigation**: Run multiple investigators simultaneously
4. **Correlation Analysis**: Find patterns across all findings
5. **Report Generation**: Create comprehensive investigation report

## Available MCP Security Tools

You have access to the following MCP (Model Context Protocol) security tools:

### SIEM Tools (Chronicle)
- `search_security_events`: Search for security events in Chronicle
- `get_security_alerts`: Retrieve security alerts
- `lookup_entity`: Look up entity information
- `list_security_rules`: List detection rules
- `get_ioc_matches`: Get IOC matches
- And more Chronicle-specific tools

### SOAR Tools (Security Orchestration)
- `list_cases`: List security cases
- `post_case_comment`: Add comments to cases
- `list_alerts_by_case`: Get alerts for a case
- `change_case_priority`: Update case priority
- `get_case_full_details`: Get complete case information
- And many more SOAR capabilities

### GTI Tools (Google Threat Intelligence/VirusTotal)
- `get_collection_report`: Get threat intelligence reports
- `search_threats`: Search for threats
- `get_domain_report`: Analyze domains
- `get_file_report`: Analyze files
- `get_ip_address_report`: Analyze IP addresses
- And more threat intelligence capabilities

### Utility Tools
- `write_report`: Write investigation reports to files
- `get_current_time`: Get current timestamp

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

## How Investigations Work

1. You orchestrate the investigation by delegating to specialized investigator agents
2. Each investigator writes findings to the shared blackboard
3. The correlation engine analyzes patterns across all findings
4. The report generator creates a comprehensive report
5. All agents have access to the same MCP tools and can use them as needed

Always use the blackboard pattern - agents communicate through shared knowledge, not directly.

Use the coordinator.investigate(context) method to start investigations.
"""
    
    # Create blackboard tools for the coordinator
    async def start_investigation(context_json: str):
        """Start a new SOC investigation with the given context."""
        import json
        try:
            # Handle if context_json is already a dict (from ADK)
            if isinstance(context_json, dict):
                context = context_json
            else:
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
    
    # Convert tools to list and add investigation tools
    tools_list = ensure_tools_list(tools)
    all_tools = tools_list + investigation_tools
    
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