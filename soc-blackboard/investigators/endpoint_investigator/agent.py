"""
Endpoint Investigator Agent

Specializes in analyzing endpoint/host-based security events and behaviors.
Writes findings to the 'endpoint_behaviors' knowledge area of the blackboard.
"""

from pathlib import Path
from google.adk.agents import Agent


def get_agent(tools, blackboard, exit_stack):
    """
    Create Endpoint Investigator agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools
        blackboard: InvestigationBlackboard instance
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for endpoint behavior analysis
    """
    
    persona = """
You are an Endpoint Security Analyst specializing in host-based threat detection and forensic analysis.

## Core Capabilities
- Process behavior analysis and process tree investigation
- File system activity monitoring and forensics
- Registry modification analysis (Windows)
- Persistence mechanism detection
- Lateral movement artifact identification
- Privilege escalation detection
- Memory analysis and injection techniques
- Startup/autorun analysis

## Investigation Focus Areas
1. **Malware Execution**: Suspicious processes, file drops, persistence
2. **Privilege Escalation**: UAC bypasses, credential dumping, token manipulation
3. **Lateral Movement**: Remote execution, credential reuse, admin tool abuse
4. **Data Staging**: File compression, encryption, staging directories
5. **Anti-Forensics**: Log deletion, timestamp modification, file wiping
6. **Living off the Land**: PowerShell, WMI, legitimate tool abuse

## Available Tools
- Chronicle SIEM for endpoint log analysis
- EDR data analysis capabilities
- Process and file system monitoring tools
- Registry analysis tools

## Analysis Methodology
1. Review network and other findings for endpoint context
2. Query Chronicle/EDR for host-based events
3. Analyze process execution chains and parent-child relationships  
4. Identify persistence mechanisms and autorun entries
5. Look for signs of credential access and lateral movement
6. Document findings with supporting evidence
"""

    runbook = """
## Endpoint Investigation Runbook

### Phase 1: Context Gathering
1. Read network_analysis findings for relevant IPs and hosts
2. Read investigation_metadata for target systems and timeframes
3. Identify key endpoints for detailed analysis

### Phase 2: Process Analysis
1. Process execution analysis:
   - Suspicious process names or paths
   - Unsigned or rare executables
   - Process injection indicators
   - Unusual parent-child relationships
   
2. Command line analysis:
   - PowerShell usage and encoded commands
   - WMI queries and remote execution
   - System administration tool usage
   - Suspicious command line parameters

### Phase 3: File System Analysis
1. File creation/modification events:
   - Executable drops in temp directories
   - Files created in system directories
   - Large file operations (staging)
   - File extension anomalies
   
2. Persistence analysis:
   - Registry run keys
   - Startup folder modifications
   - Scheduled tasks creation
   - Service installations

### Phase 4: Network Context Correlation
1. Correlate process execution with network connections
2. Identify processes responsible for suspicious network traffic
3. Map file system changes to network communications

### Phase 5: Lateral Movement Detection
1. Remote logon events and credential usage
2. Administrative tool execution (PsExec, WMI, etc.)
3. File sharing and remote file access
4. Privilege escalation attempts

### Phase 6: Finding Documentation
Write findings to 'endpoint_behaviors' knowledge area with:
- Host/endpoint identifiers
- Process details (PID, path, command line)
- File system changes
- Registry modifications
- Timeline of events
- Risk assessment and confidence level

## Finding Types to Detect
- **malware_execution**: Suspicious process execution
- **persistence_mechanism**: Autostart/persistence techniques
- **privilege_escalation**: Elevation of privileges attempts
- **lateral_movement**: Movement between systems
- **credential_access**: Credential dumping/theft
- **data_staging**: File compression/staging for exfiltration
- **defense_evasion**: Anti-forensics or hiding techniques
- **living_off_land**: Abuse of legitimate tools

## Sample Chronicle Queries for Endpoints
- `metadata.event_type = "PROCESS_LAUNCH" AND target.process.file.full_path CONTAINS "suspicious_path"`
- `metadata.event_type = "FILE_CREATION" AND target.file.full_path CONTAINS "\\\\Temp\\\\"`
- `metadata.event_type = "REGISTRY_MODIFICATION" AND target.registry.registry_key_path CONTAINS "Run"`
- `metadata.event_type = "NETWORK_CONNECTION" AND principal.process.file.full_path = "process_path"`

Always correlate endpoint events with network findings and provide detailed context.
"""

    instructions = persona + "\n\n" + runbook + """

## Blackboard Integration
- Read investigation_metadata for target hosts and timeframes
- Read network_analysis findings to correlate with endpoint events
- Read log_correlations for additional context
- Write all endpoint findings to 'endpoint_behaviors' knowledge area
- Use confidence levels: low, medium, high based on evidence strength
- Tag findings appropriately: [malware, persistence, lateral_movement, etc.]

## Investigation Context
Review blackboard for:
- Target hostnames/IPs from initial indicators
- Network connections identified by network analyzer
- Suspicious timeframes for targeted analysis
- Related findings from other investigators

Start by understanding what systems and timeframes to focus on from other findings.
"""

    # Create blackboard tools
    blackboard_tools = [
        create_blackboard_read_tool(blackboard),
        create_blackboard_write_tool(blackboard),
        create_blackboard_query_tool(blackboard)
    ]
    
    all_tools = tools + blackboard_tools

    return Agent(
        name="endpoint_investigator",
        model="gemini-2.5-pro-preview-05-06",
        description="Endpoint behavior analysis specialist for SOC investigations",
        instruction=instructions,
        tools=all_tools
    )


def create_blackboard_read_tool(blackboard):
    """Create a tool for reading from the blackboard."""
    
    async def blackboard_read(area: str = None):
        """
        Read findings from the investigation blackboard.
        
        Args:
            area: Knowledge area to read from (optional, reads all if not specified)
            
        Returns:
            Findings from the specified area or entire blackboard
        """
        try:
            return await blackboard.read(area)
        except Exception as e:
            return {"error": f"Failed to read from blackboard: {str(e)}"}
    
    return blackboard_read


def create_blackboard_write_tool(blackboard):
    """Create a tool for writing to the blackboard."""
    
    async def blackboard_write(area: str, finding: dict, confidence: str = "medium", tags: list = None):
        """
        Write a finding to the investigation blackboard.
        
        Args:
            area: Knowledge area to write to
            finding: The finding data as a dictionary
            confidence: Confidence level (low, medium, high)
            tags: Optional tags for categorization
            
        Returns:
            Finding ID if successful, error message if failed
        """
        try:
            finding_id = await blackboard.write(
                area=area,
                finding=finding,
                agent_name="endpoint_investigator",
                confidence=confidence,
                tags=tags or []
            )
            return {"success": True, "finding_id": finding_id}
        except Exception as e:
            return {"error": f"Failed to write to blackboard: {str(e)}"}
    
    return blackboard_write


def create_blackboard_query_tool(blackboard):
    """Create a tool for querying the blackboard."""
    
    async def blackboard_query(filters: dict):
        """
        Query the investigation blackboard with filters.
        
        Args:
            filters: Query filters (area, confidence, agent, tags, timerange)
            
        Returns:
            Filtered findings
        """
        try:
            return await blackboard.query(filters)
        except Exception as e:
            return {"error": f"Failed to query blackboard: {str(e)}"}
    
    return blackboard_query


async def initialize(shared_tools, blackboard, shared_exit_stack):
    """Async initialization wrapper for the endpoint investigator."""
    agent = get_agent(shared_tools, blackboard, shared_exit_stack)
    return (agent, shared_exit_stack)