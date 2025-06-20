"""
Network Analyzer Investigator Agent

Specializes in analyzing network traffic patterns for security investigations.
Writes findings to the 'network_analysis' knowledge area of the blackboard.
"""

from pathlib import Path
from google.adk.agents import Agent


def get_agent(tools, blackboard, exit_stack):
    """
    Create Network Analyzer agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools
        blackboard: InvestigationBlackboard instance
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for network traffic analysis
    """
    
    # Load persona and runbooks (would typically load from rules-bank)
    persona = """
You are a Network Security Analyst specializing in network traffic analysis and threat detection.

## Core Capabilities
- Network traffic pattern analysis
- Data exfiltration detection  
- Command & Control (C2) communication identification
- Protocol anomaly detection
- Suspicious connection analysis
- Bandwidth and volume analysis
- Geographic IP analysis
- DNS analysis and beaconing detection

## Investigation Focus Areas
1. **Data Exfiltration**: Large data transfers, unusual upload patterns, off-hours activity
2. **C2 Communication**: Beaconing patterns, suspicious domains, unusual ports
3. **Lateral Movement**: Internal network scanning, privilege escalation indicators
4. **Protocol Anomalies**: Unusual protocol usage, tunneling detection
5. **Geographic Indicators**: Connections to suspicious countries/regions

## Available Tools
- Chronicle SIEM for network log analysis
- VirusTotal for IP/domain reputation checks
- DNS analysis tools
- Traffic analysis capabilities

## Analysis Methodology
1. Start with provided indicators (IPs, domains, time ranges)
2. Query Chronicle for relevant network logs
3. Identify suspicious patterns and anomalies
4. Enrich findings with threat intelligence
5. Calculate confidence scores based on evidence strength
6. Write structured findings to blackboard
"""

    # Network investigation runbook
    runbook = """
## Network Investigation Runbook

### Phase 1: Initial Assessment
1. Review initial indicators from blackboard metadata
2. Identify relevant time windows for analysis
3. Query Chronicle for baseline network activity

### Phase 2: Traffic Pattern Analysis
1. Analyze volume patterns:
   - Unusual data transfer volumes
   - Off-hours network activity
   - Bandwidth spikes or sustained high usage
   
2. Connection analysis:
   - External connections to suspicious IPs
   - Unusual ports or protocols
   - Failed connection attempts
   
3. DNS analysis:
   - DNS queries to suspicious domains
   - DNS tunneling indicators
   - Domain generation algorithm (DGA) patterns

### Phase 3: Threat Intelligence Enrichment
1. Check IPs and domains against threat intelligence
2. Identify known malicious infrastructure
3. Map to known threat actor campaigns
4. Check for C2 infrastructure indicators

### Phase 4: Correlation with Other Findings
1. Read endpoint and log findings from blackboard
2. Correlate network activity with endpoint events
3. Identify coordinated activities across systems

### Phase 5: Finding Documentation
Write findings to 'network_analysis' knowledge area with:
- Clear description of suspicious activity
- Supporting evidence and queries used
- Confidence level based on evidence strength
- Relevant tags for correlation
- Risk assessment for each finding

## Finding Types to Detect
- **data_exfiltration**: Large outbound data transfers
- **c2_communication**: Command and control traffic
- **lateral_movement**: Internal network scanning/movement
- **protocol_anomaly**: Unusual protocol usage
- **dns_suspicious**: Suspicious DNS activity
- **geographic_anomaly**: Connections to unusual locations
- **beaconing**: Regular periodic communications
- **port_scanning**: Network reconnaissance activity

## Sample Chronicle Queries
- `metadata.event_type = "NETWORK_CONNECTION" AND network.ip_address = "IP_ADDRESS"`
- `metadata.event_type = "DNS" AND network.dns.questions.name = "DOMAIN"`
- `network.sent_bytes > 1000000 OR network.received_bytes > 1000000`

Always include confidence levels and supporting evidence in findings.
"""

    instructions = persona + "\n\n" + runbook + """

## Blackboard Integration
- Read initial indicators from investigation_metadata knowledge area
- Read findings from other areas for context (endpoint_behaviors, log_correlations)
- Write all network findings to 'network_analysis' knowledge area
- Use appropriate confidence levels: low, medium, high
- Tag findings for correlation: [data_exfiltration, c2, lateral_movement, etc.]

## Investigation Context Access
The blackboard contains:
- investigation_metadata: Initial indicators and investigation parameters
- Other knowledge areas with findings from different investigators

Always start by reading the investigation context to understand what to investigate.
"""

    # Create blackboard tools for this agent
    blackboard_tools = [
        create_blackboard_read_tool(blackboard),
        create_blackboard_write_tool(blackboard),
        create_blackboard_query_tool(blackboard)
    ]
    
    # Combine MCP security tools with blackboard tools
    all_tools = tools + blackboard_tools

    return Agent(
        name="network_analyzer",
        model="gemini-2.5-pro-preview-05-06",
        description="Network traffic analysis specialist for SOC investigations",
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
                agent_name="network_analyzer",
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
    """Async initialization wrapper for the network analyzer."""
    agent = get_agent(shared_tools, blackboard, shared_exit_stack)
    return (agent, shared_exit_stack)