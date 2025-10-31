"""
Log Correlator Investigator Agent

Specializes in correlating events across multiple log sources and systems.
Writes findings to the 'log_correlations' knowledge area of the blackboard.
"""

from google.adk.agents import Agent

# Try relative import first, fall back to absolute
try:
    from ...tools.utils import load_persona_and_runbooks, get_blackboard_instructions
except ImportError:
    from tools.utils import load_persona_and_runbooks, get_blackboard_instructions


def get_agent(tools, exit_stack):
    """
    Create Log Correlator agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools (tuple of toolsets)
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for multi-source log correlation
    """
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="log_correlator",
        runbook_names=["log_correlation_blackboard"],
        default_persona="You are a Log Analysis Specialist focused on correlating security events."
    )
    
    runbook = """
## Log Correlation Investigation Runbook

### Phase 1: Context Analysis
1. Read all existing blackboard findings for context
2. Extract key indicators: users, IPs, hostnames, timeframes
3. Identify relevant log sources and systems

### Phase 2: Authentication Analysis
1. Correlate authentication events:
   - Failed logon attempts followed by success
   - Account lockouts and password resets
   - Privilege escalation events
   - Service account usage anomalies

2. Access pattern analysis:
   - Off-hours access attempts
   - Geographic access anomalies
   - Unusual system access patterns

### Phase 3: System Activity Correlation
1. Cross-system event correlation:
   - Process execution aligned with network activity
   - File access correlated with authentication
   - Service installations with privilege changes

2. Timeline reconstruction:
   - Build comprehensive event sequences
   - Identify gaps or missing logs
   - Correlate with network and endpoint findings

### Phase 4: Anomaly Detection
1. Behavioral analysis:
   - Deviation from user baselines
   - Unusual system activity patterns
   - Anomalous service/process behaviors

2. Security control analysis:
   - Firewall allow/deny patterns
   - Antivirus detection/quarantine events
   - DLP policy violations

### Phase 5: Finding Documentation
Write to 'log_correlations' knowledge area:
- Cross-system event correlations
- Authentication anomalies
- Timeline reconstructions
- Behavioral deviations
- Evidence supporting other findings

## Finding Types
- **auth_anomaly**: Authentication-related suspicious activity
- **access_pattern**: Unusual access or usage patterns
- **timeline_correlation**: Events correlated across time/systems
- **behavioral_deviation**: Departure from normal behavior
- **security_control**: Security system alerts or violations
- **privilege_anomaly**: Unusual privilege usage or escalation

Use Chronicle's correlation capabilities and cross-reference with other blackboard areas.
"""

    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## Log Correlation Specific Instructions
- Write all correlations to 'log_correlations' knowledge area
- Tag findings appropriately: [auth_anomaly, access_pattern, timeline_correlation, etc.]
- Read ALL knowledge areas for comprehensive correlation
- Focus on patterns spanning multiple systems and timeframes
- Support and enhance findings from other investigators
"""

    return Agent(
        name="log_correlator",
        model="gemini-2.5-pro-preview-05-06",
        description="Multi-source log correlation specialist",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the log correlator."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)