"""
Timeline Builder Investigator Agent

Specializes in constructing chronological event sequences for investigations.
Writes findings to the 'timeline_events' knowledge area of the blackboard.
"""

from google.adk.agents import Agent

# Try relative import first, fall back to absolute
try:
    from ...tools.utils import load_persona_and_runbooks, get_blackboard_instructions
except ImportError:
    from tools.utils import load_persona_and_runbooks, get_blackboard_instructions


def get_agent(tools, exit_stack):
    """
    Create Timeline Builder agent for SOC investigations.
    
    Args:
        tools: Shared MCP security tools (tuple of toolsets)
        exit_stack: Shared exit stack for resource management
        
    Returns:
        Agent configured for timeline construction and analysis
    """
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="timeline_builder",
        runbook_names=["timeline_reconstruction_blackboard"],
        default_persona="You are a Digital Forensics Timeline Analyst specializing in event reconstruction."
    )
    
    runbook = """
## Timeline Construction Investigation Runbook

### Phase 1: Event Collection
1. Read all blackboard knowledge areas for timestamped events:
   - Network connections and communications
   - Process executions and file operations
   - Authentication and access events
   - Log correlation findings
   - IOC first/last seen timestamps

2. Extract temporal data:
   - Event timestamps (normalize timezones)
   - Duration information where available
   - Sequence indicators (process IDs, session IDs)
   - Confidence levels from source findings

### Phase 2: Timeline Construction
1. Chronological ordering:
   - Sort all events by timestamp
   - Handle timestamp precision variations
   - Resolve timezone discrepancies
   - Identify and flag timestamp anomalies

2. Event correlation:
   - Group events by time windows
   - Identify causal relationships
   - Link related activities across systems
   - Correlate with external timeline data

### Phase 3: Pattern Analysis
1. Event clustering:
   - Identify bursts of activity
   - Find periodic or scheduled events
   - Detect automation vs manual activity
   - Spot coordinated multi-system events

2. Gap analysis:
   - Identify suspicious timeline gaps
   - Detect potential log manipulation
   - Find periods of missing activity
   - Highlight anti-forensics indicators

### Phase 4: Attack Phase Mapping
1. Kill chain mapping:
   - Initial reconnaissance activities
   - Initial access and exploitation
   - Persistence mechanism establishment
   - Privilege escalation events
   - Lateral movement activities
   - Data staging and exfiltration
   - Anti-forensics and cleanup

2. Critical moment identification:
   - First compromise indicators
   - Privilege escalation points
   - Lateral movement initiation
   - Data access and exfiltration
   - Detection evasion attempts

### Phase 5: Timeline Narrative
1. Sequence documentation:
   - Chronological event descriptions
   - Attack progression narrative
   - Decision point analysis
   - Impact timeline assessment

2. Evidence correlation:
   - Link timeline events to findings
   - Support conclusions with temporal evidence
   - Identify strongest evidence points
   - Build forensic event chains

### Phase 6: Finding Documentation
Write to 'timeline_events' knowledge area:
- Complete chronological event sequence
- Event clusters and activity bursts
- Attack phase mappings
- Critical moments and decision points
- Timeline gaps and anomalies
- Narrative descriptions of key sequences

## Finding Types
- **complete_timeline**: Full chronological sequence
- **event_cluster**: Groups of related temporal events
- **attack_phase**: Events mapped to kill chain phases
- **critical_moment**: Key decision points or escalations
- **timeline_gap**: Missing events or suspicious gaps
- **correlation_window**: Temporal relationship patterns

Focus on building a coherent narrative that explains the sequence of events.
"""

    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## Timeline Builder Specific Instructions
- Write all timeline constructions to 'timeline_events' knowledge area
- Tag findings by attack phase: [recon, initial_access, persistence, etc.]
- Extract temporal data from ALL blackboard findings
- Build comprehensive chronological sequences
- Identify and document timeline gaps and critical moments
"""

    return Agent(
        name="timeline_builder",
        model="gemini-2.5-pro-preview-05-06",
        description="Chronological event timeline construction specialist",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    """Async initialization wrapper for the timeline builder."""
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)