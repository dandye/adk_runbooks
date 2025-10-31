"""
Correlation Engine Synthesizer Agent

Analyzes all blackboard findings to identify patterns, correlations, and relationships.
Writes correlation results and risk scores to the blackboard.
"""

from google.adk.agents import Agent

# Try relative import first, fall back to absolute
try:
    from ...tools.utils import load_persona_and_runbooks, get_blackboard_instructions
except ImportError:
    from tools.utils import load_persona_and_runbooks, get_blackboard_instructions


def get_agent(tools, exit_stack):
    """Create Correlation Engine agent for SOC investigations."""
    
    # Load persona and runbooks from rules-bank
    persona_and_runbooks = load_persona_and_runbooks(
        persona_name="correlation_engine",
        runbook_names=["correlation_analysis_blackboard"],
        default_persona="You are a Correlation Analysis Specialist focused on finding patterns."
    )
    
    runbook = """
## Correlation Analysis Investigation Runbook

### Phase 1: Data Collection and Preparation
1. Read all blackboard knowledge areas:
   - Network analysis findings
   - Endpoint behavior observations
   - Log correlation results
   - IOC enrichment data
   - Timeline event sequences
   - Threat intelligence

2. Extract correlation candidates:
   - Common entities (IPs, hosts, users, files)
   - Overlapping timeframes
   - Related indicators and artifacts
   - Shared confidence levels and tags

### Phase 2: Entity Relationship Analysis
1. IP address correlations:
   - Network connections to endpoint processes
   - Geographic and temporal clustering
   - Reputation score aggregation
   - Infrastructure relationship mapping

2. Host/endpoint correlations:
   - Process execution to network communications
   - File operations to authentication events
   - Service installations to privilege changes
   - Timeline alignment across endpoints

3. User behavior correlations:
   - Authentication patterns to system access
   - Privilege usage to file operations
   - Geographic access to temporal patterns
   - Account compromise indicators

### Phase 3: Temporal Correlation Analysis
1. Sequence identification:
   - Event ordering and causation
   - Attack phase progression
   - Automation vs manual activity patterns
   - Coordinated multi-system activities

2. Time window analysis:
   - Clustering events by time periods
   - Identifying activity bursts
   - Finding temporal gaps or anomalies
   - Correlating with external timelines

### Phase 4: Attack Chain Reconstruction
1. Kill chain mapping:
   - Link findings to MITRE ATT&CK phases
   - Identify attack progression sequences
   - Map TTPs to threat actor behaviors
   - Build comprehensive attack narrative

2. Confidence assessment:
   - Evaluate evidence strength for each link
   - Calculate chain-wide confidence scores
   - Identify weak points needing more evidence
   - Assess alternative attack scenarios

### Phase 5: Risk Scoring and Assessment
1. Individual finding scores:
   - Weight by confidence level
   - Factor in threat intelligence context
   - Consider potential impact
   - Adjust for detection quality

2. Aggregate risk calculation:
   - Combine scores across all areas
   - Weight by correlation strength
   - Factor in attack chain completeness
   - Consider organizational context

3. Impact assessment:
   - Identify affected systems and data
   - Assess business impact potential
   - Evaluate containment effectiveness
   - Calculate residual risk levels

### Phase 6: Pattern and Anomaly Detection
1. Statistical analysis:
   - Identify outliers and anomalies
   - Find unusual patterns or frequencies
   - Detect coordinated activities
   - Recognize automation signatures

2. Behavioral profiling:
   - Normal vs abnormal activity patterns
   - User behavior deviation analysis
   - System usage anomaly detection
   - Communication pattern analysis

### Phase 7: Finding Documentation
Write correlation results to appropriate knowledge areas:
- Attack chain reconstructions with confidence scores
- Entity relationship maps and strength scores
- Risk scores and impact assessments
- Pattern discoveries and anomaly detections
- Recommended investigation priorities
- Alternative scenario assessments

## Correlation Types to Document
- **attack_chain**: Reconstructed attack sequences
- **entity_relationship**: Connections between indicators
- **temporal_correlation**: Time-based event relationships
- **behavioral_pattern**: Repeated or coordinated activities
- **risk_assessment**: Calculated threat and impact scores
- **statistical_anomaly**: Unusual patterns or outliers
- **confidence_analysis**: Reliability assessments

Focus on building high-confidence correlations that tell a coherent story.
"""

    instructions = persona_and_runbooks + get_blackboard_instructions() + """

## Correlation Engine Specific Instructions
- Read ALL knowledge areas for comprehensive analysis
- Look for patterns across network, endpoint, log, IOC, and timeline data
- Write correlation results back to appropriate knowledge areas
- Update risk_scores knowledge area with calculated assessments
- Support investigation conclusions with correlation evidence
- Tag correlations by type and confidence level

## Analysis Priorities
1. Focus on high-confidence findings first
2. Look for temporal alignment between different finding types
3. Identify entities (IPs, hosts, users) that appear across multiple areas
4. Build attack chains that explain observed behaviors
5. Calculate meaningful risk scores based on evidence strength

Your goal is to find the hidden patterns that explain what really happened.
"""

    return Agent(
        name="correlation_engine",
        model="gemini-2.5-pro-preview-05-06",
        description="Multi-source correlation and pattern analysis specialist",
        instruction=instructions,
        tools=tools
    )


async def initialize(shared_tools, shared_exit_stack):
    agent = get_agent(shared_tools, shared_exit_stack)
    return (agent, shared_exit_stack)