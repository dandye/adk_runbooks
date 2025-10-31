# Blackboard Investigation Orchestration Runbook

## Overview
This runbook guides the orchestration of multi-agent security investigations using the blackboard pattern.

## Prerequisites
- Access to all MCP security tools (Chronicle, SOAR, GTI)
- Understanding of the blackboard pattern
- Knowledge of available investigator agents
- Access to investigation monitoring dashboard

## Investigation Workflow

### Phase 1: Investigation Initialization
1. **Receive Investigation Request**
   - From SOAR case ID
   - From manual investigation context
   - From automated triggers

2. **Fetch SOAR Case Details** (if applicable)
   - Use `get_case_full_details` for complete information
   - Extract indicators, priority, and context
   - DO NOT ask user for additional details

3. **Create Investigation Context**
   ```json
   {
       "case_id": "INC-2024-001",
       "title": "Investigation Title",
       "priority": "high|medium|low",
       "initial_indicators": [
           {"type": "ip|domain|hash|username", "value": "indicator_value"}
       ],
       "data_sources": ["chronicle", "edr", "firewall_logs"],
       "investigation_type": "malware|phishing|data_exfiltration|etc"
   }
   ```

### Phase 2: Blackboard Setup
1. **Initialize Blackboard**
   - Create unique investigation ID
   - Set up knowledge areas
   - Initialize metadata with context
   - Enable persistence and monitoring

2. **Register with Monitoring**
   - Create research log
   - Initialize web dashboard tracking
   - Set up real-time status updates

### Phase 3: Agent Selection
1. **Analyze Investigation Type**
   - Network-focused: Network Analyzer
   - Endpoint-focused: Endpoint Investigator
   - Threat Intelligence: IOC Enricher
   - Authentication issues: Log Correlator
   - Timeline needed: Timeline Builder

2. **Select Appropriate Investigators**
   - Choose based on indicators
   - Consider investigation type
   - Include IOC Enricher for all investigations
   - Add specialized agents as needed

### Phase 4: Parallel Investigation
1. **Launch Investigators**
   - Run selected agents in parallel
   - Monitor agent status and progress
   - Track findings as they're written

2. **Monitor Progress**
   - Check for agent errors
   - Ensure findings are being written
   - Track investigation phases
   - Update monitoring dashboard

### Phase 5: Correlation Analysis
1. **Run Correlation Engine**
   - After investigators complete
   - Analyze all blackboard findings
   - Identify patterns and relationships
   - Calculate risk scores

2. **Review Correlations**
   - Check confidence levels
   - Validate relationships
   - Identify key findings

### Phase 6: Report Generation
1. **Run Report Generator**
   - After correlation completes
   - Generate comprehensive report
   - Include executive summary
   - Document all findings

2. **Export Results**
   - Save investigation data
   - Generate HTML research log
   - Export blackboard contents
   - Create final deliverables

## Agent Selection Guidelines

### Always Include:
- **IOC Enricher**: For threat intelligence on all indicators
- **Correlation Engine**: For pattern analysis
- **Report Generator**: For final documentation

### Conditional Selection:
- **Network Analyzer**: When network indicators present (IPs, domains)
- **Endpoint Investigator**: When host indicators present or malware suspected
- **Log Correlator**: For authentication anomalies or multi-system events
- **Timeline Builder**: When chronological analysis is critical

## Error Handling
1. **Agent Failures**
   - Log errors to blackboard
   - Continue with other agents
   - Note gaps in final report

2. **API Failures**
   - Implement retry logic
   - Use exponential backoff
   - Document API issues

3. **Incomplete Data**
   - Proceed with available information
   - Note data gaps in findings
   - Adjust confidence levels

## Investigation Monitoring
- Use web dashboard for real-time status
- Check research logs for detailed activity
- Monitor agent progress and errors
- Track investigation phases

## Post-Investigation
1. **Update SOAR Case**
   - Add investigation findings
   - Update case status
   - Link to full report

2. **Archive Investigation**
   - Save blackboard data
   - Export research logs
   - Clean up active resources

## Best Practices
- Always fetch SOAR case details automatically
- Run agents in parallel for efficiency
- Monitor progress through web dashboard
- Document confidence levels for all findings
- Ensure complete evidence chain in reports
- Use appropriate confidence scoring