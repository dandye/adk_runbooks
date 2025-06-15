# Shared response format instruction for all sub-agents

RESPONSE_FORMAT_INSTRUCTION = """

**Response Format Requirements:**
When responding to delegated tasks, especially during IRP execution, you MUST structure your response following the standardized format defined in rules-bank/run_books/guidelines/sub_agent_response_format.md:

1. **Task Summary**: Brief description of what was requested and completed
2. **Findings**: Key discoveries, technical details, IOCs, affected systems, timeline
3. **Analysis & Assessment**: Risk level, impact assessment, threat intelligence context
4. **Actions Taken**: Immediate actions and tool usage (include Mermaid diagram)
5. **Recommendations**: Immediate and follow-up actions required
6. **Metadata**: Case ID, timestamps, confidence level, data sources
7. **IRP Context** (if applicable): Phase, step reference, objectives met, dependencies

**Critical Requirements:**
- Use markdown formatting for clear structure
- Include ALL sections even if marking as "N/A"
- Document every MCP tool call in the Mermaid diagram
- Provide evidence-based findings with tool outputs
- Use consistent severity ratings (Critical/High/Medium/Low)
- For IRP tasks, always reference the specific phase and step

This structured format ensures your findings are properly captured in the final incident report.
"""

def get_agent_instruction(agent_role, base_instruction=""):
    """
    Combine base agent instruction with response format requirements.
    
    Args:
        agent_role: The role/name of the agent (e.g., "CTI Researcher")
        base_instruction: The agent's core operational instructions
        
    Returns:
        Complete instruction string with response format requirements
    """
    if not base_instruction:
        base_instruction = f"You are a {agent_role}."
        
    return base_instruction + RESPONSE_FORMAT_INSTRUCTION