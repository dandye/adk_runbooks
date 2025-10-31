"""
Utility functions for SOC Blackboard agents.

Includes persona and runbook loading functionality.
"""

import os
from pathlib import Path


def load_persona_and_runbooks(persona_name: str, runbook_names: list = None, 
                             default_persona: str = "Default persona description.") -> str:
    """
    Loads persona description from rules-bank and appends contents from runbook files.
    
    Args:
        persona_name: Name of the persona file (without .md extension)
        runbook_names: List of runbook names (without .md extension)
        default_persona: Default description if persona file is not found
        
    Returns:
        A string containing the persona description and appended runbook contents
    """
    # Get the path to rules-bank relative to this file
    # soc-blackboard/tools/utils.py -> rules-bank/
    rules_bank_dir = Path(__file__).parent.parent.parent / "rules-bank"
    
    # Load persona
    persona_description = ""
    persona_path = rules_bank_dir / "personas" / f"{persona_name}.md"
    
    try:
        with open(persona_path, 'r') as f:
            persona_description = f.read()
    except FileNotFoundError:
        persona_description = default_persona
        print(f"Warning: Persona file not found at {persona_path}. Using default description.")
    
    # Load runbooks if specified
    if runbook_names:
        for runbook_name in runbook_names:
            runbook_path = rules_bank_dir / "run_books" / f"{runbook_name}.md"
            try:
                with open(runbook_path, 'r') as f:
                    runbook_content = f.read()
                persona_description += "\n\n" + runbook_content
            except FileNotFoundError:
                print(f"Warning: Runbook file not found at {runbook_path}. Skipping.")
    
    return persona_description


def get_blackboard_instructions():
    """
    Returns common blackboard integration instructions for all agents.
    """
    return """

## Blackboard Integration
- Read initial indicators from investigation_metadata knowledge area
- Read findings from other areas for context
- Write all findings to your designated knowledge area
- Use appropriate confidence levels: low, medium, high
- Tag findings for correlation
- Include timestamps and evidence for all findings

## Investigation Context Access
The blackboard contains:
- investigation_metadata: Initial indicators and investigation parameters
- Other knowledge areas with findings from different investigators

Always start by reading the investigation context to understand what to investigate.

## Tool Usage
You have access to:
- MCP Security tools (Chronicle, GTI, SOAR)
- Blackboard tools (blackboard_read, blackboard_write, blackboard_query)
- Reporting tools (write_report, get_current_time)
"""