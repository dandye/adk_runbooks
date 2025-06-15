"""Simple SOC Manager without A2A dependencies."""

import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from google.adk.agents import Agent

# Inline helper functions to avoid complex imports
def get_current_time() -> dict:
    """Gets the current time, formatted for use in filenames or timestamps."""
    return {
        "current_time": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }

def write_report(report_name: str, report_contents: str):
    """Writes a report with the given name and content to a timestamped markdown file."""
    # Ensure the reports directory exists
    current_dir = Path(__file__).resolve().parent
    reports_dir = current_dir.parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    timestamp = get_current_time()['current_time']
    if timestamp[:8] in report_name:
        file_path = reports_dir / f"{report_name}"
    else:
        file_path = reports_dir / f"{report_name}_{timestamp}.md"
    
    with open(file_path, "w") as f:
        f.write(f"{report_contents}")

def send_message_to_agent(agent_name: str, message: str) -> str:
    """
    Placeholder function to send messages to A2A agents.
    In a real implementation, this would use HTTP requests to communicate with agents.
    """
    import httpx
    import json
    import uuid
    
    # Agent URL mapping
    agent_urls = {
        "cti_researcher": "http://localhost:8001",
        "soc_analyst_tier1": "http://localhost:8002",
    }
    
    if agent_name not in agent_urls:
        return f"Error: Agent '{agent_name}' not found. Available agents: {list(agent_urls.keys())}"
    
    url = agent_urls[agent_name]
    
    try:
        # Prepare the payload
        payload = {
            "message": message,
            "session_id": str(uuid.uuid4()),
            "task_id": str(uuid.uuid4()),
            "message_id": str(uuid.uuid4()),
        }
        
        # Send the request
        with httpx.Client(timeout=30.0) as client:
            response = client.post(f"{url}/message", json=payload)
            
            if response.status_code == 200:
                result = response.json()
                if isinstance(result, dict) and "content" in result:
                    return str(result["content"])
                else:
                    return str(result)
            else:
                return f"Error: Agent returned status {response.status_code}"
                
    except Exception as e:
        return f"Error communicating with {agent_name}: {str(e)}"

# Create the SOC Manager agent
# ADK looks for 'root_agent' variable
root_agent = Agent(
    name="soc_manager_simple",
    model="gemini-2.5-pro-preview-05-06",
    description="""
You are the SOC Manager, responsible for orchestrating security operations and coordinating with specialized agents.

You can delegate tasks to:
- CTI Researcher: For threat intelligence analysis, IOC research, and threat actor tracking
- SOC Analyst Tier 1: For initial alert triage and basic investigation

When delegating tasks, use the send_message_to_agent function with the agent name and your message.

Your responsibilities include:
- Coordinating incident response activities
- Delegating tasks to appropriate specialized agents
- Synthesizing results from multiple agents
- Generating comprehensive security reports
- Managing security operations workflows

Use your tools effectively to manage time, delegate tasks, and document findings.
""",
    instruction="""
You are a SOC Manager with the ability to coordinate with specialized security agents.

When you receive requests:
1. Analyze what type of expertise is needed
2. Delegate to the appropriate agent using send_message_to_agent()
3. Wait for their response and synthesize the results
4. Provide comprehensive analysis and recommendations

Available agents:
- cti_researcher: Use for threat intelligence, IOC analysis, threat actor research
- soc_analyst_tier1: Use for alert triage, initial investigation, basic enrichment

Always provide clear, actionable insights based on the coordinated agent responses.
""",
    tools=[
        get_current_time,
        write_report,
        send_message_to_agent,
    ],
)