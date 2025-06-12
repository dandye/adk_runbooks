![Screenshot 2025-05-18 at 4 16 04 PM](https://github.com/user-attachments/assets/338a92af-1721-4b6f-9c9c-c451c9581129)

# Claude Setup Guide

This guide covers the setup and configuration steps for running ADK Runbooks with Claude.

## Setup

Do *NOT* use `uv` to run `adk` with a pyproject.yaml file. (It causes intractable dependency resolution issues.)

Instead, do this:
```
git clone https://github.com/dandy/adk_runbooks.git
cd adk_runbooks/multi-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
adk run manager
```

# Or with uv as pip replacement:
```
git clone https://github.com/dandy/adk_runbooks.git
cd adk_runbooks/multi-agent
python -m venv .venv
source .venv/bin/activate
uv pip sync requirements.txt
adk run manager
```

## Configuration

There are two places to configure for your environment:
 * `./multi-agent/manager/.env` file in
 * `./multi-agent/manager/tools/tools.py` needs your MCP Security configuration
   * Fix the hard-coded paths in that file like `/Users/dandye/Projects/mcp_security/server/...`

## Multi-Agent Systems in ADK

This example demonstrates how to create a multi-agent system in ADK, where specialized security agents collaborate to handle complex cybersecurity tasks, each focusing on their area of expertise.

### What is a Multi-Agent System?

A Multi-Agent System is an advanced pattern in the Agent Development Kit (ADK) that allows multiple specialized agents to work together to handle complex tasks. Each agent can focus on a specific domain or functionality, and they can collaborate through delegation and communication to solve problems that would be difficult for a single agent.

### Project Structure Requirements

For multi-agent systems to work properly with ADK, your project must follow a specific structure:

```
project_root/
├── multi-agent/                 # This example's root
│   ├── manager/                 # Main agent package (root_agent_folder)
│   │   ├── __init__.py          # Must import agent.py
│   │   ├── agent.py             # Must define root_agent
│   │   ├── .env                 # Environment variables (or .env.example)
│   │   └── sub_agents/          # Directory for all sub-agents
│   │       ├── __init__.py      # Empty or imports sub-agents
│   │       ├── cti_researcher/  # Sub-agent package
│   │       │   ├── __init__.py  # Must import agent.py
│   │       │   └── agent.py     # Must define an agent variable
│   │       ├── detection_engineer/
│   │       │   ├── __init__.py
│   │       │   └── agent.py
│   │       ├── ... (other security agents)
│   │       └── tools.py         # Configure paths to MCP Security in this file
├── .venv/                       # Virtual environment (example location)
└── README.md                    # This file
```

#### Essential Structure Components:

1.  **Root Agent Package** (`manager/` in this example)
    *   Must have the standard agent structure.
    *   The `agent.py` file must define a `root_agent` variable.

2.  **Sub-agents Directory** (`manager/sub_agents/` in this example)
    *   Each sub-agent should be in its own directory (e.g., `cti_researcher/`, `soc_analyst_tier1/`) following the same structure as regular agents.

3.  **Importing Sub-agents**
    *   The root agent (`manager/agent.py`) must import sub-agents to use them. Example:
        ```python
        from .sub_agents.cti_researcher.agent import cti_researcher_agent
        from .sub_agents.soc_analyst_tier1.agent import soc_analyst_tier1_agent
        # ... and so on for other agents
        ```

4.  **Command Location**
    *   Always run `adk web` from the directory containing the root agent package and this README (i.e., from the `multi-agent/` directory in this example's context, assuming it's checked out as a standalone project or from its parent if it's part of a larger structure like `adk_runbooks`).

This structure ensures that ADK can discover and correctly load all agents in the hierarchy.

### Multi-Agent Architecture Options

ADK offers two primary approaches to building multi-agent systems:

#### 1. Sub-Agent Delegation Model

Using the `sub_agents` parameter, the root agent can fully delegate tasks to specialized agents:

```python
# In manager/agent.py
root_agent = Agent(
    name="manager",
    model="gemini-2.5-pro-preview-05-06", # Example model
    description="Manager agent for security operations",
    instruction="You are a manager agent that delegates cybersecurity tasks to specialized agents...",
    sub_agents=[
        cti_researcher_agent,
        soc_analyst_tier1_agent,
        # ... other imported sub-agent instances
    ],
)
```

**Characteristics:**
- Complete delegation - sub-agent takes over the entire response.
- The sub-agent decision is final and takes control of the conversation.
- Root agent acts as a "router" determining which specialist should handle the query.

#### 2. Agent-as-a-Tool Model

Using the `AgentTool` wrapper, agents can be used as tools by other agents:

```python
# In manager/agent.py
from google.adk.tools.agent_tool import AgentTool
# Assuming other_security_tool_agent is another defined agent
# and get_current_time is a standard tool

root_agent = Agent(
    name="manager",
    model="gemini-2.5-pro-preview-05-06", # Example model
    description="Manager agent for security operations",
    instruction="You are a manager agent that uses specialized security agents as tools...",
    tools=[
        AgentTool(some_other_security_agent), # Example
        # get_current_time, # Example of a non-agent tool
    ],
)
```

**Characteristics:**
- Sub-agent returns results to the root agent.
- Root agent maintains control and can incorporate the sub-agent's response into its own.
- Multiple tool calls can be made to different agent tools in a single response.
- Gives the root agent more flexibility in how it uses the results.

### Limitations When Using Multi-Agents

#### Sub-agent Restrictions

**Built-in tools cannot be used within a sub-agent when using the `sub_agents` delegation model directly if those tools are intended for the root agent's direct use in the same turn.** Sub-agents in the `sub_agents` list operate somewhat independently once delegated to.

If a sub-agent needs its own tools (including built-in ones), define them within that sub-agent's `Agent` constructor.

#### Workaround Using Agent Tools for Complex Tool Orchestration

To have a root agent orchestrate multiple agents that themselves might use built-in or custom tools, the `AgentTool` approach is generally more flexible:

```python
from google.adk.tools import agent_tool
# Assume search_agent and coding_agent are defined elsewhere with their own tools
# from google.adk.tools.built_in import google_search, code_execution

# search_agent = Agent(...)
# coding_agent = Agent(...)

root_agent = Agent(
    name="RootAgent",
    model="gemini-2.5-pro-preview-05-06", # Example model
    description="Root Agent orchestrating other agents",
    tools=[
        agent_tool.AgentTool(agent=search_agent),
        agent_tool.AgentTool(agent=coding_agent)
    ],
)
```
This approach wraps agents as tools, allowing the root agent to call them and integrate their results.

## Running the Example

To run this multi-agent example:

1.  Navigate to the `multi-agent` directory (the directory containing this README and the `manager` folder).

2.  Start the interactive web UI:
    ```bash
    adk web
    ```

3.  Access the web UI by opening the URL shown in your terminal (typically `http://localhost:8000`).

4.  Select the "manager" agent from the dropdown menu in the top-left corner of the UI.

5.  Start chatting with your agent in the textbox at the bottom of the screen.

### Troubleshooting

If your multi-agent setup doesn't appear properly in the dropdown menu:
- Make sure you're running `adk web` from the correct directory (e.g., `multi-agent/`).
- Verify that each agent's `__init__.py` properly imports its respective `agent.py` (e.g., `from .agent import specific_agent_instance_name`).
- Check that the root agent (`manager/agent.py`) properly imports all its sub-agent instances.

### Example Prompts to Try

- "Investigate threat actor FIN7 and their recent activities." (CTI Researcher)
- "How can I create a detection rule for suspicious PowerShell execution?" (Detection Engineer)
- "We've detected ransomware on a workstation. What are the immediate steps?" (Incident Responder)
- "A user received a phishing email. Can you analyze the headers?" (SOC Analyst Tier 1/2)
- "There are multiple alerts for unusual outbound traffic from server X. Can you investigate?" (SOC Analyst Tier 2/3)
- "Proactively hunt for signs of credential dumping in our logs." (Threat Hunter)

You can exit the conversation or stop the server by pressing `Ctrl+C` in your terminal.

## Additional Resources

- [ADK Multi-Agent Systems Documentation](https://google.github.io/adk-docs/agents/multi-agent-systems/)
- [Agent Tools Documentation](https://google.github.io/adk-docs/tools/function-tools/#3-agent-as-a-tool)