# ADK Runbooks Project Documentation

Welcome to the ADK Runbooks project! This site serves as the central hub for documentation related to the Agent Development Kit (ADK) runbooks, a collection of automated procedures, security content, and operational guides designed to streamline cybersecurity operations. Here you'll find information on setting up the project, configuring its components, understanding the multi-agent architecture, and leveraging the extensive Rules Bank for detection and response. Whether you're a SOC analyst, detection engineer, or incident responder, this documentation aims to provide the necessary resources to effectively utilize and contribute to the ADK Runbooks ecosystem.

## Setup

Do *NOT* use `uv` to run `adk` with a pyproject.yaml file. (It causes intractable dependency resolution issues.)

Instead, do this:
```bash
git clone https://github.com/dandy/adk_runbooks.git
cd adk_runbooks/multi-agent
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
adk run manager
```

Or with uv as pip replacement:
```bash
git clone https://github.com/dandy/adk_runbooks.git
cd adk_runbooks/multi-agent
python -m venv .venv
source .venv/bin/activate
uv pip sync requirements.txt
adk run manager
```

For building this documentation site locally:
1. Navigate to the `adk_runbooks_debugging` directory (the parent of this `rules-bank` directory).
2. Ensure you have a Python virtual environment activated.
3. Install dependencies:
   ```bash
   pip install -r requirements-docs.txt
   ```
4. Build the documentation:
   ```bash
   make html
   ```
5. View the site by opening `build/html/index.html` in your browser.

## Configuration

There are two places to configure for your environment:
 * `./multi-agent/manager/.env` file in
 * `./multi-agent/manager/tools/tools.py` needs your MCP Security configuration
   * Fix the hard-coded paths in that file like `/Users/dandye/Projects/mcp_security/server/...`

## Multi-Agent Systems in ADK

This example demonstrates how to create a multi-agent system in ADK, where specialized security agents collaborate to handle complex cybersecurity tasks, each focusing on their area of expertise.

### What is a Multi-Agent System?

A Multi-Agent System is an advanced pattern in the Agent Development Kit (ADK) that allows multiple specialized agents to work together to handle complex tasks. Each agent can focus on a specific domain or functionality, and they can collaborate through delegation and communication to solve problems that would be difficult for a single agent.

*(Note: Further details on Multi-Agent Systems, Project Structure, Architecture Options, Limitations, and Running the Example are available in the main project README.md. Consider creating separate pages for these if detailed documentation is desired here.)*

<!-- Consider adding a toctree entry for a page dedicated to the multi-agent system if you create one -->
<!-- e.g. multi_agent_system_overview -->

## Project Documentation Contents

This site contains detailed information about various components of the ADK Runbooks project. Explore the sections below to find specific documentation.

### Core Documents
These documents outline the foundational strategies, protocols, and plans for the ADK Runbooks project and the Rules Bank. They provide high-level guidance and operational frameworks.
```{toctree}
:maxdepth: 2
:caption: Core Documents:

indicator_handling_protocols
detection_strategy
project_plan
mcp_tool_best_practices
analytical_query_patterns
automated_response_playbook_criteria
coding_conventions
data_normalization_map
detection_improvement_process
log_source_overview
sop_automation_effectiveness_review
```

### AI Documentation
This section covers documents related to the design, operation, and review of AI systems within the security context.
```{toctree}
:maxdepth: 2
:caption: AI Documents:

ai/index
```

### Atomic Runbooks
This section contains a collection of atomic runbooks, which are focused, reusable procedures for specific security tasks. These are typically categorized by the primary entity type they address (e.g., IP Address, Domain, Hash).
```{toctree}
:maxdepth: 2
:caption: Atomic Runbooks:

atomic_runbooks/index
```

### General Security Runbooks
This area houses a broader collection of runbooks for various security operations, including comprehensive investigation guides, triage procedures, and specific incident response plans.
```{toctree}
:maxdepth: 2
:caption: General Security Runbooks:

run_books/index
```

### Templates and Use Cases
Here you'll find templates to help standardize the creation of new runbooks and documentation detailing specific detection use cases.
```{toctree}
:maxdepth: 2
:caption: Templates & Use Cases:

detection_use_cases/duc_template_package
runbook_templates/atomic_runbook_template
reporting_templates
```

### Security Personas
Understanding the roles and responsibilities of different security team members is crucial for effective collaboration and tailored procedures. This section describes various security personas.
```{toctree}
:maxdepth: 1
:caption: Security Personas:

personas/index
```

### Development and Planning
This section includes documents related to ongoing development, future planning, and suggestions for the ADK Runbooks project.
```{toctree}
:maxdepth: 2
:caption: Development & Planning:

suggested_mcp_tools
```
