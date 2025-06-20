# Detection-as-Code (DAC) Agent

An autonomous agent for Detection-as-Code rule tuning based on SOAR case feedback and analyst input.

## Overview

The DAC Agent implements the workflow described in `rules-bank/run_books/detection_as_code_rule_tuning.md`, providing automated detection rule tuning based on:

- SOAR case analysis and analyst feedback
- False positive identification and pattern analysis
- Automated rule modification and testing
- Git-based version control and CI/CD integration
- Continuous monitoring and improvement

## Architecture

```
SOAR Cases → DAC Agent → Rule Analysis → Git Operations → CI/CD → SIEM Deployment
     ↑                        ↓              ↓
Analyst Feedback         Rule Repository   Pull Requests
```

## Key Features

### Autonomous Operation
- Continuously monitors SOAR cases for tuning opportunities
- Extracts analyst feedback and tuning requirements
- Makes intelligent decisions without user prompts
- Maintains detailed audit logs of all actions

### Rule Management
- Locates and analyzes detection rule files
- Generates precise rule modifications (exclusions, thresholds)
- Validates YAML syntax and rule logic
- Estimates impact on historical events

### Version Control Integration
- Creates descriptive branch names (`tune/rule-name-case-id`)
- Generates comprehensive commit messages
- Links changes to original SOAR cases
- Creates pull requests with security review checklists

### MCP Server Integration
- **SOAR MCP Server**: Case monitoring and analyst feedback extraction
- **SIEM MCP Server**: Rule validation and event analysis
- **GTI MCP Server**: Threat intelligence context

## Setup

### Prerequisites
1. Google ADK installed and configured
2. Access to MCP Security servers (see `external/mcp-security/`)
3. GitHub CLI (`gh`) installed and authenticated
4. SOAR platform access with API credentials
5. Chronicle/SecOps access for SIEM operations

### Installation
```bash
cd dac-agent

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your credentials
```

### Configuration
Update `.env` file with:
- `GOOGLE_API_KEY`: For Gemini model access
- `SOAR_URL` and `SOAR_APP_KEY`: SOAR platform credentials
- `CHRONICLE_PROJECT_ID`: Google Cloud project for Chronicle
- `GITHUB_TOKEN`: GitHub personal access token
- Additional MCP server configurations

## Usage

### Running the Agent
```bash
# From the dac-agent directory
adk run dac_agent

# Or use the web interface
adk web
```

### Manual Execution
```python
from dac_agent.agent import get_root_agent

# Initialize and run
agent = await get_root_agent()
response = await agent.process_request(
    "Monitor SOAR cases and tune detection rules based on recent false positive feedback"
)
```

## Workflow Implementation

The agent follows the detection_as_code_rule_tuning.md workflow:

### 1. Monitor Phase
- Searches closed SOAR cases with tuning indicators
- Filters for specific root causes (false_positive, normal_behavior)
- Extracts analyst comments with tuning instructions

### 2. Analysis Phase
- Locates corresponding rule files in repository
- Analyzes current rule logic and syntax
- Identifies modification points and security implications

### 3. Modification Phase
- Generates precise rule changes (exclusions, thresholds)
- Creates feature branches with descriptive names
- Validates changes before committing

### 4. Integration Phase
- Creates pull requests with comprehensive descriptions
- Includes security review checklists
- Links to original SOAR cases and analyst feedback

### 5. Monitoring Phase
- Tracks CI/CD pipeline execution
- Monitors post-deployment metrics
- Documents outcomes for continuous improvement

## Tools Available

### MCP Tools
- **SOAR Operations**: List cases, read comments, extract feedback
- **SIEM Operations**: Search events, validate rules, estimate impact
- **Threat Intelligence**: Context enrichment via GTI

### Custom Tools
- `git_create_branch()`: Create feature branches
- `git_commit_changes()`: Commit specific files
- `git_push_branch()`: Push branches to origin
- `create_github_pr()`: Create pull requests via gh CLI
- `validate_yaml_file()`: Rule syntax validation
- `find_rule_files()`: Search for rule files by pattern

### Utility Tools
- `get_current_time()`: Timestamp generation
- `write_report()`: Generate tuning reports
- `load_persona_and_runbooks()`: Load configuration

## Security Considerations

### Conservative Approach
- Applies security-first principles for ambiguous cases
- Avoids overly broad exclusions
- Maintains detection effectiveness
- Documents all decisions for audit

### Review Process
- All changes go through pull request review
- Includes security impact assessment
- Requires approval before deployment
- Maintains rollback capabilities

### Access Control
- Requires proper authentication for all services
- Uses least-privilege access patterns
- Maintains audit logs of all operations

## Monitoring and Metrics

### Key Performance Indicators
- Rules tuned per week
- False positive reduction percentage
- Automation success rate
- Time to deployment

### Logging
- All decisions and actions logged
- SOAR case processing details
- Rule modification rationale
- Git operations and PR creation

### Reports
- Weekly tuning summary reports
- False positive trend analysis
- Rule effectiveness metrics
- Automation performance statistics

## Troubleshooting

### Common Issues

**MCP Server Connection Failures**
```bash
# Check MCP server status
cd external/mcp-security
./server/secops/secops_mcp/server.py --help

# Verify environment configuration
cat .env
```

**Git Operations Failing**
```bash
# Check GitHub CLI authentication
gh auth status

# Verify repository access
git remote -v
```

**Rule File Not Found**
```bash
# Check rule repository structure
find ../rules -name "*.yaml" -o -name "*.yml"
```

### Debug Mode
Set `LOG_LEVEL=DEBUG` in `.env` for detailed logging.

## Integration with Existing Workflow

The DAC Agent is designed to integrate with the existing ADK Runbooks multi-agent system:

- Can be called as a sub-agent by the manager agent
- Shares MCP server connections for efficiency
- Follows established persona and runbook patterns
- Generates reports compatible with existing templates

## Future Enhancements

- Machine learning for pattern recognition in false positives
- Automated rule performance testing
- Integration with additional SIEM platforms
- Enhanced natural language processing of analyst feedback
- Predictive tuning based on threat landscape changes