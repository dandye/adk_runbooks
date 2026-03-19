# Detection-as-Code Rule Tuning Workflow

## Overview

This workflow demonstrates an automated approach to tuning detection rules using Detection-as-Code principles, integrating SOAR case feedback with version-controlled rule management and CI/CD deployment.

## Architecture


> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```mermaid
graph LR
    A[SOAR Cases] -->|Analyst Feedback| B[AI Agent]
    B -->|Read Cases| C[MCP SOAR Server]
    B -->|Find Rules| D[Local Rules Repo]
    B -->|Create PR| E[GitHub MCP Server]
    D -->|Update Logic| F[Rule Changes]
    F -->|Pull Request| G[GitHub]
    G -->|CI/CD Pipeline| H[SIEM Platform]
    H -->|Deploy| I[Production Rules]
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Prerequisites

### Required Components
- **SIEM Platform** (Google SecOps, Chronicle, Splunk, etc.)
- **SOAR Platform** with case management
- **Git Repository** for detection rules
- **CI/CD Pipeline** (GitHub Actions, GitLab CI)
- **MCP Servers**:
  - SIEM MCP Server (search events, manage rules)
  - SOAR MCP Server (list cases, read comments)
  - GitHub MCP Server (create branches, PRs)
- **AI Agent** (Claude, Gemini) with MCP integration

### Configuration
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```yaml
# .env configuration
SIEM_API_ENDPOINT=https://your-siem.example.com
SOAR_API_ENDPOINT=https://your-soar.example.com
GITHUB_TOKEN=your_github_token
AI_MODEL=gemini-2.5-pro-preview
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Automated Workflow

### Step 1: Monitor SOAR Cases for Tuning Opportunities

The AI agent continuously monitors closed SOAR cases for tuning signals:

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```python
# Example monitoring query
search_criteria = {
    "status": "closed",
    "root_cause": ["normal_behavior", "false_positive", "authorized_activity"],
    "has_analyst_comments": True,
    "time_range": "last_7_days"
}
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Step 2: Extract Tuning Requirements from Case Comments

When a case contains tuning instructions, the agent extracts:
- **Rule Name**: Which detection rule triggered the alert
- **Tuning Type**: Exclusion, threshold adjustment, logic refinement
- **Specific Conditions**: Field values, hostnames, user accounts to exclude

Example analyst comment:
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```
This case was a false positive. User jack.torrance is authorized to execute 
ScreenConnect in our environment. Rule should be tuned to exclude events 
where hostname != "desktop-7xl2kp3".
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Step 3: Locate and Analyze Local Rule Files

The agent searches the local rules repository:

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```bash
rules/
├── network/
├── endpoint/
│   ├── rmm_tools_execution.yaml
│   └── suspicious_process.yaml
└── cloud/
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

Rule format example:
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```yaml
# rmm_tools_execution.yaml
id: rmm-tools-execution
name: "Remote Monitoring Management Tools Execution"
description: "Detects execution of RMM tools that could be abused"
severity: medium
logic:
  query: |
    event.type = "process" AND
    process.name IN ("ScreenConnect.exe", "TeamViewer.exe", "AnyDesk.exe")
tags:
  - attack.t1219
  - remote_access
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Step 4: Generate Rule Modifications

The agent applies the tuning based on analyst feedback:

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```yaml
# Updated rule with exclusion
logic:
  query: |
    event.type = "process" AND
    process.name IN ("ScreenConnect.exe", "TeamViewer.exe", "AnyDesk.exe") AND
    NOT (process.name = "ScreenConnect.exe" AND 
         user.name = "jack.torrance" AND 
         host.name = "desktop-7xl2kp3")
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Step 5: Create Branch and Pull Request

The agent uses Git operations to propose changes:

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```bash
# Create feature branch
git checkout -b tune/rmm-tools-case-4232

# Commit changes
git add rules/endpoint/rmm_tools_execution.yaml
git commit -m "Tune RMM tools rule based on case #4232 feedback

- Added exclusion for authorized ScreenConnect usage
- User: jack.torrance on host: desktop-7xl2kp3
- Reduces false positives for legitimate IT operations"

# Push and create PR
git push origin tune/rmm-tools-case-4232
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

Pull request includes:
- Link to original SOAR case
- Analyst comment justification
- Specific changes made
- Expected impact on false positive rate

### Step 6: Automated Validation and Deployment

GitHub Actions workflow (`deploy-rules.yml`):

    %% Step: Save Findings to Memory


    AutomatedAgent->>Memory: Save Novel Findings


    Memory-->>AutomatedAgent: Findings Saved

```yaml
name: Deploy Detection Rules
on:
  pull_request:
    paths:
      - 'rules/**'
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Validate Rule Syntax
        run: |
          yamllint rules/
          detection-cli validate rules/
      
      - name: Test Rule Logic
        run: |
          # Test against sample events
          detection-cli test --rule ${{ github.event.pull_request.changed_files }}
      
      - name: Check Historical Impact
        run: |
          # Query last 30 days to estimate impact
          detection-cli backtest --rule ${{ github.event.pull_request.changed_files }}

  deploy:
    if: github.ref == 'refs/heads/main'
    needs: validate
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to SIEM
        run: |
          detection-cli deploy --env production
          
      - name: Notify Team
        run: |
          slack-notify "#detections" "Rule updates deployed from PR #${{ github.event.pull_request.number }}"
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Manual Review Process

### Security Review Checklist
- [ ] Exclusion doesn't create detection blind spots
- [ ] Tuning is specific to the false positive pattern
- [ ] No overly broad exclusions (e.g., entire subnets)
- [ ] Maintains detection for actual threats
- [ ] Includes expiration date for temporary exclusions

### Approval Workflow
1. **Detection Engineer**: Reviews technical implementation
2. **SOC Lead**: Validates operational impact
3. **Security Architect**: Approves high-risk changes

## Monitoring and Metrics

### Key Performance Indicators
- **False Positive Reduction**: Track % decrease after tuning
- **Tuning Velocity**: Rules tuned per week
- **Automation Rate**: % of tunings handled automatically
- **Rollback Frequency**: How often tunings are reverted

### Dashboard Example
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```
┌─────────────────────────────────────┐
│  Detection Rule Tuning Dashboard     │
├─────────────────────────────────────┤
│ Rules Tuned This Week: 15           │
│ FP Rate Reduction: 72%              │
│ Automated Tunings: 12/15 (80%)      │
│ Pending Reviews: 3                   │
└─────────────────────────────────────┘
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Example Use Cases

### Use Case 1: Authorized Software Exclusion
**Scenario**: IT deploys new RMM tool
**Action**: Exclude specific deployment patterns
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```yaml
exclusions:
  - condition: "process.signer = 'IT_DEPT_CERT' AND host.ou = 'IT_Workstations'"
    expires: "2025-12-31"
    reason: "Authorized IT deployment"
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Use Case 2: Business Process Tuning
**Scenario**: Finance runs daily automated reports triggering alerts
**Action**: Time-based exclusion
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```yaml
exclusions:
  - condition: "user.name = 'svc_finance' AND time.hour BETWEEN 2 AND 4"
    reason: "Scheduled finance reporting"
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### Use Case 3: Environmental Noise Reduction
**Scenario**: Dev environment generates testing alerts
**Action**: Environment-based filtering
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```yaml
logic:
  query: |
    original_query AND
    NOT (environment.type = "development" AND 
         source.ip IN ("10.1.0.0/16"))
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Best Practices

### 1. Feedback Loop Integration
- Capture analyst decisions in SOAR cases
- Use standardized comment templates
- Tag cases requiring rule tuning

### 2. Version Control Discipline
- One rule change per commit
- Descriptive branch names (tune/rule-name-issue)
- Link commits to SOAR cases

### 3. Testing Rigor
- Validate against historical true positives
- Test exclusions don't over-match
- Monitor post-deployment metrics

### 4. Documentation Standards
Each tuning should document:
- Original false positive pattern
- Business justification
- Expected impact
- Review/expiration date

## Troubleshooting

### Common Issues

**Issue**: Rule updates not deploying
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```bash
# Check CI/CD logs
gh run list --workflow=deploy-rules.yml
gh run view <run-id>

# Validate rule syntax locally
detection-cli validate rules/endpoint/rmm_tools_execution.yaml
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

**Issue**: Over-tuning causing missed detections
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```bash
# Review exclusion patterns
grep -r "NOT\|exclude\|exception" rules/

# Audit recent tunings
git log --oneline --grep="tune" --since="30 days ago"
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## Advanced Automation

### Scheduled Tuning Reviews
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```python
# Weekly automated review
async def weekly_tuning_review():
    # Find rules with high FP rates
    high_fp_rules = await siem.get_rules_by_fp_rate(threshold=0.7)
    
    # Check for existing SOAR feedback
    for rule in high_fp_rules:
        cases = await soar.search_cases(rule_name=rule.name)
        if cases_with_tuning_feedback(cases):
            await create_tuning_pr(rule, cases)
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

### ML-Assisted Pattern Recognition
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```python
# Identify common false positive patterns
def analyze_fp_patterns(cases):
    patterns = []
    for case in cases:
        if case.root_cause == "false_positive":
            patterns.append(extract_event_features(case))
    
    # Cluster similar patterns
    clusters = ml_model.cluster_patterns(patterns)
    return suggest_exclusions(clusters)
    %% Step: Save Findings to Memory

    AutomatedAgent->>Memory: Save Novel Findings

    Memory-->>AutomatedAgent: Findings Saved
```

## References

- [Google SecOps Detection Rules](https://cloud.google.com/security-command-center/docs/how-to-use-detection-rules)
- [MCP Security Tools](https://github.com/GoogleCloudPlatform/mcp-security-tools)
- [Detection Engineering with CI/CD](https://detect.fyi/detection-as-code)
- [SOAR Integration Best Practices](https://www.gartner.com/en/documents/3991893)

