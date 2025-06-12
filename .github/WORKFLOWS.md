# GitHub Workflows

This directory contains GitHub Actions workflows for the ADK Runbooks project.

## Claude Code Action

The `claude-pr-assistant.yml` workflow provides AI-powered code assistance for pull requests using the official Anthropic Claude Code Action.

### Setup

#### Option 1: Quick Setup (Recommended)
1. Install Claude Code CLI: `npm install -g @anthropics/claude-code`
2. Run: `claude /install-github-app`
3. Follow the guided setup process

#### Option 2: Manual Setup
1. **Add Anthropic API Key**: 
   - Go to your repository's Settings → Secrets and variables → Actions
   - Add a new repository secret named `ANTHROPIC_API_KEY`
   - Set the value to your Anthropic API key

2. **Verify Permissions**:
   - The workflow uses `GITHUB_TOKEN` (automatically provided)
   - Ensure your repository allows GitHub Actions to create pull request comments

### Features

- **Interactive Code Assistant**: Claude answers questions about code, architecture, and programming
- **Code Review**: Analyzes PR changes and suggests improvements  
- **Code Implementation**: Can implement simple fixes, refactoring, and new features
- **PR/Issue Integration**: Works seamlessly with GitHub comments and PR reviews
- **Flexible Tool Access**: Access to GitHub APIs and file operations
- **Progress Tracking**: Visual progress indicators with checkboxes that update as Claude completes tasks

### Usage

#### Interactive Mode
Comment on any pull request with `@claude` followed by your request:

**Code Review:**
```
@claude Can you review this PR and suggest any improvements?
```

**Security Analysis:**
```
@claude Can you explain the security implications of this MCP server configuration change?
```

**ADK Best Practices:**
```
@claude Does this agent initialization pattern follow ADK best practices?
```

**Code Implementation:**
```
@claude Can you help fix the failing tests in this PR?
```

**Architecture Questions:**
```
@claude How does this change affect the multi-agent orchestration pattern?
```

### Triggers

The workflow activates when:
- Someone comments `@claude` in a pull request
- Someone adds a pull request review comment containing `@claude`

### Project Context

The workflow is configured with ADK Runbooks-specific context:
- Multi-agent cybersecurity system built on Google ADK
- MCP (Model Context Protocol) server integrations
- Security-focused code review priorities
- ADK compatibility and version management
- Runbook and persona pattern validation

### Customization

You can modify the workflow by editing `.github/workflows/claude-pr-assistant.yml`:

- **Model**: Change the Claude model (default: claude-3-5-sonnet-20241022)
- **System Prompt**: Update project-specific context and instructions
- **Triggers**: Modify when the workflow runs
- **Permissions**: Adjust what Claude can access

### Troubleshooting

If the workflow isn't working:

1. Check that `ANTHROPIC_API_KEY` is set in repository secrets
2. Verify the workflow file syntax is valid YAML
3. Ensure GitHub Actions are enabled for the repository
4. Check the Actions tab for workflow run logs and error messages
5. Make sure you're using `@claude` (not just "claude") in comments
6. Verify the comment is on a pull request (not a regular issue)

### Additional Resources

- [Official Claude Code Action Repository](https://github.com/anthropics/claude-code-action)
- [Claude Code Action on GitHub Marketplace](https://github.com/marketplace/actions/claude-code-action-official)
- [Anthropic GitHub Actions Documentation](https://docs.anthropic.com/en/docs/claude-code/github-actions)