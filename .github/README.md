# GitHub Workflows

This directory contains GitHub Actions workflows for the ADK Runbooks project.

## Claude PR Assistant

The `claude-pr-assistant.yml` workflow provides AI-powered code review and assistance for pull requests using Claude.

### Setup

1. **Add Anthropic API Key**: 
   - Go to your repository's Settings → Secrets and variables → Actions
   - Add a new repository secret named `ANTHROPIC_API_KEY`
   - Set the value to your Anthropic API key

2. **Verify Permissions**:
   - The workflow uses `GITHUB_TOKEN` (automatically provided)
   - Ensure your repository allows GitHub Actions to create pull request comments

### Features

- **Automatic PR Review**: Claude reviews all new and updated pull requests
- **Interactive Comments**: Use `@claude` in PR comments to ask specific questions
- **Project-Aware**: Configured with ADK Runbooks project context for relevant feedback
- **Security Focus**: Special attention to cybersecurity best practices

### Usage

#### Automatic Review
The workflow automatically triggers on:
- New pull requests
- Pull request updates (new commits)
- Pull request reopening

#### Interactive Mode
Comment on any pull request with `@claude` followed by your question:
```
@claude Can you explain the security implications of this MCP server configuration change?
```

```
@claude Does this agent initialization pattern follow ADK best practices?
```

### Customization

You can modify the workflow by editing `.github/workflows/claude-pr-assistant.yml`:

- **Model**: Change the Claude model used (default: claude-3-5-sonnet)
- **Instructions**: Update the project-specific guidance for code reviews
- **Triggers**: Modify when the workflow runs

### Troubleshooting

If the workflow isn't working:

1. Check that `ANTHROPIC_API_KEY` is set in repository secrets
2. Verify the workflow file syntax is valid YAML
3. Ensure GitHub Actions are enabled for the repository
4. Check the Actions tab for workflow run logs and error messages