# Tool: get_finding_remediation

**MCP Server:** scc-mcp

**Description:** Gets the remediation steps (nextSteps) for a specific finding within a project.

**Arguments:**

*   `project_id` (str): The Google Cloud project ID.
*   `resource_name` (str, optional): The full resource name associated with the finding.
*   `category` (str, optional): The category of the finding.
*   `finding_id` (str, optional): The ID of the finding to search for directly.

**Returns:**

*   The remediation steps for the finding.
