# SCC MCP Tools Reference

This document provides a reference for the tools available in the SCC MCP server.

## Available Tools

### top_vulnerability_findings
Lists the top ACTIVE, HIGH or CRITICAL severity findings of class VULNERABILITY for a specific project.

**Arguments:**
*   `project_id` (str): The Google Cloud project ID.
*   `max_findings` (int, optional): The maximum number of findings to return. Defaults to 20.

**Returns:**
*   A list of vulnerability findings.

### get_finding_remediation
Gets the remediation steps (nextSteps) for a specific finding within a project.

**Arguments:**
*   `project_id` (str): The Google Cloud project ID.
*   `resource_name` (str, optional): The full resource name associated with the finding.
*   `category` (str, optional): The category of the finding.
*   `finding_id` (str, optional): The ID of the finding to search for directly.

**Returns:**
*   The remediation steps for the finding.
