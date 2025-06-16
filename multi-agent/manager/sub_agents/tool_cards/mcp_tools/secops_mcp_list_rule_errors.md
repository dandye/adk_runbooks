# Tool: list_rule_errors

**MCP Server:** secops-mcp

**Description:** Lists execution errors for a specific Chronicle SIEM rule.

**Arguments:**

*   `rule_id` (str): Unique ID of the rule to list errors for.
*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `Dict[str, Any]`: A dictionary containing rule execution errors.
