# Tool: list_security_rules

**MCP Server:** secops-mcp

**Description:** List security detection rules configured in Chronicle SIEM.

**Arguments:**

*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `Dict[str, Any]`: Raw response from the Chronicle API, typically containing a list of rule objects.
