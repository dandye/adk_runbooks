# Tool: search_security_rules

**MCP Server:** secops-mcp

**Description:** Search security detection rules configured in Chronicle SIEM.

**Arguments:**

*   `query` (str): Regex string to use for searching SecOps rules.
*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `Dict[str, Any]`: Raw response from the Chronicle API, typically containing a list of rule objects.
