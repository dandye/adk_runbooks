# Tool: get_security_alerts

**MCP Server:** secops-mcp

**Description:** Get security alerts directly from Chronicle SIEM.

**Arguments:**

*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `hours_back` (int, optional): How many hours to look back for alerts. Defaults to 24.
*   `max_alerts` (int, optional): Maximum number of alerts to return. Defaults to 10.
*   `status_filter` (str, optional): Query string to filter alerts by status. Defaults to excluding closed alerts.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `str`: A formatted string summarizing the retrieved security alerts.
