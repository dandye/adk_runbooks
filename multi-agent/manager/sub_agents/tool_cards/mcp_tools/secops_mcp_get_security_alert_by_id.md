# Tool: get_security_alert_by_id

**MCP Server:** secops-mcp

**Description:** Get security alert by ID directly from Chronicle SIEM.

**Arguments:**

*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").
*   `alert_id` (str, optional): The ID of the alert to retrieve.
*   `include_detections` (bool, optional): Whether to include detections in the response. Defaults to True.

**Returns:**

*   `str`: A formatted string summarizing the retrieved security alert.
