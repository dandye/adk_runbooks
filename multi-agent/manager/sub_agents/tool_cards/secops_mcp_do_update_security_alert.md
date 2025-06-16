# Tool: do_update_security_alert

**MCP Server:** secops-mcp

**Description:** Update security alert attributes directly in Chronicle SIEM.

**Arguments:**

*   `alert_id` (str): The unique ID of the Chronicle security alert to update.
*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): The Chronicle customer ID.
*   `region` (str, optional): The Google Cloud region where the Chronicle instance is hosted.
*   `reason` (str, optional): Reason for closing an alert.
*   `priority` (str, optional): Alert priority.
*   `status` (str, optional): Alert status.
*   `verdict` (str, optional): Verdict on the alert.
*   `severity` (int, optional): Severity score [0-100] of the alert.
*   `comment` (str, optional): Analyst comment.
*   `root_cause` (str, optional): Alert root cause.

**Returns:**

*   `str`: A confirmation message indicating whether the alert was updated successfully.
