# Tool: get_ioc_matches

**MCP Server:** secops-mcp

**Description:** Get Indicators of Compromise (IoCs) matches from Chronicle SIEM.

**Arguments:**

*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `hours_back` (int, optional): How many hours back to look for IoC matches. Defaults to 24.
*   `max_matches` (int, optional): Maximum number of IoC matches to return. Defaults to 20.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `str`: A formatted string summarizing the IoC matches found.
