# Tool: search_security_events

**MCP Server:** secops-mcp

**Description:** Search for security events in Chronicle SIEM using natural language.

**Arguments:**

*   `text` (str): Natural language description of the events you want to find.
*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `hours_back` (int, optional): How many hours back from the current time to search. Defaults to 24.
*   `max_events` (int, optional): Maximum number of event records to return. Defaults to 100.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `Dict[str, Any]`: A dictionary containing the UDM query and the search results.
