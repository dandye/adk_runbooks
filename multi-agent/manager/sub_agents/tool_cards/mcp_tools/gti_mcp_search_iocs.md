# Tool: search_iocs

**MCP Server:** gti-mcp

**Description:** Search Indicators of Compromise (IOC) in the Google Threat Intelligence platform.

**Arguments:**

*   `query` (str): Search query to find IOCs.
*   `limit` (int, optional): Limit the number of IoCs to retrieve. 10 by default.
*   `order_by` (str, optional): Order the results. "last_submission_date-" by default.

**Returns:**

*   List of Indicators of Compromise (IoCs).
