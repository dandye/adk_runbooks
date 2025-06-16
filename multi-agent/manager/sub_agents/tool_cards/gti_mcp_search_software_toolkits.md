# Tool: search_software_toolkits

**MCP Server:** gti-mcp

**Description:** Search software toolkits (or just tools) in the Google Threat Intelligence platform.

**Arguments:**

*   `query` (str): Search query to find threats.
*   `limit` (int, optional): Limit the number of threats to retrieve. 10 by default.
*   `order_by` (str, optional): Order results by the given order key. "relevance-" by default.

**Returns:**

*   List of collections, aka threats.
