# Tool: search_threats

**MCP Server:** gti-mcp

**Description:** Search threats in the Google Threat Intelligence platform.

**Arguments:**

*   `query` (str): Search query to find threats.
*   `collection_type` (str, optional): Filter your search results to a specific *type* of threat.
*   `limit` (int, optional): Limit the number of threats to retrieve. 10 by default.
*   `order_by` (str, optional): Order results by the given order key. "relevance-" by default.

**Returns:**

*   List of collections, aka threats.
