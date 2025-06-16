# Tool: get_threat_profile_associations_timeline

**MCP Server:** gti-mcp

**Description:** Retrieves the associations timeline for the given Threat Profile.

**Arguments:**

*   `profile_id` (str): Threat Profile identifier at Google Threat Intelligence.
*   `limit` (int, optional): Limit the number of timeline associations to retrieve. 10 by default.

**Returns:**

*   List of dictionaries containing timeline associations.
