# Tool: get_threat_profile_recommendations

**MCP Server:** gti-mcp

**Description:** Returns the list of objects associated to a given Threat Profile.

**Arguments:**

*   `profile_id` (str): Threat Profile identifier at Google Threat Intelligence.
*   `limit` (int, optional): Limit the number of recommendations to retrieve. 10 by default.

**Returns:**

*   List of Threat (collection) objects identifiers associated to the Threat Profile.
