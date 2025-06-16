# Tool: lookup_entity

**MCP Server:** secops-mcp

**Description:** Look up an entity (IP, domain, hash, user, etc.) in Chronicle SIEM for enrichment.

**Arguments:**

*   `entity_value` (str): Value to look up (e.g., IP address, domain name, file hash, username).
*   `project_id` (str, optional): Google Cloud project ID.
*   `customer_id` (str, optional): Chronicle customer ID.
*   `hours_back` (int, optional): How many hours of historical data to consider for the summary. Defaults to 24.
*   `region` (str, optional): Chronicle region (e.g., "us", "europe").

**Returns:**

*   `str`: A formatted string summarizing the entity information found in Chronicle.
