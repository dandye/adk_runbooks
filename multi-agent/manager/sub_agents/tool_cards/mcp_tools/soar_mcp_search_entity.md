# Tool: search_entity

**MCP Server:** secops-soar

**Description:** Search for entities within the SOAR platform based on various criteria.

**Arguments:**

*   `term` (str, optional): A search term to match against entity identifiers or names.
*   `type` (List[str], optional): A list of entity types to filter by.
*   `is_suspicious` (bool, optional): Filter for entities marked as suspicious.
*   `is_internal_asset` (bool, optional): Filter for entities identified as internal assets.
*   `is_enriched` (bool, optional): Filter for entities that have undergone enrichment processes.
*   `network_name` (List[str], optional): Filter entities belonging to specific networks.
*   `environment_name` (List[str], optional): Filter entities belonging to specific environments.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
