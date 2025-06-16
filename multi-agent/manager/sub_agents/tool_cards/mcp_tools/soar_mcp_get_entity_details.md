# Tool: get_entity_details

**MCP Server:** secops-soar

**Description:** Fetch detailed information about a specific entity known to the SOAR platform.

**Arguments:**

*   `entity_identifier` (str): The unique identifier of the entity.
*   `entity_type` (str): The type of the entity.
*   `entity_environment` (str): The environment context for the entity.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
