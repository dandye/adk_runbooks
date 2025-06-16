# Tool: list_alert_group_identifiers_by_case

**MCP Server:** secops-soar

**Description:** List alert group identifiers associated with a specific case ID in the SOAR platform.

**Arguments:**

*   `case_id` (str): The unique identifier (ID) of the case for which alert group identifiers should be retrieved.
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
