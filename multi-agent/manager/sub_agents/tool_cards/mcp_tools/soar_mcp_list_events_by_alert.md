# Tool: list_events_by_alert

**MCP Server:** secops-soar

**Description:** List the underlying security events associated with a specific alert within a given case.

**Arguments:**

*   `case_id` (str): The unique identifier (ID) of the case containing the alert.
*   `alert_id` (str): The unique identifier (ID) of the specific alert whose associated events are to be listed.
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
