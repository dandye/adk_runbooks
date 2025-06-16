# Tool: get_case_full_details

**MCP Server:** secops-soar

**Description:** Retrieve comprehensive details for a specific case by aggregating its core information, associated alerts, and comments.

**Arguments:**

*   `case_id` (str): The unique identifier (ID) of the case for which full details are required.

**Returns:**

*   `dict`: A dictionary containing the aggregated results from three separate API calls.
