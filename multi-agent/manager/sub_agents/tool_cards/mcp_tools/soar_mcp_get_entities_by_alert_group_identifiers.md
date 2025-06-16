# Tool: get_entities_by_alert_group_identifiers

**MCP Server:** secops-soar

**Description:** Retrieve entities (e.g., IP addresses, hostnames, users) involved in specific alert groups within a case.

**Arguments:**

*   `case_id` (str): The unique identifier (ID) of the case containing the alert groups.
*   `alert_group_identifiers` (List[str]): A list of identifiers for the specific alert groups whose involved entities are to be retrieved.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
