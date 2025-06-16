# Tool: change_case_priority

**MCP Server:** secops-soar

**Description:** Change the priority level of a specific case in the SOAR platform.

**Arguments:**

*   `case_id` (str): The unique identifier (ID) of the case whose priority needs to be updated.
*   `case_priority` (CasePriority): The new priority level to assign to the case.

**Returns:**

*   `dict`: A dictionary representing the raw API response from the SOAR platform.
