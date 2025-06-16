# Tool: create_research_request_form

**Description:** Create a CTI research request form for the analyst to fill out.

**Arguments:**

*   `threat_type` (str, optional): Type of threat to research (e.g., APT, malware, ransomware).
*   `iocs` (str, optional): Indicators of Compromise to investigate (comma-separated).
*   `actor_name` (str, optional): Threat actor name to research.
*   `campaign_name` (str, optional): Campaign name to investigate.
*   `collection_id` (str, optional): GTI collection ID to analyze.
*   `time_range` (str, optional): Time range for the investigation (e.g., "last 7 days").
*   `priority` (str, optional): Priority level (high/medium/low).

**Returns:**

*   `dict[str, Any]`: A dictionary containing the research request form data.
