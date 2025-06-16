# Tool: create_alert_triage_form

**Description:** Create an alert triage form for the SOC analyst to fill out.

**Arguments:**

*   `alert_id` (str, optional): Alert ID from the SIEM/security system.
*   `alert_type` (str, optional): Type of security alert (e.g., malware, phishing, suspicious login).
*   `severity` (str, optional): Alert severity level (critical/high/medium/low).
*   `source_system` (str, optional): System that generated the alert.
*   `affected_assets` (str, optional): Affected systems, users, or IP addresses.
*   `event_time` (str, optional): When the security event occurred.
*   `description` (str, optional): Brief description of the alert.
*   `initial_indicators` (str, optional): Initial IOCs or suspicious indicators.

**Returns:**

*   `dict[str, Any]`: A dictionary containing the alert triage form data.
