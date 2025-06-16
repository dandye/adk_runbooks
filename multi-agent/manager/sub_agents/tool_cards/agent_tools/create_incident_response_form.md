# Tool: create_incident_response_form

**Description:** Create an incident response form for the incident responder to fill out.

**Arguments:**

*   `incident_id` (str, optional): Incident ID from the incident management system.
*   `incident_type` (str, optional): Type of security incident (e.g., malware, phishing, data breach, ransomware).
*   `severity` (str, optional): Incident severity level (critical/high/medium/low).
*   `affected_systems` (str, optional): Systems, networks, or assets affected by the incident.
*   `incident_scope` (str, optional): Scope of the incident (single host, network segment, enterprise-wide).
*   `detection_time` (str, optional): When the incident was first detected.
*   `containment_status` (str, optional): Current containment status.
*   `threat_indicators` (str, optional): IOCs and threat indicators associated with the incident.

**Returns:**

*   `dict[str, Any]`: A dictionary containing the incident response form data.
