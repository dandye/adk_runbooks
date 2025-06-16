# Tool: create_detection_rule_form

**Description:** Create a detection rule development form for the detection engineer to fill out.

**Arguments:**

*   `rule_name` (str, optional): Name of the detection rule.
*   `rule_type` (str, optional): Type of detection rule (e.g., SIEM, YARA, Sigma, custom).
*   `severity` (str, optional): Rule severity level (critical/high/medium/low).
*   `platform` (str, optional): Target platform (e.g., Splunk, QRadar, Chronicle, Elastic).
*   `detection_logic` (str, optional): The detection logic/query.
*   `mitre_tactics` (str, optional): MITRE ATT&CK tactics/techniques.
*   `iocs` (str, optional): IOCs or indicators this rule detects.
*   `false_positive_rate` (str, optional): Expected false positive rate.

**Returns:**

*   `dict[str, Any]`: A dictionary containing the detection rule form data.
