# Tool: create_advanced_investigation_form

**Description:** Create an advanced investigation form for the SOC Tier 3 analyst to fill out.

**Arguments:**

*   `case_id` (str, optional): Case ID from the case management system.
*   `threat_type` (str, optional): Type of advanced threat (e.g., APT, sophisticated malware, nation-state).
*   `complexity` (str, optional): Investigation complexity level (critical/high/medium/low).
*   `investigation_scope` (str, optional): Scope of the investigation (enterprise-wide, multi-vector, long-term).
*   `threat_actors` (str, optional): Suspected threat actors or groups.
*   `attack_timeline` (str, optional): Timeline of the attack progression.
*   `campaign_indicators` (str, optional): Campaign-level IOCs and TTPs.
*   `attribution_confidence` (str, optional): Confidence level in threat attribution.

**Returns:**

*   `dict[str, Any]`: A dictionary containing the advanced investigation form data.
