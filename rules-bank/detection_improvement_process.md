# Detection Improvement Process for AI Agents

This document outlines the process for AI agents to identify, document, and report potential detection gaps. This formalizes the "Detection Gaps Identification" and "Feedback to Detection Engineering" loop described in the "Blueprint for AI Agents in Cybersecurity."

## Objective

-   To enable AI agents to contribute to the continuous improvement of the organization's detection capabilities.
-   To provide a structured way for AI agents to report observed activities that were not detected by existing rules or signatures.
-   To ensure that feedback from AI agents is actionable for the Detection Engineering team.

## Criteria for Identifying a Potential Detection Gap by an AI Agent

An AI agent may identify a potential detection gap when:

1.  **Post-Incident Analysis:** During the investigation of an alert or incident (e.g., using `indicator_handling_protocols.md`), the agent uncovers malicious activity or TTPs that did *not* trigger a specific, relevant detection rule.
    -   *Example:* An agent investigates a phishing email, finds a downloaded malware hash. GTI confirms the hash is malicious. SIEM search shows the malware executed on a host, but no EDR or SIEM rule specifically alerted on this execution or subsequent C2 communication related to this specific malware family.
2.  **Threat Intelligence Correlation:** An agent processes new threat intelligence (e.g., a new CTI report on an actor targeting the organization's industry) and identifies TTPs or IOCs for which no corresponding detection logic appears to exist (cross-referencing `detection_strategy.md` or querying existing rule sets if possible).
3.  **Behavioral Anomaly Not Covered:** An agent observes a pattern of behavior that is anomalous (deviates from `baseline_behavior.md`) and suspicious, but doesn't match any existing detection rule's logic.
    -   *Example:* A user account suddenly starts accessing unusual network shares at odd hours, and existing rules for lateral movement don't cover this specific pattern.
4.  **Ineffective Existing Detection:** An existing detection rule *did* fire, but its scope was too narrow, or its severity was misjudged, failing to capture the true extent or risk of the activity. The agent, through broader investigation, identifies this shortcoming.

## Information Required When Reporting a Detection Gap

When an AI agent flags a potential detection gap, it must provide the following information in a structured format (e.g., a JSON object or a standardized section in a SOAR case comment):

1.  **Gap Summary:** A concise description of the observed activity and why it's considered a detection gap.
2.  **Source of Identification:** How was the gap identified (e.g., "Post-incident analysis of Alert XYZ", "Correlation with CTI Report ABC").
3.  **Observed Activity / TTP:**
    -   Detailed description of the malicious/suspicious activity or TTP observed (e.g., MITRE ATT&CK ID if applicable).
    -   Timestamp(s) of the observed activity.
4.  **Key Indicators:** List all relevant atomic and computed indicators associated with the observed activity (IPs, domains, hashes, user accounts, file paths, command lines, etc.).
5.  **Supporting Evidence (Log Snippets/References):**
    -   Provide direct UDM event snippets (e.g., from `secops-mcp - search_security_events`) or references to relevant log entries (e.g., `metadata.product_log_id`).
    -   Include at least 1-3 representative log examples.
6.  **Affected Systems/Users (if known):**
    -   Hostnames, IP addresses, user accounts involved.
7.  **Hypothesis for New/Improved Detection (Optional but Recommended):**
    -   Suggest potential logic for a new detection rule (e.g., "Detect PowerShell execution with base64 encoded commands originating from non-interactive processes").
    -   Suggest improvements to existing rules if applicable.
8.  **Confidence Score (Agent's assessment):** High/Medium/Low confidence that this is a true detection gap requiring attention.
9.  **Reporting Agent ID:** Identifier of the AI agent reporting the gap.
10. **Associated Case/Alert ID (if applicable):** Link to the SOAR case or SIEM alert that led to this discovery.

## Designated Channel/Tool for Reporting

-   **Primary Method:** Create a new "Detection Gap" ticket/task in the designated Detection Engineering backlog system (e.g., JIRA, ServiceNow) using an API integration if available. The ticket description should be populated with the structured information above.
-   **Secondary Method (if API not available):** Post a specially formatted comment to the related SOAR case (if one exists) using a specific tag like `#DetectionGap`. This comment should contain all the required information. A human analyst or a dedicated automation can then periodically review these tags and create manual tickets.
-   **Fallback:** If no SOAR case is relevant, the agent can log the gap to a dedicated internal logging system or queue for review by the SOC/Detection Engineering team.

## Follow-up Process (by Detection Engineering Team)

1.  **Review and Triage:** The Detection Engineering team reviews reported gaps.
2.  **Validation:** Confirm if it's a true gap or if existing (perhaps misconfigured or low-severity) detections should have caught it.
3.  **Prioritization:** Prioritize the development of new detections based on risk, prevalence, and alignment with `detection_strategy.md` and `internal_threat_profile.md`.
4.  **Development & Deployment:** Develop, test, and deploy new detection rules/logic.
5.  **Feedback Loop:** Update the reporting AI agent (or the system it uses) on the status (e.g., "Accepted", "Rejected - False Positive", "Implemented - Rule ID XYZ"). This helps the agent learn and refine its gap identification.

---

This process aims to make AI agents valuable partners in proactively strengthening the organization's security posture.

---

## References and Inspiration

-   The concept of AI agents contributing to detection engineering and feedback loops is a key theme in:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
-   The importance of feedback loops for improving AI performance and detection effectiveness is highlighted in the PICERL framework:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
