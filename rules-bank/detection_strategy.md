# Detection Strategy Overview

This document outlines the organization's high-level strategy for security detection development, key platforms, focus areas, and how AI agents contribute to and are measured within this strategy.

## Purpose

-   To define a clear and consistent approach to threat detection.
-   To guide the efforts of the Detection Engineering team and AI agents involved in detection tasks.
-   To align detection efforts with organizational risk, threat intelligence, and compliance requirements.
-   To support the "Preparation" phase of the PICERL AI Performance Framework.

## Core Detection Philosophy

Our detection strategy is based on a defense-in-depth approach, aiming for:
1.  **Threat-Informed Defense:** Prioritizing detections based on known adversary TTPs relevant to our industry and organization (see `internal_threat_profile.md`).
2.  **Behavioral Analytics:** Focusing on detecting anomalous or malicious behaviors rather than relying solely on static IOCs.
3.  **High Fidelity Alerts:** Striving to create detections that have a low false-positive rate and provide actionable insights.
4.  **Continuous Improvement:** Regularly reviewing and refining detections based on operational feedback, new threat intelligence, and evolving attacker techniques.

Key Detection Methodologies

**Signature-based Detection:**
  : Identifies known threats by looking for specific patterns (signatures) in data.

**Anomaly-based Detection:**
  : Establishes a baseline of normal behavior and flags deviations from this baseline.

**Behavioral Detection:**
  : Focuses on sequences of actions or behaviors that indicate malicious intent, even if individual actions appear benign.

## Key Detection Platforms

-   **Primary SIEM:** Google Chronicle (for UDM-based event correlation, rule development, and threat hunting).
-   **Endpoint Detection & Response (EDR):** [Specify EDR Vendor/Product, e.g., CrowdStrike Falcon, SentinelOne Singularity] (for host-level behavioral detections and response).
-   **Network Security Monitoring (NSM):** [Specify IDS/IPS/NDR tools, e.g., Suricata, Zeek, Vectra AI] (for network-based threat detection).
-   **Cloud Security Posture Management (CSPM) & Cloud Workload Protection Platform (CWPP):** Google Security Command Center (SCC), [Other Cloud Native Tools] (for cloud misconfigurations and threats).

## Detection Focus Areas & Prioritization

Detections are prioritized based on:
1.  **Alignment with `internal_threat_profile.md`:** TTPs and threat actors deemed high risk to the organization.
2.  **MITRE ATT&CK Framework:** Focusing on achieving broad coverage across relevant tactics and techniques, particularly:
    -   Initial Access (e.g., Phishing, Exploitation of Public-Facing Applications)
    -   Execution (e.g., PowerShell, Command and Scripting Interpreter)
    -   Persistence (e.g., Create Account, Scheduled Task/Job)
    -   Privilege Escalation (e.g., Valid Accounts, Exploitation for Privilege Escalation)
    -   Defense Evasion (e.g., Masquerading, Obfuscated Files or Information)
    -   Credential Access (e.g., OS Credential Dumping, Brute Force)
    -   Discovery (e.g., Network Service Scanning, Account Discovery)
    -   Lateral Movement (e.g., Remote Services, Exploitation of Remote Services)
    -   Collection (e.g., Data from Local System, Data from Network Shared Drive)
    -   Command and Control (e.g., Proxy, Application Layer Protocol)
    -   Exfiltration (e.g., Exfiltration Over C2 Channel, Exfiltration Over Alternative Protocol)
    -   Impact (e.g., Data Destruction, Data Encrypted for Impact)
3.  **Critical Asset Protection:** Detections focused on protecting assets identified in `asset_inventory_guidelines.md` as critical.
4.  **Compliance Requirements:** Detections necessary to meet specific regulatory or compliance mandates.
5.  **High-Impact Scenarios:** Ransomware, data breaches, widespread service disruption.

## Detection Engineering Lifecycle & AI Integration

This lifecycle, inspired by the "Integrating Detection Engineering with Automation" article, outlines the stages of detection development and how AI agents and the `rules-bank` contribute.

### 1. Concept & Research

-   **Objective:** Identify and prioritize potential detection use-cases.
-   **Activities:**
    -   Analyze threat intelligence (CTI feeds, `internal_threat_profile.md`).
    -   Review incident lessons learned and post-mortem reports.
    -   Conduct proactive threat hunting (manual or AI-assisted using `analytical_query_patterns.md`).
    -   Assess regulatory/compliance drivers.
    -   Perform "Detection Use-Case Analysis":
        -   Define the threat/TTP.
        -   Map to MITRE ATT&CK.
        -   Identify required data sources (`log_source_overview.md`).
        -   Formulate initial detection logic hypothesis.
-   **AI Agent Contribution:**
    -   Process CTI feeds and highlight relevant TTPs/IOCs against `internal_threat_profile.md`.
    -   Assist in historical log analysis for hypothesis validation using `analytical_query_patterns.md`.
    -   Help populate `detection_use_cases/duc_[USE_CASE_NAME]_package.md` templates.

### 2. Engineering (Design & Development)

-   **Objective:** Develop robust and scalable detection rules.
-   **Activities:**
    -   Refine detection logic based on research.
    -   Develop rule syntax for target platforms (e.g., YARA-L for Chronicle, EDR query language).
    -   Utilize `data_normalization_map.md` for consistent field usage.
    -   Consider business/compliance impacts.
    -   Develop initial IR SOP considerations and assess automation feasibility (populating the `duc_[USE_CASE_NAME]_package.md`).
    -   Prototype and test rules in a development/testing environment.
-   **AI Agent Contribution:**
    -   Assist in translating pseudo-code logic into specific tool queries by leveraging `mcp_tool_best_practices.md`.
    -   (Future) Suggest rule optimizations or variations based on learned patterns.

### 3. Testing & Validation

-   **Objective:** Ensure detection rules are accurate, minimize false positives, and integrate with response processes.
-   **Activities:**
    -   Test rules against simulated and real-world attack scenarios (purple teaming).
    -   Validate against known benign activity (`common_benign_alerts.md`, `whitelists.md`).
    -   Evaluate SOP effectiveness for alerts generated by the new rule.
    -   Test any associated automation workflows for accuracy and reliability.
-   **AI Agent Contribution:**
    -   (Future) Assist in generating test data or simulating benign/malicious activity patterns.
    -   Execute initial triage on test alerts to help assess TP/FP rates.

### 4. Delivery (Deployment & Documentation)

-   **Objective:** Deploy validated detection rules and associated procedures into production.
-   **Activities:**
    -   Deploy rules to production monitoring systems.
    -   Finalize and publish IR SOPs (runbooks) associated with the new detections.
    -   Update `automated_response_playbook_criteria.md` if new automated responses are linked.
    -   Document the new detection rule (purpose, logic, expected alerts, SOP link) in a central repository.
-   **AI Agent Contribution:**
    -   AI agents begin processing alerts generated by new rules, following documented SOPs and `indicator_handling_protocols.md`.

### 5. Optimization & Metrics (Continuous Improvement)

-   **Objective:** Continuously monitor, refine, and improve detection effectiveness and the overall process.
-   **Activities:**
    -   Track Detection Engineering Metrics (TP/FP rates, ATT&CK coverage, effectiveness over time).
    -   Monitor Operating Procedures Metrics (SOP efficiency, manual vs. automated steps).
    -   Track Automation and Orchestration Metrics (alerts processed automatically, speed of response).
    -   Gather feedback from human analysts and AI performance data (`ai_decision_review_guidelines.md`, `ai_performance_logging_requirements.md`).
    -   Feed learnings back into the "Concept & Research" phase via `detection_improvement_process.md` and `sop_automation_effectiveness_review.md`.
-   **AI Agent Contribution:**
    -   Provide data for performance metrics (as defined in `ai_performance_logging_requirements.md`).
    -   Identify potential detection gaps or areas for SOP refinement through operational experience, feeding into `detection_improvement_process.md`.
    -   Flag frequently failing or overridden automation steps.

## Target Detection Metrics & AI Contribution (PICERL - Preparation & Learning)

-   **Overall Detection Effectiveness:**
    -   *Metric:* True Positive (TP) Rate: (Number of true positive alerts) / (Total alerts generated by a rule/set of rules).
    -   *Metric:* False Positive (FP) Rate: (Number of false positive alerts) / (Total alerts generated by a rule/set of rules).
    -   *Target:* Aim for a high TP rate and a low FP rate (specific percentages to be defined and tracked per rule category).
-   **MITRE ATT&CK Coverage:**
    -   *Metric:* Percentage of prioritized ATT&CK techniques (from Focus Areas above) with at least one active, validated detection rule.
    -   *Target:* Achieve X% coverage of prioritized TTPs within Y months.
-   **Detection Effectiveness Over Time:**
    -   *Metric:* Trend of TP/FP rates for key detection categories. Are detections improving or degrading?
-   **AI Agent Contributions to Detection Strategy:**
    1.  **Gap Identification:**
        -   *AI Task:* Identify potential detection gaps based on observed unalerted malicious activity or new threat intelligence, as per `detection_improvement_process.md`.
        -   *Metric:* Number of valid detection gaps identified by AI agents per quarter.
        -   *Metric:* Percentage of AI-identified gaps leading to new/improved detections.
    2.  **Rule Suggestion/Refinement (Future Capability):**
        -   *AI Task (Advanced):* Propose new detection logic or refinements to existing rules based on large-scale log analysis and pattern recognition.
        -   *Metric:* Number of AI-suggested rules/refinements adopted by Detection Engineering.
    3.  **Hunting Support:**
        -   *AI Task:* Execute broad hunting queries based on hypotheses (potentially from `analytical_query_patterns.md`) to uncover activity that could inform new detections.
        -   *Metric:* Number of successful hunts (leading to incident or detection improvement) initiated or significantly assisted by AI.
    4.  **Prioritization Assistance:**
        -   *AI Task:* Correlate observed environmental data against `internal_threat_profile.md` and ATT&CK to highlight areas where detection focus might be most valuable.

## Key Detection Thresholds / Sensitivity

-   (To be defined based on specific rule sets and organizational risk tolerance. E.g., "Brute force login detection: alert after 5 failed attempts in 1 minute from a single IP to a single account.")
-   AI agents should be aware of these thresholds when analyzing activity and determining if an event sequence warrants escalation or matches a detection pattern.

This strategy will be reviewed and updated at least annually, or as significant changes in the threat landscape or business environment occur.

---

## References and Inspiration

-   The metrics and AI contribution sections are informed by the PICERL framework:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
-   The Detection Engineering Lifecycle integration is inspired by:
    -   Stojkovski, Filip. "Integrating Detection Engineering with Automation." *Cyber Security Automation and Orchestration*, May 29, 2024. [https://www.cybersec-automation.com/p/detection-engineering-automation-incident-response](https://www.cybersec-automation.com/p/detection-engineering-automation-incident-response)
-   The general approach to AI Agents in Cybersecurity is also informed by:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
