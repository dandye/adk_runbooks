# Project Plan: Enhance LLM Agent Context

**Project Goal:** To create a comprehensive set of context files within the rules-bank directory, improving the LLM Agent's understanding of the environment, tools, policies, and relevant threats.

**Project Phases & Tasks:**

**Phase 1: Environment & Infrastructure Context**
*   **Objective:** Document the technical environment to provide operational context.
*   **Tasks:**
    1.  **Create `network_map.md`**:
        *   Gather information on key network segments (DMZ, Prod, User nets).
        *   Document IP ranges and primary functions for each segment.
        *   *Potential Action:* Ask user/Network Team for this information or relevant documentation.
    2.  **Create `asset_inventory_guidelines.md`**:
        *   Document host/server naming conventions.
        *   List common OS types deployed.
        *   Identify and map critical assets to roles/owners (if possible).
        *   *Potential Action:* Ask user/IT Asset Management for guidelines or inventory access.
    3.  **Create `critical_applications.md`**:
        *   List key business applications.
        *   Map applications to supporting servers/IPs.
        *   Describe expected communication patterns.
        *   *Potential Action:* Ask user/Application Owners for this information.
    4.  **Create `cloud_architecture.md`**:
        *   Outline GCP project structure.
        *   List key cloud services in use (GKE, Cloud SQL, etc.).
        *   Describe basic cloud network topology (VPCs, subnets).
        *   *Potential Action:* Ask user/Cloud Team for architecture diagrams or descriptions.
    5.  **Create `security_products_inventory.md`**:
        *   List key security products deployed (e.g., EDR vendor/product, Firewall vendor/product, Email Gateway, Vulnerability Scanner, etc.).
        *   Briefly note the primary function of each product.
        *   *Potential Action:* Ask user/Security Engineering/SOC Manager for this inventory.
    6.  **Create `baseline_behavior.md`**:
        *   Document known normal operational patterns (e.g., expected administrative script activity times/sources, typical outbound traffic patterns for key servers, common benign scan activity).
        *   This can help differentiate anomalous activity from expected noise.
        *   *Potential Action:* Gather this from user/SOC team experience/historical analysis.
    7.  **Create `log_source_overview.md`**:
        *   Identify critical log sources (OS, network, cloud, application, security tools).
        *   Document primary location/ingestion method (e.g., Chronicle Parser, Splunk Index).
        *   Note typical retention periods.
        *   *Potential Action:* Ask user/Security Engineering/Platform Admins.
    *   **Rationale:** Inspired by the heavy reliance on log analysis in both NIST SP 800-61r3 and CISA Playbooks. Provides essential context for detection and investigation.

**Phase 2: Tool Configuration & Usage**
*   **Objective:** Document specific tool configurations and best practices.
*   **Tasks:**
    1.  **Create `tool_configurations.md`**:
        *   Identify and list important Chronicle Reference List names (Blocklists, Allowlists).
        *   Document key SOAR playbook names/IDs and their triggers.
        *   Define preferred default timeframes/limits for searches.
        *   *Potential Action:* Ask user/Security Engineering about these configurations.
    2.  **Create `mcp_tool_best_practices.md`**:
        *   Compile tips for optimizing `search_security_events`.
        *   Note important fields or interpretation guidance for GTI tools.
        *   Add any other tool-specific usage advice.
        *   *Potential Action:* Gather this information iteratively based on experience or ask user/senior analysts.
    3.  **Create `tool_rate_limits.md`**:
        *   Document known rate limits (e.g., Chronicle UDM query limits per hour).
        *   *Potential Action:* Check tool documentation or ask user/tool administrators.
    4.  **Create `detection_strategy.md`**:
        *   Outline the high-level strategy for detection development (e.g., focus areas, use of MITRE ATT&CK, threat intelligence driven).
        *   Mention key detection platforms (e.g., Chronicle SIEM, EDR).
        *   Include key detection thresholds or sensitivity levels where applicable.
        *   Reference `internal_threat_profile.md` for priority threats.
        *   *Potential Action:* Ask user/Detection Engineering Lead/SOC Manager.
    *   **Rationale:** Aligns with the "Detect" function of NIST CSF 2.0 and provides context for how detections are created and prioritized.

**Phase 3: Governance, Policies & Procedures**
*   **Objective:** Codify key organizational processes relevant to security operations and governance. (Aligned with NIST CSF 2.0 "Govern" function).
*   **Tasks:**
    1.  **Create `governance_overview.md`**:
        *   Describe the overall cybersecurity governance structure.
        *   Outline the risk management approach and appetite.
        *   Reference key policies (linking to where they might exist if not directly in rules-bank).
        *   *Potential Action:* Ask user/CISO Office/Compliance Manager.
    *   **Rationale:** Directly addresses the "Govern" function of NIST CSF 2.0.
    2.  **Create `incident_severity_matrix.md`**:
        *   Define criteria for Low, Medium, High, Critical incidents.
        *   *Potential Action:* Ask user/SOC Manager for the existing matrix or definitions.
    2.  **Create `escalation_paths.md`**:
        *   Document who to notify for specific incident types (Ransomware, PII exposure, etc.).
        *   *Potential Action:* Ask user/IR Lead/SOC Manager for escalation procedures.
    3.  **Create `reporting_templates.md`**:
        *   Provide standard formats/sections for common reports (Daily Summary, Post-Incident).
        *   *Potential Action:* Ask user/SOC Manager for existing templates.
    4.  **Create `approved_remediations.md`**:
        *   List pre-approved actions for common low-severity findings.
        *   *Potential Action:* Ask user/Security Engineering/SOC Manager for this list.
    5.  **Create `key_contacts.md`**:
        *   List relevant teams/individuals (Network Ops, Identity, Legal).
        *   *Potential Action:* Ask user/SOC Manager for contact points.
    6.  **Create `vulnerability_management_process.md`**:
        *   Describe the tools used for vulnerability scanning (e.g., SCC, Tenable).
        *   Outline scanning frequency and scope.
        *   Explain the prioritization process (linking to `incident_severity_matrix.md`).
        *   Describe standard remediation workflows and timelines.
        *   *Potential Action:* Ask user/Vulnerability Management Team/Security Engineering.
    *   **Rationale:** Incorporates insights from the CISA Vulnerability Response Playbook.
    7.  **Create `communication_plan_templates.md`**:
        *   Provide templates/guidelines for internal and external communications during different incident stages/types.
        *   Reference `escalation_paths.md` and `key_contacts.md`.
        *   *Potential Action:* Ask user/IR Lead/Corporate Communications.
    *   **Rationale:** Addresses communication needs highlighted in both NIST SP 800-61r3 and CISA playbooks.

**Phase 4: Threat Intelligence & Context**
*   **Objective:** Document organization-specific threat context and known benign activity.
*   **Tasks:**
    1.  **Create `internal_threat_profile.md`**:
        *   List high-concern threat actors, campaigns, or TTPs specific to the organization.
        *   *Potential Action:* Ask user/CTI Team for this profile.
    2.  **Create `whitelists.md`**:
        *   List known-good IPs, domains, hashes, process names specific to the environment.
        *   *Potential Action:* Gather this from user/Security Engineering/existing documentation.
    3.  **Create `common_benign_alerts.md`**:
        *   Describe alerts often triggered by benign activity (scans, admin scripts).
        *   Outline typical handling procedures for these.
        *   *Potential Action:* Gather this from user/SOC team experience.

**Phase 5: Recovery & Resilience**
*   **Objective:** Document plans and procedures related to recovering from cybersecurity incidents. (Aligned with NIST CSF 2.0 "Recover" function).
*   **Tasks:**
    1.  **Create `disaster_recovery_plan_summary.md`**:
        *   Provide a high-level summary of DR/BCP plans relevant to SOC/IR activities.
        *   Outline key recovery time objectives (RTOs) and recovery point objectives (RPOs) for critical systems.
        *   *Potential Action:* Ask user/Business Continuity Team/IT Operations for summaries.
    2.  **Create `backup_strategy_overview.md`**:
        *   Summarize backup methods, locations, and frequency for critical systems (identified in Phase 1).
        *   Outline general procedures for data restoration validation.
        *   *Potential Action:* Ask user/Backup Administrators/IT Operations.

**Phase 6: Runbook Refinement & Optimization**
*   **Objective:** Continuously improve the clarity, efficiency, and robustness of existing runbooks based on operational experience and evolving capabilities.
*   **Tasks (Ongoing/Iterative):**
    1.  **Enhance Error Handling & Fallbacks:**
        *   Review `enrich_ioc.md` and other runbooks to add specific guidance for handling tool errors (e.g., "If GTI lookup fails due to quota, note limitation and rely on SIEM context").
        *   Suggest concrete alternative steps (e.g., "If primary SIEM search fails, try broader time window or alternative query structure").
        *   Integrate checks against `tool_rate_limits.md` before calling tools with known limits.
    2.  **Improve Context Integration:**
        *   Modify `triage_alerts.md` to suggest checking `common_benign_alerts.md`.
        *   Update investigation runbooks to prompt referencing `network_map.md` or `asset_inventory_guidelines.md` when assessing internal entity criticality.
    3.  **Refine Common Steps:**
        *   Analyze `enrich_ioc.md` - could it be split into `enrich_ip.md`, `enrich_domain.md`, etc., for more specific logic/fallbacks?
        *   Review other common steps for potential modularization.
    4.  **Clarify Decision Logic:**
        *   Refine assessment steps in runbooks like `triage_alerts.md` with specific examples (e.g., "If source IP is internal AND user is known admin AND target is domain controller AND time matches known patching window -> Likely BTP. Else -> Investigate further.").
        *   Explicitly link decision criteria to `incident_severity_matrix.md` where applicable.
    5.  **Standardize Reporting Outputs:**
        *   Define a standard "Key Findings" structure in `reporting_templates.md` to be used across triage, investigation, and hunt reports.
    6.  **Align with Personas:**
        *   Review runbooks like `deep_dive_ioc_analysis.md` or `advanced_threat_hunting.md` and add "*(Tier 2+/Tier 3 Recommended)*" annotations to particularly complex steps or tool usage.
    7.  **Incorporate Visualizations:**
        *   Update `case_event_timeline_and_process_analysis.md` to explicitly require a Mermaid process tree diagram in the report.
        *   Encourage adding simple relationship diagrams (e.g., `graph LR; Host-->IP; IP-->Domain;`) in investigation reports.
    8.  **Address Tool Limitations:**
        *   Ensure `find_relevant_soar_case.md` clearly documents the `list_cases` entity search limitation and suggests specific workarounds (manual search, SIEM correlation).
    *   **Rationale:** Ensures runbooks remain effective, reflect real-world conditions, incorporate lessons learned (like tool errors), and leverage the full context available within the rules-bank directory.

**Phase 7: Enhancing for Autonomous SecOps Orchestration (ASO)**
*   **Objective:** Further evolve the `rules-bank` to explicitly support an Autonomous SecOps Orchestration model, mapping AI agent capabilities and `rules-bank` content to SANS IR stages, and defining how AI agents can autonomously execute larger portions of the IR lifecycle. This phase is primarily inspired by the "Beyond the Tiered SOC" article.
*   **Tasks:**
    1.  **Map `rules-bank` to SANS IR Stages & ASO Capabilities:**
        *   Modify `ai_performance_framework_picerl.md` (or create a new, complementary `aso_sans_ir_mapping.md`) to explicitly map SANS IR stages (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned) to relevant `rules-bank` documents and AI agent capabilities for each stage.
        *   Incorporate the "Five Ws" (Who, What, When, Where, Why) as key questions for AI to address at each IR stage.
        *   *Rationale:* Provides a clear operational model for AI agents within a recognized IR framework, supporting the ASO vision.
    2.  **Define "Autonomous Workflow Snippets" within Atomic Runbooks:**
        *   Modify `atomic_runbook_template.md` and existing/future atomic runbooks to include a new section: `Autonomous_Execution_Criteria_and_Logic`.
        *   This section will detail conditions under which an AI agent can autonomously execute the runbook and potentially chain to the next, referencing `automated_response_playbook_criteria.md` for high-impact actions.
        *   *Rationale:* Embeds autonomous decision-making logic directly into runbooks, moving closer to ASO.
    3.  **Develop "Orchestration Runbooks" for Common Scenarios:**
        *   Create a new directory: `rules-bank/orchestration_runbooks/`.
        *   Develop a template: `orch_[SCENARIO_NAME]_template.md`.
        *   These higher-level runbooks will define orchestration logic for common alert scenarios (e.g., "SIEM Alert: Admin account created resource in unusual region"), detailing AI Triage, Enrichment, Identification, Containment, Remediation, and Lessons Learned phases by sequencing atomic runbooks.
        *   *Rationale:* Directly implements the ASO concept by defining how AI autonomously manages significant parts of the IR lifecycle.
    4.  **Integrate "Forensic Evidence Gathering" Capabilities into Runbooks:**
        *   Modify relevant atomic and orchestration runbooks to add steps or considerations for "Forensic Evidence Gathering" (e.g., snapshotting instances, collecting process lists/network connections, EDR telemetry dumps).
        *   *Rationale:* Ensures necessary data for deeper forensic analysis is considered and potentially collected early in an AI-driven process.
    5.  **Explicitly Document "Human-Generated Event" (HGE) to ASO Workflows:**
        *   Modify or link from `hge_triage_protocols.md` (if created, or a similar document) to show how HGEs feed into relevant `Orchestration_Runbooks`.
        *   *Rationale:* Bridges the gap between human-reported issues and the AI-driven SOC model.
    *   **Overall Rationale for Phase 7:** These tasks are designed to make the `rules-bank` the central nervous system for an AI-driven, autonomous SOC, aligning with the vision presented in "Beyond the Tiered SOC."

**Next Steps:**

This plan outlines the creation of the suggested files. We can tackle these phases and tasks sequentially or prioritize based on which information would provide the most immediate value.

Would you like to start working on creating one of these files, perhaps beginning with Phase 1? Or would you like to adjust this plan? Please let me know how you'd like to proceed and toggle to ACT MODE when you're ready for me to start creating the files.

**Key Foundational Articles & Inspiration:**

This project plan and its evolution have been inspired by the following key articles:

1.  **Blueprint for AI Agents in Cybersecurity: Leveraging AI Agents to Evolve Cybersecurity Practices**
    *   Author: Filip Stojkovski & Dylan Williams
    *   URL: https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity
    *   *Contribution:* Provided the initial framework for AI agent roles (Triage, Threat Hunting, Response) and core concepts like indicator classification and data normalization challenges.
2.  **Measuring ROI of AI agents in security operations: Introducing PICERL Index**
    *   Author: Filip Stojkovski
    *   URL: https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0
    *   *Contribution:* Introduced the PICERL (Preparation, Identification, Containment, Eradication, Recovery, Learning) index, guiding the creation of documents focused on AI performance measurement, feedback loops, and explainability.
3.  **Integrating Detection Engineering with Automation**
    *   Author: Filip Stojkovski
    *   URL: https://www.cybersec-automation.com/p/detection-engineering-automation-incident-response
    *   *Contribution:* Emphasized the tight coupling of Detection Engineering, IR SOPs, and Automation, and introduced a DE lifecycle (Concept, Research, Engineering, Delivery, Optimization) that informed the structure of `detection_strategy.md` and the concept of "Detection Use-Case Packages."
4.  **Beyond the Tiered SOC: Rethinking the SOC with Autonomous SecOps Orchestration**
    *   Author: Filip Stojkovski
    *   URL: https://www.cybersec-automation.com/p/beyond-the-tiered-soc
    *   *Contribution:* Advocates for an Autonomous SecOps Orchestration (ASO) model mapped to SANS IR stages, inspiring Phase 7 of this plan to further enhance `rules-bank` for AI autonomy and functional team operations.

**Additional Inspiration (from original plan):**

 1. Incident Response Recommendations and Considerations for Cybersecurity Risk Management
    * A CSF 2.0 Community Profile. NIST Special Publication 800.
    * URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
 1. Cybersecurity Incident & Vulnerability Response Playbooks
    * Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems
    * URL: https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
 1. The NIST Cybersecurity Framework (CSF) 2.0
    * URL: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
 1. Cybersecurity Log Management Planning Guide
    * NIST Special Publication NIST SP 800-92r1 (Initial Public Draft)
    * URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf
 1. SOCFortress Playbooks
     * This repository contains incident response playbooks and workflows organized according to NIST-800.61 r2 standards. Each playbook is broken down into 6 sections and includes PDF versions for auditors and customers. It's designed specifically for SOC analysts.
    * GitHub URL: https://github.com/socfortress/Playbooks
      * [Incident Response Plan for Malware](https://github.com/socfortress/Playbooks/blob/main/IRP-Malware/README.md)
      * [Incident Response Plan for Compromised Account](https://github.com/socfortress/Playbooks/blob/main/IRP-AccountCompromised/README.md)
      * [Incident Reponse Plan for Phishing](https://github.com/socfortress/Playbooks/blob/main/IRP-Phishing/README.md)
      * [Incident Reponse Plan for Ransomware](https://github.com/socfortress/Playbooks/blob/main/IRP-Ransom/README.md)
 1. Open Source SOC Documentation (OSSOCDOCS)
    * This comprehensive project provides a complete library of SOC documentation including SOPs, policies, processes, and best practices. It follows a structured pyramid approach with detailed runbooks that offer step-by-step instructions for specific security operations like investigating malicious URLs or responding to specific alerts.
    * GitHub URL: https://github.com/madirish/ossocdocs
 1. Microsoft Student SOC Toolkit
    * This toolkit provides resources to prepare students for SOC work, including structured learning modules, hands-on experience, and certification pathways. It contains implementation guidance, a comprehensive training course, and simulated security incidents to build practical knowledge in incident response and threat detection.
    * GitHub URL: https://github.com/microsoft/SOC
 1. Awesome SOC Collection
    * This is a collection of documentation sources and field best practices for building and running a SOC. It includes strategies for structuring SOCs, communication practices, performance metrics, and advanced SOC functionalities like threat hunting and red teaming.
    * GitHub URL: https://github.com/cyb3rxp/awesome-soc
 1. Security Operations Center Topic on GitHub
    * The GitHub "security-operations-center" topic page lists numerous projects related to SOC operations, including Python modules for SOC enhancement, security maturity tracking matrices, and automation tools that integrate platforms like Wazuh, Shuffle, and TheHive.
    * GitHub URL: https://github.com/topics/security-operations-center
 1. Incident Response Recommendations and Considerations for Cybersecurity Risk Management
    * A CSF 2.0 Community Profile. NIST Special Publication 800.
    * URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
 1. Cybersecurity Incident & Vulnerability Response Playbooks
    * Operational Procedures for Planning and Conducting Cybersecurity Incident and Vulnerability Response Activities in FCEB Information Systems
    * URL: https://www.cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf
 1. The NIST Cybersecurity Framework (CSF) 2.0
    * URL: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf
 1. Cybersecurity Log Management Planning Guide
    * NIST Special Publication NIST SP 800-92r1 (Initial Public Draft)
    * URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-92r1.ipd.pdf
 1. SOCFortress Playbooks
     * This repository contains incident response playbooks and workflows organized according to NIST-800.61 r2 standards. Each playbook is broken down into 6 sections and includes PDF versions for auditors and customers. It's designed specifically for SOC analysts.
    * GitHub URL: https://github.com/socfortress/Playbooks
      * [Incident Response Plan for Malware](https://github.com/socfortress/Playbooks/blob/main/IRP-Malware/README.md)
      * [Incident Response Plan for Compromised Account](https://github.com/socfortress/Playbooks/blob/main/IRP-AccountCompromised/README.md)
      * [Incident Reponse Plan for Phishing](https://github.com/socfortress/Playbooks/blob/main/IRP-Phishing/README.md)
      * [Incident Reponse Plan for Ransomware](https://github.com/socfortress/Playbooks/blob/main/IRP-Ransom/README.md)
 1. Open Source SOC Documentation (OSSOCDOCS)
    * This comprehensive project provides a complete library of SOC documentation including SOPs, policies, processes, and best practices. It follows a structured pyramid approach with detailed runbooks that offer step-by-step instructions for specific security operations like investigating malicious URLs or responding to specific alerts.
    * GitHub URL: https://github.com/madirish/ossocdocs
 1. Microsoft Student SOC Toolkit
    * This toolkit provides resources to prepare students for SOC work, including structured learning modules, hands-on experience, and certification pathways. It contains implementation guidance, a comprehensive training course, and simulated security incidents to build practical knowledge in incident response and threat detection.
    * GitHub URL: https://github.com/microsoft/SOC
 1. Awesome SOC Collection
    * This is a collection of documentation sources and field best practices for building and running a SOC. It includes strategies for structuring SOCs, communication practices, performance metrics, and advanced SOC functionalities like threat hunting and red teaming.
    * GitHub URL: https://github.com/cyb3rxp/awesome-soc
 1. Security Operations Center Topic on GitHub
    * The GitHub "security-operations-center" topic page lists numerous projects related to SOC operations, including Python modules for SOC enhancement, security maturity tracking matrices, and automation tools that integrate platforms like Wazuh, Shuffle, and TheHive.
    * GitHub URL: https://github.com/topics/security-operations-center
