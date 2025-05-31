# AI Performance Framework: PICERL Index

This document introduces the PICERL Index (Preparation, Identification, Containment, Eradication, Recovery, and Learning) as a framework for measuring and improving the effectiveness of AI agents in Security Operations. It outlines how various documents within this `rules-bank` support each phase and lists key metrics for AI agent performance.

# References
 * [Measuring ROI of AI Agents in Security Operations](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)

## The PICERL Index Overview

The PICERL Index, inspired by established incident response frameworks like NIST, breaks down the security incident lifecycle into six key phases. The goal is to assess and enhance AI agent contributions across this entire lifecycle, moving beyond simple alert closure rates to a more holistic view of AI effectiveness and continuous improvement.

**P** - Preparation
**I** - Identification
**C** - Containment
**E** - Eradication
**R** - Recovery
**L** - Learning

## Phase Breakdown, `rules-bank` Support, and Key AI Metrics

---

### 1. Preparation (P)

-   **Objective:** Ensure the environment, tools, and AI agents are ready to effectively handle security operations. This phase is foundational.
-   **`rules-bank` Support:**
    -   `log_source_overview.md`: Defines critical log sources and their status.
    -   `asset_inventory_guidelines.md`: Provides context on assets.
    -   `network_map.md`: Outlines network structure.
    -   `cloud_architecture.md`: Describes cloud environment.
    -   `security_products_inventory.md`: Lists security tools.
    -   `data_normalization_map.md`: Ensures AI can understand data from various sources.
    -   `mcp_tool_best_practices.md`: Guides AI in using tools correctly.
    -   `tool_rate_limits.md`: Informs AI of operational constraints.
    -   `detection_strategy.md`: Outlines detection priorities and approaches.
    -   `governance_overview.md`: Provides high-level policy context.
-   **Key AI Metrics (Inspired by PICERL Article):**
    -   **Log Source Coverage (AI-Monitored):**
        -   *Metric:* Percentage of critical assets (from `asset_inventory_guidelines.md`) with active and healthy log reporting to SIEM (verified by AI).
        -   *AI Contribution:* AI agent can periodically check log source health (e.g., last log timestamp from critical sources listed in `log_source_overview.md`) and report gaps.
    -   **Time-to-Value (AI Integrations):**
        -   *Metric:* Speed of integrating new tools/data sources for AI agent consumption.
        -   *AI Contribution:* While not directly measured by the agent, the clarity of `data_normalization_map.md` and `mcp_tool_best_practices.md` can accelerate this.
    -   **Detection Engineering Metrics (AI-Assisted):**
        -   *Metric:* True Positive (TP) / False Positive (FP) rates for detections where AI plays a role (e.g., AI-suggested rules, AI-driven hunts leading to new detections).
        -   *AI Contribution:* AI uses `detection_improvement_process.md` to suggest new rules or refine existing ones.
    -   **MITRE ATT&CK Coverage (AI-Enhanced Visibility):**
        -   *Metric:* Percentage of relevant ATT&CK techniques with active detection or hunting coverage, potentially identified or validated by AI.
        -   *AI Contribution:* AI can correlate observed activity with ATT&CK TTPs (using `indicator_handling_protocols.md`) and identify gaps against `detection_strategy.md`.
    -   **SOP/Runbook Efficiency (AI Execution):**
        -   *Metric:* Percentage of runbook steps (from various `rules-bank` runbooks) successfully automated or assisted by AI.
        -   *AI Contribution:* AI executes structured runbooks, leveraging documents like `automated_response_playbook_criteria.md`.
    -   **Automation/Orchestration Usage (AI-Driven):**
        -   *Metric:* Number of tasks/workflows initiated and completed by AI agents. Automation failure/rollback rates.
        -   *AI Contribution:* AI directly drives automation based on `rules-bank` logic.

---

### 2. Identification (I)

-   **Objective:** Accurately and rapidly detect, analyze, and triage potential security incidents.
-   **`rules-bank` Support:**
    -   `indicator_handling_protocols.md`: Guides initial investigation of IOCs.
    -   `analytical_query_patterns.md`: Provides query templates for common investigations.
    -   `incident_severity_matrix.md`: Helps AI in assessing severity.
    -   `common_benign_alerts.md`: Helps AI filter noise.
    -   `whitelists.md`: Provides known-good entities.
    -   `internal_threat_profile.md`: Highlights priority threats.
-   **Key AI Metrics:**
    -   **MTTD/MTTA (AI-Assisted):** Mean Time to Detect / Mean Time to Acknowledge for alerts processed by AI.
    -   **Mean Time to Triage (MTTT) by AI:** Time from alert ingestion to AI's first-pass decision (e.g., close, escalate, investigate).
    -   **Auto-Closed Alert Ratio & Reversal Rate:** Percentage of alerts auto-closed by AI; percentage of those auto-closures later reopened by humans.
    -   **Escalation Rate & Accuracy:** Percentage of alerts escalated by AI; percentage of those escalations deemed appropriate by human analysts. (Supported by `ai_decision_review_guidelines.md`).
    -   **AI Decision Accuracy (TP/FP for Triage):** Accuracy of AI in classifying alerts as true positive, false positive, or needing further human review.
    -   **Feedback Loop Metrics:** Rate and quality of feedback provided by human analysts on AI decisions; rate of AI incorporating this feedback. (Supported by `ai_decision_review_guidelines.md` and `detection_improvement_process.md`).
    -   **Explainability Time/Score:** Time taken for a human analyst to understand an AI's decision; quality of AI's explanation. (Supported by `ai_explainability_standards.md`).

---

### 3. Containment (C)

-   **Objective:** Limit the scope and impact of an incident.
-   **`rules-bank` Support:**
    -   `automated_response_playbook_criteria.md`: Defines safe triggers and procedures for AI-driven containment actions.
    -   `escalation_paths.md`: Guides AI on when to involve humans for high-impact containment.
-   **Key AI Metrics:**
    -   **MTTI/MTTR (Mean Time to Isolate/Mean Time to Remediate - AI Initiated/Assisted):** Speed at which AI identifies and helps initiate/prepare containment actions.
    -   **Containment Accuracy (AI-Driven):** Precision of AI in identifying the correct entities/systems for containment and executing actions without impacting legitimate critical infrastructure. (Validated against `automated_response_playbook_criteria.md`).

---

### 4. Eradication (E)

-   **Objective:** Remove the threat from the environment.
-   **`rules-bank` Support:**
    -   `automated_response_playbook_criteria.md`: May include criteria for eradication steps (e.g., deleting malware, disabling compromised accounts).
    -   Specific runbooks for malware removal, account remediation, etc.
-   **Key AI Metrics:**
    -   **Eradication Accuracy (AI-Assisted):** Effectiveness of AI-recommended or AI-executed eradication steps.
    -   **Time to Eradication (for AI-handled components):** Speed of completing eradication tasks where AI is involved.

---

### 5. Recovery (R)

-   **Objective:** Restore systems and services to normal operation.
-   **`rules-bank` Support:**
    -   `disaster_recovery_plan_summary.md`: Provides context on RTOs/RPOs.
    -   `backup_strategy_overview.md`: Informs AI about backup availability for restoration.
    -   `automated_response_playbook_criteria.md`: Rollback procedures can be seen as part of recovery.
-   **Key AI Metrics:**
    -   **Mean Time to Recover (MTTR - AI-Assisted Documentation/Validation):** While AI might not perform physical recovery, it can assist in documenting recovery steps, validating system restoration against baselines, or monitoring for post-recovery issues.
    -   **AI Contribution to Recovery Documentation:** Completeness and accuracy of incident details logged by AI that aid in post-incident recovery and review.

---

### 6. Learning (L) - Continuous Improvement & Trust

-   **Objective:** Continuously improve processes, detections, AI models, and overall security posture based on lessons learned.
-   **`rules-bank` Support:**
    -   `detection_improvement_process.md`: Formalizes AI feedback into detection engineering.
    -   `ai_decision_review_guidelines.md`: Structures human feedback to AI.
    -   `ai_explainability_standards.md`: Drives improvements in AI transparency.
    -   `agent_operational_learnings.yaml` (Future): A structured log of AI successes/failures to learn from.
    -   All runbooks and contextual documents are subject to refinement based on learnings.
-   **Key AI Metrics:**
    -   **Model Drift Tracking:** Changes in AI performance metrics (e.g., decision accuracy, escalation accuracy) over time.
    -   **Escalation-to-Accuracy Ratio (Trend):** Is the AI learning to escalate more appropriately over time?
    -   **Explainability Score (Trend):** Are AI explanations becoming clearer and more useful?
    -   **Adversarial Robustness (Periodic Testing):** How well does the AI perform against simulated adversarial inputs or red team exercises designed to fool it? (This would require specific testing procedures not yet in `rules-bank`).
    -   **Rate of `rules-bank` Updates Triggered by AI Insights:** How often does AI-driven analysis or feedback lead to improvements in the `rules-bank` itself?

---

This framework, supported by the `rules-bank`, aims to create a virtuous cycle where AI agents not only perform tasks but also contribute to their own improvement and the enhancement of the overall security operations capability.

---

## References and Inspiration

-   The concepts and structure of the PICERL Index discussed in this document are heavily inspired by the article:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
-   The general approach to AI Agents in Cybersecurity is also informed by:
    -   Stojkovski, Filip & Williams, Dylan. "Blueprint for AI Agents in Cybersecurity." *Cyber Security Automation and Orchestration*, November 26, 2024. [https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity](https://www.cybersec-automation.com/p/blueprint-for-ai-agents-in-cybersecurity)
