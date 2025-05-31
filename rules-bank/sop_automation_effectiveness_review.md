# SOP & Automation Effectiveness Review Process

This document outlines the process for periodically reviewing the effectiveness of Standard Operating Procedures (SOPs)/runbooks and their associated automation. The goal is to ensure they remain efficient, relevant, and aligned with the organization's security posture and the capabilities of both human analysts and AI agents. This supports the "Optimization & Metrics" aspect of the Detection Engineering lifecycle and the "Learning" phase of the PICERL framework.

## Purpose

-   To establish a formal process for the continuous improvement of IR SOPs and automation workflows.
-   To ensure SOPs and automation are effective in real-world scenarios and not just "ancient and dusty playbooks."
-   To identify bottlenecks, inefficiencies, or areas where automation is failing or could be improved.
-   To leverage metrics and feedback (from humans and AI) to drive these improvements.

## Scope of Review

This review process applies to:
-   All documented IR SOPs / runbooks within the `rules-bank` (or linked from it).
-   All automation workflows and scripts associated with these SOPs, particularly those involving AI agents or SOAR playbooks.
-   The criteria defined in `automated_response_playbook_criteria.md`.

## Review Frequency

-   **Full Review:** Conducted quarterly for all major SOPs and automation playbooks.
-   **Targeted Review:** Triggered ad-hoc based on:
    -   Significant incidents where a specific SOP/automation was heavily used or found lacking.
    -   Consistently poor metrics for a particular SOP/automation (e.g., high failure rate, frequent human overrides of AI actions).
    -   Introduction of new tools or major changes to existing tool capabilities that impact SOPs.
    -   Updates to `internal_threat_profile.md` that may render certain SOPs less relevant or require new ones.

## Review Process & Participants

1.  **Data Gathering & Preparation (Lead: SOC Lead / AI Operations Lead, Support: AI Agents, Analysts):**
    -   Collect relevant metrics from `ai_performance_framework_picerl.md` and `ai_performance_logging_requirements.md` for the review period, focusing on:
        -   SOP Efficiency (e.g., average time to complete SOP, manual vs. automated steps).
        -   Automation Usage (e.g., number of times automation playbook X was run, success/failure/rollback rates).
        -   MTTT/MTTI/MTTR for processes involving the SOP/automation.
        -   AI Decision Accuracy & Reversal Rates for AI steps within the SOP.
        -   Analyst feedback from `ai_decision_review_guidelines.md` related to the SOP/automation.
    -   AI agents can be tasked to generate summary reports of these metrics.
2.  **Review Meeting (Participants: SOC Lead, AI Ops Lead, Senior Analysts, Detection Engineering Rep, Automation/SOAR Dev Rep):**
    -   Discuss the collected metrics and analyst feedback.
    -   Walk through selected SOPs/automation playbooks, step-by-step.
    -   Identify:
        -   **Bottlenecks:** Steps that consistently take too long or cause delays.
        -   **Inefficiencies:** Redundant steps, outdated tool usage, overly complex procedures.
        -   **Automation Failures/Gaps:** Steps where automation frequently fails, requires manual intervention, or where new automation could provide significant benefit.
        -   **SOP Clarity Issues:** Ambiguous instructions, outdated information.
        -   **Alignment with Current Threats:** Is the SOP still relevant for current TTPs in `internal_threat_profile.md`?
        -   **AI Agent Performance:** How effectively are AI agents executing their assigned steps within the SOP? Are their decision points logical and effective?
3.  **Identify Improvement Actions:**
    -   Propose specific updates to SOP documents.
    -   Suggest modifications or new development for automation scripts/SOAR playbooks.
    -   Recommend changes to `automated_response_playbook_criteria.md` if current criteria are problematic.
    -   Identify needs for new `rules-bank` content (e.g., a new `analytical_query_pattern.md` if a common investigation step is missing).
    -   Assign action items and owners.
4.  **Implement Changes:**
    -   Update SOP documents in the `rules-bank`.
    -   Develop/modify automation scripts and playbooks.
    -   Update relevant `rules-bank` criteria or contextual documents.
5.  **Communicate Changes:**
    -   Inform the SOC team and other relevant stakeholders of significant changes to SOPs or automation.
    -   Ensure AI agent configurations/knowledge bases are updated if they directly consume the modified SOPs.
6.  **Monitor Impact:**
    -   Track relevant metrics after changes are implemented to assess the impact of improvements.

## AI Agent Role in the Review Process

-   **Data Provision:** AI agents can automatically gather and report on many of the performance metrics required for the review (as defined in `ai_performance_logging_requirements.md`).
-   **Pattern Identification (Future):** Advanced AI could potentially identify patterns indicative of SOP/automation issues (e.g., "Step X in Playbook Y has a 70% failure rate when dealing with Alert Type Z").
-   **Feedback Source:** The AI's own operational logs and decision overrides (captured via `ai_decision_review_guidelines.md`) serve as crucial input to the review.

## Documentation

-   Findings, action items, and outcomes of each review meeting should be documented (e.g., in a dedicated meeting minutes repository or a tracking system).
-   Updates to SOPs and other `rules-bank` documents must follow version control practices.

---

## References and Inspiration

-   The concept of an "Optimization & Metrics" feedback loop is central to the Detection Engineering lifecycle described in:
    -   Stojkovski, Filip. "Integrating Detection Engineering with Automation." *Cyber Security Automation and Orchestration*, May 29, 2024. [https://www.cybersec-automation.com/p/detection-engineering-automation-incident-response](https://www.cybersec-automation.com/p/detection-engineering-automation-incident-response)
-   The focus on continuous improvement and learning aligns with the "Learning" phase of the PICERL framework:
    -   Stojkovski, Filip. "Measuring ROI of AI agents in security operations." *Cyber Security Automation and Orchestration*, May 29, 2025. [https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0](https://www.cybersec-automation.com/p/measuring-roi-of-ai-agents-in-security-operations-9a67fdab64192ed0)
