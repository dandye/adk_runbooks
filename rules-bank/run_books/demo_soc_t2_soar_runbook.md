---
type: Runbook
title: "SOC Analyst Tier 2 Demo Runbook (SOAR Focus)"
description: "Use when executing Tier 2 SOC escalation runbooks in Google SecOps SOAR."
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
related:
  - ./index.md
  - ./basic_ioc_enrichment.md
  - ../indicator_handling_protocols.md
---

# SOC Analyst Tier 2 Demo Runbook (SOAR Focus)

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_demo_soc_t2_payload_node["1. extract_demo_soc_t2_payload_node<br/><i>(Extract Case Payload)</i>"]
    extract_demo_soc_t2_payload_node --> analyze_soc_t2_case_node["2. analyze_soc_t2_case_node<br/><i>(Analyze Severity & Tier 3 Escalation Needs)</i>"]
    analyze_soc_t2_case_node --> demo_soc_t2_router{"3. demo_soc_t2_router<br/><i>(Event.actions.route)</i>"}

    demo_soc_t2_router -- "ESCALATE_TIER_3" --> handle_escalate_tier_3_branch["4a. handle_escalate_tier_3_branch<br/><i>(Escalate Case to Tier 3 IR)</i>"]
    demo_soc_t2_router -- "RESOLVE_TIER_2" --> handle_resolve_tier_2_branch["4b. handle_resolve_tier_2_branch<br/><i>(Resolve Case at Tier 2)</i>"]

    handle_escalate_tier_3_branch --> document_demo_soc_t2_report_node["5. document_demo_soc_t2_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_resolve_tier_2_branch --> document_demo_soc_t2_report_node
```

As a SOC Analyst Tier 2, your work revolves around the SOAR platform.

-   Utilize the tools available from the `secops-soar` server to:
    -   Manage and investigate cases.
    -   List and analyze alerts within cases.
    -   Retrieve event details associated with alerts.
    -   Add comments and update case priority.
    -   Interact with entities known to the SOAR platform.
-   Execute response actions and playbooks as directed.
-   Document all actions and findings within the SOAR case.
-   If a task is outside your scope or capabilities, clearly state that and delegate back to the Manager.

## Rubrics

The following rubric is used to evaluate the execution of this **Triage/Response** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Context & Enrichment** | 25 | Correctly extracted entities and enriched them with relevant context (GTI, SIEM). |
| **Analysis & Decision** | 25 | Analyzed the enriched data to make a sound decision (FP/TP, Escalate/Close). |
| **Action Execution** | 20 | Performed the required response actions (e.g., isolation, containment) correctly. |
| **Documentation** | 15 | Clearly documented findings and actions in the case/ticket. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Context & Enrichment (25 Points)
- **10 pts**: Accurately extracted key entities (IPs, users, hashes) from the input.
- **15 pts**: Performed necessary enrichment (e.g., `enrich_ioc`) to gather reputation and history.

#### 2. Analysis & Decision (25 Points)
- **15 pts**: Interpreted the context correctly to determine the nature of the alert.
- **10 pts**: Reached a logical conclusion or next step (e.g., "Escalate to Tier 2" or "Isolate Host").

#### 3. Action Execution (20 Points)
- **10 pts**: Called the correct tools to perform response actions (if applicable) or investigative steps.
- **10 pts**: Verified the success of actions or handled errors appropriately.

#### 4. Documentation (15 Points)
- **15 pts**: Posted a comprehensive comment or update to the SOAR case summarizing the triage.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
