---
name: prioritize-and-investigate-case
description: Use when scoring case urgency, prioritizing the queue, and running core investigations.
category: investigation
version: 1.0.0
---

# Prioritize and Investigate a Case

From a list of cases, identify cases of the highest severity and potential impact based on underlying alerts and detections. Get rule logic to validate the detections in the cases. After identifying the highest N priority cases -> Explain the entirety of the case to the analyst in the context of the underlying rule logic (explain the rule logic and how it applies to this case). Get entity context to determine if there are additional alerts, detections, or events that may not have been included in the case but are potentially applicable.

Use the tools:


 * List Cases and include the environment
 * Get Alerts in a Case
 * Get Detections in a Case
 * Get Events from Alerts and/or Detections in a Case
 * Get rule logic
 * Evaluate Alert/Event against rule logic
 * UDM search for activity from principal or target
 * **Common Steps:** {doc}`common_steps/find_relevant_soar_case </run_books/common_steps/find_relevant_soar_case>`

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_prioritization_payload_node["1. extract_prioritization_payload_node<br/><i>(Extract Case Payload)</i>"]
    extract_prioritization_payload_node --> compute_case_risk_score_node["2. compute_case_risk_score_node<br/><i>(Calculate Risk Score & Priority)</i>"]
    compute_case_risk_score_node --> case_risk_router{"3. case_risk_router<br/><i>(Event.actions.route)</i>"}

    case_risk_router -- "IMMEDIATE_ESCALATION" --> handle_immediate_escalation_branch["4a. handle_immediate_escalation_branch<br/><i>(Elevate Priority & Escalate)</i>"]
    case_risk_router -- "STANDARD_TRIAGE" --> handle_standard_triage_branch["4b. handle_standard_triage_branch<br/><i>(Standard Triage Pathway)</i>"]

    handle_immediate_escalation_branch --> document_prioritization_report_node["5. document_prioritization_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_standard_triage_branch --> document_prioritization_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant FindCase as common_steps/find_relevant_soar_case.md

    User->>AutomatedAgent: Prioritize and investigate cases
    AutomatedAgent->>SOAR: list_cases()
    SOAR-->>AutomatedAgent: List of cases (C1, C2... Priority P1, P2...)
    Note over AutomatedAgent: Analyze cases, identify high priority (e.g., Case X based on initial priority/alerts)
    AutomatedAgent->>SOAR: get_case_full_details(case_id=X)
    SOAR-->>AutomatedAgent: Full details for Case X (alerts, comments, etc.)
    Note over AutomatedAgent: Confirm priority based on full details. May use change_case_priority if needed.
    AutomatedAgent->>SOAR: list_alerts_by_case(case_id=X)
    SOAR-->>AutomatedAgent: Alerts for Case X (A1, A2...)
    Note over AutomatedAgent: Initialize ALL_CASE_ENTITIES = set()
    loop For each Alert Ai in Case X
        AutomatedAgent->>SOAR: list_events_by_alert(case_id=X, alert_id=Ai)
        SOAR-->>AutomatedAgent: Events for Alert Ai (containing rule_id, entities E1, E2...)
        Note over AutomatedAgent: Add E1, E2... to ALL_CASE_ENTITIES
        Note over AutomatedAgent: Extract rule_id from event/alert data
        AutomatedAgent->>SIEM: list_security_rules(rule_id=rule_id)
        SIEM-->>AutomatedAgent: Rule logic/definition for rule_id
        AutomatedAgent->>SIEM: list_rule_detections(rule_id=rule_id)
        SIEM-->>AutomatedAgent: Detections associated with rule_id
        Note over AutomatedAgent: Analyze events/detections against rule logic
        loop For each relevant Entity Ej in Events
            AutomatedAgent->>SIEM: lookup_entity(entity_value=Ej)
            SIEM-->>AutomatedAgent: Entity context for Ej
            AutomatedAgent->>SIEM: search_security_events(text="Events involving entity Ej", hours_back=...)
            SIEM-->>AutomatedAgent: Broader UDM events for Ej
        end
    end
    Note over AutomatedAgent: Check for related SOAR cases using all identified entities
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=list(ALL_CASE_ENTITIES), CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: RELATED_SOAR_CASES
    Note over AutomatedAgent: Synthesize findings, correlate rule logic with events/entities, include related cases
    AutomatedAgent->>SOAR: post_case_comment(case_id=X, comment="Investigation Summary: Case X involves rule [Rule Name] triggered by events [...]. Entities [...] investigated. Related Cases: ${RELATED_SOAR_CASES}. Findings: [...]")
    SOAR-->>AutomatedAgent: Comment confirmation
    AutomatedAgent->>AutomatedAgent: attempt_completion(result="Completed investigation for Case X. Summary posted as comment.")

```

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
