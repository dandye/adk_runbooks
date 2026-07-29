---
type: Runbook
title: Investigate a Case + external tools
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
---

# Investigate a Case + external tools

Using SecOps, GTI, and Okta. Start with a Case (anomalous login Alerts). Find the entities involved and look up any related indicators. Find any users involved and look up Okta information to determine any suspicious characteristics. If confident in disposition, disable that User. Finally, provide a report about any identified activity for security analyst consumption.

Uses tools:

 * List Cases
 * Get Alerts in a Case
 * Entity Lookup
 * GTI Lookup
 * Event Search
 * OKTA user information
 * OKTA action"
 * **Common Steps:** {doc}`common_steps/find_relevant_soar_case </run_books/common_steps/find_relevant_soar_case>`


```{mermaid}
sequenceDiagram
    participant User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant Okta as okta-mcp
    participant FindCase as common_steps/find_relevant_soar_case.md

    User->>AutomatedAgent: Investigate Case Y (Anomalous Login)
    AutomatedAgent->>SOAR: list_alerts_by_case(case_id=Y)
    SOAR-->>AutomatedAgent: Alerts for Case Y (Entities: User U, IP I, Host H...)
    Note over AutomatedAgent: Store identified entities (IDENTIFIED_ENTITIES = [U, I, H...])
    loop For each relevant Entity Ei in IDENTIFIED_ENTITIES
        AutomatedAgent->>SIEM: lookup_entity(entity_value=Ei)
        SIEM-->>AutomatedAgent: SIEM context for Ei
        AutomatedAgent->>GTI: get_file_report/get_domain_report/get_ip_address_report(entity=Ei)
        GTI-->>AutomatedAgent: GTI context for Ei
        AutomatedAgent->>SIEM: search_security_events(text="Events involving entity Ei", hours_back=...)
        SIEM-->>AutomatedAgent: Related UDM events for Ei
    end
    Note over AutomatedAgent: Check for related SOAR cases
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=IDENTIFIED_ENTITIES, CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: RELATED_SOAR_CASES
    Note over AutomatedAgent: Identify primary user entity (User U)
    AutomatedAgent->>Okta: lookup_okta_user(user=U)
    Okta-->>AutomatedAgent: Okta user details for User U
    Note over AutomatedAgent: Analyze Okta details for suspicious activity/characteristics
    AutomatedAgent->>User: Confirm: "Okta user U shows suspicious activity. Disable user? (Yes/No)"
    User->>AutomatedAgent: Response (e.g., "Yes")
    alt Disable User Confirmed
        AutomatedAgent->>Okta: disable_okta_user(user=U)
        Okta-->>AutomatedAgent: Disable confirmation
    end
    Note over AutomatedAgent: Synthesize all findings (incl. related cases) into a report summary
    AutomatedAgent->>SOAR: post_case_comment(case_id=Y, comment="Investigation Summary: Anomalous login for User U from IP I. GTI/SIEM checks performed. Related Cases: ${RELATED_SOAR_CASES}. Okta details reviewed. User disabled due to suspicious activity. Findings: [...]")
    SOAR-->>AutomatedAgent: Comment confirmation
    AutomatedAgent->>AutomatedAgent: attempt_completion(result="Completed investigation for Case Y. User U potentially disabled. Summary posted as comment.")

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
