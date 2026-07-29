---
type: Runbook
title: Close duplicate/similar Cases Workflow
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
---

# Close duplicate/similar Cases Workflow

```{mermaid}
  sequenceDiagram
      participant User
      participant AutomatedAgent as Automated Agent (MCP Client)
      participant list_cases as list_cases (secops-soar)
      participant list_alerts_by_case as list_alerts_by_case (secops-soar)
      participant list_alert_group_identifiers_by_case as list_alert_group_identifiers_by_case (secops-soar)
      participant siemplify_get_similar_cases as siemplify_get_similar_cases (secops-soar)
      participant post_case_comment as post_case_comment (secops-soar)
      participant siemplify_close_case as siemplify_close_case (secops-soar)
      participant attempt_completion as attempt_completion (AutomatedAgent)

      User->>AutomatedAgent: Request case analysis and closure
      AutomatedAgent->>list_cases: list_cases()
      list_cases-->>AutomatedAgent: List of recent cases (IDs: C1, C2, ... CN)
      loop For each Case Ci
          AutomatedAgent->>list_alerts_by_case: list_alerts_by_case(case_id=Ci)
          list_alerts_by_case-->>AutomatedAgent: Alerts for Ci
          AutomatedAgent->>list_alert_group_identifiers_by_case: list_alert_group_identifiers_by_case(case_id=Ci)
          list_alert_group_identifiers_by_case-->>AutomatedAgent: Alert Group IDs for Ci
      end
      loop For each Case Cj
          AutomatedAgent->>siemplify_get_similar_cases: siemplify_get_similar_cases(case_id=Cj, criteria=RuleGenerator, days_back=7, alert_group_ids=...)
          siemplify_get_similar_cases-->>AutomatedAgent: List of similar case IDs for Cj
      end
      AutomatedAgent->>User: Present potential duplicate cases (e.g., Ck, Cl are duplicates of Cm)
      AutomatedAgent->>User: Confirm: "Confirm cases to close & provide reason/root_cause (Yes/No)"
      User->>AutomatedAgent: Confirmation (e.g., Close Ck, Cl. Reason: Duplicate)
      loop For each confirmed Case C_dup (Ck, Cl)
          AutomatedAgent->>post_case_comment: post_case_comment(case_id=C_dup, comment="Closing as duplicate of Cm")
          post_case_comment-->>AutomatedAgent: Comment confirmation
          AutomatedAgent->>siemplify_close_case: siemplify_close_case(case_id=C_dup, reason="Duplicate", root_cause="Consolidated Investigation")
          siemplify_close_case-->>AutomatedAgent: Closure confirmation
      end
      AutomatedAgent->>attempt_completion: attempt_completion(Summary of closed cases)
      Note right of AutomatedAgent: Slack notification not possible due to tool limitations.
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
