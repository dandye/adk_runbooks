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

The following rubric is used to evaluate the execution of this **Duplicate/Similar Case Closure** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Data Gathering & Similarity Setup** | 20 | Correctly listed relevant cases, retrieved associated alerts/alert groups, and invoked similarity tools with appropriate parameters. |
| **Similarity Analysis & Duplicate Identification** | 30 | Accurately interpreted similarity results to identify true duplicate/related cases and avoided incorrect merges. |
| **Case Consolidation & Closure Execution** | 20 | Properly consolidated information, selected the right cases to close, and executed closure actions with correct reasons and comments. |
| **Documentation** | 15 | Clearly documented the similarity rationale, decisions, and actions in the primary case/ticket. |
| **Operational Artifacts** | 15 | Produced required artifacts: sequence diagram, execution metadata (date/cost), and summary of consolidated cases. |

### Evaluation Criteria Details

#### 1. Data Gathering & Similarity Setup (20 Points)
- **10 pts**: Retrieved the correct set of candidate cases (e.g., via `list_cases`) and associated context (alerts and alert group identifiers) needed for similarity analysis.
- **10 pts**: Invoked similarity tooling (e.g., `siemplify_get_similar_cases`) with sensible criteria (such as days_back, alert_group_ids) based on the workflow and input.

#### 2. Similarity Analysis & Duplicate Identification (30 Points)
- **15 pts**: Interpreted similarity outputs correctly to determine which cases are likely duplicates or closely related (e.g., mapping Ck, Cl as duplicates of Cm).
- **15 pts**: Applied sound logic and thresholds when deciding which cases to propose/confirm for closure, minimizing both missed duplicates and false matches.

#### 3. Case Consolidation & Closure Execution (20 Points)
- **10 pts**: After user confirmation, closed only the intended duplicate/similar cases, preserving the correct primary/reference case and using appropriate closure reasons (e.g., "Duplicate"). |
- **10 pts**: Added or updated case comments (e.g., via `post_case_comment`) and performed any required closure actions (e.g., `siemplify_close_case`) reliably, handling tool errors where applicable.

#### 4. Documentation (15 Points)
- **15 pts**: Posted a comprehensive comment or update summarizing: which cases were analyzed, which were closed as duplicates, the justification for duplication, and any remaining follow-ups in the surviving case.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced or updated a Mermaid sequence diagram that accurately reflects the steps taken in this run (tools, loops, user confirmations).
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost (or analogous execution metrics) for the run.
- **5 pts**: **Summary Report**: Generated a concise summary of the similarity analysis, duplicate closures performed, and the final state of the surviving/primary case.
