# SOC Analyst Tier 2 Demo Runbook (SOAR Focus)

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
