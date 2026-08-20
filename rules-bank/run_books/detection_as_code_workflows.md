---
type: Runbook
title: "Runbook: Detection-as-Code Workflow (Placeholder)"
description: "Use when authoring, testing, and managing detection rules using Git-based CI/CD workflows."
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
related:
  - ./index.md
  - ./basic_ioc_enrichment.md
  - ../indicator_handling_protocols.md
---

# Runbook: Detection-as-Code Workflow (Placeholder)

## Objective

*(Define the goal, e.g., To outline the process for developing, testing, reviewing, and deploying new detection rules using a Detection-as-Code methodology, potentially involving version control and CI/CD pipelines.)*

## Scope

*(Define what is included/excluded, e.g., Covers rule creation in a specific format (YARA-L, Sigma), testing procedures, peer review process, and deployment mechanism. Excludes infrastructure setup for the pipeline.)*

## Inputs

*   `${RULE_IDEA}`: Description of the threat or behavior the new rule should detect.
*   `${RELEVANT_LOG_SOURCES}`: Log sources needed for the detection.
*   `${TEST_DATA_LOCATION}`: Location of data suitable for testing the rule.
*   *(Optional) `${VERSION_CONTROL_BRANCH}`: Branch for developing the rule.*

## Tools

*   `secops-mcp`: `search_security_events` (for testing), `validate_udm_query` (if available), `list_security_rules` (to check existing rules)
*   *(Potentially Version Control tools like Git if integrated via MCP)*
*   *(Potentially CI/CD pipeline tools if integrated via MCP)*
*   *(Potentially rule deployment tools if available via MCP, e.g., `create_detection_rule`)*
*   `secops-soar`: `post_case_comment` (for tracking/review)

## Workflow Steps & Diagram

1.  **Rule Development:** Draft the detection logic based on `${RULE_IDEA}` and `${RELEVANT_LOG_SOURCES}`.
2.  **Testing:** Test the rule logic against `${TEST_DATA_LOCATION}` using `search_security_events` or other methods. Validate syntax (e.g., `validate_udm_query`).
3.  **Version Control:** Commit the rule definition to the appropriate `${VERSION_CONTROL_BRANCH}`.
4.  **Peer Review:** Initiate a code review process for the new rule.
5.  **Deployment:** Merge the rule to the main branch and trigger the deployment pipeline (or manually deploy using appropriate tools like `create_detection_rule`).
6.  **Monitoring:** Monitor the rule's performance post-deployment.

```{mermaid}
sequenceDiagram
    participant Developer/Engineer
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SIEM as secops-mcp
    participant VersionControl as Git (Conceptual)
    participant CI_CD as CI/CD Pipeline (Conceptual)
    participant SOAR as secops-soar (Optional)

    Developer/Engineer->>AutomatedAgent: Start Detection-as-Code Workflow\nInput: RULE_IDEA, LOG_SOURCES, TEST_DATA...

    %% Step 1: Rule Development
    Note over AutomatedAgent: Draft detection logic (e.g., YARA-L)

    %% Step 2: Testing
    AutomatedAgent->>SIEM: search_security_events(text="Test Query for Rule", ...)
    SIEM-->>AutomatedAgent: Test Results
    opt Validate Query Tool Available
        AutomatedAgent->>SIEM: validate_udm_query(query=...)
        SIEM-->>AutomatedAgent: Validation Result
    end
    Note over AutomatedAgent: Refine rule based on testing

    %% Step 3: Version Control
    AutomatedAgent->>VersionControl: (Conceptual) Commit rule definition to branch

    %% Step 4: Peer Review
    Note over AutomatedAgent: Initiate Peer Review Process (Manual/External)

    %% Step 5: Deployment
    AutomatedAgent->>VersionControl: (Conceptual) Merge rule to main branch
    VersionControl->>CI_CD: (Conceptual) Trigger Deployment Pipeline
    CI_CD->>SIEM: (Conceptual) Deploy rule (e.g., via create_detection_rule)
    SIEM-->>CI_CD: Deployment Status
    CI_CD-->>AutomatedAgent: Deployment Result

    %% Step 6: Monitoring
    Note over AutomatedAgent: Monitor rule performance (Manual/Alerting)
    opt Document Deployment
        AutomatedAgent->>SOAR: post_case_comment(case_id=..., comment="Rule [Rule Name] deployed via DaC workflow.")
        SOAR-->>AutomatedAgent: Comment Confirmation
    end

    AutomatedAgent->>Developer/Engineer: attempt_completion(result="Detection-as-Code workflow initiated/completed for rule idea. Deployment status: [...]")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Rule successfully deployed to production environment, monitoring initiated.)*

## Rubrics

The following rubric is used to evaluate the execution of this **Detection Engineering** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Requirement Analysis** | 20 | Correctly understood the detection requirement or validation goal. |
| **Technical Implementation** | 30 | Correctly implemented/validated the rule logic or workflow. |
| **Validation & Testing** | 20 | Performed adequate testing to ensure effectiveness and minimize FPs. |
| **Git/Process Compliance** | 15 | Followed proper Git workflows and version control practices. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Requirement Analysis (20 Points)
- **20 pts**: Accurately identified the scope of the detection change or validation task.

#### 2. Technical Implementation (30 Points)
- **15 pts**: Generated or modified the code/YAML with correct syntax.
- **15 pts**: Logic accurately addresses the requirement.

#### 3. Validation & Testing (20 Points)
- **20 pts**: Executed validation tools or test cases to verify the change.

#### 4. Git/Process Compliance (15 Points)
- **15 pts**: Created branches, commits, and PRs according to standards.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
