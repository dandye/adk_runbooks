---
name: compare-gti-collection
description: Use when correlating GTI collection indicators against local telemetry and event logs.
category: investigation
version: 1.0.0
---

# Compare GTI Collection to IoCs, Events in SecOps

From a GTI Collection (could be a Private Collection as well), search the past 3 days for any UDM events containing:
 1) Indicators of Compromise
 2) IOC++ (Modeled behvaioral data) (Would need to interpret relevant UDM fields)
 3) Get Chronicle SIEM IoC Matches (`get_ioc_matches`)
 4) Produce report on findings
 5) Add report to SOAR Case

Analyze results and compare against GTI Collection context (report or campaign). (Optional) Notable indicators are added to SQLite Table. Provide analyst report with prescribed follow on response actions.

Uses tools:

 * `gti-mcp_get_collection_report`
 * `secops-mcp_get_ioc_matches`
 * `secops-mcp_search_security_events`
 * `secops-mcp_get_security_alerts`
 * `gti-mcp_*` (various lookups like `get_file_report`, `get_entities_related_to_a_collection`, `get_collection_mitre_tree`, etc.)
 * (Optional) Add to SQLite Table
 * `soar-mcp_post_case_comment`
 * `soar-mcp_list_cases` (Optional, for finding existing case)

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_collection_node["1. extract_collection_node<br/><i>(Extract GTI Collection Payload)</i>"]
    extract_collection_node --> fetch_gti_collection_iocs_node["2. fetch_gti_collection_iocs_node<br/><i>(Fetch GTI Collection IOCs & Actor Metadata)</i>"]
    fetch_gti_collection_iocs_node --> match_siem_events_node["3. match_siem_events_node<br/><i>(SIEM Event & IOC Match Search)</i>"]
    match_siem_events_node --> gti_overlap_router{"4. gti_overlap_router<br/><i>(Event.actions.route)</i>"}

    gti_overlap_router -- "CAMPAIGN_MATCHED" --> handle_campaign_matched_branch["5a. handle_campaign_matched_branch<br/><i>(Document Critical Campaign Match)</i>"]
    gti_overlap_router -- "NO_MATCH" --> handle_no_match_branch["5b. handle_no_match_branch<br/><i>(Document No Overlap)</i>"]

    handle_campaign_matched_branch --> document_gti_report_node["6. document_gti_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_no_match_branch --> document_gti_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar

    User->>AutomatedAgent: Sweep environment based on GTI Collection ID 'GTI-XYZ'
    AutomatedAgent->>GTI: get_collection_report(id='GTI-XYZ')
    GTI-->>AutomatedAgent: Collection details (Report/Campaign context)

    Note over AutomatedAgent: **Explicitly Extract IOCs**
    loop For each Relationship R in [files, domains, ip_addresses, urls]
        AutomatedAgent->>GTI: get_entities_related_to_a_collection(id='GTI-XYZ', relationship_name=R)
        GTI-->>AutomatedAgent: Associated IOCs for type R (IOC_LIST)
    end

    Note over AutomatedAgent: **Explicitly Identify TTPs**
    AutomatedAgent->>GTI: get_collection_mitre_tree(id='GTI-XYZ')
    GTI-->>AutomatedAgent: Associated MITRE TTPs
    Note over AutomatedAgent: Analyze TTPs and report content for behavioral patterns

    AutomatedAgent->>SIEM: get_ioc_matches(hours_back=72) %% Default 3 days
    SIEM-->>AutomatedAgent: List of recent IOC matches in environment

    Note over AutomatedAgent: **Search SIEM for IOCs**
    loop For each IOC Ii from IOC_LIST
        AutomatedAgent->>SIEM: search_security_events(text="Events containing IOC Ii", hours_back=72)
        SIEM-->>AutomatedAgent: UDM events related to IOC Ii
        AutomatedAgent->>SIEM: get_security_alerts(query="alert contains Ii", hours_back=72)
        SIEM-->>AutomatedAgent: Alerts related to IOC Ii
    end

    Note over AutomatedAgent: **Search SIEM for TTPs**
    Note over AutomatedAgent: Interpret identified TTPs into UDM search queries
    loop For each Behavioral Pattern Bp based on TTPs
        AutomatedAgent->>SIEM: search_security_events(text="Events matching pattern Bp", hours_back=72)
        SIEM-->>AutomatedAgent: UDM events potentially matching pattern Bp
    end

    Note over AutomatedAgent: Analyze results (IOC matches, events, alerts) against GTI context
    Note over AutomatedAgent: Identify notable indicators (N1, N2...) found in environment
    loop For each Notable Indicator Ni
        Note over AutomatedAgent: Add Ni to Chronicle Data Table (Conceptual Step - No direct tool)
        AutomatedAgent->>SIEM: (Conceptual) Add Ni to Data Table 'Notable_Indicators'
    end

    Note over AutomatedAgent: Synthesize report: Findings, GTI context correlation, Recommended Actions

    Note over AutomatedAgent: **Check for Existing SOAR Case**
    AutomatedAgent->>SOAR: list_cases(filter="Contains GTI-XYZ or key IOCs") %% Conceptual Filter
    SOAR-->>AutomatedAgent: Existing Case List (May be empty)

    alt Existing Case Found (CaseID_Found)
        AutomatedAgent->>SOAR: post_case_comment(case_id=CaseID_Found, comment="Sweep Report for GTI-XYZ: Found indicators [N1, N2...]. Events [...] observed. Recommended actions: [...]")
        SOAR-->>AutomatedAgent: Comment confirmation
        AutomatedAgent->>AutomatedAgent: attempt_completion(result="Environment sweep based on GTI Collection 'GTI-XYZ' complete. Report posted to existing case CaseID_Found.")
    else No Existing Case Found
        Note over AutomatedAgent: Generate report locally (as done previously)
        AutomatedAgent->>AutomatedAgent: write_report(report_name="gti_comparison_report_GTI-XYZ_${timestamp}.md", report_contents=ReportMarkdown)
        AutomatedAgent->>AutomatedAgent: attempt_completion(result="Environment sweep based on GTI Collection 'GTI-XYZ' complete. Report generated. Recommend manual case creation if needed.")
    end

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
