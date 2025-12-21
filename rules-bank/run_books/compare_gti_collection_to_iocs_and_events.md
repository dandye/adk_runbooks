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

The following rubric is used to evaluate the execution of this **investigative/analytical** runbook (GTI Collection comparison and SIEM analysis) by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **GTI Collection Analysis** | 25 | Successfully retrieved and analyzed GTI Collection context, IOCs, and TTPs. |
| **SIEM Search & IOC Matching** | 30 | Effectively searched SIEM for IOCs and behavioral indicators, retrieved IOC matches from Chronicle. |
| **Comparison & Correlation** | 20 | Accurately compared GTI collection data against environment findings and identified relevant matches. |
| **Analysis & Impact Assessment** | 15 | Analyzed findings in context of the GTI collection threat context and assessed potential impact. |
| **Report Quality & Documentation** | 10 | Produced a comprehensive report with findings and recommended follow-on actions, posted to SOAR case. |

### Evaluation Criteria Details

#### 1. GTI Collection Analysis (25 Points)
- **10 pts**: Successfully retrieved GTI Collection report and extracted relevant threat context (campaign, actor, report details).
- **15 pts**: Extracted IOCs (files, domains, IPs, URLs) and TTPs (MITRE techniques) from the collection.

#### 2. SIEM Search & IOC Matching (30 Points)
- **15 pts**: Executed effective SIEM searches for IOCs over the specified timeframe (3 days) using appropriate UDM queries.
- **15 pts**: Retrieved Chronicle IOC matches and searched for behavioral patterns (IOC++) based on TTPs from the collection.

#### 3. Comparison & Correlation (20 Points)
- **10 pts**: Systematically compared GTI Collection IOCs against SIEM findings and IOC matches.
- **10 pts**: Identified and documented relevant matches, correlating them with the GTI collection context.

#### 4. Analysis & Impact Assessment (15 Points)
- **10 pts**: Analyzed findings in the context of the GTI threat intelligence (campaign objectives, actor TTPs, attack patterns).
- **5 pts**: Assessed the potential impact or severity of identified matches in the environment.

#### 5. Report Quality & Documentation (10 Points)
- **5 pts**: Generated a comprehensive analysis report covering GTI collection context, search methodology, findings, and correlations.
- **5 pts**: Posted the report to a SOAR case (existing or recommended for creation) and provided clear follow-on action recommendations.
