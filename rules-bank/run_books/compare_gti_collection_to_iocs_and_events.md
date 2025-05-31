# Compare GTI Collection to IoCs, Events in SecOps

From a GTI Collection (could be a Private Collection as well), search the past 3 days for any UDM events containing:
 1) Indicators of Compromise
 2) IOC++ (Modeled behvaioral data) (Would need to interpret relevant UDM fields)
 3) Get Chronicle SIEM IoC Matches (`get_ioc_matches`)
 4) Produce report on findings
 5) Add report to SOAR Case

Analyze results and compare against GTI Collection context (report or campaign). (Optional) Notable indicators are added to SQLite Table. Provide analyst report with prescribed follow on response actions.

Uses tools:

 * `gti-mcp.get_collection_report`
 * `secops-mcp.get_ioc_matches`
 * `secops-mcp.search_security_events`
 * `secops-mcp.get_security_alerts`
 * `gti-mcp.*` (various lookups like `get_file_report`, `get_entities_related_to_a_collection`, `get_collection_mitre_tree`, etc.)
 * (Optional) Add to SQLite Table
 * `secops-soar.post_case_comment`
 * `secops-soar.list_cases` (Optional, for finding existing case)

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
