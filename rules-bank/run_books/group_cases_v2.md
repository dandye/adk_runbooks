# Runbook: Group Cases v2 (Placeholder)

## Objective

*(Define the goal, e.g., To analyze a set of recent SOAR cases, identify logical groupings based on shared entities or alert types, prioritize the groups, and generate a summary report.)*

## Scope

*(Define what is included/excluded, e.g., Focuses on analyzing existing case data and alerts. May involve basic enrichment but not deep investigation of each case.)*

## Inputs

*   *(Optional) `${NUMBER_OF_CASES}`: Number of recent cases to analyze (e.g., 5, 10).*
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback period for cases.*
*   *(Optional) `${GROUPING_CRITERIA}`: Specific criteria for grouping (e.g., shared hostname, alert type, CVE).*

## Tools

*   `secops-soar`: `list_cases`, `get_case_full_details`, `list_alerts_by_case`, `get_entities_by_alert_group_identifiers`
*   `secops-mcp`: `lookup_entity`
*   `gti-mcp`: (Relevant enrichment tools)
*   `write_report`

## Workflow Steps & Diagram

1.  **List Cases:** Retrieve recent cases using `list_cases`.
2.  **Gather Case Details:** For each case, get details using `get_case_full_details` and `list_alerts_by_case`. Extract key entities.
3.  **Group Cases:** Analyze entities and alert details across cases to identify logical groups based on `${GROUPING_CRITERIA}` or observed similarities.
4.  **Prioritize Groups:** Assess the priority of each group based on alert severity, entity criticality, or potential impact.
5.  **Enrich Key Entities (Optional):** Perform basic enrichment on key shared entities within high-priority groups using `lookup_entity` and GTI tools.
6.  **Generate Summary Report:** Create a report summarizing the case groups, prioritization rationale, and key findings using `write_report`.

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp

    Analyst/User->>AutomatedAgent: Start Group Cases v2 Workflow\nInput: NUMBER_OF_CASES, ...

    %% Step 1: List Cases
    AutomatedAgent->>SOAR: list_cases(limit=NUMBER_OF_CASES)
    SOAR-->>AutomatedAgent: List of Cases (C1, C2...)

    %% Step 2: Gather Details
    loop For each Case Ci
        AutomatedAgent->>SOAR: get_case_full_details(case_id=Ci)
        SOAR-->>AutomatedAgent: Details for Ci
        AutomatedAgent->>SOAR: list_alerts_by_case(case_id=Ci)
        SOAR-->>AutomatedAgent: Alerts for Ci
        Note over AutomatedAgent: Extract Key Entities for Ci
    end

    %% Step 3 & 4: Group & Prioritize
    Note over AutomatedAgent: Analyze entities/alerts across cases, form groups (G1, G2...), prioritize groups

    %% Step 5: Enrich (Optional)
    opt Enrich High Priority Groups
        loop For each High Priority Group Gp
            Note over AutomatedAgent: Identify key shared entities (Ep1, Ep2...)
            loop For each Entity Epi
                AutomatedAgent->>SIEM: lookup_entity(entity_value=Epi)
                SIEM-->>AutomatedAgent: SIEM Summary
                AutomatedAgent->>GTI: get_..._report(ioc=Epi)
                GTI-->>AutomatedAgent: GTI Enrichment
            end
        end
    end

    %% Step 6: Generate Report
    Note over AutomatedAgent: Synthesize findings into report content
    AutomatedAgent->>AutomatedAgent: write_report(report_name="case_grouping_report_${timestamp}.md", report_contents=ReportMarkdown)
    Note over AutomatedAgent: Report file created

    AutomatedAgent->>Analyst/User: attempt_completion(result="Case grouping analysis complete. Report generated.")

```

## Completion Criteria

*(Define how successful completion is determined, e.g., Cases analyzed, groups identified and prioritized, summary report generated.)*
