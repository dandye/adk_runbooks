# Runbook: Group Cases v2

## Objective

To analyze a defined set of recent SOAR cases, identify logical groupings based on shared entities or alert types, prioritize these groups by potential impact or severity, and generate a summary report of the findings. This helps in understanding related security events and focusing investigative efforts.

## Scope

This runbook covers:
*   Retrieving a list of recent SOAR cases.
*   Gathering detailed information (including alerts and key entities) for each case.
*   Analyzing case data to identify logical groupings based on specified or observed criteria.
*   Prioritizing the identified case groups.
*   Optionally performing basic enrichment of key shared entities within high-priority groups.
*   Generating a Markdown report summarizing the case groups, prioritization rationale, and key findings.

This runbook explicitly **excludes**:
*   Deep investigation of individual cases within the groups (this would typically follow for high-priority groups).
*   Containment or eradication actions.
*   Automated closure of grouped cases (though findings might inform manual closure decisions).

## Inputs

*   *(Optional) `${NUMBER_OF_CASES}`: Number of recent cases to analyze (e.g., 5, 10). Defaults to a predefined number (e.g., 10) if not specified.*
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback period in hours for selecting cases. If not provided, `NUMBER_OF_CASES` will be the primary filter.*
*   *(Optional) `${GROUPING_CRITERIA}`: Specific criteria for grouping cases (e.g., "shared_hostname", "alert_type", "CVE", "malware_family"). If not provided, grouping will be based on observed similarities in entities and alert details.*
*   *(Derived) `${CASE_LIST}`: List of SOAR case IDs selected for analysis.*
*   *(Derived) `${CASE_DETAILS_MAP}`: A map or structure holding details (alerts, entities) for each case in `${CASE_LIST}`.*
*   *(Derived) `${CASE_GROUPS}`: Identified groups of related case IDs.*
*   *(Derived) `${PRIORITIZED_GROUPS}`: The `${CASE_GROUPS}` ordered by assessed priority.*
*   *(Derived) `${ENRICHMENT_DATA_SUMMARY}`: (Optional) Summary of enrichment for key entities in high-priority groups.*

## Outputs

*   `${REPORT_FILE_PATH}`: The full path to the generated Markdown summary report.
*   `${REPORT_CONTENT}`: The full Markdown content of the generated report.
*   `${GROUPING_ANALYSIS_SUMMARY}`: A brief textual summary of how cases were grouped and prioritized.

## Tools

*   `secops-soar`: `list_cases`, `get_case_full_details`, `list_alerts_by_case`, `get_entities_by_alert_group_identifiers`
*   `secops-mcp`: `lookup_entity`
*   `gti-mcp`: Relevant enrichment tools (e.g., `get_ip_address_report`, `get_domain_report`)
*   `write_to_file` (Replaces `write_report`)

## Workflow Steps & Diagram

1.  **List Cases:** Retrieve recent cases using `secops-soar.list_cases`, filtered by `${NUMBER_OF_CASES}` or `${TIME_FRAME_HOURS}`. Store in `${CASE_LIST}`.
2.  **Gather Case Details:** For each case ID in `${CASE_LIST}`:
    *   Use `secops-soar.get_case_full_details` to get overall case information.
    *   Use `secops-soar.list_alerts_by_case` to get associated alerts.
    *   Use `secops-soar.get_entities_by_alert_group_identifiers` (if applicable, or parse entities from alerts/events) to extract key entities.
    *   Store all details in `${CASE_DETAILS_MAP}`.
3.  **Group Cases:** Analyze entities and alert details across all cases in `${CASE_DETAILS_MAP}`. Identify logical groups (`${CASE_GROUPS}`) based on `${GROUPING_CRITERIA}` (if provided) or observed similarities (e.g., shared critical entities, common alert types, overlapping timeframes).
4.  **Prioritize Groups:** Assess the priority of each group in `${CASE_GROUPS}` based on factors like combined alert severity, number of cases in the group, criticality of shared entities, or potential impact. Store as `${PRIORITIZED_GROUPS}`.
5.  **Enrich Key Entities (Optional):** For high-priority groups in `${PRIORITIZED_GROUPS}`, identify key shared entities. Perform basic enrichment on these entities using `secops-mcp.lookup_entity` and relevant `gti-mcp` tools. Store in `${ENRICHMENT_DATA_SUMMARY}`.
6.  **Generate Summary Report:** Create a Markdown report (`${REPORT_CONTENT}`) summarizing the `${PRIORITIZED_GROUPS}`, the rationale for grouping and prioritization, and key findings (including `${ENRICHMENT_DATA_SUMMARY}` if available). Use `write_to_file` to save the report to `${REPORT_FILE_PATH}` (e.g., `./reports/case_grouping_report_${timestamp}.md`).

```{mermaid}
sequenceDiagram
    participant Analyst/User
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SOAR as secops-soar
    participant SIEM as secops-mcp
    participant GTI as gti-mcp

    Analyst/User->>AutomatedAgent: Start Group Cases v2 Workflow\nInput: NUMBER_OF_CASES (opt), TIME_FRAME_HOURS (opt), GROUPING_CRITERIA (opt)

    %% Step 1: List Cases
    AutomatedAgent->>SOAR: list_cases(limit=NUMBER_OF_CASES, time_frame_hours=TIME_FRAME_HOURS)
    SOAR-->>AutomatedAgent: List of Cases (CASE_LIST: C1, C2...)

    %% Step 2: Gather Details
    Note over AutomatedAgent: Initialize CASE_DETAILS_MAP
    loop For each Case Ci in CASE_LIST
        AutomatedAgent->>SOAR: get_case_full_details(case_id=Ci)
        SOAR-->>AutomatedAgent: Details for Ci
        AutomatedAgent->>SOAR: list_alerts_by_case(case_id=Ci)
        SOAR-->>AutomatedAgent: Alerts for Ci
        AutomatedAgent->>SOAR: get_entities_by_alert_group_identifiers(case_id=Ci, ...)
        SOAR-->>AutomatedAgent: Entities for Ci
        Note over AutomatedAgent: Store all details in CASE_DETAILS_MAP[Ci]
    end

    %% Step 3 & 4: Group & Prioritize
    Note over AutomatedAgent: Analyze CASE_DETAILS_MAP based on GROUPING_CRITERIA or similarities.
    Note over AutomatedAgent: Form CASE_GROUPS (G1, G2...).
    Note over AutomatedAgent: Prioritize groups into PRIORITIZED_GROUPS.

    %% Step 5: Enrich (Optional)
    opt Enrich High Priority Groups
        Note over AutomatedAgent: Initialize ENRICHMENT_DATA_SUMMARY
        loop For each High Priority Group Gp in PRIORITIZED_GROUPS
            Note over AutomatedAgent: Identify key shared entities (Ep1, Ep2...)
            loop For each Entity Epi in Gp
                AutomatedAgent->>SIEM: lookup_entity(entity_value=Epi)
                SIEM-->>AutomatedAgent: SIEM Summary for Epi
                AutomatedAgent->>GTI: get_..._report(ioc=Epi) %% Appropriate GTI tool
                GTI-->>AutomatedAgent: GTI Enrichment for Epi
                Note over AutomatedAgent: Store in ENRICHMENT_DATA_SUMMARY
            end
        end
    end

    %% Step 6: Generate Report
    Note over AutomatedAgent: Synthesize findings into REPORT_CONTENT (Markdown)
    AutomatedAgent->>AutomatedAgent: write_to_file(path="./reports/case_grouping_report_${timestamp}.md", content=REPORT_CONTENT)
    Note over AutomatedAgent: Report file created (REPORT_FILE_PATH)
    Note over AutomatedAgent: Prepare GROUPING_ANALYSIS_SUMMARY

    AutomatedAgent->>Analyst/User: attempt_completion(result="Case grouping analysis complete. Report: REPORT_FILE_PATH. Summary: GROUPING_ANALYSIS_SUMMARY.")

```

## Completion Criteria

*   A list of recent SOAR cases (`${CASE_LIST}`) has been retrieved based on the specified criteria.
*   Detailed information, including alerts and key entities, has been gathered for each case in the list and stored (`${CASE_DETAILS_MAP}`).
*   Cases have been analyzed and grouped into logical clusters (`${CASE_GROUPS}`) based on defined or observed criteria.
*   The identified case groups have been prioritized (`${PRIORITIZED_GROUPS}`).
*   (Optional) Key shared entities within high-priority groups have undergone basic enrichment, and a summary (`${ENRICHMENT_DATA_SUMMARY}`) is available.
*   A comprehensive Markdown summary report (`${REPORT_CONTENT}`), detailing the groups, prioritization, and key findings, has been generated and saved to `${REPORT_FILE_PATH}`.
*   A `${GROUPING_ANALYSIS_SUMMARY}` is available.
