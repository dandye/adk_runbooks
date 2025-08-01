# Basic IOC Enrichment Runbook

## Objective

Standardize the initial enrichment process for a single Indicator of Compromise (IOC) identified in an alert or case, suitable for Tier 1 SOC Analysts.

## Scope

This runbook covers fundamental enrichment steps using readily available GTI and SIEM lookup tools, plus limited SIEM event searching. It aims to provide quick, actionable context to aid in the decision to close or escalate.

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...", "http://bad.url/path").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash", "URL").
*   *(Optional) `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers if needed for context in SOAR actions.*
*   *(Optional) `${CASE_ID}`: Relevant case ID if documentation is desired.*
*   *(Optional) `${SIEM_SEARCH_HOURS}`: Lookback period for SIEM event search (default: 24).*

## Outputs

*   `${GTI_FINDINGS}`: Summary of key findings from the relevant GTI report.
*   `${GTI_RELATIONSHIPS}`: Summary of key related entities found via GTI pivoting.
*   `${SIEM_ENTITY_SUMMARY}`: Summary from the SIEM entity lookup.
*   `${SIEM_IOC_MATCH_STATUS}`: Boolean or indicator (Yes/No) if the IOC was found in recent SIEM IOC matches.
*   `${SIEM_RECENT_EVENTS}`: Summary of recent SIEM events involving the IOC.
*   `${FOUND_CASES}`: List of potentially related open SOAR cases.
*   `${ASSESSMENT}`: Analyst's initial risk assessment (e.g., Low/Medium/High/Informational).
*   `${RECOMMENDATION}`: Suggested next steps (e.g., Escalate, Monitor, Close FP, Trigger Containment).
*   `${DOCUMENTATION_STATUS}`: Status of documentation attempt in SOAR.
*   `${REPORT_GENERATION_STATUS}`: Status of optional report generation.

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`, `get_entities_related_to_a_file`, `get_entities_related_to_a_domain`, `get_entities_related_to_an_ip_address`, `get_entities_related_to_an_url`
*   `secops-mcp`: `lookup_entity`, `get_ioc_matches`, `search_security_events`
*   `secops-soar`: `list_cases`, `post_case_comment`
*   You may ask follow up question
*   `write_report`
*   **Common Steps:** {doc}`common_steps/enrich_ioc </run_books/common_steps/enrich_ioc>`, {doc}`common_steps/pivot_on_ioc_gti </run_books/common_steps/pivot_on_ioc_gti>`, {doc}`common_steps/find_relevant_soar_case </run_books/common_steps/find_relevant_soar_case>`, {doc}`common_steps/document_in_soar </run_books/common_steps/document_in_soar>`, {doc}`common_steps/generate_report_file </run_books/common_steps/generate_report_file>`

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, and optional inputs like `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, `${SIEM_SEARCH_HOURS}` (default 24).
2.  **Enrich IOC (GTI + SIEM Lookup):** Execute `common_steps/enrich_ioc.md` with `${IOC_VALUE}` and `${IOC_TYPE}`. Obtain `${GTI_FINDINGS}`, `${SIEM_ENTITY_SUMMARY}`, `${SIEM_IOC_MATCH_STATUS}`.
3.  **Fetch Key GTI Relationships:**
    *   Determine relevant relationships based on `${IOC_TYPE}` (e.g., for File Hash: `["contacted_domains", "contacted_ips"]`; for Domain: `["resolutions"]`). Let this be `REL_LIST`.
    *   Execute `common_steps/pivot_on_ioc_gti.md` with `${IOC_VALUE}`, `${IOC_TYPE}`, and `RELATIONSHIP_NAMES=REL_LIST`. Obtain `${GTI_RELATIONSHIPS}`.
4.  **Search Recent SIEM Events:**
    *   Construct a basic query for `secops-mcp.search_security_events` targeting `${IOC_VALUE}` (e.g., `text="${IOC_VALUE}"`).
    *   Execute the search with `hours_back=${SIEM_SEARCH_HOURS}`.
    *   Store a summary of findings (e.g., count, key event types, involved hosts/users) in `${SIEM_RECENT_EVENTS}`.
5.  **Search Relevant SOAR Cases:**
    *   Execute `common_steps/find_relevant_soar_case.md` with `SEARCH_TERMS=["${IOC_VALUE}"]` and `CASE_STATUS_FILTER="Opened"`.
    *   Obtain `${RELEVANT_CASE_IDS}` and `${RELEVANT_CASE_SUMMARIES}`. Let `${FOUND_CASES}` = `${RELEVANT_CASE_SUMMARIES}` (or `${RELEVANT_CASE_IDS}` if summaries aren't needed/available).
6.  **Synthesize Findings & Assess Risk:**
    *   Combine all findings: `${GTI_FINDINGS}`, `${GTI_RELATIONSHIPS}`, `${SIEM_ENTITY_SUMMARY}`, `${SIEM_IOC_MATCH_STATUS}`, `${SIEM_RECENT_EVENTS}`, `${FOUND_CASES}`.
    *   Guide the analyst (via output prompt or internal logic) to make an initial risk assessment (`${ASSESSMENT}`) based on the combined data (e.g., GTI reputation, SIEM activity presence/volume, relation to existing cases).
    *   Suggest potential next steps (`${RECOMMENDATION}`) based on the assessment (e.g., Escalate, Monitor, Close FP, Trigger IOC Containment).
7.  **Conditional Documentation:**
    *   **If `${CASE_ID}` was provided:**
        *   Prepare `COMMENT_TEXT` summarizing all findings, the assessment, and recommendation (e.g., "Basic IOC Enrichment for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI Rep: [...], GTI Relations: [...], SIEM Summary: [...], SIEM Match: [...], Recent Events: [...], Related Cases: [...]. Assessment: `${ASSESSMENT}`. Recommendation: `${RECOMMENDATION}`.").
        *   Execute `common_steps/document_in_soar.md` with `CASE_ID=${CASE_ID}` and `COMMENT_TEXT`. Obtain `${DOCUMENTATION_STATUS}`.
    *   **Else (`${CASE_ID}` not provided):** Set `${DOCUMENTATION_STATUS}` = "Skipped (No Case ID)".
8.  **Optional Report Generation:**
    *   You may ask follow up question to ask the user: "Generate a markdown report file for this enrichment?". Obtain `${REPORT_CHOICE}`.
    *   **If `${REPORT_CHOICE}` is "Yes":**
        *   Prepare `REPORT_CONTENT` similar to `COMMENT_TEXT` but formatted for a standalone report.
        *   Execute `common_steps/generate_report_file.md` with `REPORT_CONTENT`, `REPORT_TYPE="ioc_enrichment"`, `REPORT_NAME_SUFFIX=${IOC_VALUE}`. Obtain `${REPORT_GENERATION_STATUS}`.
    *   **Else:** Set `${REPORT_GENERATION_STATUS}` = "Skipped".
9.  **Completion:** Conclude the runbook execution. Present the key findings, assessment, recommendation, documentation status, and report generation status to the analyst.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant EnrichIOC as common_steps/enrich_ioc.md
    participant PivotGTI as common_steps/pivot_on_ioc_gti.md
    participant FindCase as common_steps/find_relevant_soar_case.md
    participant DocumentInSOAR as common_steps/document_in_soar.md
    participant GenerateReport as common_steps/generate_report_file.md
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant SOAR as secops-soar
    participant User

    Analyst->>AutomatedAgent: Start Basic IOC Enrichment v2\nInput: IOC_VALUE, IOC_TYPE, CASE_ID (opt), ...

    %% Step 2: Enrich IOC (GTI Report + SIEM Lookup + SIEM Match)
    AutomatedAgent->>EnrichIOC: Execute(Input: IOC_VALUE, IOC_TYPE)
    EnrichIOC-->>AutomatedAgent: Results: GTI_FINDINGS, SIEM_ENTITY_SUMMARY, SIEM_IOC_MATCH_STATUS

    %% Step 3: Fetch Key GTI Relationships
    Note over AutomatedAgent: Determine relevant RELATIONSHIP_NAMES (REL_LIST)
    AutomatedAgent->>PivotGTI: Execute(Input: IOC_VALUE, IOC_TYPE, RELATIONSHIP_NAMES=REL_LIST)
    PivotGTI-->>AutomatedAgent: Results: GTI_RELATIONSHIPS

    %% Step 4: Search Recent SIEM Events
    AutomatedAgent->>SIEM: search_security_events(text=IOC_VALUE, hours_back=SIEM_SEARCH_HOURS)
    SIEM-->>AutomatedAgent: Recent SIEM Events Summary (SIEM_RECENT_EVENTS)

    %% Step 5: Search Relevant SOAR Cases
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=[IOC_VALUE], CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: RELEVANT_CASE_IDS, RELEVANT_CASE_SUMMARIES (FOUND_CASES)

    %% Step 6: Synthesize Findings & Assess Risk
    Note over AutomatedAgent: Combine all findings (incl. FOUND_CASES). Guide analyst assessment (ASSESSMENT) & recommendation (RECOMMENDATION).

    %% Step 7: Conditional Documentation
    alt CASE_ID provided
        Note over AutomatedAgent: Prepare COMMENT_TEXT with all findings, assessment, recommendation
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
        DocumentInSOAR-->>AutomatedAgent: Results: DOCUMENTATION_STATUS
    else CASE_ID not provided
        Note over AutomatedAgent: DOCUMENTATION_STATUS = "Skipped"
    end

    %% Step 8: Optional Report Generation
    AutomatedAgent->>User: Confirm: "Generate markdown report? (Yes/No)"
    User-->>AutomatedAgent: Report Choice (REPORT_CHOICE)
    alt REPORT_CHOICE is "Yes"
        Note over AutomatedAgent: Prepare REPORT_CONTENT
        AutomatedAgent->>GenerateReport: Execute(Input: REPORT_CONTENT, REPORT_TYPE="ioc_enrichment", REPORT_NAME_SUFFIX=IOC_VALUE)
        GenerateReport-->>AutomatedAgent: Results: REPORT_GENERATION_STATUS
    else REPORT_CHOICE is "No"
        Note over AutomatedAgent: REPORT_GENERATION_STATUS = "Skipped"
    end

    %% Step 9: Completion
    AutomatedAgent->>Analyst: attempt_completion(result="Basic IOC enrichment v2 complete for IOC_VALUE. Assessment: ASSESSMENT. Recommendation: RECOMMENDATION. Documentation: DOCUMENTATION_STATUS. Report: REPORT_GENERATION_STATUS.")
