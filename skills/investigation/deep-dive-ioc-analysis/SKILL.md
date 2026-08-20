---
name: deep-dive-ioc-analysis
description: Use when performing exhaustive forensic and intelligence analysis on
  complex indicators of compromise.
category: investigation
version: 1.0.0
type: Skill
title: 'Skill: Deep Dive IOC Analysis Runbook'
generated:
  by: process:google-labs-jules
  at: 2025-12-20 22:04:42-05:00
---

# Deep Dive IOC Analysis Runbook

## Objective

Perform an exhaustive analysis of a single, potentially critical Indicator of Compromise (IOC) escalated from Tier 1 or identified during an investigation. This goes beyond the basic enrichment done by Tier 1, leveraging advanced tool features and pivoting techniques.

## Scope

This runbook covers in-depth analysis of a single IOC (IP, Domain, Hash, URL) using available GTI and SIEM tools to uncover related infrastructure, activity, and context.

## Inputs

*   `${IOC_VALUE}`: The specific IOC value (e.g., "198.51.100.10", "evil-domain.com", "abcdef123456...", "http://bad.url/path").
*   `${IOC_TYPE}`: The type of IOC (e.g., "IP Address", "Domain", "File Hash", "URL").
*   `${CASE_ID}`: The relevant SOAR case ID for documentation.
*   `${ALERT_GROUP_IDENTIFIERS}`: Relevant alert group identifiers from the SOAR case.
*   *(Optional) `${TIME_FRAME_HOURS}`: Lookback period in hours for SIEM searches (default: 168 = 7 days).*
*   *(Optional) `${SKIP_SOAR}`: Boolean, set to true if no CASE_ID is provided and SOAR documentation should be skipped.*

## Tools

*   `gti-mcp`: `get_ip_address_report`, `get_domain_report`, `get_file_report`, `get_url_report`, `get_entities_related_to_an_ip_address`, `get_entities_related_to_a_domain`, `get_entities_related_to_a_file`, `get_entities_related_to_an_url`, `get_file_behavior_summary` (optional for hashes), `get_collection_report` (optional).
*   `secops-mcp`: `lookup_entity`, `search_security_events`, `get_security_alerts`.
*   `secops-soar`: `post_case_comment`, `get_case_full_details`, `list_cases`.
*   `write_report` (for local report generation if skipping SOAR).
*   **Common Steps:** `skills/common/pivot-on-ioc-gti/SKILL.md`, `skills/common/enrich-ioc/SKILL.md`, `skills/common/correlate-ioc-with-alerts-cases/SKILL.md`, `skills/common/find-relevant-soar-case/SKILL.md`, `skills/common/document-in-soar/SKILL.md`, `skills/common/generate-report-file/SKILL.md`.

## Workflow Steps & Diagram

1.  **Receive Input & Context:** Obtain `${IOC_VALUE}`, `${IOC_TYPE}`, optionally `${CASE_ID}`, `${ALERT_GROUP_IDENTIFIERS}`, `${TIME_FRAME_HOURS}`, `${SKIP_SOAR}`. If `${CASE_ID}` is provided and `${SKIP_SOAR}` is not true, get case details via `soar-mcp_get_case_full_details`.
2.  **Detailed GTI Report:**
    *   Use the appropriate `gti-mcp_get_..._report` tool based on `${IOC_TYPE}` to retrieve the full GTI analysis report (`${GTI_REPORT_DETAILS}`) for `${IOC_VALUE}`.
    *   Record key details: reputation, classifications, first/last seen dates, associated threats (malware families, actors - `${ASSOCIATED_THREAT_IDS}`), key behaviors (if file hash).
3.  **GTI Pivoting:**
    *   Execute `skills/common/pivot-on-ioc-gti/SKILL.md` with `${IOC_VALUE}`, `${IOC_TYPE}`, and relevant `${RELATIONSHIP_NAMES}` (determined based on IOC type and report details). Obtain `${RELATED_ENTITIES}`.
    *   *(Optional: If IOC is File Hash, use `gti-mcp_get_file_behavior_summary`)*.
4.  **Deep SIEM Search:**
    *   Use `secops-mcp_search_security_events` with detailed UDM queries covering `${TIME_FRAME_HOURS}` (default 168). Search for:
        *   Activity directly involving `${IOC_VALUE}`.
        *   Activity involving significant IOCs from `${RELATED_ENTITIES}`.
    *   Analyze event details (`${SIEM_SEARCH_RESULTS}`).
    *   **Identify observed related IOCs:** Note any IOCs from `${RELATED_ENTITIES}` that were actually found in the `${SIEM_SEARCH_RESULTS}`. Let this list be `${OBSERVED_RELATED_IOCS}`.
5.  **SIEM Context & Correlation:**
    *   Initialize `SIEM_ENRICHMENT_RESULTS`.
    *   **Prioritize observed IOCs:** For each key IOC `Ki` (including `${IOC_VALUE}` and IOCs in `${OBSERVED_RELATED_IOCS}`):
        *   Execute `skills/common/enrich-ioc/SKILL.md` with `IOC_VALUE=Ki` and appropriate `IOC_TYPE`. Store results in `SIEM_ENRICHMENT_RESULTS[Ki]`.
    *   *(Note: For related IOCs from GTI not observed in SIEM searches, enrichment can be skipped or performed with lower priority if analyst deems necessary).*
    *   Execute `skills/common/correlate-ioc-with-alerts-cases/SKILL.md` with `IOC_LIST` containing `${IOC_VALUE}` and `${OBSERVED_RELATED_IOCS}`. Obtain `${RELATED_SIEM_ALERTS}` and `${RELATED_SOAR_CASES_CORRELATION}`.
    *   **Broader Case Search:** Execute `skills/common/find-relevant-soar-case/SKILL.md` with `SEARCH_TERMS` = list of `${IOC_VALUE}` + `${OBSERVED_RELATED_IOCS}` + key entities from `${SIEM_SEARCH_RESULTS}` (e.g., involved hosts/users) and `CASE_STATUS_FILTER="Opened"`. Obtain `${RELATED_SOAR_CASES_BROAD}`.
6.  **(Optional) Enrich Associated Threats:**
    *   If `${ASSOCIATED_THREAT_IDS}` were identified in Step 2:
        *   For each Threat ID `Ti` in `${ASSOCIATED_THREAT_IDS}`:
            *   Use `gti-mcp_get_collection_report` with `id=Ti` to get context on the associated malware/actor. Store in `${ASSOCIATED_THREAT_DETAILS}`.
7.  **Synthesize & Document/Report:**
    *   Combine all findings: `${GTI_REPORT_DETAILS}`, `${RELATED_ENTITIES}`, `${SIEM_SEARCH_RESULTS}`, `SIEM_ENRICHMENT_RESULTS`, `${RELATED_SIEM_ALERTS}`, `${RELATED_SOAR_CASES_CORRELATION}`, `${RELATED_SOAR_CASES_BROAD}`, `${ASSOCIATED_THREAT_DETAILS}` (optional).
    *   Assess the overall impact and scope. Identify potentially compromised assets or users. Formulate `ASSESSMENT` and `RECOMMENDATION`.
    *   **If `${CASE_ID}` provided and `${SKIP_SOAR}` is not true:**
        *   Prepare `COMMENT_TEXT` summarizing the deep dive: "Deep Dive Analysis for `${IOC_VALUE}` (`${IOC_TYPE}`): GTI Details: [...]. GTI Pivots found: [...]. SIEM Search revealed: [...]. SIEM Enrichment (Observed): [...]. Related Alerts: [...]. Related Cases (Correlation): [...]. Related Cases (Broad Search): [...]. Associated Threats: [...]. Assessment: `${ASSESSMENT}`. Recommendation: `${RECOMMENDATION}`".
        *   Execute `skills/common/document-in-soar/SKILL.md` with `${CASE_ID}` and `${COMMENT_TEXT}`. Obtain `${COMMENT_POST_STATUS}`.
    *   **Else (No CASE_ID or SKIP_SOAR is true):**
        *   Prepare `REPORT_CONTENTS_VAR` similar to `COMMENT_TEXT` but formatted for a standalone Markdown report, including a Mermaid diagram of the workflow performed.
        *   Construct `REPORT_NAME_VAR` (e.g., `deep_dive_ioc_${IOC_VALUE_Sanitized}_${timestamp}.md`).
        *   Execute `skills/common/generate-report-file/SKILL.md` with `REPORT_CONTENTS=${REPORT_CONTENTS_VAR}` and `REPORT_NAME=${REPORT_NAME_VAR}`. Obtain `${REPORT_FILE_PATH}` and `${WRITE_STATUS}`.
8.  **Completion:** Conclude the runbook execution. Inform analyst of completion status and report location (SOAR comment or local file path).

### ADK Graph-Based Workflow Diagram

```{mermaid}
graph TD
    START(["START"]) --> extract_deep_dive_payload_node["1. extract_deep_dive_payload_node<br/><i>(Extract Deep Dive Payload)</i>"]
    extract_deep_dive_payload_node --> query_gti_deep_dive_node["2. query_gti_deep_dive_node<br/><i>(GTI Deep Dive & Threat Attribution)</i>"]
    query_gti_deep_dive_node --> deep_dive_threat_router{"3. deep_dive_threat_router<br/><i>(Event.actions.route)</i>"}

    deep_dive_threat_router -- "ADVANCED_PERSISTENT_THREAT" --> handle_apt_branch["4a. handle_apt_branch<br/><i>(Trigger Enterprise APT Containment)</i>"]
    deep_dive_threat_router -- "COMMODITY_MALWARE" --> handle_commodity_branch["4b. handle_commodity_branch<br/><i>(Standard EDR Quarantine)</i>"]
    deep_dive_threat_router -- "BENIGN" --> handle_benign_deep_dive_branch["4c. handle_benign_deep_dive_branch<br/><i>(Document Benign Outcome)</i>"]

    handle_apt_branch --> document_deep_dive_report_node["5. document_deep_dive_report_node<br/><i>(SOAR Comment & Report Summary)</i>"]
    handle_commodity_branch --> document_deep_dive_report_node
    handle_benign_deep_dive_branch --> document_deep_dive_report_node
```

### Sequence Diagram

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant GTI as gti-mcp
    participant PivotOnIOC as skills/common/pivot-on-ioc-gti/SKILL.md
    participant SIEM as secops-mcp
    participant EnrichIOC as skills/common/enrich-ioc/SKILL.md
    participant CorrelateIOC as skills/common/correlate-ioc-with-alerts-cases/SKILL.md
    participant FindCase as skills/common/find-relevant-soar-case/SKILL.md
    participant DocumentInSOAR as skills/common/document-in-soar/SKILL.md
    participant GenerateReport as skills/common/generate-report-file/SKILL.md
    participant SOAR as secops-soar %% Underlying tool for documentation & context

    Analyst->>AutomatedAgent: Start Deep Dive IOC Analysis\nInput: IOC_VALUE, IOC_TYPE, CASE_ID (opt), SKIP_SOAR (opt), ...

    %% Step 1: Context
    opt CASE_ID provided AND SKIP_SOAR is false
        AutomatedAgent->>SOAR: get_case_full_details(case_id=CASE_ID)
        SOAR-->>AutomatedAgent: Case Details
    end

    %% Step 2: Detailed GTI Report
    AutomatedAgent->>GTI: get_..._report(ioc=IOC_VALUE) %% Based on IOC_TYPE
    GTI-->>AutomatedAgent: Detailed GTI Report (GTI_REPORT_DETAILS, ASSOCIATED_THREAT_IDS)

    %% Step 3: GTI Pivoting
    Note over AutomatedAgent: Determine relevant RELATIONSHIP_NAMES
    AutomatedAgent->>PivotOnIOC: Execute(Input: IOC_VALUE, IOC_TYPE, RELATIONSHIP_NAMES)
    PivotOnIOC-->>AutomatedAgent: Results: RELATED_ENTITIES
    opt IOC_TYPE is File Hash
        AutomatedAgent->>GTI: get_file_behavior_summary(hash=IOC_VALUE)
        GTI-->>AutomatedAgent: File Behavior Summary
    end

    %% Step 4: Deep SIEM Search
    Note over AutomatedAgent: Construct UDM queries for IOC_VALUE and RELATED_ENTITIES
    AutomatedAgent->>SIEM: search_security_events(text=Query1, hours_back=TIME_FRAME_HOURS)
    SIEM-->>AutomatedAgent: SIEM Search Results 1
    AutomatedAgent->>SIEM: search_security_events(text=Query2, hours_back=TIME_FRAME_HOURS)
    SIEM-->>AutomatedAgent: SIEM Search Results 2 (SIEM_SEARCH_RESULTS)
    Note over AutomatedAgent: Identify OBSERVED_RELATED_IOCS from SIEM_SEARCH_RESULTS

    %% Step 5: SIEM Context & Correlation
    Note over AutomatedAgent: Initialize SIEM_ENRICHMENT_RESULTS
    Note over AutomatedAgent: Prepare prioritized IOC list (IOC_VALUE + OBSERVED_RELATED_IOCS)
    loop For each prioritized IOC Ki
        AutomatedAgent->>EnrichIOC: Execute(Input: IOC_VALUE=Ki, IOC_TYPE=...)
        EnrichIOC-->>AutomatedAgent: Results: Store in SIEM_ENRICHMENT_RESULTS[Ki]
    end
    AutomatedAgent->>CorrelateIOC: Execute(Input: IOC_LIST=[Prioritized List], TIME_FRAME_HOURS)
    CorrelateIOC-->>AutomatedAgent: Results: RELATED_SIEM_ALERTS, RELATED_SOAR_CASES_CORRELATION
    Note over AutomatedAgent: Prepare broader search list (IOCs + key entities from SIEM results)
    AutomatedAgent->>FindCase: Execute(Input: SEARCH_TERMS=[Broad List], CASE_STATUS_FILTER="Opened")
    FindCase-->>AutomatedAgent: Results: RELATED_SOAR_CASES_BROAD

    %% Step 6: Optional Threat Enrichment
    opt ASSOCIATED_THREAT_IDS exist
        loop For each Threat ID Ti
            AutomatedAgent->>GTI: get_collection_report(id=Ti)
            GTI-->>AutomatedAgent: Associated Threat Details
        end
    end

    %% Step 7: Synthesize & Document/Report
    Note over AutomatedAgent: Synthesize all findings, assess impact, prepare COMMENT_TEXT or REPORT_CONTENT with Recommendation
    alt CASE_ID provided AND SKIP_SOAR is false
        AutomatedAgent->>DocumentInSOAR: Execute(Input: CASE_ID, COMMENT_TEXT)
        DocumentInSOAR-->>AutomatedAgent: Results: COMMENT_POST_STATUS
        AutomatedAgent->>Analyst: attempt_completion(result="Deep Dive IOC Analysis complete for IOC_VALUE. Findings documented in case CASE_ID.")
    else No CASE_ID or SKIP_SOAR is true
        Note over AutomatedAgent: Prepare REPORT_CONTENTS_VAR including Mermaid diagram
        Note over AutomatedAgent: Construct REPORT_NAME_VAR (e.g., deep_dive_ioc_${IOC_VALUE_Sanitized}_${timestamp}.md)
        AutomatedAgent->>GenerateReport: Execute(Input: REPORT_CONTENTS=REPORT_CONTENTS_VAR, REPORT_NAME=REPORT_NAME_VAR)
        GenerateReport-->>AutomatedAgent: Results: REPORT_FILE_PATH, WRITE_STATUS
        AutomatedAgent->>Analyst: attempt_completion(result="Deep Dive IOC Analysis complete for IOC_VALUE. Report generated at REPORT_FILE_PATH.")
    end

## Rubrics

The following rubric is used to evaluate the execution of this **Threat Hunt/Analysis** runbook by an LLM agent.

### Grading Scale (0-100 Points)

| Criteria | Points | Description |
| :--- | :--- | :--- |
| **Scope & Query** | 25 | Defined a clear scope and executed effective queries (UDM, search). |
| **Data Analysis** | 30 | Analyzed results to identify patterns, anomalies, or malicious behavior. |
| **Findings** | 15 | Accurately identified and filtered findings (True Positives vs. False Positives). |
| **Documentation** | 15 | Documented the hunt methodology and results clearly. |
| **Operational Artifacts** | 15 | Produced required artifacts: Sequence diagram, execution metadata (date/cost), and summary. |

### Evaluation Criteria Details

#### 1. Scope & Query (25 Points)
- **10 pts**: Correctly defined the time range and entities/indicators for the hunt.
- **15 pts**: Constructed and executed valid, efficient queries to retrieve relevant data.

#### 2. Data Analysis (30 Points)
- **15 pts**: Effectively analyzed the returned data for the hypothesized threat.
- **15 pts**: Correlated events or indicators to strengthen the analysis.

#### 3. Findings (15 Points)
- **15 pts**: Correctly classified the findings and provided evidence for the conclusion.

#### 4. Documentation (15 Points)
- **15 pts**: Recorded the hunt process, queries used, and findings in the system of record.

#### 5. Operational Artifacts (15 Points)
- **5 pts**: **Sequence Diagram**: Produced a Mermaid sequence diagram visualizing the steps taken.
- **5 pts**: **Execution Metadata**: Recorded the date, duration, and estimated token cost.
- **5 pts**: **Summary Report**: Generated a concise summary of the actions and outcomes.
