# Runbook: IOC Threat Hunt

## Objective

To proactively hunt for specific Indicators of Compromise (IOCs) across the environment. This hunt is typically based on threat intelligence feeds, IOCs identified from recent incidents, or specific hypotheses regarding potential threats. The goal is to identify any presence or activity related to these IOCs within the defined timeframe.

## Scope

This runbook covers:
*   Receiving a list of IOCs and their types.
*   Optionally checking these IOCs against the SIEM's integrated threat intelligence feeds (`get_ioc_matches`).
*   Iteratively searching the SIEM for each IOC using appropriate UDM queries.
*   Enriching any identified hits (both the IOC itself and involved entities like hosts/users) using SIEM and GTI tools.
*   Documenting the hunt process, queries, findings (positive and negative), and enrichment results in a SOAR case.
*   Escalating confirmed malicious activity or concluding the hunt if no significant findings.

This runbook explicitly **excludes**:
*   Deep-dive investigation beyond the initial enrichment of found IOCs/entities (this would typically trigger a different runbook).
*   Containment or eradication actions (findings are escalated for such actions).
*   Complex TTP-based hunting (this runbook focuses on known IOCs).

## Inputs

*   `${IOC_LIST}`: Comma-separated list of IOC values to hunt for (e.g., "1.2.3.4,evil.com,hash123"). This is mandatory.
*   `${IOC_TYPES}`: Corresponding comma-separated list of IOC types for each IOC in `${IOC_LIST}` (e.g., "IP Address,Domain,File Hash"). This is mandatory.
*   `${HUNT_TIMEFRAME_HOURS}`: Lookback period in hours for SIEM searches (e.g., 72, 168). Defaults to 72 if not specified.
*   *(Optional) `${HUNT_CASE_ID}`: SOAR case ID for tracking the hunt activities and findings. If not provided, a new case might be recommended or findings documented locally.*
*   *(Optional) `${REASON_FOR_HUNT}`: Brief description of why these IOCs are being hunted (e.g., "From TI report XYZ", "Related to incident ABC").*
*   *(Derived) `${SIEM_SEARCH_RESULTS}`: Collection of results from `secops-mcp.search_security_events` for each IOC.*
*   *(Derived) `${ENRICHMENT_DATA}`: Collection of enrichment details for IOCs with hits and associated entities.*

## Outputs

*   `${HUNT_FINDINGS_SUMMARY}`: A summary of the hunt, including IOCs searched, hits found, key enrichment details, and whether escalation occurred.
*   `${DOCUMENTATION_STATUS}`: Status of documenting the hunt in the SOAR case (if `${HUNT_CASE_ID}` was provided).
*   `${ESCALATION_STATUS}`: Indicates if confirmed malicious activity was found and escalated.

## Tools

*   `secops-mcp`: `search_security_events`, `lookup_entity`, `get_ioc_matches`
*   `gti-mcp`: (Relevant enrichment tools like `get_ip_address_report`, `get_domain_report`, etc.)
*   `secops-soar`: `post_case_comment` (for documenting hunt/findings)

## Workflow Steps & Diagram

1.  **Receive Inputs:** Obtain `${IOC_LIST}`, `${IOC_TYPES}`, `${HUNT_TIMEFRAME_HOURS}`, etc.
2.  **Initial Check (Optional):** Use `secops-mcp.get_ioc_matches` to see if any IOCs in the list have recent matches in the SIEM's integrated feeds.
3.  **Iterative SIEM Search:**
    *   For each IOC in `${IOC_LIST}`:
        *   Construct appropriate UDM queries for `secops-mcp.search_security_events` based on the IOC value and type.
        *   Execute the search over `${HUNT_TIMEFRAME_HOURS}`.
        *   Analyze results for any hits (e.g., network connections, file executions, DNS lookups).
4.  **Enrich Findings:**
    *   If hits are found for an IOC:
        *   Use `secops-mcp.lookup_entity` for the IOC and any involved entities (hosts, users).
        *   Use relevant `gti-mcp` tools to enrich the IOC itself.
5.  **Document Hunt & Findings:**
    *   Use `secops-soar.post_case_comment` in `${HUNT_CASE_ID}` (if provided) or a dedicated hunt case.
    *   Document: IOCs Hunted, Timeframe, Queries Used, Summary of Findings (including IOCs with no hits), Details of any confirmed hits and enrichment data.
6.  **Escalate or Conclude:**
    *   If confirmed malicious activity related to the hunted IOCs is found, escalate by creating/updating an incident case.
    *   If no significant findings, conclude the hunt and document it.

```{mermaid}
sequenceDiagram
    participant Analyst/Hunter
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant SIEM as secops-mcp
    participant GTI as gti-mcp
    participant SOAR as secops-soar

    Analyst/Hunter->>AutomatedAgent: Start IOC Threat Hunt\nInput: IOC_LIST, IOC_TYPES, HUNT_TIMEFRAME_HOURS, ...

    %% Step 2: Initial Check (Optional)
    opt Check IOC Matches
        AutomatedAgent->>SIEM: get_ioc_matches(hours_back=HUNT_TIMEFRAME_HOURS)
        SIEM-->>AutomatedAgent: Recent IOC Matches
        Note over AutomatedAgent: Correlate with IOC_LIST
    end

    %% Step 3: Iterative SIEM Search
    loop For each IOC Ii in IOC_LIST
        Note over AutomatedAgent: Construct UDM query Qi for Ii
        AutomatedAgent->>SIEM: search_security_events(text=Qi, hours_back=HUNT_TIMEFRAME_HOURS)
        SIEM-->>AutomatedAgent: Search Results for Ii
        Note over AutomatedAgent: Analyze results for hits
    end

    %% Step 4: Enrich Findings
    opt Hits Found for IOC Ij (Involved Entities E1, E2...)
        AutomatedAgent->>SIEM: lookup_entity(entity_value=Ij)
        SIEM-->>AutomatedAgent: SIEM Summary for Ij
        AutomatedAgent->>GTI: get_..._report(ioc=Ij)
        GTI-->>AutomatedAgent: GTI Enrichment for Ij
        loop For each Involved Entity Ek (E1, E2...)
            AutomatedAgent->>SIEM: lookup_entity(entity_value=Ek)
            SIEM-->>AutomatedAgent: SIEM Summary for Ek
        end
    end

    %% Step 5: Document Hunt
    AutomatedAgent->>SOAR: post_case_comment(case_id=HUNT_CASE_ID, comment="IOC Hunt Summary: IOCs [...], Findings [...], Enrichment [...]")
    SOAR-->>AutomatedAgent: Comment Confirmation

    %% Step 6: Escalate or Conclude
    alt Confirmed Activity Found
        Note over AutomatedAgent: Escalate findings (Create/Update Incident Case)
        AutomatedAgent->>Analyst/Hunter: attempt_completion(result="IOC Hunt complete. Findings escalated.")
    else No Significant Findings
        AutomatedAgent->>Analyst/Hunter: attempt_completion(result="IOC Hunt complete. No significant findings. Hunt documented.")
    end
```

## Completion Criteria

*(Define how successful completion is determined, e.g., All IOCs searched, results analyzed, findings documented/escalated.)*
