---
type: Runbook
title: "Guided TTP Hunt Runbook (Example: Credential Access)"
generated:
  by: process:google-labs-jules
  at: 2025-12-20T22:04:42-05:00
---

# Guided TTP Hunt Runbook (Example: Credential Access)

## Objective

Proactively hunt for evidence of specific MITRE ATT&CK Credential Access techniques (e.g., OS Credential Dumping T1003, Credentials from Password Stores T1555) based on threat intelligence or a hypothesis, suitable for Tier 2 execution.

## Scope

This runbook provides a template for hunting specific TTPs. This example focuses on common credential access techniques but can be adapted for others. It emphasizes SIEM-based hunting.

## Inputs

*   `${TECHNIQUE_IDS}`: Comma-separated list of MITRE ATT&CK Technique IDs to hunt (e.g., "T1003.001,T1555.003").
*   `${TIME_FRAME_HOURS}`: Lookback period in hours for SIEM searches (default: 72).
*   *(Optional) `${TARGET_SCOPE_QUERY}`: A UDM query fragment to narrow the scope (e.g., `principal.hostname = "server1"` or `principal.user.department = "finance"`).*
*   *(Optional) `${HUNT_HYPOTHESIS}`: Brief description of the reason for the hunt.*

## Tools

*   `gti-mcp`: `get_threat_intel` (for technique understanding), `search_threats` (for related tools/actors).
*   `secops-mcp`: `search_security_events` (core hunting tool), `lookup_entity` (for enriching findings).
*   `secops-soar`: `post_case_comment` (for documenting hunt/findings), `list_cases` (optional, check related cases).

## Workflow Steps & Diagram

1.  **Receive Input & Define Scope:** Obtain `${TECHNIQUE_IDS}`, `${TIME_FRAME_HOURS}`, optionally `${TARGET_SCOPE_QUERY}` and `${HUNT_HYPOTHESIS}`.
2.  **Research Techniques (GTI/External):**
    *   For each technique ID in `${TECHNIQUE_IDS}`:
        *   Use `gti-mcp_get_threat_intel` (e.g., `query="Explain MITRE ATT&CK technique T1003.001"`) to understand the technique's description, common procedures, and potential detection methods.
        *   *(Optional: Use `gti-mcp_search_threats` querying for the technique ID to find associated tools, malware, or actors).*
        *   *(Manual Step: Review MITRE ATT&CK website for detailed procedures and detection guidance).*
3.  **Develop SIEM Hunt Queries:**
    *   Based on the research, formulate specific `secops-mcp_search_security_events` UDM queries targeting indicators for each technique. Examples:
        *   **T1003.001 (LSASS Memory):** `metadata.event_type="PROCESS_LAUNCH" AND target.process.file.full_path = "C:\Windows\System32\lsass.exe"` (Look for suspicious parent processes accessing lsass.exe - requires careful analysis of parent/target relationships in results). Or search for specific tools accessing LSASS: `metadata.event_type="PROCESS_LAUNCH" AND principal.process.command_line CONTAINS "lsass"` AND `principal.process.file.full_path != "C:\Windows\System32\svchost.exe"` (Example, needs refinement).
        *   **T1555.003 (Credentials from Web Browsers):** `metadata.event_type="FILE_OPEN" AND (target.file.full_path CONTAINS "Login Data" OR target.file.full_path CONTAINS "Web Data") AND principal.process.file.full_path NOT IN ("chrome.exe", "firefox.exe", "msedge.exe")` (Example, needs refinement based on browser paths and legitimate access).
        *   **General:** Search for execution of known credential dumping tools (Mimikatz, LaZagne, etc.) via `principal.process.file.full_path` or `principal.process.command_line`.
    *   Combine technique-specific queries with `${TARGET_SCOPE_QUERY}` if provided.
4.  **Execute SIEM Searches:**
    *   Run the developed queries using `secops-mcp_search_security_events` with `hours_back=${TIME_FRAME_HOURS}`.
5.  **Analyze Results:**
    *   Review the search results for suspicious or anomalous activity matching the technique's expected behavior. Look for low-prevalence events, unusual parent-child process relationships, or access from unexpected applications.
6.  **Enrich Findings:**
    *   If suspicious events are found, use `secops-mcp_lookup_entity` for involved users, hosts, IPs, and file hashes.
    *   Use `gti-mcp` tools (`get_file_report`, `get_ip_address_report`, etc.) to enrich suspicious indicators.
7.  **Document Hunt & Findings:**
    *   Use `soar-mcp_post_case_comment` in a dedicated hunting case or a relevant existing case (`${CASE_ID}` if applicable).
    *   Document: Hunt Hypothesis/Objective, Techniques Hunted (`${TECHNIQUE_IDS}`), Scope (`${TARGET_SCOPE_QUERY}`), Timeframe, Queries Used, Summary of Findings (including negative results), Details of any suspicious activity identified, Enrichment results.
8.  **Escalate or Conclude:**
    *   If confirmed malicious activity is found, escalate by creating a new incident case or linking findings to an existing one.
    *   If no significant findings, conclude the hunt and document it.
9.  **Completion:** Conclude the runbook execution.

```{mermaid}
sequenceDiagram
    participant Analyst
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar
    participant MITRE as MITRE ATT&CK (External)

    Analyst->>AutomatedAgent: Start Guided TTP Hunt\nInput: TECHNIQUE_IDS, TIME_FRAME_HOURS, TARGET_SCOPE_QUERY (opt), HUNT_HYPOTHESIS (opt)

    %% Step 2: Research Techniques
    loop For each Technique ID Ti in TECHNIQUE_IDS
        AutomatedAgent->>GTI: get_threat_intel(query="Explain MITRE ATT&CK technique Ti")
        GTI-->>AutomatedAgent: Technique Description/Context
        AutomatedAgent->>MITRE: (Manual) Review ATT&CK Website for Ti
        MITRE-->>AutomatedAgent: Detailed Procedures/Detections
    end

    %% Step 3: Develop SIEM Queries
    Note over AutomatedAgent: Formulate UDM queries based on research & inputs

    %% Step 4: Execute SIEM Searches
    loop For each developed Query Qi
        AutomatedAgent->>SIEM: search_security_events(text=Qi, hours_back=TIME_FRAME_HOURS)
        SIEM-->>AutomatedAgent: Search Results for Qi
    end

    %% Step 5: Analyze Results
    Note over AutomatedAgent: Analyze results for suspicious patterns/anomalies

    %% Step 6: Enrich Findings
    opt Suspicious Activity Found (Entities E1, E2...)
        loop For each Suspicious Entity Ei
            AutomatedAgent->>SIEM: lookup_entity(entity_value=Ei)
            SIEM-->>AutomatedAgent: SIEM Summary for Ei
            AutomatedAgent->>GTI: get_..._report(ioc=Ei)
            GTI-->>AutomatedAgent: GTI Report for Ei
        end
    end

    %% Step 7: Document Hunt
    Note over AutomatedAgent: Prepare hunt summary comment
    AutomatedAgent->>SOAR: post_case_comment(case_id=[Hunt Case/Relevant Case], comment="Guided Hunt Summary: Techniques [...], Scope [...], Queries [...], Findings [...], Enrichment [...]")
    SOAR-->>AutomatedAgent: Comment Confirmation

    %% Step 8 & 9: Escalate or Conclude
    alt Confirmed Malicious Activity Found
        Note over AutomatedAgent: Escalate findings (Create new case or link to existing)
        AutomatedAgent->>Analyst: attempt_completion(result="Guided TTP Hunt complete. Findings escalated.")
    else No Significant Findings
        AutomatedAgent->>Analyst: attempt_completion(result="Guided TTP Hunt complete. No significant findings. Hunt documented.")
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
