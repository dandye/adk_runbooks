# Runbook: Threat Intelligence Workflows

## Objective

To outline common workflows for Cyber Threat Intelligence (CTI) Researchers. This includes researching new or known threat actors, analyzing malware families or campaigns, understanding vulnerabilities, and disseminating actionable intelligence to relevant teams (SOC, IR, Detection Engineering, Vulnerability Management).

## Scope

This runbook covers typical CTI tasks using Google Threat Intelligence (GTI) tools as the primary source, augmented by SIEM (secops-mcp) for local correlation and SOAR (secops-soar) for documentation and dissemination. It may link to or inform specific hunting or analysis runbooks. The example workflow focuses on researching a threat actor.

This runbook explicitly **excludes**:
*   Deep malware reverse engineering (though GTI behavioral reports might be consumed).
*   Active incident response (though CTI findings heavily support IR).
*   Direct configuration of security controls (findings are disseminated for others to action).

## Inputs

*   **General for CTI tasks (vary by specific workflow):**
    *   `${THREAT_NAME}`: Name of a threat actor, malware family, campaign.
    *   `${IOC_VALUE}`: A specific Indicator of Compromise (IP, domain, hash, URL).
    *   `${GTI_COLLECTION_ID}`: A specific GTI Collection ID for an actor, malware, campaign, report, etc. This is often a primary input for focused research.
    *   `${VULNERABILITY_ID}`: CVE or other vulnerability identifier.
    *   `${INTELLIGENCE_REQUIREMENT}`: A specific question or area of focus for research (e.g., "What are the latest TTPs for APT X?", "Is malware Y prevalent in our industry?").
*   **For the Example Workflow (Researching a Threat Actor):**
    *   `${THREAT_ACTOR_ID}`: GTI Collection ID or known name of the target threat actor. This is mandatory for the example.
    *   *(Derived) `${ACTOR_DETAILS}`: Output from `gti-mcp.get_collection_report`.*
    *   *(Derived) `${RELATED_MALWARE}`, `${RELATED_CAMPAIGNS}`, `${RELATED_TTPS}`, `${RELATED_IOCS}`: Outputs from `gti-mcp.get_entities_related_to_a_collection`.*
    *   *(Derived) `${MITRE_TREE}`: Output from `gti-mcp.get_collection_mitre_tree`.*
    *   *(Derived) `${TIMELINE_EVENTS}`: Output from `gti-mcp.get_collection_timeline_events`.*
    *   *(Derived) `${LOCAL_CORRELATION_RESULTS}`: Summary of SIEM searches for related IOCs/TTPs.*
    *   *(Derived) `${REPORT_CONTENT}`: The final Markdown report content.*

## Outputs

*   **General for CTI tasks (vary by specific workflow):**
    *   Threat intelligence reports (Markdown files).
    *   Summaries of threat actor TTPs, IOCs, and infrastructure.
    *   Contextual information for ongoing incidents or hunts.
    *   Recommendations for new detections or security control adjustments.
*   **For the Example Workflow (Researching a Threat Actor):**
    *   `${REPORT_FILE_PATH}`: The path to the generated threat actor profile Markdown file.
    *   `${DISSEMINATION_STATUS}`: Status of sharing the findings (e.g., SOAR comment posted).

## Tools

*   `gti-mcp`: `get_collection_report`, `search_threat_actors`, `get_entities_related_to_a_collection`, `get_collection_mitre_tree`, `get_collection_timeline_events`, and other GTI tools as needed for specific research.
*   `secops-mcp`: `search_security_events`, `lookup_entity`, `get_ioc_matches` (for local correlation).
*   `secops-soar`: `post_case_comment`, `list_cases`, `siemplify_add_general_insight` (for dissemination and context).
*   `write_to_file` (Replaces `write_report` for generating local Markdown reports).
*   *(External OSINT tools/feeds - Manual step, not MCP tools)*

## Workflow Steps & Diagram

*(This section would outline common CTI processes, potentially branching based on the type of intelligence task.)*

**Example Workflow: Researching a Threat Actor**

1.  **Receive Input:** Obtain Threat Actor Name or ID (`${THREAT_ACTOR_ID}`).
2.  **Initial GTI Lookup:** Use `gti-mcp.search_threat_actors` (if name provided) or directly use `gti-mcp.get_collection_report` if `${THREAT_ACTOR_ID}` is a GTI Collection ID. Store result in `${ACTOR_DETAILS}`.
3.  **Explore Relationships:** Use `gti-mcp.get_entities_related_to_a_collection` with `${THREAT_ACTOR_ID}` for various relationship types (e.g., "malware_families", "campaigns", "attack_techniques", "domains", "ip_addresses", "files") to find associated malware (`${RELATED_MALWARE}`), campaigns (`${RELATED_CAMPAIGNS}`), TTPs (`${RELATED_TTPS}`), IOCs (`${RELATED_IOCS}`).
4.  **Analyze TTPs:** Use `gti-mcp.get_collection_mitre_tree` with `${THREAT_ACTOR_ID}`. Store in `${MITRE_TREE}`.
5.  **Review Timelines:** Use `gti-mcp.get_collection_timeline_events` with `${THREAT_ACTOR_ID}`. Store in `${TIMELINE_EVENTS}`.
6.  **Correlate Locally (Optional):** Use `secops-mcp` tools (`search_security_events`, `lookup_entity`) to search for related IOCs/TTPs (from `${RELATED_IOCS}`, `${RELATED_TTPS}`) in the local environment. Store summary in `${LOCAL_CORRELATION_RESULTS}`.
7.  **Synthesize & Report:** Compile findings (`${ACTOR_DETAILS}`, `${RELATED_MALWARE}`, etc., `${MITRE_TREE}`, `${TIMELINE_EVENTS}`, `${LOCAL_CORRELATION_RESULTS}`) into a threat actor profile. Store as Markdown in `${REPORT_CONTENT}`. Use `write_to_file` to save the report (e.g., `path="./reports/actor_profile_${THREAT_ACTOR_ID}_${timestamp}.md", content=${REPORT_CONTENT}`). Store path in `${REPORT_FILE_PATH}`.
8.  **Disseminate:** Share findings via `secops-soar.post_case_comment` (e.g., to a general intel case or relevant incident cases) or other established channels. Store status in `${DISSEMINATION_STATUS}`.

```{mermaid}
sequenceDiagram
    participant Researcher
    participant AutomatedAgent as Automated Agent (MCP Client)
    participant GTI as gti-mcp
    participant SIEM as secops-mcp
    participant SOAR as secops-soar

    Researcher->>AutomatedAgent: Research Threat Actor\nInput: THREAT_ACTOR_ID

    %% Step 2: Initial GTI Lookup
    AutomatedAgent->>GTI: get_collection_report(id=THREAT_ACTOR_ID)
    GTI-->>AutomatedAgent: Actor Details (ACTOR_DETAILS)

    %% Step 3: Explore Relationships
    AutomatedAgent->>GTI: get_entities_related_to_a_collection(id=THREAT_ACTOR_ID, relationship_name="malware_families")
    GTI-->>AutomatedAgent: Related Malware (RELATED_MALWARE)
    AutomatedAgent->>GTI: get_entities_related_to_a_collection(id=THREAT_ACTOR_ID, relationship_name="attack_techniques")
    GTI-->>AutomatedAgent: Related TTPs (RELATED_TTPS)
    %% Add other relationship calls for IOCs, campaigns

    %% Step 4: Analyze TTPs
    AutomatedAgent->>GTI: get_collection_mitre_tree(id=THREAT_ACTOR_ID)
    GTI-->>AutomatedAgent: MITRE TTP Tree (MITRE_TREE)

    %% Step 5: Review Timelines
    AutomatedAgent->>GTI: get_collection_timeline_events(id=THREAT_ACTOR_ID)
    GTI-->>AutomatedAgent: Timeline Events (TIMELINE_EVENTS)

    %% Step 6: Correlate Locally (Optional)
    opt Correlate Locally
        Note over AutomatedAgent: Extract key IOCs/TTPs from RELATED_IOCS, RELATED_TTPS
        loop For each IOC/TTP Indicator Ii
            AutomatedAgent->>SIEM: search_security_events(text="Search for Ii")
            SIEM-->>AutomatedAgent: Local Activity Results
        end
        Note over AutomatedAgent: Store in LOCAL_CORRELATION_RESULTS
    end

    %% Step 7: Synthesize & Report
    Note over AutomatedAgent: Compile Threat Actor Profile into REPORT_CONTENT
    AutomatedAgent->>AutomatedAgent: write_to_file(path="./reports/actor_profile_${THREAT_ACTOR_ID}_${timestamp}.md", content=REPORT_CONTENT)
    Note over AutomatedAgent: Report Saved (REPORT_FILE_PATH)

    %% Step 8: Disseminate
    AutomatedAgent->>SOAR: post_case_comment(case_id=..., comment="Threat Actor Profile for THREAT_ACTOR_ID available: REPORT_FILE_PATH")
    SOAR-->>AutomatedAgent: Comment Confirmation (DISSEMINATION_STATUS)

    AutomatedAgent->>Researcher: attempt_completion(result="Threat Actor research complete. Profile generated at REPORT_FILE_PATH. Dissemination: DISSEMINATION_STATUS")

```

## Completion Criteria

*   The specified threat intelligence requirement (e.g., researching a threat actor) has been addressed using appropriate GTI and other tools.
*   Relevant intelligence (e.g., actor details, IOCs, TTPs, timelines) has been gathered and analyzed.
*   (If applicable) Correlation with the local environment has been attempted.
*   Findings have been synthesized into a structured report (e.g., Markdown file), and the `${REPORT_FILE_PATH}` is available.
*   The intelligence has been disseminated through appropriate channels (e.g., SOAR comment), and `${DISSEMINATION_STATUS}` is recorded.
