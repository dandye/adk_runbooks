# SOAR MCP Tools Reference

This document provides a reference for the tools available in the SOAR MCP server.

## Available Tools

### list_cases
List cases available in the Security Orchestration, Automation, and Response (SOAR) platform.

**Arguments:**
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### post_case_comment
Post a comment to a specific case within the SOAR platform.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the specific case to which this comment should be added.
*   `comment` (str): The textual content of the comment to be recorded within the case history.

**Returns:**
*   `dict`: A dictionary representing the raw API response.

### list_alerts_by_case
List the security alerts associated with a specific case ID in the SOAR platform.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case for which associated alerts should be retrieved.
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**
*   `dict`: A dictionary representing the raw API response.

### list_alert_group_identifiers_by_case
List alert group identifiers associated with a specific case ID in the SOAR platform.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case for which alert group identifiers should be retrieved.
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### list_events_by_alert
List the underlying security events associated with a specific alert within a given case.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case containing the alert.
*   `alert_id` (str): The unique identifier (ID) of the specific alert whose associated events are to be listed.
*   `next_page_token` (str, optional): The nextPageToken to fetch the next page of results.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### change_case_priority
Change the priority level of a specific case in the SOAR platform.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case whose priority needs to be updated.
*   `case_priority` (CasePriority): The new priority level to assign to the case.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### get_entities_by_alert_group_identifiers
Retrieve entities (e.g., IP addresses, hostnames, users) involved in specific alert groups within a case.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case containing the alert groups.
*   `alert_group_identifiers` (List[str]): A list of identifiers for the specific alert groups whose involved entities are to be retrieved.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### get_entity_details
Fetch detailed information about a specific entity known to the SOAR platform.

**Arguments:**
*   `entity_identifier` (str): The unique identifier of the entity.
*   `entity_type` (str): The type of the entity.
*   `entity_environment` (str): The environment context for the entity.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### search_entity
Search for entities within the SOAR platform based on various criteria.

**Arguments:**
*   `term` (str, optional): A search term to match against entity identifiers or names.
*   `type` (List[str], optional): A list of entity types to filter by.
*   `is_suspicious` (bool, optional): Filter for entities marked as suspicious.
*   `is_internal_asset` (bool, optional): Filter for entities identified as internal assets.
*   `is_enriched` (bool, optional): Filter for entities that have undergone enrichment processes.
*   `network_name` (List[str], optional): Filter entities belonging to specific networks.
*   `environment_name` (List[str], optional): Filter entities belonging to specific environments.

**Returns:**
*   `dict`: A dictionary representing the raw API response from the SOAR platform.

### get_case_full_details
Retrieve comprehensive details for a specific case by aggregating its core information, associated alerts, and comments.

**Arguments:**
*   `case_id` (str): The unique identifier (ID) of the case for which full details are required.

**Returns:**
*   `dict`: A dictionary containing the aggregated results from three separate API calls.
