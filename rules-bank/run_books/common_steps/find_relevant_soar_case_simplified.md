---
type: "Playbook"
title: "Common Step: Find Relevant SOAR Case (Simplified)"
description: "Simplified plain-English procedure to locate relevant SOAR cases by search terms."
resource: "adk_runbooks/rules-bank/run_books/common_steps/find_relevant_soar_case_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "SOAR case"
    - "search term"
  technical_verbs:
    - "triage"
---

# Common Step: Find Relevant SOAR Case

## Objective
Identify existing SOAR cases that are relevant to an ongoing investigation based on search terms.

## Inputs
*   `SEARCH_TERMS`: Keywords, entity names, or IOC values to search.

## Core Steps

1. Search SOAR Case Repository:
   * Query SOAR API with `SEARCH_TERMS` across title, description, and entity fields.

2. Filter and Rank Cases:
   * Filter results by status (Open / In Progress) and return top matching cases.
