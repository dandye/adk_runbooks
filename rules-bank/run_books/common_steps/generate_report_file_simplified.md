---
type: "Playbook"
title: "Common Step: Generate Report File (Simplified)"
description: "Simplified plain-English procedure to save generated report markdown to local files."
resource: "adk_runbooks/rules-bank/run_books/common_steps/generate_report_file_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "report file"
    - "markdown"
    - "artifact"
  technical_verbs:
    - "triage"
---

# Common Step: Generate Report File

## Objective
Save generated markdown report content to a local file with standardized naming.

## Inputs
*   `FILE_PATH`: Target destination file path.
*   `REPORT_CONTENT`: Markdown report text.

## Core Steps

1. Validate File Path and Content:
   * Make sure destination directory exists and content is non-empty.

2. Write File to Disk:
   * Write `REPORT_CONTENT` to `FILE_PATH`.
