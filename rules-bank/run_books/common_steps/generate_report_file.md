# Common Step: Generate Report File

## Objective

Save generated report content (typically Markdown) to a file with a standardized naming convention.

## Scope

This sub-runbook executes the `write_report` action. It assumes the report content and report name are provided by the calling runbook.

## Inputs

*   `${REPORT_CONTENTS}`: The full content of the report (usually Markdown text).
*   `${REPORT_NAME}`: The desired name for the report file (e.g., "ioc_investigation_report_case123_20250519.md"). The `.md` extension will be added by the tool if not present. The report will be saved in a default `reports/` directory.

## Outputs

*   `${REPORT_FILE_PATH}`: The full path to the saved report file.
*   `${WRITE_STATUS}`: Confirmation or status of the file writing attempt.

## Tools

*   `write_report`

## Workflow Steps & Diagram

1.  **Receive Input:** Obtain `${REPORT_CONTENTS}` and `${REPORT_NAME}` from the calling runbook.
2.  **Prepare Report Details:**
    *   The `${REPORT_NAME}` is provided directly.
    *   The `${REPORT_CONTENTS}` is provided directly.
3.  **Write Report:** Call `write_report` with `report_name=${REPORT_NAME}` and `report_contents=${REPORT_CONTENTS}`. The tool will handle saving this to a predefined reports directory (e.g. `reports/`) and adding a `.md` extension if needed.
4.  **Return Status:** Store the result/status of the write operation in `${WRITE_STATUS}` and the actual file path (returned by `write_report`) in `${REPORT_FILE_PATH}`. Return `${REPORT_FILE_PATH}` and `${WRITE_STATUS}` to the calling runbook.

```{mermaid}
sequenceDiagram
    participant CallingRunbook
    participant GenerateReportFile as generate_report_file.md (This Runbook)

    CallingRunbook->>GenerateReportFile: Execute Report Generation\nInput: REPORT_CONTENTS, REPORT_NAME

    %% Step 2: Prepare Report Details
    Note over GenerateReportFile: REPORT_NAME and REPORT_CONTENTS are provided

    %% Step 3: Write Report
    GenerateReportFile->>GenerateReportFile: write_report(report_name=REPORT_NAME, report_contents=REPORT_CONTENTS)
    Note over GenerateReportFile: Store write status (WRITE_STATUS) and returned REPORT_FILE_PATH

    %% Step 4: Return Status
    GenerateReportFile-->>CallingRunbook: Return Results:\nREPORT_FILE_PATH,\nWRITE_STATUS

```

## Completion Criteria

The `write_report` action has been attempted. The status (`${WRITE_STATUS}`) and the actual file path (`${REPORT_FILE_PATH}`) are available.
