---
type: "Playbook"
title: "Common Step: Confirm Action with User (Simplified)"
description: "Simplified plain-English procedure to confirm high-impact actions before execution."
resource: "adk_runbooks/rules-bank/run_books/common_steps/confirm_action_simplified.md"
timestamp: "2026-08-05T21:50:00Z"
provenance:
  source_type: "generative_ai"
  source_tool: "ste-writing-style"
  timestamp: "2026-08-05T21:50:00Z"
ste_vocabulary:
  technical_names:
    - "impact"
    - "security control"
  technical_verbs:
    - "isolate"
    - "contain"
---

# Common Step: Confirm Action with User

## Objective
Ask the human analyst to confirm high-impact actions (for example, host isolation or user disablement).

## Inputs
*   `ACTION_DESCRIPTION`: Clear description of the proposed action.
*   `TARGET_ENTITY`: Host, user, or IP to be modified.

## Core Steps

1. Present Confirmation Prompt:
   * Display the proposed action, target entity, and potential operational impact to the user.

2. Await User Response:
   * Proceed with action only when the user confirms with 'Yes' or explicit approval.
