# Proposal: Integrating Gas Town Concepts into ADK Multi-Agent System

## Overview
This proposal suggests incorporating key architectural innovations from the [Gas Town](https://github.com/steveyegge/gastown) project to enhance the robustness, persistence, and observability of our SOC multi-agent system.

Gas Town is a multi-agent workspace manager that introduces the "Propulsion Principle" (Git-backed state) and "Beads" (Git-backed issue tracking) to solve common problems in agent orchestration, such as context loss and lack of structured coordination.

## Key Innovations

### 1. The Propulsion Principle (Git-Backed Persistence)
**Concept:** Use Git worktrees and commits to persist agent state.
**Application:**
- Each investigation case becomes a branch or a separate git-tracked directory.
- Agents commit their intermediate thoughts, tool outputs, and decision logs to this branch.
- **Benefit:** Solves "context loss on restart". Allows human operators to audit the exact state of an agent at any point. Enables "time-travel debugging" for investigations.

### 2. Beads (Git-Backed Task Tracking)
**Concept:** Discrete units of work ("Beads") stored as files in Git.
**Application:**
- Incident Response Plan (IRP) steps are instantiated as "Beads" (e.g., structured YAML/JSON files) in the case directory.
- Status (TODO, IN_PROGRESS, DONE) is tracked via file content or git status.
- **Benefit:** Formalizes the delegation process. Replaces ephemeral prompt-based delegation with persistent, structured task assignments. This aligns perfectly with "Detection as Code" -> "Investigation as Code".

### 3. The Town (Standardized Workspace)
**Concept:** A standardized directory structure for all active agents and tasks.
**Application:**
- Define a standard layout for `active_investigations/`.
- **Benefit:** Predictable file paths for logs, reports, and artifacts. Agents can easily find each other's work if permissions allow.

## Proposed Architecture Changes

### Enhanced Manager ("The Mayor")
The `manager` agent (currently `root_agent`) will evolve into a coordinator similar to Gas Town's "Mayor".
- **Current:** Delegates via prompt instructions.
- **Proposed:** Delegates by creating "Convoy" directories containing "Bead" files.
- **Responsibility:** Monitors the `active_investigations/` directory for stalled Beads and re-assigns them or alerts a human.

### Persistent Sub-Agents ("Crew/Polecats")
Sub-agents (e.g., `soc_analyst_tier1`, `threat_hunter`) will operate within the standardized workspace.
- **Workflow:**
    1.  Check out a Bead (task).
    2.  Perform investigation steps (queries, analysis).
    3.  Write findings to the Bead file or associated artifact files.
    4.  Commit changes to the case branch.
    5.  Mark Bead as COMPLETE.

## Implementation Roadmap

### Phase 1: Task Reification ("Beads")
- Define a `Bead` schema (YAML) for SOC tasks.
- Example:
  ```yaml
  bead_id: "gt-abc12"
  type: "triage"
  target: "alert-12345"
  assigned_to: "soc_analyst_tier1"
  status: "pending"
  irp_context: "compromised_user_account_response"
  ```
- Update `manager` to generate these files when an IRP is triggered.

### Phase 2: Workspace & Persistence
- Create a `WorkspaceManager` tool/utility.
- Implement automatic git committing after key agent actions (e.g., "Report Written", "Query Executed").

### Phase 3: Dashboard & Review
- Leverage the structured file system to build a simple dashboard (or use standard Git tools) to visualize the progress of an investigation.

## Conclusion
By adopting the "Propulsion Principle" and "Beads", we can transform our SOC agents from ephemeral runtime entities into a robust, auditable, and resilient "Investigation as Code" platform.
