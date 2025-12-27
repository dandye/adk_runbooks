# Adaptation Strategy for ADK Multi-Agent System

Based on the paper ["Adaptation of Agentic AI" (arXiv:2512.16301)](file:///usr/local/google/home/dandye/Projects/adk_runbooks__worktrees/adaptation/adaptation_of_agentic_ai_2512.16301v2.pdf), this document outlines a plan to integrate advanced adaptation mechanisms into the current ADK project.

## 1. Theoretical Framework (The 2x2 Matrix)

The paper introduces a unified framework categorizing adaptation into four paradigms:

| Optimization Target | **Tool Execution Signaled (A1)** | **Agent Output Signaled (A2)** |
| :--- | :--- | :--- |
| **Agent Adaptation** | **A1**: Optimize agent via verifiable tool outcomes (e.g., code execution success, retrieval stats). | **A2**: Optimize agent via final output quality (e.g., answer correctness, self-correction). |
| **Tool Adaptation** | **T1**: Train tools independently (Agent-Agnostic). | **T2**: Train/Optimize tools to serve a *frozen* agent (Agent-Supervised). |

## 2. Current Project State

The current project (`adk_runbooks`) is a **Manager-Subagent** system where:
*   **Agent**: The `manager` (and subagents) are powered by frozen foundation models (e.g., Gemini 1.5/2.0). We generally *cannot* fine-tune these models parameters directly (Constraints of APIs).
*   **Tools**:
    *   **Core**: The **Subagents** themselves (CTI, Detection, etc.) and the **Rules Bank** (Personas, Runbooks).
    *   **Integrations**: We have initialized the `mcp-security` submodule, providing real-world capabilities (Chronicle, SOAR, GTI, SCC). This removes the previous limitation of "mocked" outcomes.

**Diagnosis**: The current system is static. Runbooks and Personas are fixed markdown files. Agents do not learn from their successes or failures.

## 3. Integration Plan: Moving to "Self-Evolving Agents"

We will implement a hybrid **T2 (Tool Adaptation)** and **A2 (Agent Output Signaled)** strategy, leveraging the fact that our "tools" (prompts/runbooks) are editable text.

### Phase 1: T2 - "Adaptive Memory" & "Runbook Optimization"

*Concept*: Treat the `rules-bank` not as static code, but as a "Tool" that can be optimized by the frozen agent.
*Paper Reference*: Section 5.2.3 (Memory as T2) and 5.2 (Agent-Supervised Tool Adaptation).

**Implementation:**
1.  **Feedback Loop & Signal**: With `mcp-security` tools now available, the `manager` can execute *real* runbooks (e.g., "Search Chronicle for IOC X"). The verifiable outcome (Success/Failure/Empty Results) is the **Optimization Signal** (A1/T1).
    *   *Example*: If a UDM search syntax failure is returned by the `secops_mcp`, this provides concrete feedback to refine the Runbook.
2.  **Runbook Refiner Tool**: Create a new tool `update_runbook` or `annotate_runbook`.
3.  **Workflow**:
    *   If a step in a Runbook was confusing or led to a sub-optimal subagent call, the Manager uses the *Feedback* to rewrite that specific section of the markdown file.
    *   *Mechanism*: The "Frozen Agent" (Manager) supervises the adaptation of the "Tool" (Runbook).

### Phase 2: A2 - "Self-Correction" & "Critic" Loop

*Concept*: Optimize the agent's *output* (the final report) via an internal feedback loop before finalizing.
*Paper Reference*: Section 4.2.1 (Self-Refine, TextGrad).

**Implementation:**
1.  **LLM Judge Integration**: The newly added `llm_judge` agent is the *perfect* external verifier for this phase.
    *   Instead of just self-critique, the Manager can proactively ask the `llm_judge` to "Grade this draft report against the rubric" *before* finalizing it.
2.  **Refinement**: The Manager updates its context/plan based on the Judge's feedback.
3.  **Optimization Signal**: The "Signal" is the explicit rubric score and feedback from the Judge (A2-style), providing a Ground Truth proxy for optimization.

### Phase 3: T2 - "Subagent-as-Tool" Specialization

*Concept*: Treat Subagents as specialized tools that are "trained" (prompt-tuned) by the Manager.
*Paper Reference*: Section 5.2.2 (Subagent-as-Tool).

**Implementation:**
1.  **Dynamic Personas**: Instead of static `personas/*.md`, allow the Manager to append "Learning Notes" to a subagent's persona.
    *   *Example*: If `cti_researcher` consistently fails to find specific attributes of a threat actor, the Manager adds a note to its system prompt: "ALWAYS check for X, Y, Z when researching actor groups."
2.  **Mechanism**: A `update_persona_instructions` tool available to the Manager.

## 4. Proposed Roadmap

1.  **Immediate**: Implement **Phase 2 (Self-Critic)** as it requires no structural changes, just workflow logic in `manager/agent.py`.
2.  **Short-Term**: Implement **Phase 1 (Runbook Refiner)**. Add a `post_mortem` phase where the `llm_judge`'s evaluation feeds into the runbook update process.
3.  **Long-Term**: Build a "Learning Module" that aggregates these changes (like the "Orion" or "ACE" examples in the paper) to prevent "Context Pollution" by keeping only high-value updates.

## 5. Justification

*   **Why T2?**: As noted in Section 6.4, T2 is more data-efficient (70x reduction) and modular. We can evolve the *Runbooks* (Tools) without retraining the Gemini model (Agent).
*   **Why A2?**: Self-correction (A2 without tools) improves reasoning reliability on complex tasks like Incident Response.
