# PR: Spike SkillToolset for Skill-Driven Dynamic MCP Tool Binding

**Target Branch:** `main`  
**Source Branch:** `issue-74-spike-skilltoolset`  
**Closes:** https://github.com/dandye/adk_runbooks/issues/74  

---

## Summary

This PR documents and tests the findings of the **SkillToolset Spike** ([#74](https://github.com/dandye/adk_runbooks/issues/74)).

The spike evaluates Google ADK 2.7.1's native `google.adk.tools.skill_toolset.SkillToolset` and the `adk_additional_tools` frontmatter metadata mechanism to achieve context-level lazy loading for Model Context Protocol (MCP) security tools.

---

## Key Findings

1. **Native Lazy Loading Confirmed:**
   * Candidate MCP tools provided to `SkillToolset(additional_tools=[...])` remain completely hidden from the agent's function declarations before skill activation.
   * Calling `load_skill(skill_name)` records the activation in session state (`_adk_activated_skill_{agent_name}`).
   * Subsequent LLM turns (via `LlmAgent.canonical_tools(ctx)`) dynamically resolve and expose the declared `adk_additional_tools` with first-class Gemini JSON schema declarations.

2. **Resolution of Prompt & Multi-Hop Latency:**
   * **Versus Static Binding:** Eliminates prompt schema bloat (from 30+ tool declarations down to the 4 core skill tools).
   * **Versus Progressive MCP Discovery (`search_mcp_tools`/`execute_mcp_tool`):** Eliminates 3 multi-turn discovery roundtrips (`search` → `get_schema` → `execute`) and restores native Gemini JSON Schema validation instead of untyped `dict` arguments.

3. **Prefix & Toolset Compatibility:**
   * Toolsets with prefixes (such as `MCPToolset(..., tool_name_prefix="secops-mcp")`) resolve cleanly when `adk_additional_tools` specifies the prefixed name (e.g. `secops-mcp_search_security_events`).
   * Missing tools declared in skills are handled gracefully without breaking agent execution.
   * Hierarchical skill categories (`skills/<category>/<skill>/SKILL.md`) parse cleanly when loaded across category directories.

---

## Deliverables Included

1. **Architecture Overview Documentation:**
   * `docs/skill_toolset_dynamic_binding_overview.md`: Complete architecture overview, data flow diagrams, comparison scorecard, and adoption roadmap.
2. **Dedicated Test Suite:**
   * `tests/test_skill_toolset_spike.py`: 5 automated tests verifying tool hiding, dynamic activation upon `load_skill`, prefixed toolset resolution, graceful handling of missing tools, and hierarchical taxonomy parsing across all 63 skills.
3. **PR Description:**
   * `PULL_REQUEST_DESCRIPTION.md`: Updated with spike findings and evidence.

---

## Verification Evidence

* **Pytest Suite (`pytest tests/ -v`)**:
  * 49 passed (including 5 dedicated spike tests in `test_skill_toolset_spike.py`).
* **Eval Harness Suite (`pytest evals/tests/ -v`)**:
  * 25 passed, 71 subtests passed (100% pass rate).
