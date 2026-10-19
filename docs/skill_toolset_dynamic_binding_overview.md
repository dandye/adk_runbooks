# Spike Findings: Skill-Driven Dynamic Binding with ADK SkillToolset

**Issue Reference:** [Issue #74: spike SkillToolset](https://github.com/dandye/adk_runbooks/issues/74)  
**Branch:** `issue-74-spike-skilltoolset`  
**Status:** Spike Completed / Feasibility Confirmed  

---

## 1. Executive Summary

This spike investigates Google ADK 2.7.1's native `google.adk.tools.skill_toolset.SkillToolset` and the `adk_additional_tools` frontmatter metadata mechanism to evaluate whether it delivers context-level lazy loading and dynamic tool binding for Model Context Protocol (MCP) security tools.

### Verdict: Fully Feasible and Native

ADK 2.7.1 natively supports dynamic tool binding without requiring custom middleware or client-side meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`). 

* **Pre-Activation:** Candidate tools passed to `SkillToolset(additional_tools=[...])` remain completely hidden from the agent's function declaration schemas.
* **On-Demand Activation:** When an agent calls `load_skill(skill_name)`, ADK's `LoadSkillTool` marks the skill as active in session state (`_adk_activated_skill_{agent_name}`).
* **Dynamic Resolution:** On subsequent LLM turns (or next execution steps), `LlmAgent.canonical_tools(ctx)` calls `SkillToolset.get_tools()`, which extracts the tools listed under `adk_additional_tools` from the active skill's frontmatter and dynamically exposes them as strongly-typed native Gemini tool declarations.

---

## 2. Technical Architecture & Data Flow

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ 1. Initial Prompt (Turn 0)                                                  │
│    Agent Prompt only contains core skill tools:                             │
│    - list_skills                                                            │
│    - load_skill                                                             │
│    - load_skill_resource                                                    │
│    - run_skill_script                                                       │
│    [Candidate MCP tools: secops-mcp, soar-mcp, gti-mcp remain HIDDEN]       │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 2. Agent triggers runbook / skill:                                          │
│    Model invokes: load_skill(skill_name="suspicious-login-triage")          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 3. State Transition in LoadSkillTool:                                       │
│    - Loads SKILL.md body and frontmatter metadata.                          │
│    - Writes: tool_context.state["_adk_activated_skill_{agent}"] =           │
│              ["suspicious-login-triage"]                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 4. Next LLM Turn (Turn 1):                                                  │
│    canonical_tools(ctx) invokes SkillToolset.get_tools(readonly_context)    │
│    - Inspects active skills: ["suspicious-login-triage"]                    │
│    - Reads metadata: adk_additional_tools:                                  │
│        - "secops-mcp_search_security_events"                                │
│        - "gti-mcp_get_ip_address_report"                                    │
│        - "soar-mcp_get_case_full_details"                                   │
│    - Filters candidate toolsets and yields matched BaseTool instances.      │
│    - Model now has direct, strongly-typed JSON schema declarations!         │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Paradigm Comparison

| Metric / Dimension | Static Tool Binding (Baseline) | Progressive MCP Discovery (`progressive_discovery_mcp_v0001`) | Skill-Driven Dynamic Binding (`SkillToolset`) |
| :--- | :--- | :--- | :--- |
| **Initial Prompt Overhead** | **High** (30+ tools injected upfront: ~20k chars) | **Low** (3 meta-tools upfront: ~2.5k chars) | **Lowest** (4 core skill tools: ~1.9k chars) |
| **Turn Penalty per Tool Call** | 1 turn (Direct tool call) | 3 turns (`search` → `get_schema` → `execute`) | **1 turn** (Direct native tool call after `load_skill`) |
| **Schema Validation** | Gemini JSON Schema | Lost (`arguments: dict` unvalidated) | **Gemini JSON Schema** (Full compile-time & runtime validation) |
| **Hallucination Risk** | High (too many schemas in working context) | Low (tools queried intentionally) | **Lowest** (exact runbook tools dynamically bound) |
| **Maintenance Burden** | High (static tool lists across agents) | Medium (MCP registry reflection) | **Low** (tools declared in `SKILL.md` frontmatter) |

---

## 4. Key Spike Observations & Gotchas

1. **Prefixed Tool Names in Toolsets:**
   When passing toolsets with prefixes (e.g. `MCPToolset(..., tool_name_prefix="secops-mcp")`), the entries in `adk_additional_tools` must include the prefix:
   ```yaml
   metadata:
     adk_additional_tools:
       - secops-mcp_search_security_events
       - soar-mcp_get_case_full_details
   ```
2. **Missing Tool Resiliency:**
   If a skill declares a tool that is not present in the candidate toolsets, `SkillToolset._resolve_additional_tools_from_state` logs a debug/warning line and skips the missing tool without raising exceptions or breaking agent execution.
3. **Hierarchical Directory Discovery:**
   ADK's `google.adk.skills.load_skills_from_dir` is non-recursive (only inspects direct subdirectories). To load skills from `adk_runbooks`'s categorized layout (`skills/<category>/<skill>/SKILL.md`), the loader must iterate category directories:
   ```python
   all_skills = []
   for category in sorted(skills_dir.iterdir()):
       if category.is_dir() and not category.name.startswith(('.', '_')):
           all_skills.extend(load_skills_from_dir(category))
   ```
   All 63 existing skills in the repository parse cleanly.

---

## 5. Implementation Roadmap

To adopt `SkillToolset` as the primary tool-loading mechanism across `adk_runbooks`:

1. **Skill Frontmatter Enrichment:**
   Add `metadata.adk_additional_tools` lists to the frontmatter of the 33 skills that invoke MCP tools.
2. **Agent Toolset Refactoring:**
   Update `multi-agent/manager/agent.py` and the 8 sub-agent factories to instantiate `SkillToolset(skills=all_skills, additional_tools=[siem_toolset, soar_toolset, gti_toolset])`.
3. **Deprecation:**
   Remove the redundant meta-tools (`search_mcp_tools`, `get_mcp_tool_schema`, `execute_mcp_tool`) and simplify agent instructions.
