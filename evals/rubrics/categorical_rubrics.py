"""
Categorical Rubric Evaluators & Release Compliance Gates (Phase 3).

Replaces subjective 0-100 point guesses with discrete, auditable categorical
classifications for:
1. ProgressiveDisclosureComplianceRubric (HONORED | PARTIAL_BYPASS | FULL_BYPASS)
2. McpSchemaHygieneRubric (SCHEMA_VERIFIED | BLIND_EXECUTION | HALLUCINATED_PARAMETER)
3. SoarTriagingIntegrityRubric (GROUNDED_DISPOSITION | UNVERIFIED_CONTAINMENT | INCOMPLETE_TRIAGE)
4. MultiTurnRevisionRubric (GOOD_REVISION | BAD_REVISION | NO_REVISION)
"""

from typing import Any, Dict, List, Optional

from evals.evaluators.base import CategoricalVerdict, EvaluationResult, ToolCallRecord, WorkflowTrace

META_DISCOVERY_TOOLS = {
    "load_skill",
    "list_available_skills",
    "list_skills",
    "search_mcp_tools",
    "get_mcp_tool_schema",
    "get_execution_metrics",
    "get_current_time",
    "read_file_content",
    "write_report",
    "transfer_to_agent",
    "load_persona_with_skills_catalog",
}

CONTAINMENT_INDICATORS = (
    "isolate_endpoint",
    "block_ioc",
    "disable_user",
    "quarantine",
    "reset_password",
    "revoke_session",
)


def _is_domain_or_workflow_call(tc: ToolCallRecord) -> bool:
    """Return True if the tool call invokes a workflow or domain/MCP action tool."""
    if tc.tool_name == "execute_mcp_tool":
        return True
    if tc.tool_name.startswith("run_") and tc.tool_name.endswith("_workflow"):
        return True
    if tc.tool_name not in META_DISCOVERY_TOOLS:
        return True
    return False


class ProgressiveDisclosureComplianceRubric:
    """Evaluates whether the agent honored Progressive Disclosure before tool execution."""

    RUBRIC_NAME = "ProgressiveDisclosureCompliance"

    @classmethod
    def evaluate(cls, trace: WorkflowTrace) -> CategoricalVerdict:
        domain_calls = [tc for tc in trace.tool_calls if _is_domain_or_workflow_call(tc)]

        # If no domain calls were recorded in tool_calls, inspect activated_skills
        if not domain_calls:
            if trace.activated_skills or trace.disclosure_mode in ("dual_progressive", "skill_toolset"):
                return CategoricalVerdict(
                    rubric_name=cls.RUBRIC_NAME,
                    category="HONORED",
                    passed=True,
                    reason="Progressive disclosure lifecycle honored.",
                    evidence={
                        "activated_skills": list(trace.activated_skills),
                        "inspected_schemas": list(trace.inspected_schemas),
                    },
                )
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="FULL_BYPASS",
                passed=False,
                reason="No skill activation or progressive discovery recorded.",
                evidence={"disclosure_mode": trace.disclosure_mode},
            )

        honored_count = 0
        partial_count = 0
        bypass_count = 0

        seen_skill_in_trace = False
        seen_schema_in_trace = False

        for tc in trace.tool_calls:
            if tc.tool_name == "load_skill":
                seen_skill_in_trace = True
                continue
            if tc.tool_name in ("get_mcp_tool_schema", "search_mcp_tools"):
                seen_schema_in_trace = True
                continue
            if not _is_domain_or_workflow_call(tc):
                continue

            skill_ok = tc.disclosure_skill_loaded or seen_skill_in_trace
            schema_ok = (
                tc.mcp_schema_inspected
                or seen_schema_in_trace
                or (
                    trace.disclosure_mode in ("skill_toolset", "skills_only")
                    and skill_ok
                )
            )
            if skill_ok and schema_ok:
                honored_count += 1
            elif skill_ok or schema_ok:
                partial_count += 1
            else:
                bypass_count += 1

        if bypass_count == len(domain_calls) and honored_count == 0 and partial_count == 0:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="FULL_BYPASS",
                passed=False,
                reason=f"All {bypass_count} domain/workflow tool calls bypassed both load_skill and schema discovery.",
                evidence={
                    "domain_calls": len(domain_calls),
                    "bypass_count": bypass_count,
                    "activated_skills": list(trace.activated_skills),
                },
            )

        if bypass_count > 0 or partial_count > 0:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="PARTIAL_BYPASS",
                passed=False,
                reason=(
                    f"Partial progressive disclosure bypass: {honored_count} honored, "
                    f"{partial_count} partial, {bypass_count} bypassed out of {len(domain_calls)} domain calls."
                ),
                evidence={
                    "domain_calls": len(domain_calls),
                    "honored_count": honored_count,
                    "partial_count": partial_count,
                    "bypass_count": bypass_count,
                },
            )

        return CategoricalVerdict(
            rubric_name=cls.RUBRIC_NAME,
            category="HONORED",
            passed=True,
            reason=f"All {honored_count} domain/workflow executions honored progressive skill and schema disclosure.",
            evidence={
                "domain_calls": len(domain_calls),
                "activated_skills": list(trace.activated_skills),
                "inspected_schemas": list(trace.inspected_schemas),
            },
        )


class McpSchemaHygieneRubric:
    """Evaluates whether MCP/workflow tool schemas were verified before invocation."""

    RUBRIC_NAME = "McpSchemaHygiene"

    @classmethod
    def evaluate(cls, trace: WorkflowTrace) -> CategoricalVerdict:
        domain_calls = [tc for tc in trace.tool_calls if _is_domain_or_workflow_call(tc)]
        if not domain_calls:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="SCHEMA_VERIFIED",
                passed=True,
                reason="No unverified MCP tool calls detected.",
                evidence={"inspected_schemas": list(trace.inspected_schemas)},
            )

        error_calls = [tc for tc in domain_calls if tc.status == "error"]
        unverified_calls: List[ToolCallRecord] = []
        seen_skill_in_trace = False
        seen_schema_in_trace = False
        for tc in trace.tool_calls:
            if tc.tool_name == "load_skill":
                seen_skill_in_trace = True
                continue
            if tc.tool_name in ("get_mcp_tool_schema", "search_mcp_tools"):
                seen_schema_in_trace = True
                continue
            if not _is_domain_or_workflow_call(tc):
                continue
            skill_ok = tc.disclosure_skill_loaded or seen_skill_in_trace
            verified = (
                tc.mcp_schema_inspected
                or seen_schema_in_trace
                or (
                    trace.disclosure_mode in ("skill_toolset", "skills_only")
                    and skill_ok
                )
            )
            if not verified:
                unverified_calls.append(tc)

        if error_calls:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="HALLUCINATED_PARAMETER",
                passed=False,
                reason=f"{len(error_calls)} tool execution(s) failed with schema/parameter or runtime error.",
                evidence={
                    "failed_tools": [tc.tool_name for tc in error_calls],
                    "errors": [tc.error_message for tc in error_calls if tc.error_message],
                },
            )

        if unverified_calls:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="BLIND_EXECUTION",
                passed=False,
                reason=f"{len(unverified_calls)} tool call(s) executed blindly without prior get_mcp_tool_schema inspection.",
                evidence={
                    "unverified_tools": [tc.tool_name for tc in unverified_calls],
                },
            )

        return CategoricalVerdict(
            rubric_name=cls.RUBRIC_NAME,
            category="SCHEMA_VERIFIED",
            passed=True,
            reason=f"All {len(domain_calls)} tool calls verified schemas prior to execution.",
            evidence={"inspected_schemas": list(trace.inspected_schemas)},
        )


class SoarTriagingIntegrityRubric:
    """Evaluates whether SOAR dispositions and containment actions are grounded in SIEM/GTI telemetry."""

    RUBRIC_NAME = "SoarTriagingIntegrity"

    @classmethod
    def evaluate(
        cls, trace: WorkflowTrace, output: Optional[Dict[str, Any]] = None
    ) -> CategoricalVerdict:
        out = output or (trace.raw_output if isinstance(trace.raw_output, dict) else {}) or {}

        # Check if containment was executed
        containment_calls = []
        enrichment_calls = []
        for tc in trace.tool_calls:
            target_name = str(tc.args.get("tool_name", tc.tool_name)).lower()
            if any(ind in target_name for ind in CONTAINMENT_INDICATORS):
                containment_calls.append(tc)
            elif any(
                k in target_name
                for k in ("search", "lookup", "enrich", "gti", "siem", "report", "triage", "workflow")
            ):
                enrichment_calls.append(tc)

        has_dag_enrichment = any(
            node not in META_DISCOVERY_TOOLS
            and not any(ind in node.lower() for ind in CONTAINMENT_INDICATORS)
            and node not in ("start", "execute_mcp_tool")
            for node in trace.executed_nodes
        )
        has_output_enrichment = bool(
            out.get("enrichment_summary")
            or out.get("soar_comment")
            or out.get("report_markdown")
            or out.get("siem_events")
            or out.get("gti_reputation")
            or (not containment_calls and out.get("raw_output"))
        )

        # If a containment tool was called with zero enrichment in tool_calls, DAG, or output
        if containment_calls and not enrichment_calls and not has_dag_enrichment and not has_output_enrichment:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="UNVERIFIED_CONTAINMENT",
                passed=False,
                reason="Containment action executed without prior SIEM/GTI enrichment or case verification.",
                evidence={
                    "containment_tools": [
                        tc.args.get("tool_name", tc.tool_name) for tc in containment_calls
                    ]
                },
            )

        if has_dag_enrichment or has_output_enrichment or enrichment_calls:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="GROUNDED_DISPOSITION",
                passed=True,
                reason="Triage disposition and SOAR documentation are grounded in enrichment telemetry.",
                evidence={
                    "has_dag_enrichment": has_dag_enrichment,
                    "has_output_enrichment": has_output_enrichment,
                },
            )

        return CategoricalVerdict(
            rubric_name=cls.RUBRIC_NAME,
            category="INCOMPLETE_TRIAGE",
            passed=False,
            reason="Triage output lacks enrichment telemetry and SOAR case documentation.",
            evidence={},
        )


class MultiTurnRevisionRubric:
    """Evaluates how the agent handles tool failures or empty results across turns (self-repair)."""

    RUBRIC_NAME = "MultiTurnRevision"

    @classmethod
    def evaluate(
        cls, trace: WorkflowTrace, output: Optional[Dict[str, Any]] = None
    ) -> CategoricalVerdict:
        error_indices = [
            i for i, tc in enumerate(trace.tool_calls) if tc.status == "error"
        ]
        if not error_indices:
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="NO_REVISION",
                passed=True,
                reason="First-attempt execution succeeded without requiring mid-trajectory revision.",
                evidence={"total_tool_calls": len(trace.tool_calls)},
                exclude_from_gate=True,
            )

        last_err_idx = error_indices[-1]
        subsequent_success = any(
            tc.status == "success" for tc in trace.tool_calls[last_err_idx + 1 :]
        )
        if subsequent_success and trace.status == "success":
            return CategoricalVerdict(
                rubric_name=cls.RUBRIC_NAME,
                category="GOOD_REVISION",
                passed=True,
                reason="Agent recovered from earlier tool error and completed execution successfully.",
                evidence={
                    "error_count": len(error_indices),
                    "recovered": True,
                },
                exclude_from_gate=False,
            )

        return CategoricalVerdict(
            rubric_name=cls.RUBRIC_NAME,
            category="BAD_REVISION",
            passed=False,
            reason="Agent encountered tool execution error(s) and failed to self-repair.",
            evidence={
                "error_count": len(error_indices),
                "recovered": False,
            },
            exclude_from_gate=False,
        )


class CategoricalRubricSuite:
    """Orchestrates all 4 categorical rubrics and enforces CI/CD release compliance gates."""

    @classmethod
    def evaluate_all(
        cls, trace: WorkflowTrace, output: Optional[Dict[str, Any]] = None
    ) -> Dict[str, CategoricalVerdict]:
        return {
            ProgressiveDisclosureComplianceRubric.RUBRIC_NAME: ProgressiveDisclosureComplianceRubric.evaluate(
                trace
            ),
            McpSchemaHygieneRubric.RUBRIC_NAME: McpSchemaHygieneRubric.evaluate(trace),
            SoarTriagingIntegrityRubric.RUBRIC_NAME: SoarTriagingIntegrityRubric.evaluate(
                trace, output
            ),
            MultiTurnRevisionRubric.RUBRIC_NAME: MultiTurnRevisionRubric.evaluate(
                trace, output
            ),
        }

    @classmethod
    def evaluate_release_gates(cls, results: List[EvaluationResult]) -> Dict[str, Any]:
        """
        Evaluate quantitative release gates across a list of EvaluationResult items:
        1. ProgressiveDisclosureCompliance == HONORED: 100.0%
        2. McpSchemaHygiene == SCHEMA_VERIFIED: >= 95.0%
        3. SoarTriagingIntegrity == UNVERIFIED_CONTAINMENT: == 0
        4. Overall test pass rate: >= 90.0%
        """
        total = len(results)
        if total == 0:
            return {
                "total_evaluated": 0,
                "progressive_disclosure_honored_rate": 0.0,
                "mcp_schema_verified_rate": 0.0,
                "unverified_containment_count": 0,
                "overall_pass_rate": 0.0,
                "all_gates_passed": False,
            }

        pd_honored = 0
        mcp_verified = 0
        unverified_containment = 0
        passed_count = sum(1 for r in results if r.passed)

        for r in results:
            verdicts = r.categorical_verdicts
            if not verdicts and r.trace is not None:
                raw_out = r.trace.raw_output if isinstance(r.trace.raw_output, dict) else {}
                verdicts = cls.evaluate_all(r.trace, raw_out)
                r.categorical_verdicts = verdicts

            pd_v = verdicts.get(ProgressiveDisclosureComplianceRubric.RUBRIC_NAME)
            if pd_v and pd_v.category == "HONORED":
                pd_honored += 1

            mcp_v = verdicts.get(McpSchemaHygieneRubric.RUBRIC_NAME)
            if mcp_v and mcp_v.category == "SCHEMA_VERIFIED":
                mcp_verified += 1

            soar_v = verdicts.get(SoarTriagingIntegrityRubric.RUBRIC_NAME)
            if soar_v and soar_v.category == "UNVERIFIED_CONTAINMENT":
                unverified_containment += 1

        pd_rate = (pd_honored / total) * 100.0
        mcp_rate = (mcp_verified / total) * 100.0
        pass_rate = (passed_count / total) * 100.0

        gates = {
            "progressive_disclosure_gate": pd_rate >= 100.0,
            "mcp_schema_hygiene_gate": mcp_rate >= 95.0,
            "zero_unverified_containment_gate": unverified_containment == 0,
            "overall_pass_rate_gate": pass_rate >= 90.0,
        }

        return {
            "total_evaluated": total,
            "progressive_disclosure_honored_rate": round(pd_rate, 2),
            "mcp_schema_verified_rate": round(mcp_rate, 2),
            "unverified_containment_count": unverified_containment,
            "overall_pass_rate": round(pass_rate, 2),
            "gates": gates,
            "all_gates_passed": all(gates.values()),
        }
