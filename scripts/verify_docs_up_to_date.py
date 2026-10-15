#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Any
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "multi-agent"))


@dataclass(frozen=True)
class DocContractSpec:
    rel_path: str
    required_substrings: tuple[str, ...] = ()
    forbidden_substrings: tuple[str, ...] = ()
    require_frontmatter_related: tuple[str, ...] = ()


DOC_CONTRACTS: dict[str, DocContractSpec] = {
    "docs/adk_graph_workflows_overview.md": DocContractSpec(
        rel_path="docs/adk_graph_workflows_overview.md",
        required_substrings=(
            "ADK Graph Workflows",
            "docs/drive_runbooks_overview.md",
            "docs/grounded_docs_review_overview.md",
            "DriveSkillRegistry",
            "275 passing unit tests",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./skills_progressive_disclosure_overview.md",
            "./progressive_mcp_discovery_overview.md",
            "../rules-bank/multi_agent_overview.md",
            "./drive_runbooks_overview.md",
            "./grounded_docs_review_overview.md",
        ),
    ),
    "docs/blog_grounded_google_docs_runbooks.md": DocContractSpec(
        rel_path="docs/blog_grounded_google_docs_runbooks.md",
        required_substrings=(
            "H30",
            "BENCH-16",
            "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
            "83 / 83",
            "33 / 33",
            "SKILLRL-10-CAPSTONE-PRODUCTION-GOVERNANCE-GATE",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./drive_runbooks_overview.md",
            "./grounded_docs_review_overview.md",
            "./adk_graph_workflows_overview.md",
            "./evolution_ledger.md",
        ),
    ),
    "docs/blog_knowledge_catalog_decoupled_soar_stores.md": DocContractSpec(
        rel_path="docs/blog_knowledge_catalog_decoupled_soar_stores.md",
        required_substrings=(
            "Knowledge Catalog",
            "GOLD_CRITICAL",
            "select_active_case_store",
            "alloydb.secops.detection_reports",
            "neo4j.secops.knowledge_graph",
            "elasticsearch.secops.agentic_soc_runbooks",
            "655216118709.global.overview",
            "655216118709.global.schema",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./blog_grounded_google_docs_runbooks.md",
            "./grounded_docs_review_overview.md",
            "./drive_runbooks_overview.md",
        ),
    ),
    "docs/drive_runbooks_overview.md": DocContractSpec(
        rel_path="docs/drive_runbooks_overview.md",
        required_substrings=(
            "DriveSkillRegistry",
            "62 local",
            "63",
            "## 5. Grounded Google Docs review and Markdown sync",
            "export_accepted_doc_to_markdown",
            "verify_post_accept_secops_doc_readiness",
            "tests/test_drive_registry.py",
            "tests/test_drive_publish.py",
            "tests/test_seed_drive_runbooks.py",
            "direnv exec . env RUNBOOK_SOURCE=local .venv/bin/python -m pytest tests/ -q",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./skills_progressive_disclosure_overview.md",
            "./progressive_mcp_discovery_overview.md",
            "./grounded_docs_review_overview.md",
            "./blog_grounded_google_docs_runbooks.md",
            "./evolution_ledger.md",
        ),
    ),
    "docs/evolution_ledger.md": DocContractSpec(
        rel_path="docs/evolution_ledger.md",
        required_substrings=(
            "autonomous evolutionary cycles",
            "`H1` through `H30`",
            "tests/test_drive_registry.py",
            "tests/test_drive_publish.py",
            "tests/test_seed_drive_runbooks.py",
            "H30_CAPSTONE_PRODUCTION_GOVERNANCE_AND_KEV_EXPOSURE_CATALOG",
            "pillar_count = 5",
            "CAPSTONE_PRODUCTION_GOVERNANCE_AND_EXPOSURE",
            "275 passed",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(),
    ),
    "docs/grounded_docs_review_overview.md": DocContractSpec(
        rel_path="docs/grounded_docs_review_overview.md",
        required_substrings=(
            "H28_CAPABILITY_PILLAR_CATALOG",
            "pillar_count = 5",
            "H30_CAPSTONE_PRODUCTION_GOVERNANCE_AND_KEV_EXPOSURE_CATALOG",
            "CAPSTONE_PRODUCTION_GOVERNANCE_AND_EXPOSURE",
            "275 passed",
            "174 in `tests/test_docs_review_tools.py`",
            "8 in `tests/test_grounding_tools.py`",
            "26 in `tests/test_drive_registry.py`",
            "17 in `tests/test_drive_publish.py`",
            "6 in `tests/test_seed_drive_runbooks.py`",
            "cycle28_yaral2_export_and_post_accept_verification_report.json",
            "cycle29_h30_capstone_governance_verification_report.json",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./drive_runbooks_overview.md",
            "./skills_progressive_disclosure_overview.md",
            "./progressive_mcp_discovery_overview.md",
            "./blog_grounded_google_docs_runbooks.md",
            "./evolution_ledger.md",
            "./overnight_handoff_argolis_soar_grounded_docs.md",
        ),
    ),
    "docs/nine_hour_evolution_plan.md": DocContractSpec(
        rel_path="docs/nine_hour_evolution_plan.md",
        required_substrings=(
            "## 3. Execution outcome and verification summary (Cycles 1 to 29, Horizons H1 to H30)",
            "29 autonomous cycles",
            "H1 to H30",
            "pillar_count = 5",
            "H28_CAPABILITY_PILLAR_CATALOG",
            "H30_CAPSTONE_PRODUCTION_GOVERNANCE_AND_KEV_EXPOSURE_CATALOG",
            "CAPSTONE_PRODUCTION_GOVERNANCE_AND_EXPOSURE",
            "BENCH-01 to BENCH-16",
            "83 / 83 seeded defects",
            "33 / 33 negative controls",
            "F1 = 1.0000",
            "SKILLRL-01",
            "SKILLRL-10",
            "275 passed",
            "174 in `tests/test_docs_review_tools.py`",
            "8 in `tests/test_grounding_tools.py`",
            "26 in `tests/test_drive_registry.py`",
            "17 in `tests/test_drive_publish.py`",
            "6 in `tests/test_seed_drive_runbooks.py`",
            "0 new Google Docs in Night 2",
            "1xWqRXooknTaEUVKyjjWYE1tHsRxES6B86y8cDf1csEE",
            "./evolution_ledger.md",
            "./blog_grounded_google_docs_runbooks.md",
            "./grounded_docs_review_overview.md",
            "./overnight_handoff_argolis_soar_grounded_docs.md",
            "cycle28_yaral2_export_and_post_accept_verification_report.json",
            "cycle29_h30_capstone_governance_verification_report.json",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(),
    ),
    "docs/overnight_handoff_argolis_soar_grounded_docs.md": DocContractSpec(
        rel_path="docs/overnight_handoff_argolis_soar_grounded_docs.md",
        required_substrings=(
            "275 passed",
            "BENCH-01",
            "BENCH-16",
            "63",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(),
    ),
    "docs/progressive_mcp_discovery_overview.md": DocContractSpec(
        rel_path="docs/progressive_mcp_discovery_overview.md",
        required_substrings=(
            "Progressive MCP Tool Discovery",
            "docs/drive_runbooks_overview.md",
            "docs/grounded_docs_review_overview.md",
            "DriveSkillRegistry",
            "275 passing unit tests",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./skills_progressive_disclosure_overview.md",
            "./adk_graph_workflows_overview.md",
            "./superpowers/specs/2026-08-20-progressive-discovery-mcp-design.md",
            "./drive_runbooks_overview.md",
            "./grounded_docs_review_overview.md",
        ),
    ),
    "docs/skills_progressive_disclosure_comparison_report.md": DocContractSpec(
        rel_path="docs/skills_progressive_disclosure_comparison_report.md",
        required_substrings=(
            "Skills Progressive Disclosure Architecture",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./skills_progressive_disclosure_overview.md",
            "./adk_graph_workflows_overview.md",
            "./drive_runbooks_overview.md",
            "./grounded_docs_review_overview.md",
        ),
    ),
    "docs/skills_progressive_disclosure_overview.md": DocContractSpec(
        rel_path="docs/skills_progressive_disclosure_overview.md",
        required_substrings=(
            "Skills & Progressive Disclosure Framework",
            "docs/drive_runbooks_overview.md",
            "docs/grounded_docs_review_overview.md",
            "DriveSkillRegistry",
            "275 passing unit tests",
        ),
        forbidden_substrings=("tests/test_drive_runbooks.py",),
        require_frontmatter_related=(
            "./skills_progressive_disclosure_comparison_report.md",
            "./progressive_mcp_discovery_overview.md",
            "./adk_graph_workflows_overview.md",
            "./superpowers/specs/2026-08-20-convert-runbooks-to-skills-progressive-disclosure-design.md",
            "./drive_runbooks_overview.md",
            "./grounded_docs_review_overview.md",
        ),
    ),
}

PATH_REGEX = re.compile(
    r'(?:^|[\s`"(])((?:tests|scripts|multi-agent|docs|skills|evals)/[A-Za-z0-9_./-]+\.(?:py|md|json))'
)


def verify_ground_truth_metrics(violations: list[str]) -> dict[str, Any]:
    from manager.tools.docs_review_tools import generate_master_evolution_synthesis_report
    from skills.registry import SkillRegistry
    from evals.registry import WORKFLOW_REGISTRY

    report = generate_master_evolution_synthesis_report()
    expected_metrics = {
        "total_cycles_completed": 29,
        "total_horizons_delivered": 30,
        "pillar_count": 5,
        "scenario_count": 16,
        "total_seeded_defects": 83,
        "total_negative_controls": 33,
        "skillrl_rule_count": 10,
        "micro_f1": 1.0,
        "pass2_idempotency_rate": 1.0,
    }

    for key, expected_val in expected_metrics.items():
        actual_val = report.get(key)
        if actual_val != expected_val:
            violations.append(
                f"Ground-truth metric mismatch: {key} expected {expected_val!r}, got {actual_val!r}"
            )

    reg = SkillRegistry()
    unique_skills = {s.path: s for s in reg.skills.values()}
    categories = {s.category for s in unique_skills.values()}
    if len(categories) != 8:
        violations.append(
            f"SkillRegistry categories count expected 8, got {len(categories)}"
        )
    if len(unique_skills) not in (62, 63, 64):
        violations.append(
            f"SkillRegistry unique skills count expected 62, 63, or 64, got {len(unique_skills)}"
        )

    if len(WORKFLOW_REGISTRY) != 36:
        violations.append(
            f"WORKFLOW_REGISTRY count expected 36, got {len(WORKFLOW_REGISTRY)}"
        )

    return {
        "report_metrics": expected_metrics,
        "skills_count": len(unique_skills),
        "categories_count": len(categories),
        "workflow_registry_count": len(WORKFLOW_REGISTRY),
    }


def parse_frontmatter(content: str) -> dict[str, Any] | None:
    if not content.startswith("---"):
        return None
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        data = yaml.safe_load(parts[1])
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def verify_doc_contracts(docs_dir: Path, violations: list[str]) -> int:
    top_level_files = sorted(docs_dir.glob("*.md"))
    checked_count = 0

    for md_file in top_level_files:
        rel_key = f"docs/{md_file.name}"
        contract = DOC_CONTRACTS.get(rel_key)
        if contract is None:
            violations.append(f"No DocContractSpec defined for {rel_key}")
            continue

        checked_count += 1
        content = md_file.read_text(encoding="utf-8")

        for req in contract.required_substrings:
            if req not in content:
                violations.append(
                    f"{rel_key} missing required substring: {req!r}"
                )

        for forb in contract.forbidden_substrings:
            if forb in content:
                violations.append(
                    f"{rel_key} contains forbidden substring: {forb!r}"
                )

        fm = parse_frontmatter(content)
        related_list = fm.get("related", []) if fm else []
        for req_rel in contract.require_frontmatter_related:
            if req_rel not in related_list:
                violations.append(
                    f"{rel_key} frontmatter missing required related link: {req_rel!r}"
                )

    return checked_count


def verify_frontmatter_links(docs_dir: Path, violations: list[str]) -> int:
    link_count = 0
    for md_file in sorted(docs_dir.glob("*.md")):
        content = md_file.read_text(encoding="utf-8")
        fm = parse_frontmatter(content)
        if not fm:
            continue
        related = fm.get("related", [])
        if not isinstance(related, list):
            continue
        for target_rel in related:
            link_count += 1
            resolved = (md_file.parent / target_rel).resolve()
            if not resolved.exists():
                violations.append(
                    f"{md_file.name}: frontmatter related link {target_rel!r} does not exist at {resolved}"
                )
    return link_count


def verify_explicit_paths(docs_dir: Path, repo_root: Path, violations: list[str]) -> int:
    checked_paths = 0
    for md_file in sorted(docs_dir.glob("*.md")):
        content = md_file.read_text(encoding="utf-8")
        for match in PATH_REGEX.finditer(content):
            path_str = match.group(1)
            if "*" in path_str or "{" in path_str or "<" in path_str:
                continue
            checked_paths += 1
            target = repo_root / path_str
            if not target.exists():
                violations.append(
                    f"{md_file.name}: referenced path does not exist on disk: {path_str}"
                )
    return checked_paths


def verify_json_reports(docs_dir: Path, violations: list[str]) -> dict[str, Any]:
    c28_path = docs_dir / "cycle28_yaral2_export_and_post_accept_verification_report.json"
    c29_path = docs_dir / "cycle29_h30_capstone_governance_verification_report.json"

    if not c28_path.exists():
        violations.append(f"Missing {c28_path}")
        return {}
    if not c29_path.exists():
        violations.append(f"Missing {c29_path}")
        return {}

    try:
        c28 = json.loads(c28_path.read_text(encoding="utf-8"))
    except Exception as e:
        violations.append(f"Failed to parse {c28_path.name}: {e}")
        c28 = {}

    try:
        c29 = json.loads(c29_path.read_text(encoding="utf-8"))
    except Exception as e:
        violations.append(f"Failed to parse {c29_path.name}: {e}")
        c29 = {}

    if c28.get("cycle") != 28 or c28.get("horizon_id") != "H29":
        violations.append(
            f"cycle28 report expected cycle=28, horizon=H29; got cycle={c28.get('cycle')}, horizon={c28.get('horizon_id')}"
        )
    if c28.get("bench15_evaluation", {}).get("TP") != 5:
        violations.append("cycle28 report bench15 TP != 5")
    if c28.get("full_benchmark_suite", {}).get("scenario_count") != 15:
        violations.append("cycle28 report scenario_count != 15")
    if c28.get("skillrl_distillation_matrix", {}).get("rule_count") != 9:
        violations.append("cycle28 report skillrl rule_count != 9")

    if c29.get("cycle") != 29 or c29.get("horizon_id") != "H30":
        violations.append(
            f"cycle29 report expected cycle=29, horizon=H30; got cycle={c29.get('cycle')}, horizon={c29.get('horizon_id')}"
        )
    if c29.get("bench16_evaluation", {}).get("TP") != 5:
        violations.append("cycle29 report bench16 TP != 5")
    if c29.get("full_benchmark_suite", {}).get("scenario_count") != 16:
        violations.append("cycle29 report scenario_count != 16")
    if c29.get("full_benchmark_suite", {}).get("TP") != 83:
        violations.append("cycle29 report full_benchmark_suite TP != 83")
    if c29.get("full_benchmark_suite", {}).get("TN") != 33:
        violations.append("cycle29 report full_benchmark_suite TN != 33")
    if c29.get("skillrl_distillation_matrix", {}).get("rule_count") != 10:
        violations.append("cycle29 report skillrl rule_count != 10")
    if c29.get("master_evolution_synthesis", {}).get("pillar_count") != 5:
        violations.append("cycle29 report master_evolution_synthesis pillar_count != 5")

    return {
        "cycle28": {
            "cycle": c28.get("cycle"),
            "horizon": c28.get("horizon_id"),
            "scenarios": c28.get("full_benchmark_suite", {}).get("scenario_count"),
        },
        "cycle29": {
            "cycle": c29.get("cycle"),
            "horizon": c29.get("horizon_id"),
            "scenarios": c29.get("full_benchmark_suite", {}).get("scenario_count"),
            "tp": c29.get("full_benchmark_suite", {}).get("TP"),
            "tn": c29.get("full_benchmark_suite", {}).get("TN"),
        },
    }


def main() -> int:
    violations: list[str] = []
    docs_dir = REPO_ROOT / "docs"

    ground_truth = verify_ground_truth_metrics(violations)
    doc_contracts_checked = verify_doc_contracts(docs_dir, violations)
    frontmatter_links_checked = verify_frontmatter_links(docs_dir, violations)
    paths_checked = verify_explicit_paths(docs_dir, REPO_ROOT, violations)
    json_reports = verify_json_reports(docs_dir, violations)

    summary = {
        "status": "PASSED" if not violations else "FAILED",
        "doc_contracts_checked": doc_contracts_checked,
        "frontmatter_links_checked": frontmatter_links_checked,
        "explicit_paths_checked": paths_checked,
        "ground_truth": ground_truth,
        "json_reports": json_reports,
        "violations_count": len(violations),
        "violations": violations,
    }

    print(json.dumps(summary, indent=2))
    return 0 if not violations else 1


if __name__ == "__main__":
    sys.exit(main())
