"""Tests verifying SkillToolset dynamic binding with adk_additional_tools (Issue #74 Spike).

Validates:
1. Candidate tools in additional_tools remain hidden from agent schemas before skill activation.
2. Invoking load_skill records activation in state and dynamically exposes declared tools.
3. BaseToolset (MCPToolset) integration with prefixing resolves correctly.
4. Missing tool declarations in adk_additional_tools are handled gracefully.
5. Hierarchical skill taxonomy parsing across category subdirectories.
"""

import asyncio
from pathlib import Path
from typing import Any, Optional
import pytest

from google.adk.agents import Agent
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.skills import load_skills_from_dir
from google.adk.skills.models import Skill, Frontmatter
from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.base_toolset import BaseToolset
from google.adk.tools.skill_toolset import SkillToolset
from google.adk.tools.tool_context import ToolContext


def mock_vt_ip_report(ip_address: str) -> str:
    """Mock VirusTotal report tool."""
    return f"VT Clean: {ip_address}"


def mock_chronicle_search(query: str) -> str:
    """Mock Chronicle search tool."""
    return f"Chronicle Results: {query}"


def mock_soar_create_case(title: str) -> str:
    """Mock SOAR case creation tool."""
    return f"Case created: {title}"


class MockSiemToolset(BaseToolset):
    """Mock SIEM Toolset with prefix support."""

    def __init__(self, prefix: Optional[str] = "secops-mcp"):
        super().__init__(tool_name_prefix=prefix)
        self._tools = [
            FunctionTool(func=mock_chronicle_search),
        ]

    async def get_tools(self, readonly_context: Optional[ReadonlyContext] = None) -> list[BaseTool]:
        return list(self._tools)


class MockContext:
    """Mock execution context for ReadonlyContext and ToolContext."""

    def __init__(self, agent_name: str = "soc_analyst"):
        self.agent_name = agent_name
        self.invocation_id = "test-inv-001"
        self.state: dict[str, Any] = {}
        self.session: dict[str, Any] = {}
        self.custom_metadata: dict[str, Any] = {}
        self.run_config: Any = None
        self.user_content: Any = None
        self.user_id: str = "test-user"


def test_skill_toolset_hides_candidate_tools_before_activation():
    """Verify candidate tools in additional_tools are not exposed before skill activation."""
    async def _run():
        tool_vt = FunctionTool(func=mock_vt_ip_report)
        tool_soar = FunctionTool(func=mock_soar_create_case)

        skill = Skill(
            name="triage-skill",
            description="Triage skill",
            instructions="Step 1: Check IP",
            frontmatter=Frontmatter(
                name="triage-skill",
                description="Triage skill",
                metadata={"adk_additional_tools": ["mock_vt_ip_report"]},
            ),
        )

        skill_toolset = SkillToolset(
            skills=[skill],
            additional_tools=[tool_vt, tool_soar],
        )

        agent = Agent(
            name="soc_analyst",
            model="gemini-2.5-flash",
            tools=[skill_toolset],
        )

        ctx = MockContext(agent_name="soc_analyst")
        tools = await agent.canonical_tools(ctx)
        tool_names = [t.name for t in tools]

        # Verify standard skill tools are present
        assert "load_skill" in tool_names
        assert "list_skills" in tool_names

        # Verify candidate tools are completely hidden
        assert "mock_vt_ip_report" not in tool_names
        assert "mock_soar_create_case" not in tool_names

    asyncio.run(_run())


def test_skill_toolset_activates_declared_tools_on_load_skill():
    """Verify calling load_skill triggers dynamic tool binding only for declared tools."""
    async def _run():
        tool_vt = FunctionTool(func=mock_vt_ip_report)
        tool_soar = FunctionTool(func=mock_soar_create_case)

        skill_triage = Skill(
            name="triage-skill",
            description="Triage skill",
            instructions="Step 1: Check IP",
            frontmatter=Frontmatter(
                name="triage-skill",
                description="Triage skill",
                metadata={"adk_additional_tools": ["mock_vt_ip_report"]},
            ),
        )
        skill_containment = Skill(
            name="containment-skill",
            description="Containment skill",
            instructions="Step 1: Open SOAR case",
            frontmatter=Frontmatter(
                name="containment-skill",
                description="Containment skill",
                metadata={"adk_additional_tools": ["mock_soar_create_case"]},
            ),
        )

        skill_toolset = SkillToolset(
            skills=[skill_triage, skill_containment],
            additional_tools=[tool_vt, tool_soar],
        )

        agent = Agent(
            name="soc_analyst",
            model="gemini-2.5-flash",
            tools=[skill_toolset],
        )

        ctx = MockContext(agent_name="soc_analyst")

        # 1. Activate triage-skill
        tools_0 = await agent.canonical_tools(ctx)
        load_tool = next(t for t in tools_0 if t.name == "load_skill")
        resp = await load_tool.run_async(args={"skill_name": "triage-skill"}, tool_context=ctx)
        assert resp["skill_name"] == "triage-skill"

        # Verify state key
        assert ctx.state.get("_adk_activated_skill_soc_analyst") == ["triage-skill"]

        # 2. Check canonical tools after triage-skill activation
        tools_1 = await agent.canonical_tools(ctx)
        names_1 = [t.name for t in tools_1]

        assert "mock_vt_ip_report" in names_1
        assert "mock_soar_create_case" not in names_1  # Still hidden

        # 3. Activate containment-skill
        await load_tool.run_async(args={"skill_name": "containment-skill"}, tool_context=ctx)
        assert ctx.state.get("_adk_activated_skill_soc_analyst") == ["triage-skill", "containment-skill"]

        # 4. Check canonical tools after both activations
        tools_2 = await agent.canonical_tools(ctx)
        names_2 = [t.name for t in tools_2]

        assert "mock_vt_ip_report" in names_2
        assert "mock_soar_create_case" in names_2

    asyncio.run(_run())


def test_skill_toolset_prefixed_toolset_resolution():
    """Verify toolsets with prefixes (e.g. MCPToolset) resolve when declared with prefix."""
    async def _run():
        siem_toolset = MockSiemToolset(prefix="secops-mcp")

        skill = Skill(
            name="prefixed-triage",
            description="Prefixed triage",
            instructions="Query SIEM",
            frontmatter=Frontmatter(
                name="prefixed-triage",
                description="Prefixed triage",
                metadata={"adk_additional_tools": ["secops-mcp_mock_chronicle_search"]},
            ),
        )

        skill_toolset = SkillToolset(
            skills=[skill],
            additional_tools=[siem_toolset],
        )

        agent = Agent(name="soc_analyst", tools=[skill_toolset])
        ctx = MockContext("soc_analyst")

        tools_init = await agent.canonical_tools(ctx)
        assert "secops-mcp_mock_chronicle_search" not in [t.name for t in tools_init]

        # Activate
        load_tool = next(t for t in tools_init if t.name == "load_skill")
        await load_tool.run_async(args={"skill_name": "prefixed-triage"}, tool_context=ctx)

        tools_active = await agent.canonical_tools(ctx)
        assert "secops-mcp_mock_chronicle_search" in [t.name for t in tools_active]

    asyncio.run(_run())


def test_skill_toolset_missing_tool_graceful_handling():
    """Verify missing tools in adk_additional_tools do not raise exceptions."""
    async def _run():
        skill = Skill(
            name="missing-tool-skill",
            description="Missing tool",
            instructions="Do something",
            frontmatter=Frontmatter(
                name="missing-tool-skill",
                description="Missing tool",
                metadata={"adk_additional_tools": ["non_existent_tool_xyz"]},
            ),
        )

        skill_toolset = SkillToolset(skills=[skill], additional_tools=[])
        ctx = MockContext("soc_analyst")

        tools = await skill_toolset.get_tools(ctx)
        load_tool = next(t for t in tools if t.name == "load_skill")
        await load_tool.run_async(args={"skill_name": "missing-tool-skill"}, tool_context=ctx)

        tools_after = await skill_toolset.get_tools(ctx)
        assert "non_existent_tool_xyz" not in [t.name for t in tools_after]
        assert "load_skill" in [t.name for t in tools_after]

    asyncio.run(_run())


def test_hierarchical_skills_loading():
    """Verify that all 63 project skills load cleanly across category subdirectories."""
    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"

    assert skills_dir.exists(), "skills directory must exist"

    all_skills: list[Skill] = []
    categories_found = []

    for cat_dir in sorted(skills_dir.iterdir()):
        if cat_dir.is_dir() and not cat_dir.name.startswith((".", "_")):
            loaded = load_skills_from_dir(cat_dir)
            if loaded:
                categories_found.append(cat_dir.name)
                all_skills.extend(loaded)

    assert len(all_skills) >= 60, f"Expected at least 60 skills, got {len(all_skills)}"
    assert "triage" in categories_found
    assert "investigation" in categories_found
    assert "atomic" in categories_found

    # Verify no duplicate skill names
    names = [s.name for s in all_skills]
    assert len(names) == len(set(names)), "Skill names must be globally unique across categories"
