import asyncio
from pathlib import Path
import sys
import pytest

# Ensure dac-agent is on sys.path
dac_agent_dir = Path(__file__).resolve().parent.parent / "dac-agent"
if str(dac_agent_dir) not in sys.path:
    sys.path.insert(0, str(dac_agent_dir))

from agent import initialize_actual_dac_agent, root_agent, get_root_agent
from tools.tools import (
    load_skill,
    list_available_skills,
    load_persona_with_skills_catalog,
    load_persona_and_runbooks,
    get_dac_agent_tools,
)


def test_dac_agent_initialization():
    dac_agent = asyncio.run(initialize_actual_dac_agent())

    assert dac_agent is not None
    assert dac_agent.name == "dac_agent"
    assert "### Available Skills (Progressive Disclosure)" in dac_agent.description
    assert len(dac_agent.description) < 12000, f"DAC agent description too long ({len(dac_agent.description)} chars)"

    expected_skills = [
        "detection-as-code-rule-tuning",
        "detection-rule-validation-tuning",
        "detection-as-code-workflows",
        "report-writing-guidelines",
        "enrich-ioc",
        "document-in-soar",
        "generate-report-file",
    ]
    for skill in expected_skills:
        assert skill in dac_agent.description, f"Expected skill {skill} not found in dac_agent.description"

    tool_names = [getattr(t, "__name__", str(t)) for t in dac_agent.tools]
    assert any("load_skill" in name for name in tool_names), "load_skill tool missing from dac_agent"
    assert any("list_available_skills" in name for name in tool_names), "list_available_skills tool missing from dac_agent"


def test_dac_root_agent_deferred():
    assert root_agent.name == "dac_agent"
    agent = asyncio.run(get_root_agent())
    assert agent.name == "dac_agent"
    assert "### Available Skills (Progressive Disclosure)" in agent.description
    tool_names = [getattr(t, "__name__", str(t)) for t in agent.tools]
    assert any("load_skill" in name for name in tool_names)
    assert any("list_available_skills" in name for name in tool_names)


def test_dac_tools_skills_support(tmp_path: Path):
    persona_file = tmp_path / "persona.md"
    persona_file.write_text("# DAC Persona\nYou are a DAC agent.")

    combined = load_persona_with_skills_catalog(
        persona_file_path=str(persona_file),
        skill_names=["detection-as-code-rule-tuning"]
    )
    assert "# DAC Persona" in combined
    assert "### Available Skills (Progressive Disclosure)" in combined
    assert "detection-as-code-rule-tuning" in combined

    # Test load_skill tool
    content = load_skill("detection-as-code-rule-tuning")
    assert "Detection-as-Code" in content or "detection" in content.lower()

    # Test list_available_skills tool
    catalog = list_available_skills()
    assert "detection-as-code-rule-tuning" in catalog


def test_dac_legacy_load_persona_and_runbooks(tmp_path: Path):
    persona_file = tmp_path / "persona.md"
    persona_file.write_text("# DAC Persona")
    rb_file = tmp_path / "rb.md"
    rb_file.write_text("# Runbook Content")

    res = load_persona_and_runbooks(str(persona_file), [str(rb_file)])
    assert "# DAC Persona" in res
    assert "# Runbook Content" in res
