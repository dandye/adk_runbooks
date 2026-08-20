import pytest
from pathlib import Path
from unittest.mock import patch

from manager.tools.tools import (
    global_skill_registry,
    load_skill,
    list_available_skills,
    load_persona_with_skills_catalog,
    load_persona_and_runbooks,
    get_agent_tools,
)
from skills.registry import SkillRegistry


def test_load_skill_existing_and_missing(tmp_path: Path):
    # Setup test skill in tmp_path
    skill_dir = tmp_path / "triage" / "triage-alerts"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: triage-alerts\n"
        "description: Assessing incoming security alerts.\n"
        "category: triage\n"
        "---\n\n"
        "# Alert Triage Instructions\n1. Inspect alert."
    )

    test_registry = SkillRegistry(skills_dir=tmp_path)

    with patch("manager.tools.tools.global_skill_registry", test_registry):
        # Existing skill
        content = load_skill("triage-alerts")
        assert "# Alert Triage Instructions" in content
        assert "1. Inspect alert." in content

        # Normalization (underscore)
        content_und = load_skill("triage_alerts")
        assert "# Alert Triage Instructions" in content_und

        # Missing skill
        missing = load_skill("unknown-skill")
        assert "Error: Skill 'unknown-skill' not found in registry." in missing

    # Check docstring
    assert load_skill.__doc__ is not None
    assert "skill" in load_skill.__doc__.lower()


def test_list_available_skills(tmp_path: Path):
    triage_dir = tmp_path / "triage" / "triage-alerts"
    triage_dir.mkdir(parents=True)
    (triage_dir / "SKILL.md").write_text(
        "---\nname: triage-alerts\ndescription: Triage alert desc.\ncategory: triage\n---\n# T1"
    )

    hunt_dir = tmp_path / "hunting" / "hunt-ttp"
    hunt_dir.mkdir(parents=True)
    (hunt_dir / "SKILL.md").write_text(
        "---\nname: hunt-ttp\ndescription: Hunt TTP desc.\ncategory: hunting\n---\n# H1"
    )

    test_registry = SkillRegistry(skills_dir=tmp_path)

    with patch("manager.tools.tools.global_skill_registry", test_registry):
        # List all
        all_skills = list_available_skills()
        assert "triage-alerts" in all_skills
        assert "hunt-ttp" in all_skills

        # List with category
        triage_skills = list_available_skills(category="triage")
        assert "triage-alerts" in triage_skills
        assert "hunt-ttp" not in triage_skills

        # List with non-existent category
        empty_cat = list_available_skills(category="nonexistent")
        assert "nonexistent" in empty_cat or "No skills" in empty_cat

    # Check docstring
    assert list_available_skills.__doc__ is not None


def test_load_persona_with_skills_catalog(tmp_path: Path):
    # Setup persona file
    persona_file = tmp_path / "persona.md"
    persona_file.write_text("# SOC Analyst Persona\nYou are a helpful analyst.")

    # Setup skills
    skill_dir = tmp_path / "skills" / "triage" / "alert-triage"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: alert-triage\ndescription: Triage alerts.\ncategory: triage\n---\n# Triage"
    )

    test_registry = SkillRegistry(skills_dir=tmp_path / "skills")

    with patch("manager.tools.tools.global_skill_registry", test_registry):
        # With existing persona file and skill filter
        combined = load_persona_with_skills_catalog(
            persona_file_path=str(persona_file),
            skill_names=["alert-triage"]
        )
        assert "# SOC Analyst Persona" in combined
        assert "### Available Skills (Progressive Disclosure)" in combined
        assert "alert-triage" in combined

        # With missing persona file -> fallback to default description
        missing_persona = tmp_path / "non_existent_persona.md"
        fallback = load_persona_with_skills_catalog(
            persona_file_path=str(missing_persona),
            skill_names=["alert-triage"],
            default_persona_description="Default analyst description."
        )
        assert "Default analyst description." in fallback
        assert "alert-triage" in fallback

        # With skill_names=None (all skills)
        all_combined = load_persona_with_skills_catalog(
            persona_file_path=str(persona_file),
            skill_names=None
        )
        assert "# SOC Analyst Persona" in all_combined
        assert "alert-triage" in all_combined


def test_load_persona_and_runbooks_backward_compatibility(tmp_path: Path):
    persona_file = tmp_path / "persona.md"
    persona_file.write_text("# Persona Header")

    rb1 = tmp_path / "rb1.md"
    rb1.write_text("# Runbook 1")

    res = load_persona_and_runbooks(str(persona_file), [str(rb1)])
    assert "# Persona Header" in res
    assert "# Runbook 1" in res


def test_get_agent_tools_includes_skill_tools():
    tools = get_agent_tools()
    tool_names = [getattr(t, "__name__", str(t)) for t in tools]

    # Both wrapped_load_skill and wrapped_list_available_skills should be included
    assert any("load_skill" in name for name in tool_names)
    assert any("list_available_skills" in name for name in tool_names)
