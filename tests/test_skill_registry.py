import pytest
from pathlib import Path
from skills.registry import SkillRegistry, SkillMetadata


def test_registry_scan_and_load(tmp_path: Path):
    triage_dir = tmp_path / "triage" / "triage-alerts"
    triage_dir.mkdir(parents=True)
    skill_file = triage_dir / "SKILL.md"
    skill_file.write_text(
        "---\n"
        "name: triage-alerts\n"
        "description: Use when assessing incoming security alerts.\n"
        "category: triage\n"
        "version: 1.2.0\n"
        "---\n\n"
        "# Alert Triage\n\nStep 1: Inspect alert."
    )

    registry = SkillRegistry(skills_dir=tmp_path)
    assert "triage-alerts" in registry.skills
    meta = registry.get_skill("triage-alerts")
    assert meta is not None
    assert meta.name == "triage-alerts"
    assert meta.category == "triage"
    assert meta.version == "1.2.0"
    assert "Use when assessing" in meta.description

    # Test underscore access
    meta_underscore = registry.get_skill("triage_alerts")
    assert meta_underscore is not None
    assert meta_underscore.name == "triage-alerts"

    # Test catalog generation with filter
    catalog = registry.get_skill_catalog(["triage-alerts"])
    assert "### Available Skills (Progressive Disclosure)" in catalog
    assert "- **`triage-alerts`**: Use when assessing incoming security alerts." in catalog

    # Test content loading
    content = registry.get_skill_content("triage-alerts")
    assert "# Alert Triage" in content
    assert "Step 1: Inspect alert." in content


def test_registry_scan_without_frontmatter_fallback(tmp_path: Path):
    cat_dir = tmp_path / "investigation" / "memory-analysis"
    cat_dir.mkdir(parents=True)
    skill_file = cat_dir / "SKILL.md"
    skill_file.write_text("# Memory Analysis\n\nInstructions without frontmatter.")

    registry = SkillRegistry(skills_dir=tmp_path)
    assert "memory-analysis" in registry.skills
    meta = registry.get_skill("memory-analysis")
    assert meta is not None
    assert meta.name == "memory-analysis"
    assert meta.category == "investigation"
    assert meta.description == "Skill for memory-analysis"
    assert meta.version == "1.0.0"


def test_registry_normalization_and_lookup(tmp_path: Path):
    dir1 = tmp_path / "remediation" / "isolate-host"
    dir1.mkdir(parents=True)
    (dir1 / "SKILL.md").write_text(
        "---\n"
        "name: isolate-host\n"
        "description: Use when isolating compromised hosts.\n"
        "category: remediation\n"
        "---\n\n"
        "# Isolate Host"
    )

    registry = SkillRegistry(skills_dir=tmp_path)
    assert registry.get_skill("isolate-host") is not None
    assert registry.get_skill("isolate_host") is not None
    assert registry.get_skill(" isolate-host ") is not None
    assert registry.get_skill("non-existent") is None


def test_registry_catalog_generation(tmp_path: Path):
    dir1 = tmp_path / "cat_b" / "skill-b"
    dir1.mkdir(parents=True)
    (dir1 / "SKILL.md").write_text(
        "---\n"
        "name: skill-b\n"
        "description: Skill B description.\n"
        "category: b_cat\n"
        "---\n# B"
    )
    dir2 = tmp_path / "cat_a" / "skill-a"
    dir2.mkdir(parents=True)
    (dir2 / "SKILL.md").write_text(
        "---\n"
        "name: skill-a\n"
        "description: Skill A description.\n"
        "category: a_cat\n"
        "---\n# A"
    )

    registry = SkillRegistry(skills_dir=tmp_path)

    # Full catalog (no filter) - should sort by category then name
    full_catalog = registry.get_skill_catalog()
    assert "### Available Skills (Progressive Disclosure)" in full_catalog
    lines = full_catalog.strip().split("\n")
    skill_lines = [l for l in lines if l.startswith("- **`")]
    assert len(skill_lines) == 2
    assert "skill-a" in skill_lines[0]
    assert "skill-b" in skill_lines[1]

    # Filtered catalog with duplicates and alternative names
    filtered = registry.get_skill_catalog(["skill_a", "skill-a"])
    filtered_lines = [l for l in filtered.strip().split("\n") if l.startswith("- **`")]
    assert len(filtered_lines) == 1
    assert "skill-a" in filtered_lines[0]

    # Empty registry catalog
    empty_registry = SkillRegistry(skills_dir=tmp_path / "empty_dir")
    assert empty_registry.get_skill_catalog() == ""


def test_registry_get_skill_content_error_handling(tmp_path: Path):
    registry = SkillRegistry(skills_dir=tmp_path)
    content = registry.get_skill_content("missing-skill")
    assert content == "Error: Skill 'missing-skill' not found in registry."


def test_registry_list_skills_by_category(tmp_path: Path):
    dir1 = tmp_path / "cat1" / "skill-1"
    dir1.mkdir(parents=True)
    (dir1 / "SKILL.md").write_text(
        "---\nname: skill-1\ndescription: Desc 1\ncategory: cat1\n---\n# S1"
    )
    dir2 = tmp_path / "cat2" / "skill-2"
    dir2.mkdir(parents=True)
    (dir2 / "SKILL.md").write_text(
        "---\nname: skill-2\ndescription: Desc 2\ncategory: cat2\n---\n# S2"
    )

    registry = SkillRegistry(skills_dir=tmp_path)
    cat1_skills = registry.list_skills_by_category("cat1")
    assert len(cat1_skills) == 1
    assert cat1_skills[0].name == "skill-1"
    assert registry.list_skills_by_category("nonexistent") == []
