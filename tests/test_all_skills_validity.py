import pytest
from pathlib import Path
from skills.registry import SkillRegistry


EXPECTED_CATEGORIES = {
    "triage": [
        "triage-alerts",
        "suspicious-login-triage",
        "malware-triage",
        "basic-endpoint-triage-isolation",
        "cloud-vulnerability-triage",
    ],
    "irps": [
        "compromised-user-account-response",
        "phishing-response",
        "ransomware-response",
        "malware-incident-response",
    ],
    "investigation": [
        "basic-ioc-enrichment",
        "deep-dive-ioc-analysis",
        "investigate-case-external-tools",
        "prioritize-and-investigate-case",
        "close-duplicate-cases",
        "group-cases",
        "group-cases-v2",
        "case-event-timeline-analysis",
        "investigate-gti-collection",
        "compare-gti-collection",
        "ioc-containment",
    ],
    "hunting": [
        "advanced-threat-hunting",
        "apt-threat-hunt",
        "ioc-threat-hunt",
        "guided-ttp-hunt-credential-access",
        "lateral-movement-hunt-psexec-wmi",
        "proactive-hunt-gti-campaign",
    ],
    "detection": [
        "detection-rule-validation-tuning",
        "detection-as-code-workflows",
        "detection-as-code-rule-tuning",
    ],
    "reporting": [
        "create-investigation-report",
        "alert-report",
        "case-report",
        "detection-report",
        "report-writing-guidelines",
    ],
    "atomic": [
        "domain-get-gti-report",
        "domain-get-secops-threat-intel",
        "domain-lookup-entity-chronicle",
        "domain-search-dns-chronicle",
        "domain-search-network-traffic-chronicle",
        "ip-get-gti-report",
        "ip-get-secops-threat-intel",
        "ip-lookup-entity-chronicle",
        "ip-search-network-traffic-chronicle",
        "hash-get-gti-report",
        "hash-get-secops-threat-intel",
        "hash-lookup-entity-chronicle",
        "hash-search-process-events-chronicle",
        "url-get-gti-report",
        "url-get-secops-threat-intel",
        "url-search-chronicle",
        "user-lookup-entity-chronicle",
        "user-search-login-activity-chronicle",
        "user-search-process-activity-chronicle",
    ],
    "common": [
        "check-duplicate-cases",
        "enrich-ioc",
        "find-relevant-soar-case",
        "document-in-soar",
        "close-soar-artifact",
        "pivot-on-ioc-gti",
        "confirm-action",
        "generate-report-file",
        "correlate-ioc-with-alerts-cases",
    ],
}


def test_skills_directory_exists():
    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"
    assert skills_dir.exists() and skills_dir.is_dir()


def test_all_expected_skills_registered():
    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"
    registry = SkillRegistry(skills_dir=skills_dir)

    all_expected = [
        skill_name
        for skills in EXPECTED_CATEGORIES.values()
        for skill_name in skills
    ]
    assert len(registry.skills) >= 40, f"Expected at least 40 skills, got {len(registry.skills)}"

    for expected_name in all_expected:
        assert expected_name in registry.skills, f"Expected skill '{expected_name}' not registered in registry"
        meta = registry.get_skill(expected_name)
        assert meta is not None
        assert meta.name == expected_name


def test_every_skill_metadata_and_content_validity():
    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"
    registry = SkillRegistry(skills_dir=skills_dir)

    assert len(registry.skills) > 0, "No skills found in skills directory"

    # Iterate unique skill metadata objects
    seen_paths = set()
    for meta in registry.skills.values():
        if meta.path in seen_paths:
            continue
        seen_paths.add(meta.path)

        skill_name = meta.name

        # Directory name must match skill name
        assert meta.path.parent.name == skill_name, f"Dir name {meta.path.parent.name} != skill name {skill_name}"

        # Category must match directory structure (skills/<category>/<skill-name>/SKILL.md)
        expected_category = meta.path.parent.parent.name
        assert meta.category == expected_category, f"Skill {skill_name} category '{meta.category}' != expected '{expected_category}'"

        # Description must start with 'Use when'
        assert meta.description.startswith("Use when"), f"Skill {skill_name} description must start with 'Use when', got: '{meta.description}'"
        assert len(meta.description) <= 250, f"Skill {skill_name} description must be concise (< 250 chars), got {len(meta.description)}"

        # Content must be non-empty and contain markdown headers
        content = registry.get_skill_content(skill_name)
        assert content, f"Skill {skill_name} has empty content"
        assert not content.startswith("Error:"), f"Skill {skill_name} content error: {content}"
        assert "#" in content, f"Skill {skill_name} content missing markdown headings"
