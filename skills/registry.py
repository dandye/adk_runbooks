"""Centralized Skill Registry and Parsing Engine."""

from dataclasses import dataclass
import logging
from pathlib import Path
import re
import yaml

logger = logging.getLogger(__name__)


@dataclass
class SkillMetadata:
    """Metadata representing a skill parsed from SKILL.md frontmatter."""

    name: str
    description: str
    category: str
    path: Path
    version: str = "1.0.0"


class SkillRegistry:
    """Central registry for discovering, parsing, and serving skill instructions."""

    def __init__(self, skills_dir: Path | str | None = None):
        if skills_dir is None:
            self.skills_dir = Path(__file__).resolve().parent
        else:
            self.skills_dir = Path(skills_dir).resolve()
        self.skills: dict[str, SkillMetadata] = {}
        self.scan_skills()

    def reload(self) -> dict[str, SkillMetadata]:
        """Alias to re-scan and reload all skills dynamically from disk."""
        return self.scan_skills()

    def scan_skills(self) -> dict[str, SkillMetadata]:
        """Recursively scan skills directory for SKILL.md files and index metadata."""
        self.skills.clear()
        if not self.skills_dir.exists():
            return self.skills

        for skill_path in self.skills_dir.rglob("SKILL.md"):
            try:
                content = skill_path.read_text(encoding="utf-8")
                metadata = self._parse_frontmatter(content, skill_path)
                if metadata:
                    self.skills[metadata.name] = metadata
                    # Register alternative name format (hyphen <-> underscore)
                    alt_hyphen = metadata.name.replace("_", "-")
                    if alt_hyphen != metadata.name:
                        self.skills[alt_hyphen] = metadata
                    alt_underscore = metadata.name.replace("-", "_")
                    if alt_underscore != metadata.name:
                        self.skills[alt_underscore] = metadata
            except Exception as e:
                logger.warning("Failed to parse skill at %s: %s", skill_path, e)
        return self.skills

    def _parse_frontmatter(self, content: str, path: Path) -> SkillMetadata | None:
        """Extract YAML frontmatter and construct SkillMetadata."""
        match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        if not match:
            folder_name = path.parent.name
            category = path.parent.parent.name if path.parent.parent != path.parent else ""
            return SkillMetadata(
                name=folder_name,
                description=f"Skill for {folder_name}",
                category=category,
                path=path,
                version="1.0.0",
            )

        fm_text = match.group(1)
        try:
            fm_data = yaml.safe_load(fm_text) or {}
        except Exception:
            fm_data = {}

        if not isinstance(fm_data, dict):
            fm_data = {}

        name = fm_data.get("name", path.parent.name)
        description = str(fm_data.get("description", "")).strip()
        category = fm_data.get("category", path.parent.parent.name if path.parent.parent != path.parent else "")
        version = str(fm_data.get("version", "1.0.0"))

        return SkillMetadata(
            name=name,
            description=description,
            category=category,
            path=path,
            version=version,
        )

    def get_skill(self, name: str) -> SkillMetadata | None:
        """Retrieve skill metadata by name with hyphen/underscore normalization."""
        norm_name = name.strip()
        if norm_name in self.skills:
            return self.skills[norm_name]
        alt_hyphen = norm_name.replace("_", "-")
        if alt_hyphen in self.skills:
            return self.skills[alt_hyphen]
        alt_underscore = norm_name.replace("-", "_")
        if alt_underscore in self.skills:
            return self.skills[alt_underscore]
        return None

    def get_skill_content(self, name: str) -> str:
        """Retrieve full markdown content of a skill."""
        meta = self.get_skill(name)
        if not meta or not meta.path.exists():
            return f"Error: Skill '{name}' not found in registry."
        return meta.path.read_text(encoding="utf-8")

    def get_skill_catalog(self, skill_names: list[str] | None = None) -> str:
        """Generate formatted Markdown catalog for system prompt injection."""
        lines = [
            "### Available Skills (Progressive Disclosure)",
            "You have access to the following skills. When assigned a matching task or when a trigger condition is met, call the `load_skill(skill_name)` tool to retrieve complete step-by-step procedures before execution:\n",
        ]
        items: list[SkillMetadata] = []
        seen: set[str] = set()

        if skill_names is not None:
            for s in skill_names:
                meta = self.get_skill(s)
                if meta and meta.name not in seen:
                    items.append(meta)
                    seen.add(meta.name)
        else:
            for meta in self.skills.values():
                if meta.name not in seen:
                    items.append(meta)
                    seen.add(meta.name)

        if not items:
            return ""

        for item in sorted(items, key=lambda x: (x.category, x.name)):
            lines.append(f"- **`{item.name}`**: {item.description}")

        return "\n".join(lines)

    def list_skills_by_category(self, category: str) -> list[SkillMetadata]:
        """List all unique skills belonging to a specific category."""
        seen: set[str] = set()
        matched: list[SkillMetadata] = []
        for meta in self.skills.values():
            if meta.category == category and meta.name not in seen:
                matched.append(meta)
                seen.add(meta.name)
        return sorted(matched, key=lambda x: x.name)
