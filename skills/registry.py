"""Centralized Skill Registry and Parsing Engine."""

from dataclasses import dataclass, field
import logging
from pathlib import Path
import re
from typing import Any
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
    adk_additional_tools: list[str] = field(default_factory=list)


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

        raw_meta = fm_data.get("metadata")
        additional_tools: list[str] = []
        if isinstance(raw_meta, dict) and isinstance(raw_meta.get("adk_additional_tools"), list):
            additional_tools = [str(t) for t in raw_meta["adk_additional_tools"] if t]
        elif isinstance(fm_data.get("adk_additional_tools"), list):
            additional_tools = [str(t) for t in fm_data["adk_additional_tools"] if t]

        return SkillMetadata(
            name=name,
            description=description,
            category=category,
            path=path,
            version=version,
            adk_additional_tools=additional_tools,
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

    def load_adk_skills(self, skill_names: list[str] | None = None) -> list[Any]:
        """Load native google.adk.skills.models.Skill instances from the skills directory."""
        from google.adk.skills import load_skills_from_dir
        from google.adk.skills.models import Frontmatter, Skill

        allowed: set[str] | None = None
        if skill_names is not None:
            allowed = set()
            for s in skill_names:
                meta = self.get_skill(s)
                if meta:
                    allowed.add(meta.name)
                else:
                    allowed.add(s)

        loaded_skills: list[Skill] = []
        seen_names: set[str] = set()

        if self.skills_dir.exists():
            for cat_dir in sorted(self.skills_dir.iterdir()):
                if cat_dir.is_dir() and not cat_dir.name.startswith((".", "_")) and cat_dir.name != "scripts":
                    try:
                        skills_in_cat = load_skills_from_dir(cat_dir)
                        for sk in skills_in_cat:
                            if allowed is not None and sk.name not in allowed:
                                continue
                            if sk.name not in seen_names:
                                loaded_skills.append(sk)
                                seen_names.add(sk.name)
                    except Exception as e:
                        logger.debug("Fallback to SkillMetadata for %s: %s", cat_dir, e)

        # Fallback for any skills not loaded via load_skills_from_dir
        for meta in sorted(self.skills.values(), key=lambda x: x.name):
            if meta.name in seen_names:
                continue
            if allowed is not None and meta.name not in allowed:
                continue
            raw_content = meta.path.read_text(encoding="utf-8") if meta.path.exists() else ""
            m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", raw_content, re.DOTALL)
            instructions = m.group(2).strip() if m else raw_content
            sk = Skill(
                name=meta.name,
                description=meta.description,
                instructions=instructions,
                frontmatter=Frontmatter(
                    name=meta.name,
                    description=meta.description,
                    metadata={"adk_additional_tools": list(meta.adk_additional_tools)}
                    if meta.adk_additional_tools
                    else {},
                ),
            )
            loaded_skills.append(sk)
            seen_names.add(meta.name)

        return loaded_skills

    def build_skill_toolset(
        self,
        additional_tools: list[Any] | None = None,
        skill_names: list[str] | None = None,
    ) -> Any:
        """Construct a native ADK SkillToolset with dynamic tool binding."""
        from google.adk.tools.skill_toolset import SkillToolset

        skills = self.load_adk_skills(skill_names=skill_names)
        return SkillToolset(
            skills=skills,
            additional_tools=additional_tools or [],
        )
