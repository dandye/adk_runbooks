"""
Script to enrich all SKILL.md packages with unified Skills + OKF frontmatter.
"""

from pathlib import Path
import re
import yaml

base_dir = Path(__file__).resolve().parent.parent.parent
skills_dir = base_dir / "skills"
rules_bank_dir = base_dir / "rules-bank" / "run_books"

# Map of legacy runbook frontmatter metadata by name
legacy_meta = {}
for p in rules_bank_dir.rglob("*.md"):
    try:
        content = p.read_text(encoding="utf-8")
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        if m:
            data = yaml.safe_load(m.group(1))
            if isinstance(data, dict):
                norm_key = p.stem.lower().replace("_", "-")
                legacy_meta[norm_key] = data
    except Exception:
        pass


def update_skills():
    count = 0
    for skill_file in sorted(skills_dir.rglob("SKILL.md")):
        content = skill_file.read_text(encoding="utf-8")
        m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
        if not m:
            continue
        
        raw_yaml = m.group(1)
        body = m.group(2)
        
        data = yaml.safe_load(raw_yaml)
        if not isinstance(data, dict):
            continue
            
        skill_name = data.get("name", skill_file.parent.name)
        norm_name = skill_name.lower().replace("_", "-")
        
        # Derive title
        first_h1_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
        if first_h1_match:
            raw_title = first_h1_match.group(1).strip()
            # If starts with Runbook: replace with Skill:
            if raw_title.startswith("Runbook:"):
                title = "Skill:" + raw_title[len("Runbook:"):]
            elif not raw_title.startswith("Skill:"):
                title = f"Skill: {raw_title}"
            else:
                title = raw_title
        elif norm_name in legacy_meta and "title" in legacy_meta[norm_name]:
            leg_title = legacy_meta[norm_name]["title"]
            if leg_title.startswith("Runbook:"):
                title = "Skill:" + leg_title[len("Runbook:"):]
            elif not leg_title.startswith("Skill:"):
                title = f"Skill: {leg_title}"
            else:
                title = leg_title
        else:
            title = f"Skill: {skill_name.replace('-', ' ').title()}"
            
        # Determine timestamp
        if norm_name in legacy_meta and isinstance(legacy_meta[norm_name].get("generated"), dict):
            gen_info = legacy_meta[norm_name]["generated"]
        else:
            gen_info = {
                "by": "process:google-labs-jules",
                "at": "2026-08-20T02:00:00Z"
            }
            
        new_frontmatter = {
            "name": skill_name,
            "description": data.get("description", ""),
            "category": data.get("category", skill_file.parent.parent.name),
            "version": data.get("version", "1.0.0"),
            "type": "Skill",
            "title": title,
            "generated": gen_info
        }
        
        # Format YAML cleanly
        yaml_str = yaml.dump(new_frontmatter, sort_keys=False, default_flow_style=False).strip()
        new_file_content = f"---\n{yaml_str}\n---\n\n{body.lstrip()}"
        
        skill_file.write_text(new_file_content, encoding="utf-8")
        count += 1
        print(f"[*] Updated {skill_file.relative_to(base_dir)} (Title: {title})")

    print(f"\n[+] Successfully updated {count} SKILL.md packages with unified Skills + OKF frontmatter.")


if __name__ == "__main__":
    update_skills()
