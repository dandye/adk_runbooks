"""
Script to update internal markdown references in skills/ from legacy runbook paths to new skills paths.
"""

from pathlib import Path
import re

base_dir = Path(__file__).resolve().parent.parent.parent
skills_dir = base_dir / "skills"

replacements = [
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/check_duplicate_cases\.md", "skills/common/check-duplicate-cases/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/close_soar_artifact\.md", "skills/common/close-soar-artifact/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/confirm_action\.md", "skills/common/confirm-action/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/correlate_ioc_with_alerts_cases\.md", "skills/common/correlate-ioc-with-alerts-cases/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/document_in_soar\.md", "skills/common/document-in-soar/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/enrich_ioc\.md", "skills/common/enrich-ioc/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/find_relevant_soar_case\.md", "skills/common/find-relevant-soar-case/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/generate_report_file\.md", "skills/common/generate-report-file/SKILL.md"),
    (r"(\.?\.?/)?(\.agentrules/run_books/)?common_steps/pivot_on_ioc_gti\.md", "skills/common/pivot-on-ioc-gti/SKILL.md"),
    (r"(\.?\.?/)?atomic_runbooks/domain/rb_domain_([a-z_]+)\.md", r"skills/atomic/domain-\1/SKILL.md"),
    (r"(\.?\.?/)?atomic_runbooks/ip_address/rb_ip_([a-z_]+)\.md", r"skills/atomic/ip-\1/SKILL.md"),
    (r"(\.?\.?/)?atomic_runbooks/hash/rb_hash_([a-z_]+)\.md", r"skills/atomic/hash-\1/SKILL.md"),
    (r"(\.?\.?/)?atomic_runbooks/url/rb_url_([a-z_]+)\.md", r"skills/atomic/url-\1/SKILL.md"),
    (r"(\.?\.?/)?atomic_runbooks/user/rb_user_([a-z_]+)\.md", r"skills/atomic/user-\1/SKILL.md"),
]


def update_references():
    count = 0
    for skill_file in sorted(skills_dir.rglob("SKILL.md")):
        text = skill_file.read_text(encoding="utf-8")
        orig_text = text
        for pattern, repl in replacements:
            text = re.sub(pattern, repl, text)
            # Fix any underscore in atomic replacements
            def fix_underscores(match):
                return match.group(0).replace("_", "-")
            text = re.sub(r"skills/atomic/[a-z0-9_-]+/SKILL\.md", fix_underscores, text)
        if text != orig_text:
            skill_file.write_text(text, encoding="utf-8")
            count += 1
            print(f"[*] Updated references in {skill_file.relative_to(base_dir)}")
    print(f"\n[+] Updated references in {count} SKILL.md packages.")


if __name__ == "__main__":
    update_references()
